//! The four read surfaces beside the tuple console: the v2 decision inspector, the full-page
//! expand and list-objects views, the JML subject lifecycle page and the API/credential page.
//!
//! Every one of them is a `GET` with query parameters (read-only, no CSRF) except the subject
//! state form, which is a CSRF-protected `POST` onto the same fenced write the lifecycle API uses.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::check;
use crate::config::ServiceScope;
use crate::error::AppError;
use crate::handlers::console::{html_with_cookie, urlencode};
use crate::handlers::ui;
use crate::handlers::{esc, shell};
use crate::handlers::{ICON_BRANCH, ICON_LIST, ICON_PLAY, ICON_SNOW};
use crate::policy::{
    Decision, DecisionContext, Effect, Resource, Risk, SubjectAccessState, SubjectAccessStatus,
};
use crate::policy_check::{self, EvaluationError};
use crate::policy_store::PolicyStoreError;
use crate::{auth, now_secs, AppState};

const DECISIONS_HTML: &str = include_str!("../../templates/decisions.html");
const EXPAND_HTML: &str = include_str!("../../templates/expand.html");
const LIST_OBJECTS_HTML: &str = include_str!("../../templates/list_objects.html");
const SUBJECTS_HTML: &str = include_str!("../../templates/subjects.html");
const API_HTML: &str = include_str!("../../templates/api.html");

// ---------------------------------------------------------------------------
// GET /decisions — the v2 decision inspector
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct DecisionQuery {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    permission: Option<String>,
    #[serde(default)]
    resource_kind: Option<String>,
    #[serde(default)]
    resource_id: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    mfa: Option<String>,
    #[serde(default)]
    break_glass: Option<String>,
}

/// `GET /decisions` — run the same evaluation `POST /api/v2/check` runs and show the typed
/// decision, its evidence and the JSON body a caller would receive.
pub async fn decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DecisionQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();
    let risk = parse_risk(opt(&q.risk));

    let subject = opt(&q.subject);
    let permission = opt(&q.permission);
    let kind = opt(&q.resource_kind);
    let resource_id = opt(&q.resource_id);
    let context = DecisionContext {
        zone: nonempty(&q.zone).map(str::to_string),
        mfa: checked(&q.mfa),
        ip: nonempty(&q.ip).map(str::to_string),
        request_id: nonempty(&q.request_id).map(str::to_string),
        break_glass: checked(&q.break_glass),
    };

    let ready = !subject.is_empty()
        && !permission.is_empty()
        && !kind.is_empty()
        && !resource_id.is_empty();

    let (verdict, decision_defs, evidence, response_code, meta) = if ready {
        let resource = Resource {
            kind: kind.to_string(),
            id: resource_id.to_string(),
        };
        let evaluated_at = now_secs();
        let outcome = match state.policy.snapshot(permission, subject).await {
            Ok(snapshot) => {
                let subject_state = snapshot
                    .subject_status
                    .as_ref()
                    .map(|status| {
                        format!(
                            "{} · {} · v{}",
                            status.state.as_str(),
                            status.source_event_id,
                            status.source_version
                        )
                    })
                    .unwrap_or_else(|| "active · no lifecycle record".to_string());
                match policy_check::evaluate(
                    snapshot,
                    subject,
                    permission,
                    &resource,
                    &context,
                    evaluated_at,
                ) {
                    Ok(response) => Ok((response, subject_state)),
                    Err(error) => Err(match error {
                        EvaluationError::UnknownCondition => "unknown-condition",
                        EvaluationError::MalformedPolicy => "malformed-policy",
                        EvaluationError::EpochInconsistent => "epoch-inconsistent",
                    }),
                }
            }
            Err(error) => Err(match error {
                PolicyStoreError::Inconsistent => "epoch-inconsistent",
                _ => "store-unavailable",
            }),
        };

        match outcome {
            Ok((response, subject_state)) => {
                let query = format!("{subject} · {permission} · {resource_id}");
                let word = match response.decision {
                    Decision::Allow => "ALLOW",
                    Decision::Deny => "DENY",
                    Decision::Indeterminate => "INDETERMINATE",
                };
                let class = match response.decision {
                    Decision::Allow => "allow",
                    Decision::Deny => "deny",
                    Decision::Indeterminate => "indeterminate",
                };
                let json = serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| "{}".to_string());
                (
                    verdict_banner(class, word, &query, &response.reason),
                    card(
                        "Decision",
                        None,
                        ui::defs(&[
                            ("Decision", esc(word.to_ascii_lowercase().as_str()), false),
                            ("Reason", esc(&response.reason), true),
                            ("Epoch", response.epoch.to_string(), true),
                            (
                                "Evaluated at",
                                esc(&crate::handlers::fmt_datetime(response.evaluated_at)),
                                false,
                            ),
                            ("Subject state", esc(&subject_state), false),
                            ("Risk", esc(risk_label(risk)), false),
                        ]),
                    ),
                    evidence_card(&response.evidence),
                    ui::code_block(
                        "POST /api/v2/check · 200",
                        ui::highlight_json(&json),
                    ),
                    format!("evaluated at epoch {}", response.epoch),
                )
            }
            Err(reason) => (
                verdict_banner("indeterminate", "INDETERMINATE", &format!("{subject} · {permission}"), reason),
                card(
                    "Decision",
                    None,
                    ui::defs(&[
                        ("Decision", "indeterminate".to_string(), false),
                        ("Reason", esc(reason), true),
                        ("Epoch", epoch.to_string(), true),
                    ]),
                ),
                empty_tile("Evidence needs a decision the store could serve"),
                ui::code_block(
                    "POST /api/v2/check · 200",
                    ui::highlight_json(&format!(
                        "{{\n  \"decision\": \"indeterminate\",\n  \"reason\": \"{reason}\",\n  \"epoch\": {epoch},\n  \"evidence\": []\n}}"
                    )),
                ),
                format!("epoch {epoch}"),
            ),
        }
    } else {
        (
            String::new(),
            empty_tile("Fill subject, permission and resource, then evaluate"),
            String::new(),
            ui::code_block(
                "POST /api/v2/check",
                ui::highlight_json(
                    "{\n  \"subject\": \"user:w33d\",\n  \"permission\": \"ledger.post.approve\",\n  \"resource\": { \"type\": \"ledger\", \"id\": \"ledger:fin-2026\" },\n  \"context\": { \"zone\": \"eu\", \"mfa\": true, \"ip\": null, \"request_id\": null, \"break_glass\": false },\n  \"risk\": \"high\"\n}",
                ),
            ),
            format!("epoch {epoch}"),
        )
    };

    let page = shell(DECISIONS_HTML, &headers, "/decisions", &id.email, epoch)
        .replace("{{EPOCH}}", &epoch.to_string())
        .replace("{{F_SUBJECT}}", &esc(subject))
        .replace("{{F_PERMISSION}}", &esc(permission))
        .replace("{{F_KIND}}", &esc(kind))
        .replace("{{F_ID}}", &esc(resource_id))
        .replace("{{F_ZONE}}", &esc(opt(&q.zone)))
        .replace("{{F_IP}}", &esc(opt(&q.ip)))
        .replace("{{F_REQUEST_ID}}", &esc(opt(&q.request_id)))
        .replace("{{RISK_OPTIONS}}", &risk_options(risk))
        .replace("{{MFA_CHECKED}}", checked_attr(context.mfa))
        .replace("{{BG_CHECKED}}", checked_attr(context.break_glass))
        .replace("{{EVAL_META}}", &esc(&meta))
        .replace("{{RESPONSE_CODE}}", &response_code)
        .replace("{{VERDICT}}", &verdict)
        .replace("{{DECISION_DEFS}}", &decision_defs)
        .replace("{{EVIDENCE}}", &evidence)
        .replace("{{ICON_PLAY}}", ICON_PLAY);
    crate::handlers::console::html_with_cookie(page, None)
}

// ---------------------------------------------------------------------------
// GET /expand
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ExpandQuery {
    #[serde(default)]
    object: Option<String>,
    #[serde(default)]
    relation: Option<String>,
}

/// `GET /expand` — who holds a relation on an object, as a tree plus flattened members.
pub async fn expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExpandQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();
    let object = opt(&q.object);
    let relation = opt(&q.relation);

    let (tree, direct, members, defs, meta, tree_count, direct_count, members_count) =
        if object.is_empty() || relation.is_empty() {
            (
                empty_tile("Name an object and a relation"),
                empty_tile("no query"),
                empty_tile("no query"),
                ui::defs(&[
                    ("Depth", format!("≤ {}", check::MAX_DEPTH), false),
                    ("Epoch", epoch.to_string(), true),
                ]),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        } else {
            let e = check::expand(state.store.as_ref(), object, relation).await;
            let usersets: Vec<String> = e
                .direct
                .iter()
                .chain(e.members.iter())
                .filter(|s| check::is_userset(s))
                .cloned()
                .collect();
            let depth = ui::tree_depth(&e.tree);
            (
                format!(
                    r#"<div class="card__pad">{}</div>"#,
                    ui::access_tree(&e.tree)
                ),
                format!(
                    r#"<div class="card__pad">{}</div>"#,
                    ui::chip_row(&e.direct, "no direct grants")
                ),
                format!(
                    r#"<div class="card__pad">{}</div>"#,
                    ui::chip_row(&e.members, "no concrete members")
                ),
                ui::defs(&[
                    ("Object", esc(object), true),
                    ("Relation", esc(relation), true),
                    (
                        "Depth reached",
                        format!("{depth} of {}", check::MAX_DEPTH),
                        false,
                    ),
                    (
                        "Usersets",
                        if usersets.is_empty() {
                            "none".to_string()
                        } else {
                            esc(&usersets.join(" · "))
                        },
                        false,
                    ),
                    ("Epoch", epoch.to_string(), true),
                ]),
                esc(&format!(
                    "{} · {} · depth {depth}",
                    ui::plural(e.direct.len(), "direct grant", "direct grants"),
                    ui::plural(e.members.len(), "member", "members"),
                )),
                ui::tree_size(&e.tree).to_string(),
                e.direct.len().to_string(),
                e.members.len().to_string(),
            )
        };

    let page = shell(EXPAND_HTML, &headers, "/decisions", &id.email, epoch)
        .replace("{{F_OBJECT}}", &esc(object))
        .replace("{{F_RELATION}}", &esc(relation))
        .replace("{{QUERY_META}}", &meta)
        .replace("{{TREE}}", &tree)
        .replace("{{TREE_COUNT}}", &tree_count)
        .replace("{{DIRECT}}", &direct)
        .replace("{{DIRECT_COUNT}}", &direct_count)
        .replace("{{MEMBERS}}", &members)
        .replace("{{MEMBERS_COUNT}}", &members_count)
        .replace("{{EXPANSION_DEFS}}", &defs)
        .replace("{{ICON_BRANCH}}", ICON_BRANCH);
    html_with_cookie(page, None)
}

// ---------------------------------------------------------------------------
// GET /list-objects
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ListObjectsQuery {
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    subject: Option<String>,
}

/// `GET /list-objects` — every object a subject reaches through one relation, with the userset it
/// came through.
pub async fn list_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListObjectsQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();
    let relation = opt(&q.relation);
    let subject = opt(&q.subject);

    let (title, count, rows, by_type, subject_defs, meta) =
        if relation.is_empty() || subject.is_empty() {
            (
                "Objects".to_string(),
                String::new(),
                empty_tile("Name a relation and a subject"),
                empty_tile("no query"),
                ui::defs(&[("Epoch", epoch.to_string(), true)]),
                String::new(),
            )
        } else {
            let objects = check::list_objects(state.store.as_ref(), relation, subject).await;
            let mut rows = String::new();
            let mut via_userset = 0usize;
            for object in &objects {
                let outcome = check::check(state.store.as_ref(), object, relation, subject).await;
                let via = outcome.via.iter().find_map(|step| {
                    let subject_part = step.split_once('@').map(|(_, s)| s).unwrap_or("");
                    check::is_userset(subject_part).then(|| subject_part.to_string())
                });
                if via.is_some() {
                    via_userset += 1;
                }
                rows.push_str(&format!(
                    r#"<div class="objrow">{object}{via}</div>"#,
                    object = ui::chip("object", object, false),
                    via = match &via {
                        Some(userset) => ui::chip("userset", userset, true),
                        None => r#"<span class="objrow__via">direct</span>"#.to_string(),
                    },
                ));
            }
            if objects.is_empty() {
                rows = empty_tile("no objects for this relation and subject");
            }

            let mut types: Vec<(String, usize)> = Vec::new();
            for object in &objects {
                let prefix = match object.split_once(':') {
                    Some((kind, _)) => format!("{kind}:"),
                    None => object.clone(),
                };
                match types.iter_mut().find(|(name, _)| *name == prefix) {
                    Some((_, n)) => *n += 1,
                    None => types.push((prefix, 1)),
                }
            }
            types.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let type_rows: Vec<(&str, String, bool)> = types
                .iter()
                .map(|(name, n)| (name.as_str(), n.to_string(), false))
                .collect();

            let status = state
                .policy
                .list_subject_statuses()
                .await
                .unwrap_or_default()
                .into_iter()
                .find(|status| status.subject == subject);
            let direct = state.store.all_tuples().await;
            let direct_count = direct
                .iter()
                .filter(|t| t.subject == subject && t.relation == relation)
                .count();
            let usersets: Vec<String> = direct
                .iter()
                .filter(|t| t.subject == subject && t.relation == "member")
                .map(|t| format!("{}#member", t.object))
                .collect();

            (
                format!("Objects · {relation} · {subject}"),
                objects.len().to_string(),
                rows,
                if type_rows.is_empty() {
                    empty_tile("no objects")
                } else {
                    ui::defs(&type_rows)
                },
                ui::defs(&[
                    ("Subject", esc(subject), true),
                    (
                        "State",
                        esc(status
                            .as_ref()
                            .map(|s| s.state.as_str())
                            .unwrap_or("active · no lifecycle record")),
                        false,
                    ),
                    (
                        "Usersets",
                        if usersets.is_empty() {
                            "none".to_string()
                        } else {
                            esc(&usersets.join(" · "))
                        },
                        false,
                    ),
                    ("Direct tuples", direct_count.to_string(), false),
                    ("Epoch", epoch.to_string(), true),
                ]),
                esc(&format!(
                    "{} · {} via usersets",
                    ui::plural(objects.len(), "object", "objects"),
                    via_userset
                )),
            )
        };

    let page = shell(LIST_OBJECTS_HTML, &headers, "/decisions", &id.email, epoch)
        .replace("{{F_RELATION}}", &esc(relation))
        .replace("{{F_SUBJECT}}", &esc(subject))
        .replace("{{QUERY_META}}", &meta)
        .replace("{{OBJECTS_TITLE}}", &esc(&title))
        .replace("{{OBJECTS_COUNT}}", &count)
        .replace("{{OBJECT_ROWS}}", &rows)
        .replace("{{BY_TYPE}}", &by_type)
        .replace("{{SUBJECT_DEFS}}", &subject_defs)
        .replace("{{ICON_LIST}}", ICON_LIST);
    html_with_cookie(page, None)
}

// ---------------------------------------------------------------------------
// GET /subjects, POST /subjects — JML lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct SubjectsQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    applied: Option<String>,
    #[serde(default)]
    replayed: Option<String>,
}

/// Subject state form. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct SubjectForm {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub source_event_id: String,
    #[serde(default)]
    pub source_version: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /subjects` — every JML lifecycle record the policy store holds, and the fenced write form.
pub async fn subjects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SubjectsQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();
    let statuses = state
        .policy
        .list_subject_statuses()
        .await
        .unwrap_or_default();
    let tuples = state.store.all_tuples().await;

    let active = statuses
        .iter()
        .filter(|s| s.state == SubjectAccessState::Active)
        .count();
    let frozen = statuses
        .iter()
        .filter(|s| s.state == SubjectAccessState::Frozen)
        .count();
    let terminated = statuses
        .iter()
        .filter(|s| s.state == SubjectAccessState::Terminated)
        .count();

    let filter = opt(&q.filter);
    let filter = if filter.is_empty() { "all" } else { filter };
    let matched: Vec<&SubjectAccessStatus> = statuses
        .iter()
        .filter(|s| filter == "all" || s.state.as_str() == filter)
        .collect();

    let mut rows = String::new();
    for status in &matched {
        let grants = tuples
            .iter()
            .filter(|t| t.subject == status.subject)
            .count();
        let usersets = tuples
            .iter()
            .filter(|t| t.subject == status.subject && t.relation == "member")
            .count();
        rows.push_str(&format!(
            r#"<div class="subrow{row_class}">
  <span class="subrow__name">{subject}</span>
  {chip}
  <span class="subrow__grants">{grants} · {usersets}</span>
  <span class="subrow__epoch">epoch {epoch}</span>
  <span class="subrow__when">{when}</span>
</div>"#,
            row_class = match status.state {
                SubjectAccessState::Frozen => " subrow--frozen",
                SubjectAccessState::Terminated => " subrow--terminated",
                SubjectAccessState::Active => "",
            },
            subject = esc(&status.subject),
            chip = lifecycle_chip(status.state),
            grants = esc(&ui::plural(grants, "grant", "grants")),
            usersets = esc(&ui::plural(usersets, "userset", "usersets")),
            epoch = status.policy_epoch,
            when = esc(&crate::handlers::fmt_datetime(status.updated_at)),
        ));
    }
    if matched.is_empty() {
        rows = empty_tile("No lifecycle records. Apply a state on the right, or let Access Governance project one.");
    }

    let banner = match (nonempty(&q.applied), nonempty(&q.replayed)) {
        (Some(subject), replayed) => format!(
            r#"<div class="banner banner--ok"><span class="banner__msg">{subject} · {word} · epoch {epoch}</span></div>"#,
            subject = esc(subject),
            word = if replayed == Some("1") {
                "already at this version"
            } else {
                "state applied"
            },
            epoch = epoch,
        ),
        _ => String::new(),
    };

    let head_sub = format!(
        "{} · {frozen} frozen · {terminated} terminated · JML lifecycle from Access Governance",
        ui::plural(statuses.len(), "subject", "subjects"),
    );

    let page = shell(SUBJECTS_HTML, &headers, "/subjects", &id.email, epoch)
        .replace("{{HEAD_SUB}}", &esc(&head_sub))
        .replace("{{T_TOTAL}}", &ui::fmt_count(statuses.len()))
        .replace("{{T_ACTIVE}}", &ui::fmt_count(active))
        .replace("{{T_FROZEN}}", &ui::fmt_count(frozen))
        .replace("{{T_TERMINATED}}", &ui::fmt_count(terminated))
        .replace("{{BANNER}}", &banner)
        .replace("{{COUNT}}", &ui::fmt_count(matched.len()))
        .replace(
            "{{FILTER_CHIPS}}",
            &subject_chips(filter, statuses.len(), active, frozen, terminated),
        )
        .replace("{{ROWS}}", &rows)
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{F_SUBJECT}}", "")
        .replace("{{STATE_OPTIONS}}", STATE_OPTIONS)
        .replace("{{ICON_SNOW}}", ICON_SNOW);
    html_with_cookie(page, set_cookie)
}

/// `POST /subjects` — apply a JML state through the same fenced write the lifecycle API uses.
pub async fn set_subject_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SubjectForm>,
) -> Result<Response, AppError> {
    let id = auth::identity(&headers);
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Unauthorized("CSRF token mismatch".to_string()));
    }
    let subject = form.subject.trim();
    let source_event_id = form.source_event_id.trim();
    if subject.is_empty() || source_event_id.is_empty() {
        return Err(AppError::InvalidRequest(
            "subject and source_event_id are required".to_string(),
        ));
    }
    let access_state = match form.state.trim() {
        "active" => SubjectAccessState::Active,
        "frozen" => SubjectAccessState::Frozen,
        "terminated" => SubjectAccessState::Terminated,
        other => {
            return Err(AppError::InvalidRequest(format!(
                "state must be active, frozen or terminated (got {other:?})"
            )))
        }
    };
    let source_version: i64 = form.source_version.trim().parse().map_err(|_| {
        AppError::InvalidRequest("source_version must be a positive whole number".to_string())
    })?;

    let (epoch, replayed) = state
        .policy
        .set_subject_status(
            subject,
            access_state,
            source_event_id,
            source_version,
            now_secs(),
        )
        .await
        .map_err(|error| match error {
            PolicyStoreError::StaleVersion => AppError::InvalidRequest(
                "source_version is behind the stored version — the write is fenced".to_string(),
            ),
            PolicyStoreError::Conflict => AppError::InvalidRequest(
                "this source_version already carries a different state".to_string(),
            ),
            _ => AppError::Internal("policy store unavailable".to_string()),
        })?;

    state.audit.emit(AuditEvent::warning(
        "verdict.subject.status",
        &id.email,
        subject,
        &format!(
            "state={} source_version={source_version} epoch={epoch} (console)",
            access_state.as_str()
        ),
    ));

    Ok(crate::handlers::console::redirect_to(&format!(
        "/subjects?applied={}&replayed={}",
        urlencode(subject),
        if replayed { "1" } else { "0" }
    )))
}

// ---------------------------------------------------------------------------
// GET /api — endpoints and credentials
// ---------------------------------------------------------------------------

/// `GET /api` — the service surface: every route with the credential scope that opens it, two
/// worked calls, and the three credentials as fingerprints. Token VALUES are never rendered: an
/// SSO console reader must not be able to lift a service credential from the page.
pub async fn api_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let id = auth::identity(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();

    let endpoints = [
        ("GET", "/healthz", "200 ok", "none"),
        ("GET", "/", "console HTML", "sso"),
        ("POST", "/", "add tuple (CSRF)", "sso"),
        ("GET", "/delete", "confirm delete (CSRF on the POST)", "sso"),
        ("POST", "/delete", "delete tuple (CSRF)", "sso"),
        ("POST", "/import", "bulk import (CSRF)", "sso"),
        ("GET", "/export", "tuples.json · tuples.csv", "sso"),
        ("GET", "/decisions", "decision inspector HTML", "sso"),
        ("GET", "/expand", "expand HTML", "sso"),
        ("GET", "/list-objects", "list-objects HTML", "sso"),
        ("GET", "/subjects", "subject lifecycle HTML", "sso"),
        ("POST", "/subjects", "set subject state (CSRF)", "sso"),
        ("GET", "/api", "this page", "sso"),
        (
            "POST",
            "/api/check",
            "{object,relation,subject} → {allowed,via}",
            "decision",
        ),
        (
            "POST",
            "/api/v2/check",
            "permission/resource/context → decision + epoch + evidence",
            "decision",
        ),
        (
            "POST",
            "/api/list-objects",
            "{relation,subject} → {objects}",
            "decision",
        ),
        (
            "POST",
            "/api/expand",
            "{object,relation} → {direct,members}",
            "decision",
        ),
        (
            "POST",
            "/api/v2/projections",
            "fenced desired-state replacement for one grant",
            "projection",
        ),
        (
            "POST",
            "/api/tuples",
            "legacy tuple write → {ok,written}",
            "projection",
        ),
        (
            "POST",
            "/api/tuples/delete",
            "legacy tuple delete → {ok,deleted}",
            "projection",
        ),
        (
            "POST",
            "/api/tuples/import",
            "legacy bulk import",
            "projection",
        ),
        ("POST", "/api/tuples/export", "legacy export", "projection"),
        (
            "POST",
            "/api/v2/subject-status",
            "fenced JML active/frozen/terminated for one subject",
            "lifecycle",
        ),
    ];
    let mut rows = String::new();
    for (method, path, desc, scope) in endpoints {
        rows.push_str(&format!(
            r#"<div class="eprow"><span class="method method--{m_class}">{method}</span><span class="eprow__path">{path}</span><span class="eprow__desc">{desc}</span><span class="scope scope--{scope}">{scope}</span></div>"#,
            m_class = method.to_ascii_lowercase(),
            method = method,
            path = esc(path),
            desc = esc(desc),
            scope = scope,
        ));
    }

    let mut tokens = String::new();
    for scope in [
        ServiceScope::Decision,
        ServiceScope::Projection,
        ServiceScope::Lifecycle,
    ] {
        let (state_text, fingerprint) = match state.config.service_credentials.token(scope) {
            Some(token) => (
                format!("configured · {} bytes", token.len()),
                format!("sha256 {}", &hex_digest(token)[..16]),
            ),
            None => (
                "not configured · development mode".to_string(),
                "no fingerprint".to_string(),
            ),
        };
        tokens.push_str(&format!(
            r#"<div class="token"><span class="token__name">{name}</span><span class="token__value">{fingerprint}</span><span class="token__state">{state}</span></div>"#,
            name = scope.env_var(),
            fingerprint = esc(&fingerprint),
            state = esc(&state_text),
        ));
    }

    let examples = format!(
        "{}{}",
        ui::code_block(
            "POST /api/check",
            ui::highlight_json(
                "curl -X POST https://authz.w33d.xyz/api/check \\\n  -H \"Authorization: Bearer $VERDICT_DECISION_TOKEN\" \\\n  -d '{\"object\":\"doc:secret\",\"relation\":\"viewer\",\"subject\":\"user:w33d\"}'\n\n{\"allowed\":true,\"via\":[\"doc:secret#viewer@group:eng#member\",\"group:eng#member@user:w33d\"]}"
            ),
        ),
        ui::code_block(
            "POST /api/v2/subject-status",
            ui::highlight_json(
                "curl -X POST https://authz.w33d.xyz/api/v2/subject-status \\\n  -H \"Authorization: Bearer $VERDICT_LIFECYCLE_TOKEN\" \\\n  -d '{\"subject\":\"user:e.park\",\"state\":\"frozen\",\"source_event_id\":\"evt_ag_91c0\",\"source_version\":4}'"
            ),
        ),
    );

    let page = shell(API_HTML, &headers, "/api", &id.email, epoch)
        .replace("{{ENDPOINT_COUNT}}", &endpoints.len().to_string())
        .replace("{{ENDPOINTS}}", &rows)
        .replace("{{EXAMPLES}}", &examples)
        .replace("{{TOKENS}}", &tokens)
        .replace(
            "{{AUDIT_SINK}}",
            if state.audit.is_enabled() {
                "Watchtower · AUDIT_ENABLED"
            } else {
                "disabled · AUDIT_ENABLED unset"
            },
        );
    html_with_cookie(page, None)
}

// ---------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------

const STATE_OPTIONS: &str = r#"<option value="frozen">frozen</option><option value="active">active</option><option value="terminated">terminated</option>"#;

fn card(title: &str, count: Option<String>, body: String) -> String {
    format!(
        r#"<section class="card"><div class="card__head"><h2>{title}</h2>{count}</div>{body}</section>"#,
        title = esc(title),
        count = count
            .map(|c| format!(r#"<span class="card__count">{}</span>"#, esc(&c)))
            .unwrap_or_default(),
        body = body,
    )
}

fn verdict_banner(class: &str, word: &str, query: &str, note: &str) -> String {
    format!(
        r#"<div class="verdict verdict--{class}"><div class="verdict__head"><span class="verdict__word">{word}</span><span class="verdict__query">{query}</span></div><span class="verdict__note">{note}</span></div>"#,
        class = class,
        word = word,
        query = esc(query),
        note = esc(note),
    )
}

fn evidence_card(evidence: &[crate::policy::Evidence]) -> String {
    if evidence.is_empty() {
        return card(
            "Evidence",
            Some("0".to_string()),
            empty_tile("no edge matched"),
        );
    }
    let mut rows = String::new();
    for item in evidence {
        let cond = match item.condition_result.as_str() {
            "true" | "matched" => ("cond-true", item.condition_result.as_str()),
            "false" => ("cond-false", "false"),
            other => ("cond-none", other),
        };
        rows.push_str(&format!(
            r#"<div class="evrow{deny}"><div class="evrow__top"><span class="chip chip--{effect}">{effect}</span><span class="evrow__id">{edge}</span><span class="evrow__grant">grant {grant}</span><span class="evrow__spacer"></span><span class="chip chip--{cond_class}">{cond}</span></div><span class="evrow__path">{path}</span></div>"#,
            deny = if item.effect == Effect::Deny { " evrow--deny" } else { "" },
            effect = item.effect.as_str(),
            edge = esc(&item.edge_id),
            grant = esc(&item.source_grant_id),
            cond_class = cond.0,
            cond = esc(cond.1),
            path = esc(&item.path.join(" → ")),
        ));
    }
    card("Evidence", Some(evidence.len().to_string()), rows)
}

fn empty_tile(text: &str) -> String {
    format!(
        r#"<div class="card__pad"><div class="empty-tile">{}</div></div>"#,
        esc(text)
    )
}

fn lifecycle_chip(state: SubjectAccessState) -> String {
    let (class, icon, label) = match state {
        SubjectAccessState::Active => ("active", crate::handlers::ICON_USER_CHECK, "Active"),
        SubjectAccessState::Frozen => ("frozen", crate::handlers::ICON_SNOW, "Frozen"),
        SubjectAccessState::Terminated => {
            ("terminated", crate::handlers::ICON_USER_X, "Terminated")
        }
    };
    format!(r#"<span class="chip chip--{class}">{icon}{label}</span>"#)
}

fn subject_chips(
    active_filter: &str,
    total: usize,
    active: usize,
    frozen: usize,
    terminated: usize,
) -> String {
    let mut out = String::new();
    for (value, label, count) in [
        ("all", "All", total),
        ("active", "active", active),
        ("frozen", "frozen", frozen),
        ("terminated", "terminated", terminated),
    ] {
        out.push_str(&format!(
            r#"<a class="fchip{active}" href="/subjects?filter={value}">{label}<span class="fchip__n">{count}</span></a>"#,
            active = if value == active_filter { " is-active" } else { "" },
            value = value,
            label = label,
            count = count,
        ));
    }
    out
}

fn risk_options(current: Risk) -> String {
    let mut out = String::new();
    for (value, label) in [
        (Risk::Low, "low"),
        (Risk::Medium, "medium"),
        (Risk::High, "high"),
        (Risk::Critical, "critical"),
    ] {
        out.push_str(&format!(
            r#"<option value="{label}"{selected}>{label}</option>"#,
            label = label,
            selected = if value == current { " selected" } else { "" },
        ));
    }
    out
}

fn parse_risk(value: &str) -> Risk {
    match value {
        "critical" => Risk::Critical,
        "high" => Risk::High,
        "medium" => Risk::Medium,
        _ => Risk::Low,
    }
}

fn risk_label(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
        Risk::Critical => "critical",
    }
}

fn hex_digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn checked(field: &Option<String>) -> bool {
    matches!(field.as_deref(), Some("on") | Some("true") | Some("1"))
}

fn checked_attr(on: bool) -> &'static str {
    if on {
        " checked"
    } else {
        ""
    }
}

fn nonempty(field: &Option<String>) -> Option<&str> {
    field.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn opt(field: &Option<String>) -> &str {
    field.as_deref().map(str::trim).unwrap_or("")
}

/// Unused import guard: the module re-exports the status code type used by callers.
#[allow(dead_code)]
const _STATUS: StatusCode = StatusCode::OK;

//! The SSO admin console (`authz.w33d.xyz/`).
//!
//! Browser UI behind the gateway `auth=sso` route: the gateway injects the verified `X-Auth-*`
//! identity, which Verdict trusts (internal-only). Operators can browse, add, and delete relation
//! tuples; run a live **check tester** (object/relation/subject -> allowed + the resolution path);
//! **expand** a relation (who holds it on an object); and **list objects** (what a subject can do).
//!
//! The three read tools are `GET /` with query parameters (read-only — no CSRF needed). Tuple
//! mutations (`POST /`, `POST /delete`, `POST /import`) are double-submit CSRF protected, and a
//! delete is confirmed on its own page (`GET /delete`) so the flow works without JavaScript.
//! Every interpolated field is HTML-escaped; the inputs are opaque tuple tokens, never markup.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::check;
use crate::error::AppError;
use crate::handlers::ui;
use crate::handlers::{esc, fmt_date, shell, ICON_BRANCH, ICON_DOWNLOAD, ICON_LIST};
use crate::handlers::{ICON_PLUS, ICON_SEARCH, ICON_TRASH, ICON_UPLOAD};
use crate::store::Tuple;
use crate::tuple_io;
use crate::{auth, now_nanos, now_secs, AppState};

const CONSOLE_HTML: &str = include_str!("../../templates/console.html");
const CONFIRM_HTML: &str = include_str!("../../templates/confirm.html");

/// Tuples shown per console page.
const PAGE_SIZE: usize = 10;

/// Query parameters driving the browse view and the three read tools. All optional; a tool renders
/// its result only when its inputs are present and non-empty.
#[derive(Debug, Default, Deserialize)]
pub struct ConsoleQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    ck_object: Option<String>,
    #[serde(default)]
    ck_relation: Option<String>,
    #[serde(default)]
    ck_subject: Option<String>,
    #[serde(default)]
    ex_object: Option<String>,
    #[serde(default)]
    ex_relation: Option<String>,
    #[serde(default)]
    lo_relation: Option<String>,
    #[serde(default)]
    lo_subject: Option<String>,
    #[serde(default)]
    import_total: Option<usize>,
    #[serde(default)]
    import_written: Option<usize>,
    #[serde(default)]
    import_skipped: Option<usize>,
}

/// Add/delete form body, and the confirm page's query. Identity is NEVER taken from the form —
/// only from the gateway headers.
#[derive(Debug, Default, Deserialize)]
pub struct TupleForm {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Bulk import form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct ImportForm {
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /export?format=json|csv`.
#[derive(Debug, Default, Deserialize)]
pub struct ExportQuery {
    #[serde(default)]
    pub format: Option<String>,
}

// ---------------------------------------------------------------------------
// GET / — the console
// ---------------------------------------------------------------------------

/// `GET /` — render the console: the tuple table (searched, filtered, paged), the add and import
/// forms, and the three read tools with any results.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsoleQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();

    let tuples = state.store.all_tuples().await;
    let total = tuples.len();
    let usersets = tuples
        .iter()
        .filter(|t| check::is_userset(&t.subject))
        .count();
    let objects = distinct_objects(&tuples);

    let search = nonempty(&q.q).unwrap_or("");
    let filter = nonempty(&q.filter).unwrap_or("all");
    let matched: Vec<&Tuple> = tuples
        .iter()
        .filter(|t| matches_search(t, search) && matches_filter(t, filter))
        .collect();
    let page = q.page.unwrap_or(1).max(1);
    let start = (page - 1) * PAGE_SIZE;
    let shown: Vec<&Tuple> = matched
        .iter()
        .skip(start)
        .take(PAGE_SIZE)
        .copied()
        .collect();

    let head_sub = format!(
        "{} · {} · {} · expansion depth {}",
        ui::plural(total, "tuple", "tuples"),
        ui::plural(usersets, "userset", "usersets"),
        format_args!("epoch {epoch}"),
        check::MAX_DEPTH,
    );

    let page_html = shell(CONSOLE_HTML, &headers, "/", &id.email, epoch)
        .replace("{{HEAD_SUB}}", &esc(&head_sub))
        .replace("{{T_TUPLES}}", &ui::fmt_count(total))
        .replace("{{T_USERSETS}}", &ui::fmt_count(usersets))
        .replace("{{T_OBJECTS}}", &ui::fmt_count(objects.len()))
        .replace("{{T_EPOCH}}", &epoch.to_string())
        .replace("{{COUNT}}", &ui::fmt_count(matched.len()))
        .replace("{{Q}}", &esc(search))
        .replace(
            "{{FILTER_CHIPS}}",
            &filter_chips(&tuples, &objects, filter, search),
        )
        .replace("{{ROWS}}", &render_rows(&shown))
        .replace(
            "{{PAGER}}",
            &pager(search, filter, page, matched.len(), shown.len()),
        )
        .replace("{{CSRF}}", &esc(&csrf))
        .replace(
            "{{EXPORT_META}}",
            &esc(&format!(
                "{} · {}",
                ui::plural(total, "tuple", "tuples"),
                export_size(&tuples)
            )),
        )
        .replace("{{IMPORT_RESULT}}", &render_import_result(&q))
        .replace("{{CK_OBJECT}}", &esc(opt(&q.ck_object)))
        .replace("{{CK_RELATION}}", &esc(opt(&q.ck_relation)))
        .replace("{{CK_SUBJECT}}", &esc(opt(&q.ck_subject)))
        .replace("{{CHECK_RESULT}}", &render_check(&state, &q).await)
        .replace("{{CK_META}}", &esc(&format!("epoch {epoch}")))
        .replace("{{EX_OBJECT}}", &esc(opt(&q.ex_object)))
        .replace("{{EX_RELATION}}", &esc(opt(&q.ex_relation)))
        .replace("{{EXPAND_RESULT}}", &render_expand(&state, &q).await)
        .replace("{{LO_RELATION}}", &esc(opt(&q.lo_relation)))
        .replace("{{LO_SUBJECT}}", &esc(opt(&q.lo_subject)))
        .replace("{{LISTOBJ_RESULT}}", &render_list_objects(&state, &q).await)
        .replace("{{ICON_PLUS}}", ICON_PLUS)
        .replace("{{ICON_DOWNLOAD}}", ICON_DOWNLOAD)
        .replace("{{ICON_UPLOAD}}", ICON_UPLOAD)
        .replace("{{ICON_SEARCH}}", ICON_SEARCH)
        .replace("{{ICON_BRANCH}}", ICON_BRANCH)
        .replace("{{ICON_LIST}}", ICON_LIST);

    html_with_cookie(page_html, set_cookie)
}

// ---------------------------------------------------------------------------
// POST / — add a tuple
// ---------------------------------------------------------------------------

/// `POST /` — add a relation tuple (CSRF-checked), then bounce back to the console.
pub async fn add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TupleForm>,
) -> Result<Response, AppError> {
    let id = auth::identity(&headers);
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Unauthorized("CSRF token mismatch".to_string()));
    }
    let (object, relation, subject) = validate(&form)?;

    let tuple = Tuple {
        id: format!("tup_{}", now_nanos()),
        object: object.clone(),
        relation: relation.clone(),
        subject: subject.clone(),
        created_at: now_secs(),
    };
    let written = state.store.add_tuple(&tuple).await?;
    if written {
        state.audit.emit(AuditEvent::info(
            "verdict.tuple.write",
            &id.email,
            &check::tuple_label(&object, &relation, &subject),
            "added (console)",
        ));
        tracing::info!(object = %object, relation = %relation, subject = %subject, "tuple added");
    }
    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// GET /delete — confirm, POST /delete — remove
// ---------------------------------------------------------------------------

/// `GET /delete?object=&relation=&subject=` — the confirmation page for one tuple. Read-only, so
/// no CSRF is required to reach it; the POST it renders carries the token.
pub async fn confirm_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(form): Query<TupleForm>,
) -> Result<Response, AppError> {
    let id = auth::identity(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let epoch = state.policy.epoch().await.unwrap_or_default();
    let (object, relation, subject) = validate(&form)?;

    let consequence = format!(
        "Checks that reach {subject} only through {label} flip to DENY at the next epoch. Audit: verdict.tuple.write · actor {actor}.",
        subject = subject,
        label = check::tuple_label(&object, &relation, &subject),
        actor = id.email,
    );
    let page = shell(CONFIRM_HTML, &headers, "/", &id.email, epoch)
        .replace(
            "{{TUPLE_LINE}}",
            &ui::tuple_line(&object, &relation, &subject, false),
        )
        .replace("{{CONSEQUENCE}}", &esc(&consequence))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{OBJECT}}", &esc(&object))
        .replace("{{RELATION}}", &esc(&relation))
        .replace("{{SUBJECT}}", &esc(&subject))
        .replace("{{ICON_TRASH}}", ICON_TRASH);
    Ok(html_with_cookie(page, set_cookie))
}

/// `POST /delete` — remove a relation tuple (CSRF-checked), then bounce back to the console.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TupleForm>,
) -> Result<Response, AppError> {
    let id = auth::identity(&headers);
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Unauthorized("CSRF token mismatch".to_string()));
    }
    let (object, relation, subject) = validate(&form)?;

    let deleted = state
        .store
        .delete_tuple(&object, &relation, &subject)
        .await?;
    if deleted {
        state.audit.emit(AuditEvent::warning(
            "verdict.tuple.write",
            &id.email,
            &check::tuple_label(&object, &relation, &subject),
            "deleted (console)",
        ));
        tracing::info!(object = %object, relation = %relation, subject = %subject, "tuple deleted");
    }
    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// POST /import — bulk import tuples
// ---------------------------------------------------------------------------

/// `POST /import` — bulk-import relation tuples (CSRF-checked), then bounce back to the console.
pub async fn import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ImportForm>,
) -> Result<Response, AppError> {
    let id = auth::identity(&headers);
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Unauthorized("CSRF token mismatch".to_string()));
    }

    let format = if form.format.trim().is_empty() {
        "json"
    } else {
        form.format.trim()
    };
    let rows =
        tuple_io::parse_import_text(format, &form.content).map_err(AppError::InvalidRequest)?;
    let report = tuple_io::write_import(state.store.as_ref(), &rows).await?;
    state.audit.emit(AuditEvent::info(
        "verdict.tuple.import",
        &id.email,
        "tuples",
        &format!(
            "imported {} tuple(s); {} duplicate/existing (console)",
            report.written, report.skipped
        ),
    ));
    tracing::info!(
        total = report.total,
        written = report.written,
        skipped = report.skipped,
        "tuple import completed"
    );

    Ok(redirect(&format!(
        "/?import_total={}&import_written={}&import_skipped={}",
        report.total, report.written, report.skipped
    )))
}

// ---------------------------------------------------------------------------
// GET /export — download tuples
// ---------------------------------------------------------------------------

/// `GET /export?format=json|csv` — export all tuples. Read-only; gateway SSO protects the page.
pub async fn export(State(state): State<AppState>, Query(q): Query<ExportQuery>) -> Response {
    let tuples = state.store.all_tuples().await;
    match q
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => download_response(
            "application/json; charset=utf-8",
            "tuples.json",
            tuple_io::export_json(&tuples),
        ),
        "csv" => download_response(
            "text/csv; charset=utf-8",
            "tuples.csv",
            tuple_io::export_csv(&tuples),
        ),
        other => (
            StatusCode::BAD_REQUEST,
            Html(crate::handlers::error_page(
                StatusCode::BAD_REQUEST,
                &format!("unsupported export format {other:?} (use json or csv)"),
            )),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Every distinct `type:` prefix in the tuple set, with its tuple count, most common first.
fn distinct_objects(tuples: &[Tuple]) -> Vec<String> {
    let mut objects: Vec<String> = tuples.iter().map(|t| t.object.clone()).collect();
    objects.sort();
    objects.dedup();
    objects
}

fn object_types(tuples: &[Tuple]) -> Vec<(String, usize)> {
    let mut types: Vec<(String, usize)> = Vec::new();
    for tuple in tuples {
        let prefix = match tuple.object.split_once(':') {
            Some((kind, _)) => format!("{kind}:"),
            None => continue,
        };
        match types.iter_mut().find(|(name, _)| *name == prefix) {
            Some((_, count)) => *count += 1,
            None => types.push((prefix, 1)),
        }
    }
    types.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    types.truncate(4);
    types
}

fn matches_search(tuple: &Tuple, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.to_ascii_lowercase();
    tuple.object.to_ascii_lowercase().contains(&needle)
        || tuple.relation.to_ascii_lowercase().contains(&needle)
        || tuple.subject.to_ascii_lowercase().contains(&needle)
}

fn matches_filter(tuple: &Tuple, filter: &str) -> bool {
    match filter {
        "all" | "" => true,
        "usersets" => check::is_userset(&tuple.subject),
        prefix => tuple.object.starts_with(prefix),
    }
}

/// The filter chip row: All · usersets · the four commonest object types, each with its count.
fn filter_chips(tuples: &[Tuple], _objects: &[String], active: &str, search: &str) -> String {
    let mut chips = String::new();
    let mut push = |value: &str, label: &str, count: usize| {
        let mut href = format!("/?filter={}", urlencode(value));
        if !search.is_empty() {
            href.push_str(&format!("&q={}", urlencode(search)));
        }
        chips.push_str(&format!(
            r#"<a class="fchip{active}" href="{href}">{label}<span class="fchip__n">{count}</span></a>"#,
            active = if value == active { " is-active" } else { "" },
            href = esc(&href),
            label = esc(label),
            count = ui::fmt_count(count),
        ));
    };
    push("all", "All", tuples.len());
    push(
        "usersets",
        "usersets",
        tuples
            .iter()
            .filter(|t| check::is_userset(&t.subject))
            .count(),
    );
    for (prefix, count) in object_types(tuples) {
        push(&prefix, &prefix, count);
    }
    chips
}

/// The pagination footer: Previous · `1–10 of 1 284` · Next.
fn pager(search: &str, filter: &str, page: usize, total: usize, shown: usize) -> String {
    if total <= PAGE_SIZE {
        return String::new();
    }
    let start = (page - 1) * PAGE_SIZE + 1;
    let end = start + shown.saturating_sub(1);
    let link = |target: usize, label: &str, enabled: bool| {
        if !enabled {
            return format!(
                r#"<span class="btn btn-secondary btn-sm" aria-disabled="true">{label}</span>"#,
                label = esc(label)
            );
        }
        let mut href = format!("/?page={target}");
        if !search.is_empty() {
            href.push_str(&format!("&q={}", urlencode(search)));
        }
        if filter != "all" {
            href.push_str(&format!("&filter={}", urlencode(filter)));
        }
        format!(
            r#"<a class="btn btn-secondary btn-sm" href="{href}">{label}</a>"#,
            href = esc(&href),
            label = esc(label),
        )
    };
    format!(
        r#"<div class="table-meta"><span class="table-meta__showing"></span><div class="pagination">{prev}<span class="pagination__range">{start}–{end} of {total}</span>{next}</div></div>"#,
        prev = link(page - 1, "Previous", page > 1),
        start = start,
        end = end,
        total = ui::fmt_count(total),
        next = link(page + 1, "Next", end < total),
    )
}

/// One table row per tuple: three typed chips, the creation date, the write source and a delete
/// link into the confirmation page.
fn render_rows(tuples: &[&Tuple]) -> String {
    if tuples.is_empty() {
        return r#"<tr><td colspan="6" class="empty">No tuples match. Add one below, or clear the filter.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for t in tuples {
        let href = format!(
            "/delete?object={}&relation={}&subject={}",
            urlencode(&t.object),
            urlencode(&t.relation),
            urlencode(&t.subject),
        );
        out.push_str(&format!(
            r#"<tr>
  <td>{object}</td>
  <td>{relation}</td>
  <td>{subject}</td>
  <td class="c-when">{date}</td>
  <td class="c-src">console</td>
  <td class="c-act"><a class="btn btn-danger-soft btn-sm" href="{href}">Delete</a></td>
</tr>"#,
            object = ui::chip("object", &t.object, false),
            relation = ui::chip("relation", &t.relation, false),
            subject = ui::subject_chip(&t.subject, false),
            date = esc(&fmt_date(t.created_at)),
            href = esc(&href),
        ));
    }
    out
}

/// Render the check-tester result panel (empty string when the tester was not run).
async fn render_check(state: &AppState, q: &ConsoleQuery) -> String {
    let (Some(object), Some(relation), Some(subject)) = (
        nonempty(&q.ck_object),
        nonempty(&q.ck_relation),
        nonempty(&q.ck_subject),
    ) else {
        return String::new();
    };

    let outcome = check::check(state.store.as_ref(), object, relation, subject).await;
    let (klass, word, note) = if outcome.allowed {
        (
            "allow",
            "ALLOW",
            format!("granted in {} steps", outcome.via.len()),
        )
    } else {
        (
            "deny",
            "DENY",
            format!(
                "no direct tuple and no userset reaches this subject within {} levels",
                check::MAX_DEPTH
            ),
        )
    };

    let mut steps = String::new();
    if outcome.via.is_empty() {
        steps.push_str(&format!(r#"<p class="note">{}</p>"#, esc("no grant path")));
    } else {
        steps.push_str(r#"<ol class="path">"#);
        for (index, step) in outcome.via.iter().enumerate() {
            let (obj, rel, sub) = split_label(step);
            steps.push_str(&format!(
                r#"<li class="path__step"><span class="path__no">{no}</span><div class="path__body"><span class="tline">{line}</span><span class="path__note">{note}</span></div></li>"#,
                no = index + 1,
                line = ui::tuple_line(&obj, &rel, &sub, true),
                note = esc(if check::is_userset(&sub) {
                    "userset · expands to its members"
                } else if index == 0 {
                    "direct tuple on the object"
                } else {
                    "reaches the subject"
                }),
            ));
        }
        steps.push_str("</ol>");
    }

    format!(
        r#"<div class="verdict verdict--{klass}"><div class="verdict__head"><span class="verdict__word">{word}</span><span class="verdict__query">{query}</span></div><span class="verdict__note">{note}</span></div><div class="card__pad">{steps}</div>"#,
        klass = klass,
        word = word,
        query = esc(&check::tuple_label(object, relation, subject)),
        note = esc(&note),
        steps = steps,
    )
}

/// Render the expand result panel (empty string when expand was not run).
async fn render_expand(state: &AppState, q: &ConsoleQuery) -> String {
    let (Some(object), Some(relation)) = (nonempty(&q.ex_object), nonempty(&q.ex_relation)) else {
        return String::new();
    };

    let e = check::expand(state.store.as_ref(), object, relation).await;
    format!(
        r#"<div class="tline">{query}</div>
<span class="sublabel">Direct grants</span>{direct}
<span class="sublabel">Resolved members</span>{members}
<span class="sublabel">Access tree</span>{tree}"#,
        query =
            ui::chip("object", object, true).to_string() + &ui::chip("relation", relation, true),
        direct = ui::chip_row(&e.direct, "no direct grants"),
        members = ui::chip_row(&e.members, "no concrete members"),
        tree = ui::access_tree(&e.tree),
    )
}

/// Render the list-objects result panel (empty string when it was not run).
async fn render_list_objects(state: &AppState, q: &ConsoleQuery) -> String {
    let (Some(relation), Some(subject)) = (nonempty(&q.lo_relation), nonempty(&q.lo_subject))
    else {
        return String::new();
    };

    let objects = check::list_objects(state.store.as_ref(), relation, subject).await;
    let mut chips = String::from(r#"<div class="chips">"#);
    for object in &objects {
        chips.push_str(&ui::chip("object", object, true));
    }
    chips.push_str("</div>");
    if objects.is_empty() {
        chips = r#"<p class="note">no objects</p>"#.to_string();
    }

    format!(
        r#"<div class="tline">{subject}<span class="tsep">·</span>{relation}</div>{chips}<p class="note">{count}</p>"#,
        subject = ui::subject_chip(subject, true),
        relation = ui::chip("relation", relation, true),
        chips = chips,
        count = esc(&ui::plural(objects.len(), "object", "objects")),
    )
}

fn render_import_result(q: &ConsoleQuery) -> String {
    let (Some(total), Some(written), Some(skipped)) =
        (q.import_total, q.import_written, q.import_skipped)
    else {
        return String::new();
    };
    format!(
        r#"<div class="banner banner--ok"><span class="banner__msg">Imported {written} of {total} · {skipped} duplicate or existing</span></div>"#,
        total = total,
        written = written,
        skipped = skipped,
    )
}

/// The exported payload size, in the unit the operator will recognise.
fn export_size(tuples: &[Tuple]) -> String {
    let bytes = tuple_io::export_json(tuples).len();
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.0} KiB", bytes as f64 / 1024.0)
    }
}

/// Split `object#relation@subject` back into its three parts for chip rendering.
fn split_label(label: &str) -> (String, String, String) {
    let (object, rest) = label.split_once('#').unwrap_or((label, ""));
    let (relation, subject) = rest.split_once('@').unwrap_or((rest, ""));
    (
        object.to_string(),
        relation.to_string(),
        subject.to_string(),
    )
}

/// Percent-encode a query value (tuple tokens carry `#`, `:` and `@`).
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Validate + trim an add/delete form's triple. Each field non-empty, no internal whitespace.
fn validate(form: &TupleForm) -> Result<(String, String, String), AppError> {
    let object = form.object.trim();
    let relation = form.relation.trim();
    let subject = form.subject.trim();
    if object.is_empty() || relation.is_empty() || subject.is_empty() {
        return Err(AppError::InvalidRequest(
            "object, relation and subject are required".to_string(),
        ));
    }
    for (label, v) in [
        ("object", object),
        ("relation", relation),
        ("subject", subject),
    ] {
        if v.split_whitespace().count() != 1 {
            return Err(AppError::InvalidRequest(format!(
                "{label} must not contain whitespace"
            )));
        }
    }
    Ok((
        object.to_string(),
        relation.to_string(),
        subject.to_string(),
    ))
}

/// Borrow a trimmed non-empty value from an optional query field.
fn nonempty(opt: &Option<String>) -> Option<&str> {
    opt.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// An optional query field as a display string ("" when absent).
fn opt(field: &Option<String>) -> &str {
    field.as_deref().unwrap_or("")
}

/// A 303 redirect (post/redirect/get).
pub fn redirect_to(location: &str) -> Response {
    redirect(location)
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
    )
        .into_response()
}

fn download_response(content_type: &'static str, filename: &'static str, body: String) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .expect("valid content-disposition"),
    );
    resp
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
pub fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

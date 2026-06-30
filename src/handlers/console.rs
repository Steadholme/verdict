//! The SSO admin console (`authz.w33d.xyz/`).
//!
//! Browser UI behind the gateway `auth=sso` route: the gateway injects the verified `X-Auth-*`
//! identity, which Verdict trusts (internal-only). Operators can browse, add, and delete relation
//! tuples; run a live **check tester** (object/relation/subject -> allowed + the resolution path);
//! **expand** a relation (who holds it on an object); and **list objects** (what a subject can do).
//!
//! The three read tools are `GET /` with query parameters (read-only — no CSRF needed). The two
//! mutations (`POST /`, `POST /delete`) are double-submit CSRF protected. Every interpolated field
//! is HTML-escaped; the inputs are opaque tuple tokens, never markup.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::check;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, topbar, APP_CSS};
use crate::store::Tuple;
use crate::{auth, now_nanos, now_secs, AppState};

const CONSOLE_HTML: &str = include_str!("../../templates/console.html");

/// Query parameters driving the three read tools. All optional; a tool renders its result only
/// when its inputs are present and non-empty.
#[derive(Debug, Default, Deserialize)]
pub struct ConsoleQuery {
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
}

/// Add-tuple form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
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

// ---------------------------------------------------------------------------
// GET / — the console
// ---------------------------------------------------------------------------

/// `GET /` — render the console: the read tools (with any results), the add form, and the tuple
/// table.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsoleQuery>,
) -> Response {
    let id = auth::identity(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let tuples = state.store.list_tuples().await;
    let count = tuples.len();
    let rows = render_rows(&tuples, &csrf);

    let check_result = render_check(&state, &q).await;
    let expand_result = render_expand(&state, &q).await;
    let listobj_result = render_list_objects(&state, &q).await;

    let page = CONSOLE_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", crate::handlers::SHIELD_SVG)
        .replace("{{TOPBAR}}", &topbar("Authorization", &id.email))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{COUNT}}", &count.to_string())
        .replace("{{ROWS}}", &rows)
        .replace("{{CK_OBJECT}}", &esc(opt(&q.ck_object)))
        .replace("{{CK_RELATION}}", &esc(opt(&q.ck_relation)))
        .replace("{{CK_SUBJECT}}", &esc(opt(&q.ck_subject)))
        .replace("{{CHECK_RESULT}}", &check_result)
        .replace("{{EX_OBJECT}}", &esc(opt(&q.ex_object)))
        .replace("{{EX_RELATION}}", &esc(opt(&q.ex_relation)))
        .replace("{{EXPAND_RESULT}}", &expand_result)
        .replace("{{LO_RELATION}}", &esc(opt(&q.lo_relation)))
        .replace("{{LO_SUBJECT}}", &esc(opt(&q.lo_subject)))
        .replace("{{LISTOBJ_RESULT}}", &listobj_result);

    html_with_cookie(page, set_cookie)
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
// POST /delete — remove a tuple
// ---------------------------------------------------------------------------

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

    let deleted = state.store.delete_tuple(&object, &relation, &subject).await?;
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
// Render helpers
// ---------------------------------------------------------------------------

/// One table row per tuple, with a CSRF-protected inline delete form.
fn render_rows(tuples: &[Tuple], csrf: &str) -> String {
    if tuples.is_empty() {
        return r#"<tr><td colspan="5" class="t-empty">No tuples yet. Add one on the right.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for t in tuples {
        let subject_cell = if check::is_userset(&t.subject) {
            format!(
                r#"<span class="tag tag--userset" title="userset (indirection)">{s}</span>"#,
                s = esc(&t.subject)
            )
        } else {
            format!(r#"<span class="tag">{s}</span>"#, s = esc(&t.subject))
        };
        out.push_str(&format!(
            r#"<tr>
  <td><code>{object}</code></td>
  <td><span class="rel">{relation}</span></td>
  <td>{subject_cell}</td>
  <td class="t-date">{date}</td>
  <td class="t-actions">
    <form class="inline-form" method="post" action="/delete" onsubmit="return confirm('Delete this tuple?');">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="object" value="{object}">
      <input type="hidden" name="relation" value="{relation}">
      <input type="hidden" name="subject" value="{subject}">
      <button class="btn btn-danger btn-sm" type="submit">Delete</button>
    </form>
  </td>
</tr>"#,
            object = esc(&t.object),
            relation = esc(&t.relation),
            subject = esc(&t.subject),
            subject_cell = subject_cell,
            date = esc(&fmt_date(t.created_at)),
            csrf = esc(csrf),
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
    let (klass, verdict) = if outcome.allowed {
        ("result--allow", "ALLOWED")
    } else {
        ("result--deny", "DENIED")
    };

    let path = if outcome.via.is_empty() {
        r#"<p class="result__note">No grant path — no direct tuple and no userset reaches this subject within 5 levels.</p>"#.to_string()
    } else {
        let mut steps = String::from(r#"<ol class="path">"#);
        for step in &outcome.via {
            steps.push_str(&format!(r#"<li><code>{}</code></li>"#, esc(step)));
        }
        steps.push_str("</ol>");
        format!(r#"<p class="result__note">Resolution path:</p>{steps}"#)
    };

    format!(
        r#"<div class="result {klass}">
  <div class="result__head"><span class="result__verdict">{verdict}</span>
    <code class="result__query">{q}</code></div>
  {path}
</div>"#,
        klass = klass,
        verdict = verdict,
        q = esc(&check::tuple_label(object, relation, subject)),
        path = path,
    )
}

/// Render the expand result panel (empty string when expand was not run).
async fn render_expand(state: &AppState, q: &ConsoleQuery) -> String {
    let (Some(object), Some(relation)) = (nonempty(&q.ex_object), nonempty(&q.ex_relation)) else {
        return String::new();
    };

    let e = check::expand(state.store.as_ref(), object, relation).await;
    let direct = chips(&e.direct, "no direct grants");
    let members = chips(&e.members, "no concrete members");

    format!(
        r#"<div class="result result--info">
  <div class="result__head"><code class="result__query">{q}</code></div>
  <p class="result__note">Direct grants:</p>{direct}
  <p class="result__note">Resolved members (usersets flattened):</p>{members}
</div>"#,
        q = esc(&format!("{object}#{relation}")),
        direct = direct,
        members = members,
    )
}

/// Render the list-objects result panel (empty string when it was not run).
async fn render_list_objects(state: &AppState, q: &ConsoleQuery) -> String {
    let (Some(relation), Some(subject)) = (nonempty(&q.lo_relation), nonempty(&q.lo_subject)) else {
        return String::new();
    };

    let objects = check::list_objects(state.store.as_ref(), relation, subject).await;
    let chips = chips(&objects, "no objects");

    format!(
        r#"<div class="result result--info">
  <div class="result__head"><code class="result__query">{subject} · {relation}</code></div>
  <p class="result__note">Objects this subject can <strong>{relation}</strong>:</p>{chips}
</div>"#,
        subject = esc(subject),
        relation = esc(relation),
        chips = chips,
    )
}

/// Render a list of strings as chips, or a muted "empty" note.
fn chips(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return format!(r#"<p class="muted result__empty">{}</p>"#, esc(empty));
    }
    let mut out = String::from(r#"<div class="chips">"#);
    for item in items {
        let klass = if check::is_userset(item) { "chip chip--userset" } else { "chip" };
        out.push_str(&format!(r#"<span class="{klass}">{}</span>"#, esc(item)));
    }
    out.push_str("</div>");
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
    for (label, v) in [("object", object), ("relation", relation), ("subject", subject)] {
        if v.split_whitespace().count() != 1 {
            return Err(AppError::InvalidRequest(format!(
                "{label} must not contain whitespace"
            )));
        }
    }
    Ok((object.to_string(), relation.to_string(), subject.to_string()))
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
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(location).expect("valid location"))],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

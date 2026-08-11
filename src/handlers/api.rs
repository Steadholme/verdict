//! The `/api/*` JSON decision API — the surface every other Steadholme service consults.
//!
//! These are service-to-service endpoints (NOT browser pages), so they render compact JSON
//! envelopes and JSON errors — never the HTML error page. Authorization uses separate decision and
//! projection credentials selected explicitly by each handler. The gateway routes
//! `authz.w33d.xyz/api/` as `auth=public` and passes `Authorization` through.
//!
//! Endpoints:
//! - `POST /api/check`         `{object, relation, subject}` -> `{allowed, via}`
//! - `POST /api/tuples`        `{object, relation, subject}` -> `{ok, written}` (write a tuple)
//! - `POST /api/tuples/delete` `{object, relation, subject}` -> `{ok, deleted}`
//! - `POST /api/tuples/import` CSV/JSON tuple import -> `{ok, total, written, skipped}`
//! - `POST /api/tuples/export` `{format}` -> JSON or CSV tuple export
//! - `POST /api/list-objects`  `{relation, subject}`         -> `{objects}`
//! - `POST /api/expand`        `{object, relation}`          -> `{direct, members, tree}`

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::check;
use crate::config::ServiceScope;
use crate::store::Tuple;
use crate::tuple_io;
use crate::{auth, now_nanos, now_secs, AppState};

/// `{ "object": "...", "relation": "...", "subject": "..." }` — the request body shared by
/// check / write / delete.
#[derive(Debug, Deserialize)]
pub struct TripleReq {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub subject: String,
}

/// `{ "relation": "...", "subject": "..." }` — the `list-objects` request.
#[derive(Debug, Deserialize)]
pub struct ListObjectsReq {
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub subject: String,
}

/// `{ "object": "...", "relation": "..." }` — the `expand` request.
#[derive(Debug, Deserialize)]
pub struct ExpandReq {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub relation: String,
}

/// `{ "format": "json" | "csv" }` — the tuple export request.
#[derive(Debug, Deserialize)]
pub struct ExportReq {
    #[serde(default)]
    pub format: Option<String>,
}

/// `{ "allowed": bool, "via": [...] }`.
#[derive(Debug, Serialize)]
pub struct CheckResp {
    pub allowed: bool,
    pub via: Vec<String>,
}

/// `POST /api/check` — decide `(object, relation, subject)`. A denied result emits
/// `verdict.check.deny`.
pub async fn check_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TripleReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Decision) {
        return resp;
    }
    let (object, relation, subject) = match triple(&req) {
        Ok(t) => t,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };

    let outcome = check::check(state.store.as_ref(), &object, &relation, &subject).await;
    audit_check_decision(&state, &object, &relation, &subject, &outcome);
    (
        StatusCode::OK,
        Json(CheckResp {
            allowed: outcome.allowed,
            via: outcome.via,
        }),
    )
        .into_response()
}

/// `POST /api/tuples` — write a relation tuple (idempotent). Emits `verdict.tuple.write`.
pub async fn write_tuple(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TripleReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Projection) {
        return resp;
    }
    let (object, relation, subject) = match triple(&req) {
        Ok(t) => t,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };

    let tuple = Tuple {
        id: format!("tup_{}", now_nanos()),
        object: object.clone(),
        relation: relation.clone(),
        subject: subject.clone(),
        created_at: now_secs(),
    };
    match state.store.add_tuple(&tuple).await {
        Ok(written) => {
            if written {
                state.audit.emit(AuditEvent::info(
                    "verdict.tuple.write",
                    auth::api_actor(ServiceScope::Projection),
                    &check::tuple_label(&object, &relation, &subject),
                    "added",
                ));
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "written": written })),
            )
                .into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /api/tuples/delete` — remove a relation tuple. Emits `verdict.tuple.write` (delete).
pub async fn delete_tuple(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TripleReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Projection) {
        return resp;
    }
    let (object, relation, subject) = match triple(&req) {
        Ok(t) => t,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };

    match state.store.delete_tuple(&object, &relation, &subject).await {
        Ok(deleted) => {
            if deleted {
                state.audit.emit(AuditEvent::warning(
                    "verdict.tuple.write",
                    auth::api_actor(ServiceScope::Projection),
                    &check::tuple_label(&object, &relation, &subject),
                    "deleted",
                ));
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "deleted": deleted })),
            )
                .into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /api/tuples/import` — bulk-import tuples from JSON or CSV. The body may be a JSON array,
/// `{ "tuples": [...] }`, or `{ "format": "csv|json", "content": "..." }`.
pub async fn import_tuples(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Projection) {
        return resp;
    }

    let rows = match tuple_io::parse_import_value(&body) {
        Ok(rows) => rows,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };
    match tuple_io::write_import(state.store.as_ref(), &rows).await {
        Ok(report) => {
            state.audit.emit(AuditEvent::info(
                "verdict.tuple.import",
                auth::api_actor(ServiceScope::Projection),
                "tuples",
                &format!(
                    "imported {} tuple(s); {} duplicate/existing",
                    report.written, report.skipped
                ),
            ));
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /api/tuples/export` — export all tuples as JSON (default) or CSV.
pub async fn export_tuples(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExportReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Projection) {
        return resp;
    }

    let tuples = state.store.all_tuples().await;
    match req
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => (
            StatusCode::OK,
            Json(json!({ "tuples": tuple_io::export_rows(&tuples) })),
        )
            .into_response(),
        "csv" => download_response(
            "text/csv; charset=utf-8",
            "tuples.csv",
            tuple_io::export_csv(&tuples),
        ),
        other => json_err(
            StatusCode::BAD_REQUEST,
            &format!("unsupported export format {other:?} (use json or csv)"),
        ),
    }
}

/// `POST /api/list-objects` — objects on which `subject` holds `relation`.
pub async fn list_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ListObjectsReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Decision) {
        return resp;
    }
    let relation = req.relation.trim();
    let subject = req.subject.trim();
    if relation.is_empty() || subject.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "relation and subject are required");
    }
    let objects = check::list_objects(state.store.as_ref(), relation, subject).await;
    (StatusCode::OK, Json(json!({ "objects": objects }))).into_response()
}

/// `POST /api/expand` — who holds `relation` on `object`.
pub async fn expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExpandReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers, ServiceScope::Decision) {
        return resp;
    }
    let object = req.object.trim();
    let relation = req.relation.trim();
    if object.is_empty() || relation.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "object and relation are required");
    }
    let e = check::expand(state.store.as_ref(), object, relation).await;
    (
        StatusCode::OK,
        Json(json!({ "direct": e.direct, "members": e.members, "tree": e.tree })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scope-specific service credential gate. Returns `Some(401)` when the call is not authorized,
/// `None` when it may proceed.
pub(crate) fn guard(
    state: &AppState,
    headers: &HeaderMap,
    scope: ServiceScope,
) -> Option<Response> {
    if auth::service_authorized(headers, &state.config.service_credentials, scope) {
        None
    } else {
        Some(json_err(
            StatusCode::UNAUTHORIZED,
            "missing or invalid service token",
        ))
    }
}

fn audit_check_decision(
    state: &AppState,
    object: &str,
    relation: &str,
    subject: &str,
    outcome: &check::CheckOutcome,
) {
    let actor = auth::api_actor(ServiceScope::Decision);
    let target = check::tuple_label(object, relation, subject);
    if outcome.allowed {
        state.audit.emit(AuditEvent::info(
            "verdict.check.allow",
            actor,
            &target,
            &format!("allowed via {} step(s)", outcome.via.len()),
        ));
    } else {
        state.audit.emit(AuditEvent::notice(
            "verdict.check.deny",
            actor,
            &target,
            "no grant path",
        ));
    }
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

/// Validate + trim a `(object, relation, subject)` triple. Each field must be non-empty after
/// trimming and contain no internal whitespace (tuple identifiers are opaque tokens).
fn triple(req: &TripleReq) -> Result<(String, String, String), String> {
    let object = req.object.trim();
    let relation = req.relation.trim();
    let subject = req.subject.trim();
    if object.is_empty() || relation.is_empty() || subject.is_empty() {
        return Err("object, relation and subject are required".to_string());
    }
    for (label, v) in [
        ("object", object),
        ("relation", relation),
        ("subject", subject),
    ] {
        if v.split_whitespace().count() != 1 {
            return Err(format!("{label} must not contain whitespace"));
        }
    }
    Ok((
        object.to_string(),
        relation.to_string(),
        subject.to_string(),
    ))
}

/// A compact JSON error envelope: `{ "error": "..." }`. 401s carry `WWW-Authenticate: Bearer`.
fn json_err(status: StatusCode, message: &str) -> Response {
    let mut resp = (status, Json(json!({ "error": message }))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    resp
}

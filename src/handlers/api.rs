//! The `/api/*` JSON decision API — the surface every other HOLDFAST service consults.
//!
//! These are service-to-service endpoints (NOT browser pages), so they render compact JSON
//! envelopes and JSON errors — never the HTML error page. Authorization is Verdict's OWN
//! service-token check (`Authorization: Bearer <VERDICT_SERVICE_TOKEN>`): the gateway routes
//! `authz.w33d.xyz/api/` as `auth=public` and passes `Authorization` through, so callers reach the
//! decision point directly on the `holdfast` network.
//!
//! Endpoints:
//! - `POST /api/check`         `{object, relation, subject}` -> `{allowed, via}`
//! - `POST /api/tuples`        `{object, relation, subject}` -> `{ok, written}` (write a tuple)
//! - `POST /api/tuples/delete` `{object, relation, subject}` -> `{ok, deleted}`
//! - `POST /api/list-objects`  `{relation, subject}`         -> `{objects}`
//! - `POST /api/expand`        `{object, relation}`          -> `{direct, members}`

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::AuditEvent;
use crate::check;
use crate::store::Tuple;
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
    if let Some(resp) = guard(&state, &headers) {
        return resp;
    }
    let (object, relation, subject) = match triple(&req) {
        Ok(t) => t,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };

    let outcome = check::check(state.store.as_ref(), &object, &relation, &subject).await;
    if !outcome.allowed {
        state.audit.emit(AuditEvent::notice(
            "verdict.check.deny",
            &auth::api_actor(&headers),
            &check::tuple_label(&object, &relation, &subject),
            "no grant path",
        ));
    }
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
    if let Some(resp) = guard(&state, &headers) {
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
                    &auth::api_actor(&headers),
                    &check::tuple_label(&object, &relation, &subject),
                    "added",
                ));
            }
            (StatusCode::OK, Json(json!({ "ok": true, "written": written }))).into_response()
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
    if let Some(resp) = guard(&state, &headers) {
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
                    &auth::api_actor(&headers),
                    &check::tuple_label(&object, &relation, &subject),
                    "deleted",
                ));
            }
            (StatusCode::OK, Json(json!({ "ok": true, "deleted": deleted }))).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `POST /api/list-objects` — objects on which `subject` holds `relation`.
pub async fn list_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ListObjectsReq>,
) -> Response {
    if let Some(resp) = guard(&state, &headers) {
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
    if let Some(resp) = guard(&state, &headers) {
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
        Json(json!({ "direct": e.direct, "members": e.members })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Service-token gate. Returns `Some(401)` when the call is not authorized, `None` when it may
/// proceed.
fn guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if auth::service_authorized(headers, state.config.service_token.as_deref()) {
        None
    } else {
        Some(json_err(StatusCode::UNAUTHORIZED, "missing or invalid service token"))
    }
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
    for (label, v) in [("object", object), ("relation", relation), ("subject", subject)] {
        if v.split_whitespace().count() != 1 {
            return Err(format!("{label} must not contain whitespace"));
        }
    }
    Ok((object.to_string(), relation.to_string(), subject.to_string()))
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

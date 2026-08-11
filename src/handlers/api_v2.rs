use std::net::IpAddr;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::condition;
use crate::config::ServiceScope;
use crate::handlers::api::guard;
use crate::policy::{
    is_permission, is_resource_type, is_subject, CheckResponse, Decision, DecisionContext,
    ProjectionEdge, Resource, Risk, SubjectAccessState,
};
use crate::policy_check::{self, EvaluationError};
use crate::policy_store::{projection_payload_hash, PolicyStoreError};
use crate::{now_secs, AppState};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    pub subject: String,
    pub permission: String,
    pub resource: Resource,
    pub context: DecisionContext,
    pub risk: Risk,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequest {
    pub source_grant_id: String,
    pub source_version: i64,
    pub payload_hash: String,
    pub edges: Vec<ProjectionEdge>,
}

#[derive(Debug, Serialize)]
struct ProjectionResponse {
    ok: bool,
    epoch: i64,
    projected_edges: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectStatusRequest {
    pub subject: String,
    pub state: SubjectAccessState,
    pub source_event_id: String,
    pub source_version: i64,
}

#[derive(Debug, Serialize)]
struct SubjectStatusResponse {
    ok: bool,
    epoch: i64,
    state: SubjectAccessState,
    replayed: bool,
}

pub async fn check_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CheckRequest>, JsonRejection>,
) -> Response {
    if let Some(response) = guard(&state, &headers, ServiceScope::Decision) {
        return response;
    }
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "bad-request",
                "The request body is invalid.",
            )
        }
    };
    if let Err(message) = validate_check_request(&request) {
        return json_error(StatusCode::BAD_REQUEST, "bad-request", message);
    }
    let evaluated_at = now_secs();
    let snapshot = match state
        .policy
        .snapshot(&request.permission, &request.subject)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let reason = match error {
                PolicyStoreError::Inconsistent => "epoch-inconsistent",
                PolicyStoreError::Backend
                | PolicyStoreError::Conflict
                | PolicyStoreError::StaleVersion => "store-unavailable",
            };
            return indeterminate(evaluated_at, reason);
        }
    };
    match policy_check::evaluate(
        snapshot,
        &request.subject,
        &request.permission,
        &request.resource,
        &request.context,
        evaluated_at,
    ) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => indeterminate(
            evaluated_at,
            match error {
                EvaluationError::UnknownCondition => "unknown-condition",
                EvaluationError::MalformedPolicy => "malformed-policy",
                EvaluationError::EpochInconsistent => "epoch-inconsistent",
            },
        ),
    }
}

pub async fn set_subject_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<SubjectStatusRequest>, JsonRejection>,
) -> Response {
    if let Some(response) = guard(&state, &headers, ServiceScope::Lifecycle) {
        return response;
    }
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "bad-request",
                "The request body is invalid.",
            )
        }
    };
    if let Err(message) = validate_subject_status(&request) {
        return json_error(StatusCode::BAD_REQUEST, "bad-request", message);
    }
    match state
        .policy
        .set_subject_status(
            &request.subject,
            request.state,
            &request.source_event_id,
            request.source_version,
            now_secs(),
        )
        .await
    {
        Ok((epoch, replayed)) => (
            StatusCode::OK,
            Json(SubjectStatusResponse {
                ok: true,
                epoch,
                state: request.state,
                replayed,
            }),
        )
            .into_response(),
        Err(PolicyStoreError::Conflict) => json_error(
            StatusCode::CONFLICT,
            "subject-status-conflict",
            "The source version conflicts with durable subject status.",
        ),
        Err(PolicyStoreError::StaleVersion) => json_error(
            StatusCode::CONFLICT,
            "subject-status-stale-version",
            "The source version is older than durable subject status.",
        ),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "store-unavailable",
            "The policy authority is unavailable.",
        ),
    }
}

pub async fn replace_projection(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ProjectionRequest>, JsonRejection>,
) -> Response {
    if let Some(response) = guard(&state, &headers, ServiceScope::Projection) {
        return response;
    }
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "bad-request",
                "The request body is invalid.",
            )
        }
    };
    if let Err(message) = validate_projection(&request) {
        return json_error(StatusCode::BAD_REQUEST, "bad-request", message);
    }
    let count = request.edges.len();
    match state
        .policy
        .replace_projection(
            &request.source_grant_id,
            request.source_version,
            &request.payload_hash,
            request.edges,
            now_secs(),
        )
        .await
    {
        Ok(epoch) => (
            StatusCode::OK,
            Json(ProjectionResponse {
                ok: true,
                epoch,
                projected_edges: count,
            }),
        )
            .into_response(),
        Err(PolicyStoreError::Conflict) => json_error(
            StatusCode::CONFLICT,
            "projection-conflict",
            "The source version payload or projected edge conflicts with durable state.",
        ),
        Err(PolicyStoreError::StaleVersion) => json_error(
            StatusCode::CONFLICT,
            "projection-stale-version",
            "The source version is older than the durable projection version.",
        ),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "store-unavailable",
            "The policy authority is unavailable.",
        ),
    }
}

fn validate_check_request(request: &CheckRequest) -> Result<(), &'static str> {
    if !is_subject(&request.subject) {
        return Err("subject must be a canonical user, group userset, or service");
    }
    if !is_permission(&request.permission) {
        return Err("permission does not match the frozen entitlement grammar");
    }
    if !request.resource.validate() {
        return Err("resource is invalid");
    }
    if request
        .context
        .zone
        .as_deref()
        .is_some_and(|value| !matches!(value, "internal" | "external"))
    {
        return Err("context.zone must be internal or external");
    }
    if request
        .context
        .ip
        .as_deref()
        .is_some_and(|value| value.parse::<IpAddr>().is_err())
    {
        return Err("context.ip must be an IP address");
    }
    if request
        .context
        .request_id
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 256 || value.contains(['\n', '\r']))
    {
        return Err("context.request_id is invalid");
    }
    Ok(())
}

fn validate_projection(request: &ProjectionRequest) -> Result<(), &'static str> {
    if request.source_grant_id.is_empty()
        || request.source_grant_id.len() > 256
        || request.source_grant_id.contains(['\n', '\r', '\0'])
    {
        return Err("source_grant_id is invalid");
    }
    if request.source_version <= 0 {
        return Err("source_version must be positive");
    }
    if request.payload_hash.len() != 64
        || !request
            .payload_hash
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("payload_hash must be lowercase SHA-256 hex");
    }
    if request.edges.len() > 10_000 {
        return Err("projection contains too many edges");
    }
    for edge in &request.edges {
        if edge.edge_id.is_empty()
            || edge.edge_id.len() > 256
            || edge.projection_key.is_empty()
            || edge.projection_key.len() > 512
            || edge.edge_id.contains(['\n', '\r', '\0'])
            || edge.projection_key.contains(['\n', '\r', '\0'])
        {
            return Err("edge identifiers are invalid");
        }
        if !is_subject(&edge.subject)
            || !is_permission(&edge.permission)
            || edge.version != request.source_version
        {
            return Err("edge subject, permission, or version is invalid");
        }
        if edge
            .not_before
            .zip(edge.expires_at)
            .is_some_and(|(start, end)| end <= start)
        {
            return Err("edge validity window is invalid");
        }
        validate_selector(&edge.resource_selector)?;
        if edge
            .condition
            .as_ref()
            .is_some_and(|value| condition::validate(value).is_err())
        {
            return Err("edge condition is unknown or malformed");
        }
    }
    if projection_payload_hash(&request.edges).map_err(|_| "projection payload cannot be hashed")?
        != request.payload_hash
    {
        return Err("payload_hash does not match the canonical edge payload");
    }
    Ok(())
}

fn validate_subject_status(request: &SubjectStatusRequest) -> Result<(), &'static str> {
    if !request.subject.starts_with("user:") || !is_subject(&request.subject) {
        return Err("subject must be a canonical user subject");
    }
    if request.source_event_id.is_empty()
        || request.source_event_id.len() > 256
        || request.source_event_id.contains(['\n', '\r', '\0'])
    {
        return Err("source_event_id is invalid");
    }
    if request.source_version <= 0 {
        return Err("source_version must be positive");
    }
    Ok(())
}

fn validate_selector(selector: &serde_json::Value) -> Result<(), &'static str> {
    let selector = selector
        .as_object()
        .ok_or("resource selector must be an object")?;
    if selector.len() != 3 || selector.get("v").and_then(serde_json::Value::as_i64) != Some(1) {
        return Err("resource selector version or shape is invalid");
    }
    let kind = selector
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("resource selector type is required")?;
    let id = selector
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or("resource selector id is required")?;
    if kind == "any" {
        return if id == "*" {
            Ok(())
        } else {
            Err("resource selector is invalid")
        };
    }
    if !is_resource_type(kind) || id.is_empty() || id.len() > 512 || id.contains(['\n', '\r', '\0'])
    {
        return Err("resource selector is invalid");
    }
    Ok(())
}

fn indeterminate(evaluated_at: i64, reason: &str) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(CheckResponse {
            decision: Decision::Indeterminate,
            reason: reason.to_string(),
            epoch: 0,
            evaluated_at,
            evidence: vec![],
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert("retry-after", "5".parse().unwrap());
    response
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": {"code": code, "message": message}
        })),
    )
        .into_response()
}

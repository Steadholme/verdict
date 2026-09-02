use std::net::IpAddr;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::condition;
use crate::config::ServiceScope;
use crate::handlers::api::guard;
use crate::policy::{
    is_permission, is_resource_type, is_subject, ApplicationDecisionRecord, ApplicationRequestV2,
    ApplicationSubjectState, ApplicationSubjectStatus, CheckResponse, Decision, DecisionContext,
    DecisionV2, Evidence, ProjectionEdge, Resource, Risk, SubjectAccessState,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSubjectStatusRequest {
    pub v: i64,
    pub application_sub: String,
    pub state: ApplicationSubjectState,
    pub source_event_id: String,
    pub subject_version: i64,
    pub policy_epoch: i64,
    pub revocation_epoch: i64,
}

#[derive(Debug, Serialize)]
struct ApplicationSubjectStatusResponse {
    ok: bool,
    replayed: bool,
    subject_version: i64,
    policy_epoch: i64,
    revocation_epoch: i64,
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

pub async fn application_check_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ApplicationRequestV2>, JsonRejection>,
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
                "The RequestV2 body is invalid.",
            )
        }
    };
    if let Err(message) = validate_application_request(&request) {
        return json_error(StatusCode::BAD_REQUEST, "bad-request", message);
    }
    let issued_at = now_secs();
    let permission = format!("rikune.{}", request.canonical_tool);
    let status = match state
        .policy
        .application_subject_status(&request.application_sub)
        .await
    {
        Ok(status) => status,
        Err(_) => {
            return application_indeterminate(&request, &permission, issued_at, "store-unavailable")
        }
    };
    let mut snapshot = match state
        .policy
        .snapshot(&permission, &request.application_sub)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let reason = if matches!(error, PolicyStoreError::Inconsistent) {
                "epoch-inconsistent"
            } else {
                "store-unavailable"
            };
            return application_indeterminate(&request, &permission, issued_at, reason);
        }
    };
    // Application principals are direct and grant-scoped. A projection produced
    // for any other grant must never authorize this credential, even if a stale
    // or corrupt projection reused the same application subject.
    snapshot
        .edges
        .retain(|edge| edge.source_grant_id == request.grant_id);
    let (decision, reason, evidence, subject_version, policy_epoch) = match status.as_ref() {
        None => (
            Decision::Deny,
            "subject-unprojected".to_string(),
            vec![],
            0,
            request.policy_epoch,
        ),
        Some(status) if !status.state.allows_access() => (
            Decision::Deny,
            format!("subject-{}", status.state.as_str()),
            vec![],
            status.subject_version,
            status.policy_epoch,
        ),
        Some(status)
            if status.policy_epoch != request.policy_epoch
                || status.revocation_epoch != request.revocation_epoch =>
        {
            (
                Decision::Deny,
                "subject-epoch-stale".to_string(),
                vec![],
                status.subject_version,
                status.policy_epoch,
            )
        }
        Some(status) => match policy_check::evaluate(
            snapshot.clone(),
            &request.application_sub,
            &permission,
            &request.resource,
            &DecisionContext {
                zone: Some("external".to_string()),
                mfa: false,
                ip: None,
                request_id: Some(request.correlation_id.clone()),
                break_glass: false,
            },
            issued_at,
        ) {
            Ok(response) => (
                response.decision,
                response.reason,
                response.evidence,
                status.subject_version,
                status.policy_epoch,
            ),
            Err(error) => {
                let reason = match error {
                    EvaluationError::UnknownCondition => "unknown-condition",
                    EvaluationError::MalformedPolicy => "malformed-policy",
                    EvaluationError::EpochInconsistent => "epoch-inconsistent",
                };
                return application_indeterminate(&request, &permission, issued_at, reason);
            }
        },
    };
    let response = make_decision_v2(
        &request,
        &permission,
        decision,
        reason,
        evidence,
        snapshot.epoch,
        subject_version,
        policy_epoch,
        issued_at,
    );
    if status.is_some()
        && state
            .policy
            .record_application_decision(ApplicationDecisionRecord {
                decision: response.clone(),
                request: request.clone(),
            })
            .await
            .is_err()
    {
        return application_indeterminate(&request, &permission, issued_at, "store-unavailable");
    }
    (StatusCode::OK, Json(response)).into_response()
}

pub async fn set_application_subject_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ApplicationSubjectStatusRequest>, JsonRejection>,
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
                "The application status body is invalid.",
            )
        }
    };
    if request.v != 1
        || !is_application_subject(&request.application_sub)
        || !valid_opaque(&request.source_event_id, 256)
        || request.subject_version <= 0
        || request.policy_epoch <= 0
        || request.revocation_epoch <= 0
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "The application status body is invalid.",
        );
    }
    let status = ApplicationSubjectStatus {
        application_sub: request.application_sub,
        state: request.state,
        source_event_id: request.source_event_id,
        subject_version: request.subject_version,
        policy_epoch: request.policy_epoch,
        revocation_epoch: request.revocation_epoch,
        updated_at: now_secs(),
    };
    match state
        .policy
        .set_application_subject_status(status.clone())
        .await
    {
        Ok(replayed) => (
            StatusCode::OK,
            Json(ApplicationSubjectStatusResponse {
                ok: true,
                replayed,
                subject_version: status.subject_version,
                policy_epoch: status.policy_epoch,
                revocation_epoch: status.revocation_epoch,
            }),
        )
            .into_response(),
        Err(PolicyStoreError::Conflict) => json_error(
            StatusCode::CONFLICT,
            "application-status-conflict",
            "The application status conflicts with durable state.",
        ),
        Err(PolicyStoreError::StaleVersion) => json_error(
            StatusCode::CONFLICT,
            "application-status-stale-version",
            "The application status is stale.",
        ),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "store-unavailable",
            "The policy authority is unavailable.",
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

fn validate_application_request(request: &ApplicationRequestV2) -> Result<(), &'static str> {
    if request.v != 2 || !is_application_subject(&request.application_sub) {
        return Err("application_sub or RequestV2 version is invalid");
    }
    if !valid_opaque(&request.client_id, 256)
        || !valid_opaque(&request.credential_id, 256)
        || !valid_opaque(&request.grant_id, 256)
        || request.package_id != "pkg_analyze_mcp_client"
        || request.credential_version <= 0
        || request.policy_epoch <= 0
        || request.revocation_epoch <= 0
        || !lower_hex_64(&request.package_revision_digest)
        || !lower_hex_64(&request.request_sha256)
        || !valid_opaque(&request.session_id, 256)
        || !valid_opaque(&request.correlation_id, 256)
        || !request.resource.validate()
    {
        return Err("RequestV2 identity, resource, digest, version, or epoch is invalid");
    }
    if !matches!(
        request.canonical_tool.as_str(),
        "analysis.create" | "analysis.read" | "analysis.conversation" | "analysis.upload.cancel"
    ) {
        return Err("canonical_tool is not in the Analyze public surface");
    }
    if request.scopes.is_empty()
        || request.scopes.iter().any(|scope| !valid_scope(scope))
        || request.scopes.windows(2).any(|pair| pair[0] >= pair[1])
        || !request
            .scopes
            .iter()
            .any(|scope| scope == &request.canonical_tool)
    {
        return Err("scopes must be sorted, unique, canonical and contain canonical_tool");
    }
    Ok(())
}

fn is_application_subject(value: &str) -> bool {
    value.starts_with("application:") && is_subject(value)
}

fn valid_opaque(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|value| {
            value.is_ascii_lowercase()
                || value.is_ascii_digit()
                || matches!(value, b'.' | b':' | b'_' | b'-')
        })
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

#[derive(Serialize)]
struct DecisionDigestV2<'a> {
    domain: &'static str,
    request: &'a ApplicationRequestV2,
    subject: &'a str,
    resource: &'a Resource,
    permission: &'a str,
    decision: Decision,
    reason: &'a str,
    evidence: &'a [Evidence],
    policy_version: i64,
    subject_version: i64,
    policy_epoch: i64,
    issued_at: i64,
    expires_at: i64,
}

fn decision_digest_v2(request: &ApplicationRequestV2, response: &DecisionV2) -> String {
    let canonical = serde_json::to_vec(&DecisionDigestV2 {
        domain: "w33d.verdict.application-decision.v2",
        request,
        subject: &response.subject,
        resource: &response.resource,
        permission: &response.permission,
        decision: response.decision,
        reason: &response.reason,
        evidence: &response.evidence,
        policy_version: response.policy_version,
        subject_version: response.subject_version,
        policy_epoch: response.policy_epoch,
        issued_at: response.issued_at,
        expires_at: response.expires_at,
    })
    .expect("DecisionDigestV2 is serializable");
    hex::encode(Sha256::digest(canonical))
}

fn make_decision_v2(
    request: &ApplicationRequestV2,
    permission: &str,
    decision: Decision,
    reason: String,
    evidence: Vec<Evidence>,
    policy_version: i64,
    subject_version: i64,
    policy_epoch: i64,
    issued_at: i64,
) -> DecisionV2 {
    let mut response = DecisionV2 {
        v: 2,
        decision_id: String::new(),
        decision_digest: String::new(),
        decision,
        subject: request.application_sub.clone(),
        resource: request.resource.clone(),
        permission: permission.to_string(),
        reason,
        evidence,
        policy_version,
        subject_version,
        policy_epoch,
        issued_at,
        expires_at: issued_at + 30,
    };
    response.decision_digest = decision_digest_v2(request, &response);
    response.decision_id = format!("dec_{}", &response.decision_digest[..32]);
    response
}

pub fn verify_application_decision_v2(
    request: &ApplicationRequestV2,
    response: &DecisionV2,
    now: i64,
) -> bool {
    response.v == 2
        && lower_hex_64(&response.decision_digest)
        && response.subject == request.application_sub
        && response.resource == request.resource
        && response.permission == format!("rikune.{}", request.canonical_tool)
        && response.issued_at > 0
        && response.expires_at - response.issued_at == 30
        && now >= response.issued_at
        && now <= response.expires_at
        && response.policy_version >= 0
        && response.subject_version >= 0
        && (response.decision != Decision::Allow
            || (response.policy_epoch == request.policy_epoch && response.subject_version > 0))
        && response.decision_digest == decision_digest_v2(request, response)
        && response.decision_id == format!("dec_{}", &response.decision_digest[..32])
}

fn application_indeterminate(
    request: &ApplicationRequestV2,
    permission: &str,
    issued_at: i64,
    reason: &str,
) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(make_decision_v2(
            request,
            permission,
            Decision::Indeterminate,
            reason.to_string(),
            vec![],
            0,
            0,
            0,
            issued_at,
        )),
    )
        .into_response();
    response
        .headers_mut()
        .insert("retry-after", "5".parse().unwrap());
    response
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

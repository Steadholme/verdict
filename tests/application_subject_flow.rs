use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use verdict::audit::AuditSink;
use verdict::config::{Config, ServiceCredentials};
use verdict::handlers::api_v2::verify_application_decision_v2;
use verdict::policy::{
    ApplicationRequestV2, ApplicationSubjectState, ApplicationSubjectStatus, Decision, DecisionV2,
    Effect, PolicySnapshot, ProjectionEdge, SubjectAccessState,
};
use verdict::policy_store::{
    projection_payload_hash, InMemoryPolicyStore, PolicyStore, PolicyStoreError,
};
use verdict::store::InMemoryStore;
use verdict::{app, AppState};

const DECISION_TOKEN: &str = "decision-token-00000000000000000001";
const PROJECTION_TOKEN: &str = "projection-token-000000000000000001";
const LIFECYCLE_TOKEN: &str = "lifecycle-token-0000000000000000001";

struct InconsistentPolicyStore;

#[async_trait::async_trait]
impl PolicyStore for InconsistentPolicyStore {
    async fn snapshot(
        &self,
        _permission: &str,
        _subject: &str,
    ) -> Result<PolicySnapshot, PolicyStoreError> {
        Err(PolicyStoreError::Inconsistent)
    }

    async fn replace_projection(
        &self,
        _source_grant_id: &str,
        _source_version: i64,
        _payload_hash: &str,
        _edges: Vec<ProjectionEdge>,
        _now: i64,
    ) -> Result<i64, PolicyStoreError> {
        Err(PolicyStoreError::Backend)
    }

    async fn bump_epoch(&self, _now: i64) -> Result<i64, PolicyStoreError> {
        Err(PolicyStoreError::Backend)
    }

    async fn set_subject_status(
        &self,
        _subject: &str,
        _state: SubjectAccessState,
        _source_event_id: &str,
        _source_version: i64,
        _now: i64,
    ) -> Result<(i64, bool), PolicyStoreError> {
        Err(PolicyStoreError::Backend)
    }

    async fn application_subject_status(
        &self,
        _application_sub: &str,
    ) -> Result<Option<ApplicationSubjectStatus>, PolicyStoreError> {
        Ok(Some(ApplicationSubjectStatus {
            application_sub: "application:abcdefghijklmnop".to_string(),
            state: ApplicationSubjectState::Active,
            source_event_id: "event_abcdefghijklmnop".to_string(),
            subject_version: 7,
            policy_epoch: 11,
            revocation_epoch: 13,
            updated_at: 1,
        }))
    }
}

fn state() -> (AppState, Arc<InMemoryPolicyStore>) {
    let mut config = Config::dev();
    config.service_credentials =
        ServiceCredentials::try_new(DECISION_TOKEN, PROJECTION_TOKEN, LIFECYCLE_TOKEN).unwrap();
    let policy = Arc::new(InMemoryPolicyStore::new());
    (
        AppState {
            config: Arc::new(config),
            store: Arc::new(InMemoryStore::new()),
            policy: policy.clone(),
            audit: AuditSink::disabled(),
        },
        policy,
    )
}

fn request_v2(resource_id: &str) -> ApplicationRequestV2 {
    ApplicationRequestV2 {
        v: 2,
        application_sub: "application:abcdefghijklmnop".to_string(),
        client_id: "client_abcdefghijklmnop".to_string(),
        credential_id: "cred_abcdefghijklmnop".to_string(),
        credential_version: 3,
        grant_id: "grant_abcdefghijklmnop".to_string(),
        package_id: "pkg_analyze_mcp_client".to_string(),
        package_revision_digest: "a".repeat(64),
        scopes: vec!["analysis.create".to_string(), "analysis.read".to_string()],
        canonical_tool: "analysis.create".to_string(),
        resource: verdict::policy::Resource {
            kind: "analysis".to_string(),
            id: resource_id.to_string(),
        },
        session_id: "session_abcdefghijklmnop".to_string(),
        request_sha256: "b".repeat(64),
        policy_epoch: 11,
        revocation_epoch: 13,
        correlation_id: "corr_abcdefghijklmnop".to_string(),
    }
}

async fn post_json(state: &AppState, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    post_raw(state, uri, token, body.to_string()).await
}

async fn post_raw(state: &AppState, uri: &str, token: &str, body: String) -> (StatusCode, Value) {
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn application_v2_rejects_wrong_service_scope_and_non_exact_json() {
    let (app_state, policy) = state();
    seed_allow(policy.as_ref()).await;
    let encoded = serde_json::to_string(&request_v2("analysis_one")).unwrap();

    let (status, _) = post_raw(
        &app_state,
        "/api/v2/application-check",
        PROJECTION_TOKEN,
        encoded.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    for body in [
        format!("{},\"unknown\":true}}", encoded.strip_suffix('}').unwrap()),
        format!("{},\"v\":2}}", encoded.strip_suffix('}').unwrap()),
    ] {
        let (status, _) = post_raw(
            &app_state,
            "/api/v2/application-check",
            DECISION_TOKEN,
            body,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let lifecycle = json!({
        "v":1,"application_sub":"application:abcdefghijklmnop","state":"active",
        "source_event_id":"event_abcdefghijklmnop","subject_version":1,
        "policy_epoch":1,"revocation_epoch":1
    });
    let (status, _) = post_json(
        &app_state,
        "/api/v2/application-subject-status",
        DECISION_TOKEN,
        lifecycle,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn seed_application_permission(policy: &InMemoryPolicyStore, permission: &str) {
    policy
        .set_application_subject_status(ApplicationSubjectStatus {
            application_sub: "application:abcdefghijklmnop".to_string(),
            state: ApplicationSubjectState::Active,
            source_event_id: "event_abcdefghijklmnop".to_string(),
            subject_version: 7,
            policy_epoch: 11,
            revocation_epoch: 13,
            updated_at: 1,
        })
        .await
        .unwrap();
    let edges = vec![ProjectionEdge {
        edge_id: format!("edge_{}", permission.replace('.', "_")),
        projection_key: format!("projection_{}", permission.replace('.', "_")),
        subject: "application:abcdefghijklmnop".to_string(),
        permission: permission.to_string(),
        effect: Effect::Allow,
        resource_selector: json!({"v":1,"type":"analysis","id":"analysis_one"}),
        condition: None,
        not_before: None,
        expires_at: None,
        active: true,
        version: 1,
    }];
    let hash = projection_payload_hash(&edges).unwrap();
    policy
        .replace_projection("grant_abcdefghijklmnop", 1, &hash, edges, 2)
        .await
        .unwrap();
}

async fn seed_allow(policy: &InMemoryPolicyStore) {
    seed_application_permission(policy, "rikune.analysis.create").await;
}

#[tokio::test]
async fn application_tools_use_explicit_permission_map_and_reject_cross_mapping() {
    let mappings = [
        ("analysis.create", "rikune.analysis.create"),
        ("analysis.read", "rikune.analysis.read"),
        ("analysis.conversation", "rikune.conversation.use"),
        ("analysis.upload.cancel", "rikune.upload.cancel"),
    ];
    for (index, (canonical_tool, permission)) in mappings.iter().enumerate() {
        let (app_state, policy) = state();
        seed_application_permission(policy.as_ref(), permission).await;
        let mut request = request_v2("analysis_one");
        request.scopes = vec![canonical_tool.to_string()];
        request.canonical_tool = canonical_tool.to_string();
        let (status, body) = post_json(
            &app_state,
            "/api/v2/application-check",
            DECISION_TOKEN,
            serde_json::to_value(&request).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{canonical_tool}: {body}");
        let decision: DecisionV2 = serde_json::from_value(body).unwrap();
        assert_eq!(decision.decision, Decision::Allow, "{canonical_tool}");
        assert_eq!(decision.permission, *permission, "{canonical_tool}");
        assert!(verify_application_decision_v2(
            &request,
            &decision,
            decision.issued_at
        ));

        let wrong_permission = mappings[(index + 1) % mappings.len()].1;
        let mut tampered = decision.clone();
        tampered.permission = wrong_permission.to_string();
        assert!(
            !verify_application_decision_v2(&request, &tampered, tampered.issued_at),
            "{canonical_tool} accepted permission tamper"
        );

        let (cross_state, cross_policy) = state();
        seed_application_permission(cross_policy.as_ref(), wrong_permission).await;
        let (status, body) = post_json(
            &cross_state,
            "/api/v2/application-check",
            DECISION_TOKEN,
            serde_json::to_value(&request).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{canonical_tool}: {body}");
        let cross_decision: DecisionV2 = serde_json::from_value(body).unwrap();
        assert_eq!(cross_decision.decision, Decision::Deny, "{canonical_tool}");
        assert_eq!(cross_decision.permission, *permission, "{canonical_tool}");
        assert!(verify_application_decision_v2(
            &request,
            &cross_decision,
            cross_decision.issued_at
        ));
    }

    let (app_state, policy) = state();
    seed_allow(policy.as_ref()).await;
    for scopes in [
        vec!["rikune.analysis.create".to_string()],
        vec!["analysis.read".to_string()],
    ] {
        let mut request = request_v2("analysis_one");
        request.scopes = scopes;
        let (status, _) = post_json(
            &app_state,
            "/api/v2/application-check",
            DECISION_TOKEN,
            serde_json::to_value(request).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn application_request_v2_digest_ttl_and_stale_rejection() {
    let (state, policy) = state();
    seed_allow(policy.as_ref()).await;
    let request = request_v2("analysis_one");
    let mut request_fields: Vec<_> = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    request_fields.sort();
    let mut expected_fields = vec![
        "v",
        "application_sub",
        "client_id",
        "credential_id",
        "credential_version",
        "grant_id",
        "package_id",
        "package_revision_digest",
        "scopes",
        "canonical_tool",
        "resource",
        "session_id",
        "request_sha256",
        "policy_epoch",
        "revocation_epoch",
        "correlation_id",
    ];
    expected_fields.sort();
    assert_eq!(request_fields, expected_fields);
    let (status, body) = post_json(
        &state,
        "/api/v2/application-check",
        DECISION_TOKEN,
        serde_json::to_value(&request).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let decision: DecisionV2 = serde_json::from_value(body).unwrap();
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.expires_at - decision.issued_at, 30);
    assert_eq!(decision.subject_version, 7);
    assert_eq!(decision.policy_epoch, 11);
    assert!(verify_application_decision_v2(
        &request,
        &decision,
        decision.issued_at
    ));

    let mut changed = request.clone();
    changed.correlation_id = "corr_changedchanged".to_string();
    assert!(!verify_application_decision_v2(
        &changed,
        &decision,
        decision.issued_at
    ));
    let mut stale = decision.clone();
    stale.subject_version += 1;
    assert!(!verify_application_decision_v2(
        &request,
        &stale,
        stale.issued_at
    ));
    assert!(!verify_application_decision_v2(
        &request,
        &decision,
        decision.expires_at + 1
    ));

    let mutations = [
        ("v", json!(3)),
        ("application_sub", json!("application:ponmlkjihgfedcba")),
        ("client_id", json!("client_changedchanged")),
        ("credential_id", json!("cred_changedchanged")),
        ("credential_version", json!(4)),
        ("grant_id", json!("grant_changedchanged")),
        ("package_id", json!("pkg_changedchanged")),
        ("package_revision_digest", json!("c".repeat(64))),
        (
            "scopes",
            json!(["analysis.conversation", "analysis.create"]),
        ),
        ("canonical_tool", json!("analysis.read")),
        (
            "resource",
            json!({"type":"analysis","id":"analysis_changed"}),
        ),
        ("session_id", json!("session_changedchanged")),
        ("request_sha256", json!("d".repeat(64))),
        ("policy_epoch", json!(12)),
        ("revocation_epoch", json!(14)),
        ("correlation_id", json!("corr_changedchanged")),
    ];
    for (field, changed_value) in mutations {
        let mut encoded = serde_json::to_value(&request).unwrap();
        encoded[field] = changed_value;
        let changed: ApplicationRequestV2 = serde_json::from_value(encoded).unwrap();
        assert!(
            !verify_application_decision_v2(&changed, &decision, decision.issued_at),
            "decision digest did not bind RequestV2 field {field}"
        );
    }

    for changed in [
        {
            let mut value = decision.clone();
            value.subject = "application:ponmlkjihgfedcba".to_string();
            value
        },
        {
            let mut value = decision.clone();
            value.resource.id = "analysis_changed".to_string();
            value
        },
        {
            let mut value = decision.clone();
            value.permission = "rikune.analysis.read".to_string();
            value
        },
        {
            let mut value = decision.clone();
            value.decision = Decision::Deny;
            value
        },
        {
            let mut value = decision.clone();
            value.reason = "changed".to_string();
            value
        },
        {
            let mut value = decision.clone();
            value.evidence.clear();
            value
        },
        {
            let mut value = decision.clone();
            value.policy_version += 1;
            value
        },
        {
            let mut value = decision.clone();
            value.subject_version += 1;
            value
        },
        {
            let mut value = decision.clone();
            value.policy_epoch += 1;
            value
        },
        {
            let mut value = decision.clone();
            value.issued_at += 1;
            value.expires_at += 1;
            value
        },
        {
            let mut value = decision.clone();
            value.decision_digest = "e".repeat(64);
            value
        },
    ] {
        assert!(!verify_application_decision_v2(
            &request,
            &changed,
            changed.issued_at
        ));
    }
}

#[tokio::test]
async fn application_allow_requires_projection_and_exact_resource() {
    let (state, policy) = state();
    seed_allow(policy.as_ref()).await;
    for resource in ["wrong_analysis", "analysis_one"] {
        let mut request = request_v2(resource);
        if resource == "analysis_one" {
            request.canonical_tool = "analysis.read".to_string();
            request.scopes = vec!["analysis.read".to_string()];
        }
        let (status, body) = post_json(
            &state,
            "/api/v2/application-check",
            DECISION_TOKEN,
            serde_json::to_value(request).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["decision"], "Deny");
    }
    let mut wrong_grant = request_v2("analysis_one");
    wrong_grant.grant_id = "grant_wrongwrongwrong".to_string();
    let (status, body) = post_json(
        &state,
        "/api/v2/application-check",
        DECISION_TOKEN,
        serde_json::to_value(wrong_grant).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "Deny");
}

#[tokio::test]
async fn application_revocation_denies_an_existing_matching_projection() {
    let (state, policy) = state();
    seed_allow(policy.as_ref()).await;
    policy
        .set_application_subject_status(ApplicationSubjectStatus {
            application_sub: "application:abcdefghijklmnop".to_string(),
            state: ApplicationSubjectState::Revoked,
            source_event_id: "event_revokedrevoked".to_string(),
            subject_version: 8,
            policy_epoch: 12,
            revocation_epoch: 14,
            updated_at: 3,
        })
        .await
        .unwrap();
    let (status, body) = post_json(
        &state,
        "/api/v2/application-check",
        DECISION_TOKEN,
        serde_json::to_value(request_v2("analysis_one")).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "Deny");
    assert_eq!(body["reason"], "subject-revoked");
}

#[tokio::test]
async fn application_epoch_store_failure_is_indeterminate_http_503() {
    let (mut state, _) = state();
    state.policy = Arc::new(InconsistentPolicyStore);
    let (status, body) = post_json(
        &state,
        "/api/v2/application-check",
        DECISION_TOKEN,
        serde_json::to_value(request_v2("analysis_one")).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["decision"], "Indeterminate");
    assert_eq!(body["reason"], "epoch-inconsistent");
}

#[tokio::test]
async fn typed_application_status_is_monotonic_and_legacy_subjects_remain_valid() {
    let (state, _) = state();
    let body = json!({
        "v":1,"application_sub":"application:abcdefghijklmnop","state":"pending",
        "source_event_id":"event_abcdefghijklmnop","subject_version":1,
        "policy_epoch":1,"revocation_epoch":1
    });
    let (status, response) = post_json(
        &state,
        "/api/v2/application-subject-status",
        LIFECYCLE_TOKEN,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = post_json(
        &state,
        "/api/v2/application-subject-status",
        LIFECYCLE_TOKEN,
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["replayed"], true);
    let active = json!({
        "v":1,"application_sub":"application:abcdefghijklmnop","state":"active",
        "source_event_id":"event_activeactive","subject_version":2,
        "policy_epoch":2,"revocation_epoch":2
    });
    let (status, response) = post_json(
        &state,
        "/api/v2/application-subject-status",
        LIFECYCLE_TOKEN,
        active,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let stale = json!({
        "v":1,"application_sub":"application:abcdefghijklmnop","state":"pending",
        "source_event_id":"event_stalestale","subject_version":1,
        "policy_epoch":1,"revocation_epoch":1
    });
    let (status, _) = post_json(
        &state,
        "/api/v2/application-subject-status",
        LIFECYCLE_TOKEN,
        stale,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(verdict::policy::is_subject("user:alice"));
    assert!(verdict::policy::is_subject("service:sluice"));
    assert!(verdict::policy::is_subject("group:ops#member"));
}

#[tokio::test]
async fn lifecycle_accepts_access_publisher_event_ids_and_same_state_updates() {
    let (state, _) = state();
    let mut body = json!({
        "v":1,"application_sub":"application:abcdefghijklmnop","state":"active",
        "source_event_id":format!("access-application-status-v1:{}", "a".repeat(64)),
        "subject_version":1,"policy_epoch":1,"revocation_epoch":1
    });
    let (status, _) = post_json(
        &state,
        "/api/v2/application-subject-status",
        LIFECYCLE_TOKEN,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for version in [1, 2] {
        body["source_event_id"] = format!(
            "access-application-status-v1_{}",
            version.to_string().repeat(64)
        )
        .into();
        body["subject_version"] = version.into();
        body["revocation_epoch"] = version.into();
        let (status, response) = post_json(
            &state,
            "/api/v2/application-subject-status",
            LIFECYCLE_TOKEN,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["replayed"], false);
        assert_eq!(response["subject_version"], version);
        assert_eq!(response["revocation_epoch"], version);
    }
}

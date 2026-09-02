use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use tower::ServiceExt;

use verdict::audit::AuditSink;
use verdict::config::{Config, ServiceCredentials};
use verdict::policy::{
    ApplicationRequestV2, ApplicationSubjectState, ApplicationSubjectStatus, DecisionV2, Effect,
    ProjectionEdge, Resource, SubjectAccessState,
};
use verdict::policy_store::{projection_payload_hash, PgPolicyStore, PolicyStore};
use verdict::store::{PgStore, Store};
use verdict::{app, AppState};

const DECISION_TOKEN: &str = "decision-token-00000000000000000001";
const PROJECTION_TOKEN: &str = "projection-token-000000000000000001";
const LIFECYCLE_TOKEN: &str = "lifecycle-token-0000000000000000001";

#[tokio::test]
async fn application_request_v2_digest_ttl_and_stale_rejection() {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping application decision PG test");
        return;
    };
    let tuple_store = Arc::new(PgStore::connect(&database_url).await.unwrap());
    tuple_store.migrate().await.unwrap();
    let policy = Arc::new(PgPolicyStore::connect(&database_url).await.unwrap());
    policy.migrate().await.unwrap();
    policy.migrate().await.expect("migration is idempotent");

    let suffix = verdict::now_nanos().to_string();
    let application_sub = format!("application:app{suffix}");
    let source = format!("grant:application:{suffix}");
    let event = format!("event:{suffix}");
    let edge_id = format!("edge:application:{suffix}");
    let projection_key = format!("projection:application:{suffix}");
    let resource_id = format!("analysis_{suffix}");
    policy
        .set_application_subject_status(ApplicationSubjectStatus {
            application_sub: application_sub.clone(),
            state: ApplicationSubjectState::Pending,
            source_event_id: format!("pending_{suffix}"),
            subject_version: 6,
            policy_epoch: 10,
            revocation_epoch: 12,
            updated_at: 1,
        })
        .await
        .unwrap();
    policy
        .set_application_subject_status(ApplicationSubjectStatus {
            application_sub: application_sub.clone(),
            state: ApplicationSubjectState::Active,
            source_event_id: event,
            subject_version: 7,
            policy_epoch: 11,
            revocation_epoch: 13,
            updated_at: 2,
        })
        .await
        .unwrap();
    let edges = vec![ProjectionEdge {
        edge_id: edge_id.clone(),
        projection_key,
        subject: application_sub.clone(),
        permission: "rikune.analysis.create".to_string(),
        effect: Effect::Allow,
        resource_selector: json!({"v":1,"type":"analysis","id":resource_id}),
        condition: None,
        not_before: None,
        expires_at: None,
        active: true,
        version: 1,
    }];
    let payload_hash = projection_payload_hash(&edges).unwrap();
    policy
        .replace_projection(&source, 1, &payload_hash, edges, 2)
        .await
        .unwrap();

    let mut config = Config::dev();
    config.service_credentials =
        ServiceCredentials::try_new(DECISION_TOKEN, PROJECTION_TOKEN, LIFECYCLE_TOKEN).unwrap();
    let state = AppState {
        config: Arc::new(config),
        store: tuple_store.clone() as Arc<dyn Store>,
        policy: policy.clone(),
        audit: AuditSink::disabled(),
    };
    let request = ApplicationRequestV2 {
        v: 2,
        application_sub: application_sub.clone(),
        client_id: format!("client_{suffix}"),
        credential_id: format!("cred_{suffix}"),
        credential_version: 3,
        grant_id: format!("grant_{suffix}"),
        package_id: "pkg_analyze_mcp_client".to_string(),
        package_revision_digest: "a".repeat(64),
        scopes: vec!["analysis.create".to_string()],
        canonical_tool: "analysis.create".to_string(),
        resource: Resource {
            kind: "analysis".to_string(),
            id: resource_id,
        },
        session_id: format!("session_{suffix}"),
        request_sha256: "b".repeat(64),
        policy_epoch: 11,
        revocation_epoch: 13,
        correlation_id: format!("corr_{suffix}"),
    };
    let response = app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v2/application-check")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {DECISION_TOKEN}"))
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decision: DecisionV2 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decision.expires_at - decision.issued_at, 30);
    assert_eq!(decision.subject_version, 7);

    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let row = sqlx::query(
        "SELECT decision_digest,subject_version,policy_epoch,expires_at-issued_at AS ttl \
         FROM policy_application_decisions_v2 WHERE decision_id=$1",
    )
    .bind(&decision.decision_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row.get::<String, _>("decision_digest"),
        decision.decision_digest
    );
    assert_eq!(row.get::<i64, _>("subject_version"), 7);
    assert_eq!(row.get::<i64, _>("policy_epoch"), 11);
    assert_eq!(row.get::<i64, _>("ttl"), 30);

    let legacy_subject = format!("user:legacy-{suffix}");
    policy
        .set_subject_status(
            &legacy_subject,
            SubjectAccessState::Active,
            &format!("legacy:{suffix}"),
            1,
            3,
        )
        .await
        .unwrap();
    assert!(policy
        .snapshot("cpa.console.enter", &legacy_subject)
        .await
        .unwrap()
        .subject_status
        .is_some());

    sqlx::query("DELETE FROM policy_application_decisions_v2 WHERE application_sub=$1")
        .bind(&application_sub)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_edges_v2 WHERE source_grant_id=$1")
        .bind(&source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_projection_source WHERE source_grant_id=$1")
        .bind(&source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_application_subject_status WHERE application_sub=$1")
        .bind(&application_sub)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_subject_status WHERE subject=$1")
        .bind(&legacy_subject)
        .execute(&pool)
        .await
        .unwrap();
}

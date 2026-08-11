//! Exhaustive least-privilege service credential routing tests.

use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use verdict::audit::AuditSink;
use verdict::config::{Config, ServiceCredentials, ServiceScope};
use verdict::policy::ProjectionEdge;
use verdict::policy_store::{projection_payload_hash, InMemoryPolicyStore};
use verdict::store::InMemoryStore;
use verdict::{app, AppState};

const DECISION_TOKEN: &str = "decision-token-00000000000000000001";
const PROJECTION_TOKEN: &str = "projection-token-000000000000000001";
const LIFECYCLE_TOKEN: &str = "lifecycle-token-0000000000000000001";
const LEGACY_MASTER_TOKEN: &str = "legacy-master-token-0000000000000001";

const ENDPOINTS: &[(&str, ServiceScope)] = &[
    ("/api/check", ServiceScope::Decision),
    ("/api/v2/check", ServiceScope::Decision),
    ("/api/list-objects", ServiceScope::Decision),
    ("/api/expand", ServiceScope::Decision),
    ("/api/v2/projections", ServiceScope::Projection),
    ("/api/tuples", ServiceScope::Projection),
    ("/api/tuples/delete", ServiceScope::Projection),
    ("/api/tuples/import", ServiceScope::Projection),
    ("/api/tuples/export", ServiceScope::Projection),
    ("/api/v2/subject-status", ServiceScope::Lifecycle),
];

fn protected_state() -> AppState {
    let mut config = Config::dev();
    config.service_credentials =
        ServiceCredentials::try_new(DECISION_TOKEN, PROJECTION_TOKEN, LIFECYCLE_TOKEN).unwrap();
    AppState {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        policy: Arc::new(InMemoryPolicyStore::new()),
        audit: AuditSink::disabled(),
    }
}

fn token(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::Decision => DECISION_TOKEN,
        ServiceScope::Projection => PROJECTION_TOKEN,
        ServiceScope::Lifecycle => LIFECYCLE_TOKEN,
    }
}

fn request(path: &str, bearer: Option<&str>, body: Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn body(path: &str) -> Value {
    match path {
        "/api/check" => {
            json!({"object":"doc:scope","relation":"viewer","subject":"user:scope"})
        }
        "/api/v2/check" => json!({
            "subject": "user:scope",
            "permission": "cpa.console.enter",
            "resource": {"type":"route","id":"cpa-root"},
            "context": {
                "zone":"internal",
                "mfa":true,
                "ip":"10.0.0.7",
                "request_id":"scope-matrix",
                "break_glass":false
            },
            "risk":"critical"
        }),
        "/api/list-objects" => json!({"relation":"viewer","subject":"user:scope"}),
        "/api/expand" => json!({"object":"doc:scope","relation":"viewer"}),
        "/api/v2/projections" => {
            let edges = Vec::<ProjectionEdge>::new();
            json!({
                "source_grant_id":"grant:scope-matrix",
                "source_version":1,
                "payload_hash":projection_payload_hash(&edges).unwrap(),
                "edges":edges
            })
        }
        "/api/tuples" | "/api/tuples/delete" => {
            json!({"object":"doc:scope","relation":"viewer","subject":"user:scope"})
        }
        "/api/tuples/import" => json!({
            "tuples":[{"object":"doc:scope","relation":"viewer","subject":"user:scope"}]
        }),
        "/api/tuples/export" => json!({"format":"json"}),
        "/api/v2/subject-status" => json!({
            "subject":"user:scope",
            "state":"frozen",
            "source_event_id":"event:scope-matrix",
            "source_version":1
        }),
        other => panic!("unmapped service endpoint: {other}"),
    }
}

async fn status(state: &AppState, path: &str, bearer: Option<&str>) -> StatusCode {
    app(state.clone())
        .oneshot(request(path, bearer, body(path)))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn every_service_endpoint_accepts_only_its_exact_scope() {
    let presented = [
        ServiceScope::Decision,
        ServiceScope::Projection,
        ServiceScope::Lifecycle,
    ];

    for &(path, required) in ENDPOINTS {
        assert_eq!(
            status(&protected_state(), path, None).await,
            StatusCode::UNAUTHORIZED,
            "{path} accepted a missing credential"
        );
        assert_eq!(
            status(&protected_state(), path, Some(LEGACY_MASTER_TOKEN)).await,
            StatusCode::UNAUTHORIZED,
            "{path} accepted the removed legacy master credential"
        );

        for actual in presented {
            let response = status(&protected_state(), path, Some(token(actual))).await;
            if actual == required {
                assert_eq!(response, StatusCode::OK, "{path} rejected {actual:?}");
            } else {
                assert_eq!(
                    response,
                    StatusCode::UNAUTHORIZED,
                    "{path} accepted wrong scope {actual:?}; required {required:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn wrong_scope_requests_do_not_mutate_tuple_projection_or_lifecycle_state() {
    let state = protected_state();
    assert_eq!(
        status(&state, "/api/tuples", Some(DECISION_TOKEN)).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(state
        .store
        .subjects_for("doc:scope", "viewer")
        .await
        .is_empty());

    assert_eq!(
        status(&state, "/api/v2/projections", Some(LIFECYCLE_TOKEN)).await,
        StatusCode::UNAUTHORIZED
    );
    let snapshot = state
        .policy
        .snapshot("cpa.console.enter", "user:scope")
        .await
        .unwrap();
    assert_eq!(snapshot.epoch, 0);
    assert!(snapshot.edges.is_empty());

    assert_eq!(
        status(&state, "/api/v2/subject-status", Some(PROJECTION_TOKEN)).await,
        StatusCode::UNAUTHORIZED
    );
    let snapshot = state
        .policy
        .snapshot("cpa.console.enter", "user:scope")
        .await
        .unwrap();
    assert!(snapshot.subject_status.is_none());
}

#[tokio::test]
async fn health_and_sso_console_do_not_require_a_service_credential() {
    let state = protected_state();
    let health = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let console = app(state)
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-auth-subject", "user:admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(console.status(), StatusCode::OK);
}

fn production_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_verdict"));
    command
        .env("VERDICT_STORE", "postgres")
        .env_remove("DATABASE_URL")
        .env_remove("VERDICT_SERVICE_TOKEN")
        .env_remove("VERDICT_DECISION_TOKEN")
        .env_remove("VERDICT_PROJECTION_TOKEN")
        .env_remove("VERDICT_LIFECYCLE_TOKEN");
    command
}

fn assert_startup_rejected(mut command: Command, expected: &str) {
    let output = command.output().expect("start Verdict test process");
    assert!(!output.status.success(), "invalid production config booted");
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains(expected),
        "startup error did not contain {expected:?}: {logs}"
    );
}

#[test]
fn postgres_runtime_fails_closed_before_database_connection() {
    assert_startup_rejected(
        production_command(),
        "VERDICT_STORE=postgres requires VERDICT_DECISION_TOKEN",
    );

    let mut partial = production_command();
    partial.env("VERDICT_DECISION_TOKEN", DECISION_TOKEN);
    assert_startup_rejected(partial, "service credential configuration is partial");

    let mut duplicate = production_command();
    duplicate
        .env("VERDICT_DECISION_TOKEN", DECISION_TOKEN)
        .env("VERDICT_PROJECTION_TOKEN", DECISION_TOKEN)
        .env("VERDICT_LIFECYCLE_TOKEN", LIFECYCLE_TOKEN);
    assert_startup_rejected(duplicate, "must be pairwise distinct");

    let mut legacy = production_command();
    legacy.env("VERDICT_SERVICE_TOKEN", LEGACY_MASTER_TOKEN);
    assert_startup_rejected(legacy, "VERDICT_SERVICE_TOKEN is no longer accepted");
}

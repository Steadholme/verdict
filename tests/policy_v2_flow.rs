use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use verdict::audit::AuditSink;
use verdict::config::{Config, ServiceCredentials};
use verdict::policy::ProjectionEdge;
use verdict::policy_store::{projection_payload_hash, InMemoryPolicyStore};
use verdict::store::InMemoryStore;
use verdict::{app, AppState};

const DECISION_TOKEN: &str = "decision-token-00000000000000000001";
const PROJECTION_TOKEN: &str = "projection-token-000000000000000001";
const LIFECYCLE_TOKEN: &str = "lifecycle-token-0000000000000000001";

fn state() -> AppState {
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

fn post(uri: &str, body: Value) -> Request<Body> {
    let token = match uri {
        "/api/v2/check" => DECISION_TOKEN,
        "/api/v2/projections" => PROJECTION_TOKEN,
        "/api/v2/subject-status" => LIFECYCLE_TOKEN,
        other => panic!("unmapped v2 test endpoint: {other}"),
    };
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn projection_body(source_grant_id: &str, source_version: i64, edges: Value) -> Value {
    let edges: Vec<ProjectionEdge> = serde_json::from_value(edges).unwrap();
    let payload_hash = projection_payload_hash(&edges).unwrap();
    json!({
        "source_grant_id": source_grant_id,
        "source_version": source_version,
        "payload_hash": payload_hash,
        "edges": edges
    })
}

fn check_body() -> Value {
    json!({
        "subject": "user:alice",
        "permission": "cpa.console.enter",
        "resource": {"type": "route", "id": "cpa-root"},
        "context": {
            "zone": "internal",
            "mfa": true,
            "ip": "10.1.2.3",
            "request_id": "request-1",
            "break_glass": false
        },
        "risk": "critical"
    })
}

#[tokio::test]
async fn projection_then_check_applies_deny_override_with_ordered_evidence() {
    let state = state();
    let (status, projection) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body(
                "grant:allow",
                1,
                json!([{
                    "edge_id": "edge:z-allow",
                    "projection_key": "grant:allow:cpa.console.enter",
                    "subject": "user:alice",
                    "permission": "cpa.console.enter",
                    "effect": "allow",
                    "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
                    "version": 1
                }]),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(projection["epoch"], 1);

    let (status, _) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body(
                "grant:deny",
                1,
                json!([{
                    "edge_id": "edge:a-deny",
                    "projection_key": "grant:deny:cpa.console.enter",
                    "subject": "user:alice",
                    "permission": "cpa.console.enter",
                    "effect": "deny",
                    "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
                    "version": 1
                }]),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, decision) = call(&state, post("/api/v2/check", check_body())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision["decision"], "Deny");
    assert_eq!(decision["reason"], "deny-override");
    assert_eq!(decision["epoch"], 2);
    assert_eq!(decision["evidence"][0]["edge_id"], "edge:a-deny");
    assert_eq!(decision["evidence"][1]["edge_id"], "edge:z-allow");
}

#[tokio::test]
async fn caller_controlled_evaluation_time_is_rejected_as_bad_request() {
    let state = state();
    let mut body = check_body();
    body["evaluated_at"] = json!(1);
    let (status, response) = call(&state, post("/api/v2/check", body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "bad-request");
}

#[tokio::test]
async fn unknown_condition_cannot_be_projected() {
    let state = state();
    let (status, response) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body(
                "grant:bad",
                1,
                json!([{
                    "edge_id": "edge:bad",
                    "projection_key": "grant:bad:cpa.console.enter",
                    "subject": "user:alice",
                    "permission": "cpa.console.enter",
                    "effect": "allow",
                    "condition": {"v":1,"op":"regex","field":"zone","value":".*"},
                    "version": 1
                }]),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "bad-request");
}

#[tokio::test]
async fn projection_ingress_rejects_noncanonical_global_and_open_condition_shapes() {
    let state = state();
    let invalid_cases = [
        json!({
            "edge_id": "edge:any-not-global",
            "projection_key": "grant:bad:any-not-global",
            "subject": "user:alice",
            "permission": "cpa.console.enter",
            "effect": "allow",
            "resource_selector": {"v":1,"type":"any","id":"foo"},
            "version": 1
        }),
        json!({
            "edge_id": "edge:condition-extra",
            "projection_key": "grant:bad:condition-extra",
            "subject": "user:alice",
            "permission": "cpa.console.enter",
            "effect": "allow",
            "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
            "condition": {"v":1,"op":"eq","field":"mfa","value":true,"extra":1},
            "version": 1
        }),
        json!({
            "edge_id": "edge:nested-version",
            "projection_key": "grant:bad:nested-version",
            "subject": "user:alice",
            "permission": "cpa.console.enter",
            "effect": "allow",
            "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
            "condition": {"v":1,"op":"not","args":[{"v":1,"op":"present","field":"ip"}]},
            "version": 1
        }),
    ];

    for (index, edge) in invalid_cases.into_iter().enumerate() {
        let (status, response) = call(
            &state,
            post(
                "/api/v2/projections",
                projection_body(&format!("grant:bad-shape:{index}"), 1, json!([edge])),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}");
        assert_eq!(response["error"]["code"], "bad-request", "case {index}");
    }
}

#[tokio::test]
async fn projection_source_fencing_rejects_late_and_conflicting_payloads() {
    let state = state();
    let allow = json!([{
        "edge_id": "edge:fenced-allow",
        "projection_key": "grant:fenced:cpa.console.enter",
        "subject": "user:alice",
        "permission": "cpa.console.enter",
        "effect": "allow",
        "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
        "version": 1
    }]);
    let (status, first) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body("grant:fenced", 1, allow.clone()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, revoked) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body("grant:fenced", 2, json!([])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(revoked["epoch"].as_i64() > first["epoch"].as_i64());

    let (status, replay) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body("grant:fenced", 2, json!([])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["epoch"], revoked["epoch"]);

    let (status, stale) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body("grant:fenced", 1, allow.clone()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["error"]["code"], "projection-stale-version");

    let mut conflicting_allow = allow;
    conflicting_allow[0]["version"] = json!(2);
    let (status, conflict) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body("grant:fenced", 2, conflicting_allow),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"]["code"], "projection-conflict");

    let (status, decision) = call(&state, post("/api/v2/check", check_body())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision["decision"], "Deny");
    assert_eq!(decision["reason"], "no-grant-path");
}

#[tokio::test]
async fn jml_subject_status_denies_every_permission_and_is_version_fenced() {
    let state = state();
    let (status, _) = call(
        &state,
        post(
            "/api/v2/projections",
            projection_body(
                "grant:before-leaver",
                1,
                json!([{
                    "edge_id": "edge:before-leaver",
                    "projection_key": "grant:before-leaver:cpa.console.enter",
                    "subject": "user:alice",
                    "permission": "cpa.console.enter",
                    "effect": "allow",
                    "resource_selector": {"v":1,"type":"route","id":"cpa-root"},
                    "version": 1
                }]),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let terminated = json!({
        "subject": "user:alice",
        "state": "terminated",
        "source_event_id": "census-event-42",
        "source_version": 42
    });
    let (status, first) = call(&state, post("/api/v2/subject-status", terminated.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["state"], "terminated");
    assert_eq!(first["replayed"], false);

    let (status, decision) = call(&state, post("/api/v2/check", check_body())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision["decision"], "Deny");
    assert_eq!(decision["reason"], "subject-terminated");
    assert_eq!(
        decision["evidence"][0]["source_grant_id"],
        "jml:census-event-42"
    );

    let (status, replay) = call(&state, post("/api/v2/subject-status", terminated)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["epoch"], first["epoch"]);
    assert_eq!(replay["replayed"], true);

    let (status, conflict) = call(
        &state,
        post(
            "/api/v2/subject-status",
            json!({
                "subject": "user:alice",
                "state": "active",
                "source_event_id": "conflicting-event",
                "source_version": 42
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"]["code"], "subject-status-conflict");

    let (status, stale) = call(
        &state,
        post(
            "/api/v2/subject-status",
            json!({
                "subject": "user:alice",
                "state": "active",
                "source_event_id": "stale-event",
                "source_version": 41
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["error"]["code"], "subject-status-stale-version");
}

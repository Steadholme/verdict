//! End-to-end flow tests against the in-memory store (NO database, NO network).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising: the `/api/check` decision
//! (direct grant + userset indirection + deny), the service-token gate, tuple write/delete through
//! the API, the SSO console (browse + add + delete with the double-submit CSRF guard), the read
//! tools (check tester / expand / list-objects rendered into the page), and the healthcheck.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use verdict::audit::AuditSink;
use verdict::config::Config;
use verdict::store::InMemoryStore;
use verdict::{app, seed_examples, AppState};

const SERVICE_TOKEN: &str = "verdict-test-token";

/// State with the service token enforced + the example tuple set seeded.
async fn seeded_state() -> AppState {
    let mut config = Config::dev();
    config.service_token = Some(SERVICE_TOKEN.to_string());
    let store = Arc::new(InMemoryStore::new());
    seed_examples(store.as_ref()).await;
    AppState {
        config: Arc::new(config),
        store,
        audit: AuditSink::disabled(),
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn api_post(token: Option<&str>, uri: &str, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("valid JSON response")
}

#[tokio::test]
async fn healthz_is_public_and_plain_ok() {
    let state = seeded_state().await;
    let (status, body) = call(&state, Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn api_check_direct_grant_allowed() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "doc:readme", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = parse(&body);
    assert_eq!(v["allowed"], true);
    assert_eq!(v["via"][0], "doc:readme#viewer@user:w33d");
}

#[tokio::test]
async fn api_check_indirection_allowed_with_path() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "doc:secret", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = parse(&body);
    assert_eq!(v["allowed"], true, "userset indirection grants viewer");
    assert_eq!(v["via"][0], "doc:secret#viewer@group:eng#member");
    assert_eq!(v["via"][1], "group:eng#member@user:w33d");
}

#[tokio::test]
async fn api_check_unrelated_subject_denied() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "doc:secret", "relation": "viewer", "subject": "user:intruder"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = parse(&body);
    assert_eq!(v["allowed"], false);
    assert!(v["via"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn api_requires_service_token_when_configured() {
    let state = seeded_state().await;
    // No token -> 401.
    let (status, _) = call(
        &state,
        api_post(
            None,
            "/api/check",
            json!({"object": "doc:readme", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong token -> 401.
    let (status, _) = call(
        &state,
        api_post(
            Some("wrong"),
            "/api/check",
            json!({"object": "doc:readme", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_write_then_check_then_delete() {
    let state = seeded_state().await;

    // Write a brand-new tuple.
    let (status, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/tuples",
            json!({"object": "doc:roadmap", "relation": "editor", "subject": "user:zed"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body)["written"], true);

    // Idempotent: same triple again -> written=false.
    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/tuples",
            json!({"object": "doc:roadmap", "relation": "editor", "subject": "user:zed"}),
        ),
    )
    .await;
    assert_eq!(parse(&body)["written"], false);

    // Check it now resolves.
    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "doc:roadmap", "relation": "editor", "subject": "user:zed"}),
        ),
    )
    .await;
    assert_eq!(parse(&body)["allowed"], true);

    // Delete it.
    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/tuples/delete",
            json!({"object": "doc:roadmap", "relation": "editor", "subject": "user:zed"}),
        ),
    )
    .await;
    assert_eq!(parse(&body)["deleted"], true);

    // Now denied.
    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "doc:roadmap", "relation": "editor", "subject": "user:zed"}),
        ),
    )
    .await;
    assert_eq!(parse(&body)["allowed"], false);
}

#[tokio::test]
async fn api_list_objects_and_expand() {
    let state = seeded_state().await;

    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/list-objects",
            json!({"relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    let objs = parse(&body)["objects"].as_array().unwrap().clone();
    let objs: Vec<String> = objs.iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(objs, vec!["doc:readme", "doc:secret"]);

    let (_, body) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/expand",
            json!({"object": "doc:secret", "relation": "viewer"}),
        ),
    )
    .await;
    let v = parse(&body);
    assert_eq!(v["direct"][0], "group:eng#member");
    assert_eq!(v["members"][0], "user:w33d");
}

#[tokio::test]
async fn api_rejects_invalid_triple() {
    let state = seeded_state().await;
    let (status, _) = call(
        &state,
        api_post(
            Some(SERVICE_TOKEN),
            "/api/check",
            json!({"object": "", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- Console (SSO) --------------------------------------------------------

fn csrf_from_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    for hv in headers.get_all(header::SET_COOKIE).iter() {
        let raw = hv.to_str().ok()?;
        if let Some(rest) = raw.strip_prefix("__Host-csrf=") {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

#[tokio::test]
async fn console_renders_seeded_tuples_and_tester_path() {
    let state = seeded_state().await;
    // Render the console with the check tester pre-run for the indirection case.
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/?ck_object=doc:secret&ck_relation=viewer&ck_subject=user:w33d")
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert!(html.contains("group:eng#member"), "seeded userset tuple shown");
    assert!(html.contains("ALLOWED"), "tester verdict rendered");
    assert!(html.contains("doc:secret#viewer@group:eng#member"), "resolution path step shown");
    assert!(html.contains("admin@w33d.xyz"), "signed-in identity in top bar");
}

#[tokio::test]
async fn console_add_and_delete_with_csrf() {
    let state = seeded_state().await;

    // GET to obtain a CSRF cookie.
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = csrf_from_cookie(resp.headers()).expect("fresh CSRF cookie minted");

    // POST add with a matching cookie + form token.
    let add_body = "object=doc:plan&relation=viewer&subject=user:zed&csrf_token=".to_string() + &csrf;
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("__Host-csrf={csrf}"))
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::from(add_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(state.store.subjects_for("doc:plan", "viewer").await.contains(&"user:zed".to_string()));

    // A mismatched CSRF token is rejected (401).
    let bad = "object=doc:plan&relation=viewer&subject=user:evil&csrf_token=wrong";
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("__Host-csrf={csrf}"))
                .header("x-auth-subject", "u_admin")
                .body(Body::from(bad))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Delete the tuple we added.
    let del_body = "object=doc:plan&relation=viewer&subject=user:zed&csrf_token=".to_string() + &csrf;
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("__Host-csrf={csrf}"))
                .header("x-auth-subject", "u_admin")
                .body(Body::from(del_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(state.store.subjects_for("doc:plan", "viewer").await.is_empty());
}

#[tokio::test]
async fn dev_mode_disables_api_auth() {
    // Default dev state (no service token) -> /api/check works without a bearer.
    let store = Arc::new(InMemoryStore::new());
    seed_examples(store.as_ref()).await;
    let state = AppState {
        config: Arc::new(Config::dev()),
        store,
        audit: AuditSink::disabled(),
    };
    let (status, body) = call(
        &state,
        api_post(
            None,
            "/api/check",
            json!({"object": "doc:readme", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body)["allowed"], true);
}

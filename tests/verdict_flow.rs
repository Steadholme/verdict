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
use verdict::config::{Config, ServiceCredentials};
use verdict::policy_store::InMemoryPolicyStore;
use verdict::store::InMemoryStore;
use verdict::{app, seed_examples, AppState};

const DECISION_TOKEN: &str = "decision-token-00000000000000000001";
const PROJECTION_TOKEN: &str = "projection-token-000000000000000001";
const LIFECYCLE_TOKEN: &str = "lifecycle-token-0000000000000000001";

/// State with the service token enforced + the example tuple set seeded.
async fn seeded_state() -> AppState {
    let mut config = Config::dev();
    config.service_credentials =
        ServiceCredentials::try_new(DECISION_TOKEN, PROJECTION_TOKEN, LIFECYCLE_TOKEN).unwrap();
    let store = Arc::new(InMemoryStore::new());
    seed_examples(store.as_ref()).await;
    AppState {
        config: Arc::new(config),
        store,
        policy: Arc::new(InMemoryPolicyStore::new()),
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
    let (status, body) = call(
        &state,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn stylesheet_is_versioned_and_immutable() {
    let state = seeded_state().await;
    let resp = app(state)
        .oneshot(
            Request::builder()
                .uri("/assets/verdict-20260908.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    let css = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(css.len() > 100_000);
}

#[tokio::test]
async fn api_check_direct_grant_allowed() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        api_post(
            Some(DECISION_TOKEN),
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
            Some(DECISION_TOKEN),
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
            Some(DECISION_TOKEN),
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
            Some(PROJECTION_TOKEN),
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
            Some(PROJECTION_TOKEN),
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
            Some(DECISION_TOKEN),
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
            Some(PROJECTION_TOKEN),
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
            Some(DECISION_TOKEN),
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
            Some(DECISION_TOKEN),
            "/api/list-objects",
            json!({"relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    let objs = parse(&body)["objects"].as_array().unwrap().clone();
    let objs: Vec<String> = objs
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(objs, vec!["doc:readme", "doc:secret"]);

    let (_, body) = call(
        &state,
        api_post(
            Some(DECISION_TOKEN),
            "/api/expand",
            json!({"object": "doc:secret", "relation": "viewer"}),
        ),
    )
    .await;
    let v = parse(&body);
    assert_eq!(v["direct"][0], "group:eng#member");
    assert_eq!(v["members"][0], "user:w33d");
    assert_eq!(v["tree"][0]["subject"], "group:eng#member");
    assert_eq!(v["tree"][0]["userset"], true);
    assert_eq!(v["tree"][0]["children"][0]["subject"], "user:w33d");
}

#[tokio::test]
async fn api_rejects_invalid_triple() {
    let state = seeded_state().await;
    let (status, _) = call(
        &state,
        api_post(
            Some(DECISION_TOKEN),
            "/api/check",
            json!({"object": "", "relation": "viewer", "subject": "user:w33d"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_imports_and_exports_tuples_as_json_and_csv() {
    let state = seeded_state().await;

    let (status, body) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/tuples/import",
            json!({"tuples":[{"object":"doc:bulk","relation":"viewer","subject":"user:bulk"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = parse(&body);
    assert_eq!(report["total"], 1);
    assert_eq!(report["written"], 1);
    assert_eq!(report["skipped"], 0);
    assert!(state
        .store
        .subjects_for("doc:bulk", "viewer")
        .await
        .contains(&"user:bulk".to_string()));

    let (_, body) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/tuples/import",
            json!({"format":"csv","content":"object,relation,subject\ndoc:csv,viewer,user:csv\n"}),
        ),
    )
    .await;
    assert_eq!(parse(&body)["written"], 1);

    let (status, body) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/tuples/export",
            json!({"format":"json"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let exported = parse(&body);
    assert!(exported["tuples"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["object"] == "doc:bulk"));

    let (status, body) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/tuples/export",
            json!({"format":"csv"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let csv = String::from_utf8(body).unwrap();
    assert!(csv.starts_with("object,relation,subject\n"));
    assert!(csv.contains("doc:csv,viewer,user:csv"));

    let (status, _) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/tuples/import",
            json!({"tuples":[{"object":"doc:bad","relation":"view er","subject":"user:bad"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(state
        .store
        .subjects_for("doc:bad", "view er")
        .await
        .is_empty());
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
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        html.contains("group:eng#member"),
        "seeded userset tuple shown"
    );
    assert!(html.contains("ALLOW"), "tester verdict rendered");
    assert!(
        html.contains(r#"<span class="tc tc--userset tc--sm">group:eng#member</span>"#),
        "resolution path step shown as typed chips"
    );
    assert!(
        html.contains("admin@w33d.xyz"),
        "signed-in identity in top bar"
    );
    assert!(html.contains(r#"<link rel="stylesheet" href="/assets/verdict-20260908.css">"#));
    assert!(!html.contains("<style>"));
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
    let add_body =
        "object=doc:plan&relation=viewer&subject=user:zed&csrf_token=".to_string() + &csrf;
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
    assert!(state
        .store
        .subjects_for("doc:plan", "viewer")
        .await
        .contains(&"user:zed".to_string()));

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
    let del_body =
        "object=doc:plan&relation=viewer&subject=user:zed&csrf_token=".to_string() + &csrf;
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
    assert!(state
        .store
        .subjects_for("doc:plan", "viewer")
        .await
        .is_empty());
}

#[tokio::test]
async fn console_imports_and_exports_with_csrf() {
    let state = seeded_state().await;

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

    let import_body = format!(
        "format=csv&content=object%2Crelation%2Csubject%0Adoc%3Aconsole%2Cviewer%2Cuser%3Azed&csrf_token={csrf}"
    );
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/import")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("__Host-csrf={csrf}"))
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::from(import_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/?import_total=1&import_written=1&import_skipped=0"
    );
    assert!(state
        .store
        .subjects_for("doc:console", "viewer")
        .await
        .contains(&"user:zed".to_string()));

    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/?import_total=1&import_written=1&import_skipped=0")
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Imported 1 of 1 · 0 duplicate or existing"));
    assert!(html.contains("Import / export"));

    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/export?format=json")
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json; charset=utf-8"
    );
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("doc:console"));
}

#[tokio::test]
async fn dev_mode_disables_api_auth() {
    // Default dev state (no service token) -> /api/check works without a bearer.
    let store = Arc::new(InMemoryStore::new());
    seed_examples(store.as_ref()).await;
    let state = AppState {
        config: Arc::new(Config::dev()),
        store,
        policy: Arc::new(InMemoryPolicyStore::new()),
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

// ---------------------------------------------------------------------------
// v2 console surfaces: decision inspector, expand, list-objects, subjects, API
// ---------------------------------------------------------------------------

/// Every console page carries the same four-item app bar, so the surfaces read as one product.
#[tokio::test]
async fn every_console_page_shares_the_app_bar() {
    let state = seeded_state().await;
    for uri in [
        "/",
        "/decisions",
        "/expand",
        "/list-objects",
        "/subjects",
        "/api",
    ] {
        let (status, body) = call(&state, sso_get(uri)).await;
        assert_eq!(status, StatusCode::OK, "{uri} renders");
        let html = String::from_utf8(body).unwrap();
        for label in ["Console", "Decisions", "Subjects", "API"] {
            assert!(html.contains(label), "{uri} shows the {label} nav item");
        }
        assert!(
            !html.contains("{{"),
            "{uri} leaves no unfilled template placeholder"
        );
        assert!(html.contains(r#"<link rel="stylesheet" href="/assets/verdict-20260908.css">"#));
    }
}

/// The inspector runs the same evaluation the v2 API runs and shows the typed decision, the
/// evidence and the JSON body a caller would receive.
#[tokio::test]
async fn decision_inspector_renders_verdict_and_evidence() {
    let state = seeded_state().await;
    let edges = json!([{
        "edge_id": "edge_1b02",
        "projection_key": "ag_88c1/0",
        "subject": "user:w33d",
        "permission": "ledger.post.approve",
        "effect": "allow",
        "resource_selector": {"v": 1, "type": "any", "id": "*"},
        "condition": null,
        "not_before": null,
        "expires_at": null,
        "active": true,
        "version": 1
    }]);
    let parsed: Vec<verdict::policy::ProjectionEdge> =
        serde_json::from_value(edges.clone()).unwrap();
    let payload_hash = verdict::policy_store::projection_payload_hash(&parsed).unwrap();
    let (status, _) = call(
        &state,
        api_post(
            Some(PROJECTION_TOKEN),
            "/api/v2/projections",
            json!({
                "source_grant_id": "ag_88c1",
                "source_version": 1,
                "payload_hash": payload_hash,
                "edges": edges
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "projection accepted");

    let (status, body) = call(
        &state,
        sso_get("/decisions?subject=user:w33d&permission=ledger.post.approve&resource_kind=ledger&resource_id=ledger:fin-2026&risk=high&mfa=on"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains(r#"<span class="verdict__word">ALLOW</span>"#));
    assert!(html.contains("edge_1b02"), "evidence edge shown");
    assert!(html.contains("allow-direct"), "reason shown");
    assert!(
        html.contains("POST /api/v2/check · 200"),
        "response block shown"
    );

    // Without a request the page still renders, with no verdict banner.
    let (status, body) = call(&state, sso_get("/decisions")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(
        !html.contains("verdict__word"),
        "no verdict before evaluating"
    );
}

/// Expand walks usersets and reports the depth it reached.
#[tokio::test]
async fn expand_page_renders_the_access_tree() {
    let state = seeded_state().await;
    let (status, body) = call(&state, sso_get("/expand?object=doc:secret&relation=viewer")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(
        html.contains(r#"<ul class="tree">"#),
        "access tree rendered"
    );
    assert!(html.contains("group:eng#member"), "userset in the tree");
    assert!(html.contains("Depth reached"), "expansion facts rendered");
}

/// List objects names the userset each object came through.
#[tokio::test]
async fn list_objects_page_marks_userset_paths() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        sso_get("/list-objects?relation=viewer&subject=user:w33d"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("doc:secret"), "reachable object listed");
    assert!(
        html.contains(r#"class="tc tc--userset tc--sm">group:eng#member"#),
        "the userset that granted it is named"
    );
}

/// The subject page writes through the same fence the lifecycle API uses: a stale source_version
/// is refused, and the state is only applied with a matching CSRF token.
#[tokio::test]
async fn subjects_page_applies_and_fences_lifecycle_writes() {
    let state = seeded_state().await;
    let resp = app(state.clone())
        .oneshot(sso_get("/subjects"))
        .await
        .unwrap();
    let csrf = csrf_from_cookie(resp.headers()).expect("fresh CSRF cookie minted");

    let form = |version: &str| {
        format!("subject=user:e.park&state=frozen&source_event_id=evt_ag_91c0&source_version={version}&csrf_token={csrf}")
    };
    let post = |body: String| {
        Request::builder()
            .method("POST")
            .uri("/subjects")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("__Host-csrf={csrf}"))
            .header("x-auth-subject", "u_admin")
            .header("x-auth-email", "admin@w33d.xyz")
            .body(Body::from(body))
            .unwrap()
    };

    let (status, _) = call(&state, post(form("4"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "state applied");

    let (status, _) = call(&state, post(form("2"))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a stale source_version is fenced"
    );

    let (status, body) = call(&state, sso_get("/subjects")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("user:e.park"), "subject listed");
    assert!(html.contains(r#"chip chip--frozen"#), "frozen state shown");

    // Without a CSRF token the write is refused.
    let (status, _) = call(
        &state,
        Request::builder()
            .method("POST")
            .uri("/subjects")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-auth-subject", "u_admin")
            .header("x-auth-email", "admin@w33d.xyz")
            .body(Body::from(
                "subject=user:k.ito&state=frozen&source_event_id=e&source_version=1",
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The API page names every credential but NEVER renders a token value — an SSO console reader
/// must not be able to lift a service credential from the page.
#[tokio::test]
async fn api_page_shows_fingerprints_not_token_values() {
    let state = seeded_state().await;
    let (status, body) = call(&state, sso_get("/api")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    for token in [DECISION_TOKEN, PROJECTION_TOKEN, LIFECYCLE_TOKEN] {
        assert!(!html.contains(token), "token value never rendered");
    }
    for name in [
        "VERDICT_DECISION_TOKEN",
        "VERDICT_PROJECTION_TOKEN",
        "VERDICT_LIFECYCLE_TOKEN",
    ] {
        assert!(html.contains(name), "{name} named");
    }
    assert!(html.contains("sha256 "), "fingerprint shown instead");
    assert!(html.contains("/api/v2/subject-status"), "endpoint listed");
}

/// Deleting a tuple is confirmed on its own page; the POST still needs the CSRF token.
#[tokio::test]
async fn delete_is_confirmed_on_its_own_page() {
    let state = seeded_state().await;
    let (status, body) = call(
        &state,
        sso_get("/delete?object=doc:secret&relation=viewer&subject=group:eng%23member"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("Delete tuple"), "confirmation rendered");
    assert!(html.contains(r#"<form method="post" action="/delete""#));
    assert!(
        state
            .store
            .subjects_for("doc:secret", "viewer")
            .await
            .contains(&"group:eng#member".to_string()),
        "the confirmation page deletes nothing"
    );
}

/// An SSO GET with the gateway identity headers.
fn sso_get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", "u_admin")
        .header("x-auth-email", "admin@w33d.xyz")
        .body(Body::empty())
        .unwrap()
}

//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=verdict \
//!   -p 127.0.0.1:55480:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55480/verdict \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so it
//! runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use verdict::check;
use verdict::store::{PgStore, Store, Tuple};
use verdict::{app, build_dev_state, now_secs, seed_examples, AppState};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    let pg = Arc::new(pg);

    // Clean slate for a deterministic run.
    for (o, r, s) in [
        ("doc:readme", "viewer", "user:w33d"),
        ("group:eng", "member", "user:w33d"),
        ("doc:secret", "viewer", "group:eng#member"),
        ("doc:roadmap", "editor", "user:zed"),
    ] {
        let _ = pg.delete_tuple(o, r, s).await;
    }

    // --- direct Store-trait round-trip + idempotency -----------------------
    let now = now_secs();
    let t = |id: &str, o: &str, r: &str, s: &str| Tuple {
        id: id.to_string(),
        object: o.to_string(),
        relation: r.to_string(),
        subject: s.to_string(),
        created_at: now,
    };
    assert!(pg.add_tuple(&t("pg_1", "doc:readme", "viewer", "user:w33d")).await.unwrap());
    // ON CONFLICT DO NOTHING -> second insert of the same triple is not "written".
    assert!(!pg.add_tuple(&t("pg_1b", "doc:readme", "viewer", "user:w33d")).await.unwrap());

    pg.add_tuple(&t("pg_2", "group:eng", "member", "user:w33d")).await.unwrap();
    pg.add_tuple(&t("pg_3", "doc:secret", "viewer", "group:eng#member")).await.unwrap();

    // Reverse reads back the indexed columns.
    let mut subs = pg.subjects_for("doc:secret", "viewer").await;
    subs.sort();
    assert_eq!(subs, vec!["group:eng#member"]);
    assert!(pg.objects_with_relation("viewer").await.contains(&"doc:secret".to_string()));

    // --- the check engine over the PG-backed store -------------------------
    let direct = check::check(pg.as_ref(), "doc:readme", "viewer", "user:w33d").await;
    assert!(direct.allowed);
    let indirect = check::check(pg.as_ref(), "doc:secret", "viewer", "user:w33d").await;
    assert!(indirect.allowed, "userset indirection resolves over Postgres");
    assert_eq!(
        indirect.via,
        vec!["doc:secret#viewer@group:eng#member", "group:eng#member@user:w33d"]
    );

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    let (status, body) = raw_call(
        &state,
        Request::builder()
            .method("POST")
            .uri("/api/check")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"object":"doc:secret","relation":"viewer","subject":"user:w33d"}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("\"allowed\":true"));

    // Delete via the API and confirm.
    let (status, _) = raw_call(
        &state,
        Request::builder()
            .method("POST")
            .uri("/api/tuples/delete")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"object":"doc:secret","relation":"viewer","subject":"group:eng#member"}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(pg.subjects_for("doc:secret", "viewer").await.is_empty(), "deleted in pg");

    // --- seeding is idempotent (store already non-empty -> no-op) ----------
    let before = pg.list_tuples().await.len();
    seed_examples(pg.as_ref()).await;
    assert_eq!(pg.list_tuples().await.len(), before, "seed is a no-op on a non-empty store");

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + add/conflict/reverse-read + check engine \
         (direct + userset indirection) + API check/delete HTTP flow + idempotent seed against real \
         Postgres"
    );
}

async fn raw_call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

//! Verdict — Zanzibar-style ReBAC/ABAC policy decision point for the Steadholme stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store, no database, audit disabled) and
//! [`build_state_from_env`] (env-selected store + Watchtower audit). Integration tests consume
//! [`app`] directly via `tower::oneshot`.
//!
//! Two surfaces on one subdomain (`authz.w33d.xyz`), split at the gateway:
//! - **`/` admin console — `auth=sso`.** Browse/add/delete relation tuples, a live check tester,
//!   an expand view, and a list-objects view. The gateway injects the verified `X-Auth-*`; Verdict
//!   trusts it (internal-only). State-changing console POSTs carry a double-submit CSRF token.
//! - **`/api/*` service APIs — `auth=public` at the gateway, Verdict's scoped credential auth.**
//!   Every handler selects one independent decision, projection, or lifecycle Bearer credential;
//!   no cross-scope master credential exists.
//!
//! Endpoints:
//! - `GET  /healthz`            — liveness (public)
//! - `GET  /`                   — admin console (browse + the three read tools)
//! - `POST /`                   — add a relation tuple (CSRF)
//! - `POST /delete`             — delete a relation tuple (CSRF)
//! - `POST /import`             — bulk-import relation tuples (CSRF)
//! - `GET  /export`             — export relation tuples as CSV/JSON
//! - `POST /api/check` and `/api/v2/check` — decisions (`VERDICT_DECISION_TOKEN`)
//! - `POST /api/list-objects` and `/api/expand` — decision reads (`VERDICT_DECISION_TOKEN`)
//! - `POST /api/v2/projections` — desired-state projection (`VERDICT_PROJECTION_TOKEN`)
//! - `POST /api/tuples[/delete|/import|/export]` — legacy tuple administration
//!   (`VERDICT_PROJECTION_TOKEN`)
//! - `POST /api/v2/subject-status` — JML lifecycle (`VERDICT_LIFECYCLE_TOKEN`)

pub mod audit;
pub mod auth;
pub mod check;
pub mod condition;
pub mod config;
pub mod error;
pub mod handlers;
pub mod policy;
pub mod policy_check;
pub mod policy_store;
pub mod store;
pub mod tuple_io;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::policy_store::{InMemoryPolicyStore, PgPolicyStore, PolicyStore};
use crate::store::{InMemoryStore, PgStore, Store, Tuple};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub policy: Arc<dyn PolicyStore>,
    pub audit: AuditSink,
}

/// Build the router wiring both surfaces onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- SSO admin console ---
        .route(
            "/",
            get(handlers::console::index).post(handlers::console::add),
        )
        .route("/delete", post(handlers::console::delete))
        .route("/import", post(handlers::console::import))
        .route("/export", get(handlers::console::export))
        // --- /api/* decision API (own service-token auth inside the handlers) ---
        .route("/api/check", post(handlers::api::check_handler))
        .route("/api/v2/check", post(handlers::api_v2::check_handler))
        .route(
            "/api/v2/application-check",
            post(handlers::api_v2::application_check_handler),
        )
        .route(
            "/api/v2/projections",
            post(handlers::api_v2::replace_projection),
        )
        .route(
            "/api/v2/subject-status",
            post(handlers::api_v2::set_subject_status),
        )
        .route(
            "/api/v2/application-subject-status",
            post(handlers::api_v2::set_application_subject_status),
        )
        .route("/api/tuples", post(handlers::api::write_tuple))
        .route("/api/tuples/delete", post(handlers::api::delete_tuple))
        .route("/api/tuples/import", post(handlers::api::import_tuples))
        .route("/api/tuples/export", post(handlers::api::export_tuples))
        .route("/api/list-objects", post(handlers::api::list_objects))
        .route("/api/expand", post(handlers::api::expand))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and a disabled audit sink (no
/// network). Tests reuse this shape and swap in their own pieces. NOT seeded — tests control the
/// tuple set explicitly via [`seed_examples`].
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        policy: Arc::new(InMemoryPolicyStore::new()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// The store is selected by `VERDICT_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. On an
/// empty store the example tuple set is seeded so the console tester demonstrates indirection on
/// first run. Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let store_kind = env_nonempty("VERDICT_STORE").unwrap_or_else(|| "memory".to_string());
    let config = Config::from_env()?;
    config.validate_for_store(&store_kind)?;

    let (store, policy): (Arc<dyn Store>, Arc<dyn PolicyStore>) = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "VERDICT_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("VERDICT_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            let policy = PgPolicyStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect policy store: {e}"))?;
            policy
                .migrate()
                .await
                .map_err(|e| format!("run policy migration: {e}"))?;
            (Arc::new(pg), Arc::new(policy))
        }
        "memory" => (
            Arc::new(InMemoryStore::new()),
            Arc::new(InMemoryPolicyStore::new()),
        ),
        other => {
            return Err(format!(
                "unknown VERDICT_STORE={other} (use memory|postgres)"
            ))
        }
    };

    // Seed the example tuple set on an empty store (idempotent — skipped when tuples already exist).
    seed_examples(store.as_ref()).await;

    if config.auth_enabled() {
        tracing::info!("/api/* scoped service credential auth ENABLED");
    } else {
        tracing::warn!("/api/* scoped service credential auth DISABLED — memory development mode");
    }

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        policy,
        audit,
    })
}

/// Seed the documented example tuple set on an EMPTY store, so the console tester demonstrates
/// userset indirection on first run:
///   - `doc:readme#viewer@user:w33d`        (a direct grant)
///   - `group:eng#member@user:w33d`         (group membership)
///   - `doc:secret#viewer@group:eng#member` (a grant to a userset -> indirection)
///
/// A no-op when the store already holds tuples (so a restart never re-seeds a live deployment).
pub async fn seed_examples(store: &dyn Store) {
    if !store.list_tuples().await.is_empty() {
        return;
    }
    let now = now_secs();
    let examples = [
        ("doc:readme", "viewer", "user:w33d"),
        ("group:eng", "member", "user:w33d"),
        ("doc:secret", "viewer", "group:eng#member"),
    ];
    for (i, (object, relation, subject)) in examples.iter().enumerate() {
        let tuple = Tuple {
            id: format!("tup_seed_{i}"),
            object: object.to_string(),
            relation: relation.to_string(),
            subject: subject.to_string(),
            created_at: now,
        };
        if let Err(e) = store.add_tuple(&tuple).await {
            tracing::warn!(error = %e, "failed to seed example tuple");
        }
    }
    tracing::info!("seeded {} example tuples", examples.len());
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Current wall-clock time in epoch seconds (the tuple `created_at`).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for tuple ids.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for the double-submit CSRF token. The modulo over 62 introduces a
/// negligible bias that is irrelevant for tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

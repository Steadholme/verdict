//! Two distinct auth surfaces — Verdict's route-split constraint.
//!
//! 1. **Admin console (`/`) — gateway SSO.** `authz.w33d.xyz/` is `auth=sso`: the gateway runs the
//!    OIDC login, STRIPS any inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` /
//!    `X-Auth-Email`. Verdict is internal-only, so it TRUSTS those headers (no login of its own).
//!    State-changing console POSTs (add / delete a tuple) carry a double-submit CSRF token.
//!
//! 2. **`/api/*` service APIs — gateway `auth=public`, Verdict's scoped credential auth.** Verdict
//!    checks `Authorization: Bearer …` in constant time against exactly one of the decision,
//!    projection, or lifecycle credentials selected by the handler. The all-empty credential state
//!    is allowed only for the in-memory development path.

use axum::http::{header, HeaderMap};

use crate::config::{ServiceCredentials, ServiceScope};

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";

/// Dev/test fallback identity used ONLY when no gateway headers are present (local `cargo run` or
/// the DB-free test suite). In production every SSO request arrives with `X-Auth-*` injected.
pub const DEV_SUBJECT: &str = "dev-user";
pub const DEV_EMAIL: &str = "dev@verdict.local";

/// The signed-in operator (console only). Subject is the identity key; email is display-only.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

/// Resolve the current operator from the gateway-injected headers, falling back to the dev
/// identity when none are present.
pub fn identity(headers: &HeaderMap) -> Identity {
    Identity {
        subject: header_value(headers, HEADER_SUBJECT).unwrap_or_else(|| DEV_SUBJECT.to_string()),
        email: header_value(headers, HEADER_EMAIL).unwrap_or_else(|| DEV_EMAIL.to_string()),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// /api/* service-token auth
// ---------------------------------------------------------------------------

/// Parse an `Authorization: Bearer <token>` header, returning the token.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    (!token.is_empty()).then(|| token.to_string())
}

/// Authorize one scoped `/api/*` request. When service credentials are enabled, only the token for
/// `scope` can pass; a valid token from either other scope is still unauthorized. In the
/// all-disabled in-memory development state, every scope is allowed.
pub fn service_authorized(
    headers: &HeaderMap,
    credentials: &ServiceCredentials,
    scope: ServiceScope,
) -> bool {
    match credentials.token(scope) {
        None => true, // auth disabled (dev / DB-free)
        Some(cfg) => match bearer_token(headers) {
            Some(presented) => ct_eq(presented.as_bytes(), cfg.as_bytes()),
            None => false,
        },
    }
}

/// A short, redacted label for a service caller, used as the audit actor. It records only the
/// authorized scope and never derives any actor value from the presented credential.
pub const fn api_actor(scope: ServiceScope) -> &'static str {
    scope.actor_label()
}

// ---------------------------------------------------------------------------
// CSRF (double-submit) for console POSTs
// ---------------------------------------------------------------------------

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser only
/// ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
const CSRF_TTL: u64 = 3600;
const CSRF_LEN: usize = 40;

/// Mint a fresh CSRF token (the same value goes in the cookie and the form field).
pub fn new_csrf_token() -> String {
    crate::random_alnum(CSRF_LEN)
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// Resolve the CSRF token to embed in this render's forms. Reuses the existing cookie token when
/// present (stable across pages/tabs); otherwise mints one and returns the matching `Set-Cookie`.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => (c, None),
        _ => {
            let token = new_csrf_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn identity_falls_back_to_dev() {
        let id = identity(&HeaderMap::new());
        assert_eq!(id.subject, DEV_SUBJECT);
        assert_eq!(id.email, DEV_EMAIL);
    }

    #[test]
    fn identity_reads_gateway_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        h.insert(HEADER_EMAIL, HeaderValue::from_static("a@w33d.xyz"));
        let id = identity(&h);
        assert_eq!(id.subject, "user-42");
        assert_eq!(id.email, "a@w33d.xyz");
    }

    #[test]
    fn service_auth_disabled_when_no_token() {
        let credentials = ServiceCredentials::disabled();
        for scope in [
            ServiceScope::Decision,
            ServiceScope::Projection,
            ServiceScope::Lifecycle,
        ] {
            assert!(service_authorized(&HeaderMap::new(), &credentials, scope));
        }
    }

    #[test]
    fn service_auth_requires_the_matching_scoped_bearer() {
        const DECISION: &str = "decision-token-00000000000000000001";
        const PROJECTION: &str = "projection-token-000000000000000001";
        const LIFECYCLE: &str = "lifecycle-token-0000000000000000001";
        let credentials = ServiceCredentials::try_new(DECISION, PROJECTION, LIFECYCLE).unwrap();
        // No header -> denied.
        assert!(!service_authorized(
            &HeaderMap::new(),
            &credentials,
            ServiceScope::Decision
        ));
        // Wrong bearer -> denied.
        let mut bad = HeaderMap::new();
        bad.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        assert!(!service_authorized(
            &bad,
            &credentials,
            ServiceScope::Decision
        ));
        // Right bearer -> allowed.
        let mut good = HeaderMap::new();
        good.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer decision-token-00000000000000000001"),
        );
        assert!(service_authorized(
            &good,
            &credentials,
            ServiceScope::Decision
        ));
        // A valid credential from another scope is still denied.
        let mut wrong_scope = HeaderMap::new();
        wrong_scope.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer projection-token-000000000000000001"),
        );
        assert!(!service_authorized(
            &wrong_scope,
            &credentials,
            ServiceScope::Decision
        ));
    }

    #[test]
    fn service_actor_contains_only_scope_label() {
        assert_eq!(api_actor(ServiceScope::Decision), "service:decision");
        assert_eq!(api_actor(ServiceScope::Projection), "service:projection");
        assert_eq!(api_actor(ServiceScope::Lifecycle), "service:lifecycle");
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "nope"));
        assert!(!verify_csrf(&HeaderMap::new(), &token));
    }

    #[test]
    fn ensure_csrf_reuses_existing_cookie() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        let (t, set) = ensure_csrf(&h);
        assert_eq!(t, token);
        assert!(set.is_none());

        let (t2, set2) = ensure_csrf(&HeaderMap::new());
        assert_eq!(t2.len(), CSRF_LEN);
        assert!(set2.unwrap().contains("__Host-csrf="));
    }
}

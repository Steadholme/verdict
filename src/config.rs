//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like the rest of the
//! estate. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9140).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9140";

/// Hard cap on how many tuples the console browse view renders. A real archive / pagination is a
/// later concern, not a hypothetical to solve now.
pub const LIST_LIMIT: usize = 500;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// `/api/*` service-token (`VERDICT_SERVICE_TOKEN`). When set, an `Authorization: Bearer`
    /// match authorizes a service-to-service call (constant-time). EMPTY disables `/api/*` auth
    /// entirely (the dev default), so `cargo run` and the DB-free test suite call `/api/check`
    /// WITHOUT a token. In production this is set and every `/api/*` call must present it.
    pub service_token: Option<String>,
}

impl Config {
    /// Default development configuration (in-memory store, NO `/api/*` auth).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            service_token: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        config.service_token = env_nonempty("VERDICT_SERVICE_TOKEN");
        config
    }

    /// True when `/api/*` Bearer auth is enforced (a service token is configured).
    pub fn auth_enabled(&self) -> bool {
        self.service_token.as_deref().map(|t| !t.is_empty()).unwrap_or(false)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_disables_api_auth() {
        let c = Config::dev();
        assert!(!c.auth_enabled());
        assert_eq!(c.bind_addr, DEFAULT_BIND_ADDR);
    }
}

//! Server configuration, env-driven with working dev defaults.
//!
//! The in-memory development path may run with all service credentials disabled. Any configured
//! service credential enables the complete three-scope credential set; partial, weak, duplicate,
//! or legacy master-token configurations are rejected before the server starts.

use std::fmt;

/// Default listen address (all interfaces, internal-only port 9140).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9140";

/// Hard cap on how many tuples the console browse view renders. A real archive / pagination is a
/// later concern, not a hypothetical to solve now.
pub const LIST_LIMIT: usize = 500;

const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;

/// Least-privilege service credential scopes. Every `/api/*` handler selects exactly one scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceScope {
    Decision,
    Projection,
    Lifecycle,
}

impl ServiceScope {
    /// Environment variable that supplies this scope's credential.
    pub const fn env_var(self) -> &'static str {
        match self {
            Self::Decision => "VERDICT_DECISION_TOKEN",
            Self::Projection => "VERDICT_PROJECTION_TOKEN",
            Self::Lifecycle => "VERDICT_LIFECYCLE_TOKEN",
        }
    }

    /// Redacted audit actor label. It identifies only the authorized scope, never the credential.
    pub const fn actor_label(self) -> &'static str {
        match self {
            Self::Decision => "service:decision",
            Self::Projection => "service:projection",
            Self::Lifecycle => "service:lifecycle",
        }
    }
}

/// Structurally complete service credentials: either development auth is disabled, or all three
/// independent credentials are present and valid. The token values are deliberately private and
/// redacted from `Debug` output.
#[derive(Clone)]
pub struct ServiceCredentials {
    mode: CredentialMode,
}

#[derive(Clone)]
enum CredentialMode {
    Disabled,
    Enabled {
        decision: String,
        projection: String,
        lifecycle: String,
    },
}

impl ServiceCredentials {
    /// Development-only credential state. Every scoped service guard is disabled.
    pub const fn disabled() -> Self {
        Self {
            mode: CredentialMode::Disabled,
        }
    }

    /// Build a complete credential set. Values must be 32–512 visible ASCII bytes and pairwise
    /// distinct. Callers should generate independent random values rather than deriving one token
    /// from another.
    pub fn try_new(
        decision: impl Into<String>,
        projection: impl Into<String>,
        lifecycle: impl Into<String>,
    ) -> Result<Self, String> {
        let decision = decision.into();
        let projection = projection.into();
        let lifecycle = lifecycle.into();

        validate_token(ServiceScope::Decision, &decision)?;
        validate_token(ServiceScope::Projection, &projection)?;
        validate_token(ServiceScope::Lifecycle, &lifecycle)?;

        if secret_eq(&decision, &projection)
            || secret_eq(&decision, &lifecycle)
            || secret_eq(&projection, &lifecycle)
        {
            return Err("VERDICT_DECISION_TOKEN, VERDICT_PROJECTION_TOKEN, and \
                 VERDICT_LIFECYCLE_TOKEN must be pairwise distinct"
                .to_string());
        }

        Ok(Self {
            mode: CredentialMode::Enabled {
                decision,
                projection,
                lifecycle,
            },
        })
    }

    fn from_optional(
        decision: Option<String>,
        projection: Option<String>,
        lifecycle: Option<String>,
    ) -> Result<Self, String> {
        match (decision, projection, lifecycle) {
            (None, None, None) => Ok(Self::disabled()),
            (Some(decision), Some(projection), Some(lifecycle)) => {
                Self::try_new(decision, projection, lifecycle)
            }
            _ => Err(
                "Verdict service credential configuration is partial; set all of \
                 VERDICT_DECISION_TOKEN, VERDICT_PROJECTION_TOKEN, and \
                 VERDICT_LIFECYCLE_TOKEN, or leave all three empty for memory-only development"
                    .to_string(),
            ),
        }
    }

    /// Whether service-token authentication is enabled for all three scopes.
    pub const fn enabled(&self) -> bool {
        matches!(self.mode, CredentialMode::Enabled { .. })
    }

    /// Expected credential for one scope. `None` exists only in the all-disabled dev state.
    pub fn token(&self, scope: ServiceScope) -> Option<&str> {
        match (&self.mode, scope) {
            (CredentialMode::Disabled, _) => None,
            (CredentialMode::Enabled { decision, .. }, ServiceScope::Decision) => Some(decision),
            (CredentialMode::Enabled { projection, .. }, ServiceScope::Projection) => {
                Some(projection)
            }
            (CredentialMode::Enabled { lifecycle, .. }, ServiceScope::Lifecycle) => Some(lifecycle),
        }
    }
}

impl Default for ServiceCredentials {
    fn default() -> Self {
        Self::disabled()
    }
}

impl fmt::Debug for ServiceCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceCredentials")
            .field("enabled", &self.enabled())
            .finish_non_exhaustive()
    }
}

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Three independent `/api/*` credentials, or the all-disabled memory-development state.
    pub service_credentials: ServiceCredentials,
}

impl Config {
    /// Default development configuration (in-memory store, no `/api/*` credential checks).
    pub fn dev() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            service_credentials: ServiceCredentials::disabled(),
        }
    }

    /// Configuration with development defaults overridden by environment variables.
    ///
    /// `VERDICT_SERVICE_TOKEN` is intentionally rejected rather than treated as a fallback master
    /// token. Operators must migrate every caller to one of the three least-privilege credentials.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Self::dev();
        if let Some(value) = env_nonempty("BIND_ADDR") {
            config.bind_addr = value;
        }
        config.service_credentials = credentials_from_values(
            env_nonempty("VERDICT_SERVICE_TOKEN"),
            env_nonempty(ServiceScope::Decision.env_var()),
            env_nonempty(ServiceScope::Projection.env_var()),
            env_nonempty(ServiceScope::Lifecycle.env_var()),
        )?;
        Ok(config)
    }

    /// Validate store-specific startup requirements before connecting to any backend.
    /// PostgreSQL is a production runtime and always requires the complete credential set.
    pub fn validate_for_store(&self, store_kind: &str) -> Result<(), String> {
        if store_kind == "postgres" && !self.service_credentials.enabled() {
            return Err("VERDICT_STORE=postgres requires VERDICT_DECISION_TOKEN, \
                 VERDICT_PROJECTION_TOKEN, and VERDICT_LIFECYCLE_TOKEN"
                .to_string());
        }
        Ok(())
    }

    /// True when all scoped `/api/*` Bearer checks are enforced.
    pub const fn auth_enabled(&self) -> bool {
        self.service_credentials.enabled()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset or empty (empty means not configured).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn credentials_from_values(
    legacy: Option<String>,
    decision: Option<String>,
    projection: Option<String>,
    lifecycle: Option<String>,
) -> Result<ServiceCredentials, String> {
    if legacy.is_some() {
        return Err(
            "VERDICT_SERVICE_TOKEN is no longer accepted; configure three independent \
             VERDICT_DECISION_TOKEN, VERDICT_PROJECTION_TOKEN, and VERDICT_LIFECYCLE_TOKEN \
             credentials and migrate callers by endpoint scope"
                .to_string(),
        );
    }
    ServiceCredentials::from_optional(decision, projection, lifecycle)
}

fn validate_token(scope: ServiceScope, token: &str) -> Result<(), String> {
    if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len()) {
        return Err(format!(
            "{} must contain {TOKEN_MIN_LEN}–{TOKEN_MAX_LEN} visible ASCII bytes",
            scope.env_var()
        ));
    }
    if !token.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        return Err(format!(
            "{} must contain visible ASCII only (0x21–0x7e)",
            scope.env_var()
        ));
    }
    Ok(())
}

/// Constant-time equality for already validated secrets. Length is public configuration shape;
/// token contents never cause an early exit.
fn secret_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.bytes().zip(right.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECISION: &str = "decision-token-00000000000000000001";
    const PROJECTION: &str = "projection-token-000000000000000001";
    const LIFECYCLE: &str = "lifecycle-token-0000000000000000001";

    #[test]
    fn dev_memory_disables_api_auth() {
        let config = Config::dev();
        assert!(!config.auth_enabled());
        assert!(config.validate_for_store("memory").is_ok());
        assert_eq!(config.bind_addr, DEFAULT_BIND_ADDR);
    }

    #[test]
    fn postgres_fails_closed_without_credentials() {
        let error = Config::dev().validate_for_store("postgres").unwrap_err();
        assert!(error.contains("VERDICT_STORE=postgres requires"));
    }

    #[test]
    fn complete_distinct_credentials_are_accepted_for_postgres() {
        let mut config = Config::dev();
        config.service_credentials =
            ServiceCredentials::try_new(DECISION, PROJECTION, LIFECYCLE).unwrap();
        assert!(config.auth_enabled());
        assert!(config.validate_for_store("postgres").is_ok());
    }

    #[test]
    fn every_partial_configuration_is_rejected() {
        let cases = [
            (Some(DECISION), None, None),
            (None, Some(PROJECTION), None),
            (None, None, Some(LIFECYCLE)),
            (Some(DECISION), Some(PROJECTION), None),
            (Some(DECISION), None, Some(LIFECYCLE)),
            (None, Some(PROJECTION), Some(LIFECYCLE)),
        ];
        for (decision, projection, lifecycle) in cases {
            let result = ServiceCredentials::from_optional(
                decision.map(str::to_string),
                projection.map(str::to_string),
                lifecycle.map(str::to_string),
            );
            assert!(result.unwrap_err().contains("configuration is partial"));
        }
    }

    #[test]
    fn weak_non_visible_and_oversized_credentials_are_rejected() {
        let cases = [
            ServiceCredentials::try_new("short", PROJECTION, LIFECYCLE),
            ServiceCredentials::try_new(DECISION, "projection token with spaces 00001", LIFECYCLE),
            ServiceCredentials::try_new(DECISION, PROJECTION, "lifecycle-token\n00000000000000001"),
            ServiceCredentials::try_new(DECISION, PROJECTION, "x".repeat(TOKEN_MAX_LEN + 1)),
        ];
        for result in cases {
            assert!(result.is_err());
        }
    }

    #[test]
    fn duplicate_credentials_are_rejected_for_every_pair() {
        assert!(ServiceCredentials::try_new(DECISION, DECISION, LIFECYCLE).is_err());
        assert!(ServiceCredentials::try_new(DECISION, PROJECTION, DECISION).is_err());
        assert!(ServiceCredentials::try_new(DECISION, PROJECTION, PROJECTION).is_err());
    }

    #[test]
    fn legacy_master_credential_is_rejected_without_fallback() {
        let result = credentials_from_values(
            Some("legacy-master-token-0000000000000001".to_string()),
            Some(DECISION.to_string()),
            Some(PROJECTION.to_string()),
            Some(LIFECYCLE.to_string()),
        );
        let error = result.unwrap_err();
        assert!(error.contains("VERDICT_SERVICE_TOKEN is no longer accepted"));
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let credentials = ServiceCredentials::try_new(DECISION, PROJECTION, LIFECYCLE).unwrap();
        let rendered = format!("{credentials:?}");
        assert!(rendered.contains("enabled: true"));
        assert!(!rendered.contains(DECISION));
        assert!(!rendered.contains(PROJECTION));
        assert!(!rendered.contains(LIFECYCLE));
    }
}

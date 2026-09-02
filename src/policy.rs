use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

impl Resource {
    pub fn validate(&self) -> bool {
        is_resource_type(&self.kind)
            && !self.id.is_empty()
            && self.id.len() <= 512
            && !self.id.contains(['\n', '\r', '\0'])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DecisionContext {
    pub zone: Option<String>,
    pub mfa: bool,
    pub ip: Option<String>,
    pub request_id: Option<String>,
    pub break_glass: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PolicyEdge {
    pub edge_id: String,
    pub projection_key: String,
    pub source_grant_id: String,
    pub object: String,
    pub relation: String,
    pub subject: String,
    pub effect: Effect,
    pub resource_selector: serde_json::Value,
    pub condition: Option<serde_json::Value>,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
    pub active: bool,
    pub version: i64,
    pub projection_epoch: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub object: String,
    pub relation: String,
    pub subject: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolicySnapshot {
    pub epoch: i64,
    pub edges: Vec<PolicyEdge>,
    pub memberships: Vec<Membership>,
    pub subject_status: Option<SubjectAccessStatus>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectAccessState {
    Active,
    Frozen,
    Terminated,
}

impl SubjectAccessState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Terminated => "terminated",
        }
    }

    pub fn denies_access(self) -> bool {
        matches!(self, Self::Frozen | Self::Terminated)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SubjectAccessStatus {
    pub subject: String,
    pub state: SubjectAccessState,
    pub source_event_id: String,
    pub source_version: i64,
    pub policy_epoch: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSubjectState {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl ApplicationSubjectState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn allows_access(self) -> bool {
        self == Self::Active
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApplicationSubjectStatus {
    pub application_sub: String,
    pub state: ApplicationSubjectState,
    pub source_event_id: String,
    pub subject_version: i64,
    pub policy_epoch: i64,
    pub revocation_epoch: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub edge_id: String,
    pub source_grant_id: String,
    pub effect: Effect,
    pub path: Vec<String>,
    pub condition_result: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckResponse {
    pub decision: Decision,
    pub reason: String,
    pub epoch: i64,
    pub evaluated_at: i64,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRequestV2 {
    pub v: i64,
    pub application_sub: String,
    pub client_id: String,
    pub credential_id: String,
    pub credential_version: i64,
    pub grant_id: String,
    pub package_id: String,
    pub package_revision_digest: String,
    pub scopes: Vec<String>,
    pub canonical_tool: String,
    pub resource: Resource,
    pub session_id: String,
    pub request_sha256: String,
    pub policy_epoch: i64,
    pub revocation_epoch: i64,
    pub correlation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DecisionV2 {
    pub v: i64,
    pub decision_id: String,
    pub decision_digest: String,
    pub decision: Decision,
    pub subject: String,
    pub resource: Resource,
    pub permission: String,
    pub reason: String,
    pub evidence: Vec<Evidence>,
    pub policy_version: i64,
    pub subject_version: i64,
    pub policy_epoch: i64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct ApplicationDecisionRecord {
    pub decision: DecisionV2,
    pub request: ApplicationRequestV2,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ProjectionEdge {
    pub edge_id: String,
    pub projection_key: String,
    pub subject: String,
    pub permission: String,
    pub effect: Effect,
    #[serde(default = "any_resource_selector")]
    pub resource_selector: serde_json::Value,
    pub condition: Option<serde_json::Value>,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default = "default_version")]
    pub version: i64,
}

impl ProjectionEdge {
    pub fn into_policy_edge(self, source_grant_id: &str, epoch: i64, now: i64) -> PolicyEdge {
        PolicyEdge {
            edge_id: self.edge_id,
            projection_key: self.projection_key,
            source_grant_id: source_grant_id.to_string(),
            object: format!("permission:{}", self.permission),
            relation: "grantee".to_string(),
            subject: self.subject,
            effect: self.effect,
            resource_selector: self.resource_selector,
            condition: self.condition,
            not_before: self.not_before,
            expires_at: self.expires_at,
            active: self.active,
            version: self.version,
            projection_epoch: epoch,
            created_at: now,
            updated_at: now,
        }
    }
}

pub fn any_resource_selector() -> serde_json::Value {
    serde_json::json!({"v": 1, "type": "any", "id": "*"})
}

pub fn is_permission(value: &str) -> bool {
    let segments: Vec<_> = value.split('.').collect();
    if !(3..=4).contains(&segments.len()) {
        return false;
    }
    segments.iter().enumerate().all(|(index, segment)| {
        if segment.is_empty() {
            return false;
        }
        if index == 3 {
            segment.bytes().all(|value| {
                value.is_ascii_lowercase() || value.is_ascii_digit() || b"_-".contains(&value)
            })
        } else {
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(|first| first.is_ascii_lowercase())
                && bytes.all(|value| {
                    value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-'
                })
        }
    })
}

pub fn is_subject(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.contains(['\n', '\r', '\0']) {
        return false;
    }
    if let Some(id) = value.strip_prefix("user:") {
        return !id.is_empty() && !id.contains('#');
    }
    if let Some(id) = value.strip_prefix("service:") {
        return !id.is_empty() && !id.contains('#');
    }
    if let Some(id) = value.strip_prefix("application:") {
        return (16..=128).contains(&id.len())
            && id
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'_' || value == b'-');
    }
    value
        .strip_prefix("group:")
        .and_then(|value| value.strip_suffix("#member"))
        .is_some_and(|name| !name.is_empty() && !name.contains('#'))
}

pub fn is_resource_type(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
}

fn default_true() -> bool {
    true
}

fn default_version() -> i64 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_and_resource_grammars_match_frozen_contract() {
        assert!(is_permission("vault.console.enter"));
        assert!(is_permission("thing.resource.action.qualifier_1"));
        assert!(!is_permission("vault.enter"));
        assert!(!is_permission("Vault.console.enter"));
        assert!(is_resource_type("access-request"));
        assert!(!is_resource_type("AccessRequest"));
    }

    #[test]
    fn only_canonical_subject_shapes_are_accepted() {
        assert!(is_subject("user:u_123"));
        assert!(is_subject("service:sluice"));
        assert!(is_subject("group:infra-admins#member"));
        assert!(is_subject("application:abcdefghijklmnop"));
        assert!(!is_subject("u_123"));
        assert!(!is_subject("group:infra-admins#owner"));
    }
}

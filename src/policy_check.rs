use std::collections::HashSet;

use serde_json::Value;

use crate::condition::{self, ConditionError};
use crate::policy::{
    is_resource_type, is_subject, CheckResponse, Decision, DecisionContext, Effect, Evidence,
    Membership, PolicySnapshot, Resource,
};

const MAX_MEMBERSHIP_DEPTH: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationError {
    UnknownCondition,
    MalformedPolicy,
    EpochInconsistent,
}

struct MatchedEvidence {
    evidence: Evidence,
    specificity: i32,
    not_before: i64,
    userset: bool,
}

pub fn evaluate(
    snapshot: PolicySnapshot,
    subject: &str,
    permission: &str,
    resource: &Resource,
    context: &DecisionContext,
    evaluated_at: i64,
) -> Result<CheckResponse, EvaluationError> {
    if let Some(status) = snapshot.subject_status.as_ref() {
        if status.subject != subject || status.source_version <= 0 {
            return Err(EvaluationError::MalformedPolicy);
        }
        if status.policy_epoch <= 0 || status.policy_epoch > snapshot.epoch {
            return Err(EvaluationError::EpochInconsistent);
        }
        if status.state.denies_access() {
            return Ok(CheckResponse {
                decision: Decision::Deny,
                reason: format!("subject-{}", status.state.as_str()),
                epoch: snapshot.epoch,
                evaluated_at,
                evidence: vec![Evidence {
                    edge_id: format!("subject-status:{}", status.subject),
                    source_grant_id: format!("jml:{}", status.source_event_id),
                    effect: Effect::Deny,
                    path: vec![format!(
                        "subject-status:{}@{}",
                        status.state.as_str(),
                        status.subject
                    )],
                    condition_result: "matched".to_string(),
                }],
            });
        }
    }
    let expected_object = format!("permission:{permission}");
    let mut matches = Vec::new();
    for edge in snapshot.edges {
        if edge.object != expected_object
            || edge.relation != "grantee"
            || edge.edge_id.is_empty()
            || edge.projection_key.is_empty()
            || edge.source_grant_id.is_empty()
            || edge.version <= 0
        {
            return Err(EvaluationError::MalformedPolicy);
        }
        if edge.projection_epoch > snapshot.epoch || edge.projection_epoch < 0 {
            return Err(EvaluationError::EpochInconsistent);
        }
        if !is_subject(&edge.subject) {
            return Err(EvaluationError::MalformedPolicy);
        }
        let (resource_matches, specificity) = selector_matches(&edge.resource_selector, resource)?;
        if !resource_matches {
            continue;
        }
        if edge.not_before.is_some_and(|value| value > evaluated_at)
            || edge.expires_at.is_some_and(|value| value <= evaluated_at)
        {
            continue;
        }
        if edge
            .not_before
            .zip(edge.expires_at)
            .is_some_and(|(start, end)| end <= start)
        {
            return Err(EvaluationError::MalformedPolicy);
        }
        let Some(mut path) = resolve_subject(
            &edge.subject,
            subject,
            &snapshot.memberships,
            &mut HashSet::new(),
            0,
        )?
        else {
            continue;
        };
        let condition_result = match edge.condition.as_ref() {
            None => "not_present",
            Some(value) => match condition::evaluate(value, context, evaluated_at) {
                Ok(true) => "matched",
                Ok(false) => continue,
                Err(ConditionError::Unknown) => return Err(EvaluationError::UnknownCondition),
                Err(ConditionError::Malformed) => return Err(EvaluationError::MalformedPolicy),
            },
        };
        let edge_step = format!("{}#{}@{}", edge.object, edge.relation, edge.subject);
        path.insert(0, edge_step);
        matches.push(MatchedEvidence {
            evidence: Evidence {
                edge_id: edge.edge_id,
                source_grant_id: edge.source_grant_id,
                effect: edge.effect,
                path,
                condition_result: condition_result.to_string(),
            },
            specificity,
            not_before: edge.not_before.unwrap_or(i64::MIN),
            userset: edge.subject.contains('#'),
        });
    }
    matches.sort_by(|left, right| {
        effect_rank(left.evidence.effect)
            .cmp(&effect_rank(right.evidence.effect))
            .then_with(|| right.specificity.cmp(&left.specificity))
            .then_with(|| right.not_before.cmp(&left.not_before))
            .then_with(|| left.evidence.edge_id.cmp(&right.evidence.edge_id))
    });
    let has_deny = matches
        .iter()
        .any(|value| value.evidence.effect == Effect::Deny);
    let has_allow = matches
        .iter()
        .any(|value| value.evidence.effect == Effect::Allow);
    let allow_uses_userset = matches
        .iter()
        .any(|value| value.evidence.effect == Effect::Allow && value.userset);
    let (decision, reason) = if has_deny {
        (Decision::Deny, "deny-override")
    } else if has_allow && allow_uses_userset {
        (Decision::Allow, "allow-userset")
    } else if has_allow {
        (Decision::Allow, "allow-direct")
    } else {
        (Decision::Deny, "no-grant-path")
    };
    Ok(CheckResponse {
        decision,
        reason: reason.to_string(),
        epoch: snapshot.epoch,
        evaluated_at,
        evidence: matches.into_iter().map(|value| value.evidence).collect(),
    })
}

fn selector_matches(selector: &Value, resource: &Resource) -> Result<(bool, i32), EvaluationError> {
    let selector = selector
        .as_object()
        .ok_or(EvaluationError::MalformedPolicy)?;
    if selector.len() != 3 {
        return Err(EvaluationError::MalformedPolicy);
    }
    match selector.get("v").and_then(Value::as_i64) {
        Some(1) => {}
        Some(_) => return Err(EvaluationError::MalformedPolicy),
        None => return Err(EvaluationError::MalformedPolicy),
    }
    let kind = selector
        .get("type")
        .and_then(Value::as_str)
        .ok_or(EvaluationError::MalformedPolicy)?;
    let id = selector
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EvaluationError::MalformedPolicy)?;
    if kind == "any" {
        return if id == "*" {
            Ok((true, 0))
        } else {
            Err(EvaluationError::MalformedPolicy)
        };
    }
    if !is_resource_type(kind) || id.is_empty() || id.contains(['\n', '\r', '\0']) {
        return Err(EvaluationError::MalformedPolicy);
    }
    if kind != resource.kind {
        return Ok((false, if id == "*" { 1 } else { 2 }));
    }
    if id == "*" {
        Ok((true, 1))
    } else {
        Ok((id == resource.id, 2))
    }
}

fn resolve_subject(
    granted_subject: &str,
    target_subject: &str,
    memberships: &[Membership],
    seen: &mut HashSet<(String, String)>,
    depth: usize,
) -> Result<Option<Vec<String>>, EvaluationError> {
    if granted_subject == target_subject {
        return Ok(Some(vec![]));
    }
    let Some((object, relation)) = granted_subject.split_once('#') else {
        return Ok(None);
    };
    if relation != "member" || !object.starts_with("group:") || depth >= MAX_MEMBERSHIP_DEPTH {
        return Ok(None);
    }
    let key = (object.to_string(), relation.to_string());
    if !seen.insert(key.clone()) {
        return Ok(None);
    }
    let mut candidates: Vec<_> = memberships
        .iter()
        .filter(|edge| edge.object == object && edge.relation == relation)
        .collect();
    candidates.sort_by(|left, right| left.subject.cmp(&right.subject));
    for membership in candidates {
        if !is_subject(&membership.subject) {
            seen.remove(&key);
            return Err(EvaluationError::MalformedPolicy);
        }
        if let Some(mut path) = resolve_subject(
            &membership.subject,
            target_subject,
            memberships,
            seen,
            depth + 1,
        )? {
            path.insert(
                0,
                format!(
                    "{}#{}@{}",
                    membership.object, membership.relation, membership.subject
                ),
            );
            seen.remove(&key);
            return Ok(Some(path));
        }
    }
    seen.remove(&key);
    Ok(None)
}

fn effect_rank(effect: Effect) -> i32 {
    match effect {
        Effect::Deny => 0,
        Effect::Allow => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{any_resource_selector, PolicyEdge};

    fn edge(id: &str, subject: &str, effect: Effect) -> PolicyEdge {
        PolicyEdge {
            edge_id: id.to_string(),
            projection_key: format!("projection:{id}"),
            source_grant_id: format!("grant:{id}"),
            object: "permission:cpa.console.enter".to_string(),
            relation: "grantee".to_string(),
            subject: subject.to_string(),
            effect,
            resource_selector: any_resource_selector(),
            condition: None,
            not_before: None,
            expires_at: None,
            active: true,
            version: 1,
            projection_epoch: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn resource() -> Resource {
        Resource {
            kind: "route".to_string(),
            id: "cpa-root".to_string(),
        }
    }

    fn context() -> DecisionContext {
        DecisionContext {
            zone: Some("internal".to_string()),
            mfa: true,
            ip: None,
            request_id: None,
            break_glass: false,
        }
    }

    #[test]
    fn explicit_deny_precedes_allow_and_evidence_is_deterministic() {
        let snapshot = PolicySnapshot {
            epoch: 1,
            edges: vec![
                edge("edge:z", "user:alice", Effect::Allow),
                edge("edge:a", "user:alice", Effect::Deny),
            ],
            memberships: vec![],
            subject_status: None,
        };
        let response = evaluate(
            snapshot,
            "user:alice",
            "cpa.console.enter",
            &resource(),
            &context(),
            10,
        )
        .unwrap();
        assert_eq!(response.decision, Decision::Deny);
        assert_eq!(response.reason, "deny-override");
        assert_eq!(response.evidence[0].edge_id, "edge:a");
        assert_eq!(response.evidence[1].edge_id, "edge:z");
    }

    #[test]
    fn userset_membership_produces_an_ordered_path() {
        let snapshot = PolicySnapshot {
            epoch: 1,
            edges: vec![edge("edge:a", "group:operators#member", Effect::Allow)],
            memberships: vec![Membership {
                object: "group:operators".to_string(),
                relation: "member".to_string(),
                subject: "user:alice".to_string(),
            }],
            subject_status: None,
        };
        let response = evaluate(
            snapshot,
            "user:alice",
            "cpa.console.enter",
            &resource(),
            &context(),
            10,
        )
        .unwrap();
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.reason, "allow-userset");
        assert_eq!(response.evidence[0].path.len(), 2);
    }

    #[test]
    fn expiry_is_checked_at_request_time() {
        let mut value = edge("edge:a", "user:alice", Effect::Allow);
        value.expires_at = Some(10);
        let response = evaluate(
            PolicySnapshot {
                epoch: 1,
                edges: vec![value],
                memberships: vec![],
                subject_status: None,
            },
            "user:alice",
            "cpa.console.enter",
            &resource(),
            &context(),
            10,
        )
        .unwrap();
        assert_eq!(response.decision, Decision::Deny);
    }

    #[test]
    fn malformed_condition_is_indeterminate_not_a_false_match() {
        let mut value = edge("edge:a", "user:alice", Effect::Allow);
        value.condition = Some(serde_json::json!({"v":1,"op":"regex","field":"zone","value":".*"}));
        let result = evaluate(
            PolicySnapshot {
                epoch: 1,
                edges: vec![value],
                memberships: vec![],
                subject_status: None,
            },
            "user:alice",
            "cpa.console.enter",
            &resource(),
            &context(),
            10,
        );
        assert_eq!(result, Err(EvaluationError::UnknownCondition));
    }
}

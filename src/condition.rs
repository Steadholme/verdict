use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

use crate::policy::DecisionContext;

pub const MAX_DEPTH: usize = 8;
pub const MAX_NODES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionError {
    Unknown,
    Malformed,
}

pub fn evaluate(
    condition: &Value,
    context: &DecisionContext,
    evaluated_at: i64,
) -> Result<bool, ConditionError> {
    validate(condition)?;
    evaluate_node(condition, context, evaluated_at, true)
}

/// Validate the closed v1 condition AST without evaluating caller-controlled context.
///
/// The root carries `v`; nested nodes must not. Every operation has an exact key set so
/// misspelled or future fields fail closed at projection ingress instead of being stored as
/// policy that only becomes malformed at decision time.
pub fn validate(condition: &Value) -> Result<(), ConditionError> {
    let mut nodes = 0;
    validate_node(condition, true, 0, &mut nodes)
}

fn validate_node(
    node: &Value,
    root: bool,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ConditionError> {
    if depth > MAX_DEPTH {
        return Err(ConditionError::Malformed);
    }
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err(ConditionError::Malformed);
    }

    let object = node.as_object().ok_or(ConditionError::Malformed)?;
    if root {
        match object.get("v").and_then(Value::as_i64) {
            Some(1) => {}
            Some(_) => return Err(ConditionError::Unknown),
            None => return Err(ConditionError::Malformed),
        }
    } else if object.contains_key("v") {
        return Err(ConditionError::Malformed);
    }

    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ConditionError::Malformed)?;
    match operation {
        "and" | "or" => {
            exact_keys(object, root, &["op", "args"])?;
            let children = args(object)?;
            if children.is_empty() {
                return Err(ConditionError::Malformed);
            }
            for child in children {
                validate_node(child, false, depth + 1, nodes)?;
            }
        }
        "not" => {
            exact_keys(object, root, &["op", "args"])?;
            let children = args(object)?;
            if children.len() != 1 {
                return Err(ConditionError::Malformed);
            }
            validate_node(&children[0], false, depth + 1, nodes)?;
        }
        "present" => {
            exact_keys(object, root, &["op", "field"])?;
            field_kind(object)?;
        }
        "eq" | "ne" => {
            exact_keys(object, root, &["op", "field", "value"])?;
            validate_expected(field_kind(object)?, object.get("value").unwrap())?;
        }
        "in" => {
            exact_keys(object, root, &["op", "field", "value"])?;
            let kind = field_kind(object)?;
            let values = object
                .get("value")
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty())
                .ok_or(ConditionError::Malformed)?;
            for value in values {
                validate_expected(kind, value)?;
            }
        }
        "lt" | "le" | "gt" | "ge" => {
            exact_keys(object, root, &["op", "field", "value"])?;
            if field_name(object)? != "evaluated_at"
                || object.get("value").and_then(Value::as_i64).is_none()
            {
                return Err(ConditionError::Malformed);
            }
        }
        "between" => {
            exact_keys(object, root, &["op", "field", "value"])?;
            if field_name(object)? != "evaluated_at" {
                return Err(ConditionError::Malformed);
            }
            let bounds = object
                .get("value")
                .and_then(Value::as_array)
                .filter(|values| values.len() == 2)
                .ok_or(ConditionError::Malformed)?;
            let lower = bounds[0].as_i64().ok_or(ConditionError::Malformed)?;
            let upper = bounds[1].as_i64().ok_or(ConditionError::Malformed)?;
            if lower > upper {
                return Err(ConditionError::Malformed);
            }
        }
        "ip_in_cidr" => {
            exact_keys(object, root, &["op", "field", "value"])?;
            if field_name(object)? != "ip"
                || object
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<IpNet>().ok())
                    .is_none()
            {
                return Err(ConditionError::Malformed);
            }
        }
        _ => return Err(ConditionError::Unknown),
    }
    Ok(())
}

fn exact_keys(
    object: &serde_json::Map<String, Value>,
    root: bool,
    operation_keys: &[&str],
) -> Result<(), ConditionError> {
    let expected_len = operation_keys.len() + usize::from(root);
    if object.len() != expected_len
        || (root && !object.contains_key("v"))
        || operation_keys.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ConditionError::Malformed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FieldKind {
    String,
    Bool,
    Integer,
}

fn field_kind(object: &serde_json::Map<String, Value>) -> Result<FieldKind, ConditionError> {
    Ok(match field_name(object)? {
        "zone" | "ip" | "request_id" => FieldKind::String,
        "mfa" | "break_glass" => FieldKind::Bool,
        "evaluated_at" => FieldKind::Integer,
        _ => return Err(ConditionError::Unknown),
    })
}

fn validate_expected(kind: FieldKind, value: &Value) -> Result<(), ConditionError> {
    let valid = match kind {
        FieldKind::String => value.is_string(),
        FieldKind::Bool => value.is_boolean(),
        FieldKind::Integer => value.as_i64().is_some(),
    };
    if valid {
        Ok(())
    } else {
        Err(ConditionError::Malformed)
    }
}

fn evaluate_node(
    node: &Value,
    context: &DecisionContext,
    evaluated_at: i64,
    root: bool,
) -> Result<bool, ConditionError> {
    let object = node.as_object().ok_or(ConditionError::Malformed)?;
    if !root && object.contains_key("v") {
        return Err(ConditionError::Malformed);
    }
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ConditionError::Malformed)?;
    match operation {
        "and" => {
            let args = args(object)?;
            if args.is_empty() {
                return Err(ConditionError::Malformed);
            }
            let mut matched = true;
            for arg in args {
                matched &= evaluate_node(arg, context, evaluated_at, false)?;
            }
            Ok(matched)
        }
        "or" => {
            let args = args(object)?;
            if args.is_empty() {
                return Err(ConditionError::Malformed);
            }
            let mut matched = false;
            for arg in args {
                matched |= evaluate_node(arg, context, evaluated_at, false)?;
            }
            Ok(matched)
        }
        "not" => {
            let args = args(object)?;
            if args.len() != 1 {
                return Err(ConditionError::Malformed);
            }
            Ok(!evaluate_node(&args[0], context, evaluated_at, false)?)
        }
        "present" => Ok(field_value(object, context, evaluated_at)?.is_some()),
        "eq" | "ne" => {
            let actual = field_value(object, context, evaluated_at)?;
            let expected = object.get("value").ok_or(ConditionError::Malformed)?;
            ensure_same_type(actual.as_ref(), expected)?;
            let equal = actual.as_ref().is_some_and(|actual| actual == expected);
            Ok(if operation == "eq" { equal } else { !equal })
        }
        "in" => {
            let actual = field_value(object, context, evaluated_at)?;
            let expected = object
                .get("value")
                .and_then(Value::as_array)
                .ok_or(ConditionError::Malformed)?;
            if expected.is_empty() {
                return Err(ConditionError::Malformed);
            }
            if let Some(actual) = actual.as_ref() {
                for value in expected {
                    ensure_same_type(Some(actual), value)?;
                }
                Ok(expected.contains(actual))
            } else {
                Ok(false)
            }
        }
        "lt" | "le" | "gt" | "ge" => {
            let actual = field_value(object, context, evaluated_at)?;
            let actual = actual
                .as_ref()
                .and_then(Value::as_i64)
                .ok_or(ConditionError::Malformed)?;
            let expected = object
                .get("value")
                .and_then(Value::as_i64)
                .ok_or(ConditionError::Malformed)?;
            Ok(match operation {
                "lt" => actual < expected,
                "le" => actual <= expected,
                "gt" => actual > expected,
                "ge" => actual >= expected,
                _ => unreachable!(),
            })
        }
        "between" => {
            let actual = field_value(object, context, evaluated_at)?;
            let actual = actual
                .as_ref()
                .and_then(Value::as_i64)
                .ok_or(ConditionError::Malformed)?;
            let bounds = object
                .get("value")
                .and_then(Value::as_array)
                .filter(|values| values.len() == 2)
                .ok_or(ConditionError::Malformed)?;
            let lower = bounds[0].as_i64().ok_or(ConditionError::Malformed)?;
            let upper = bounds[1].as_i64().ok_or(ConditionError::Malformed)?;
            if lower > upper {
                return Err(ConditionError::Malformed);
            }
            Ok((lower..=upper).contains(&actual))
        }
        "ip_in_cidr" => {
            if field_name(object)? != "ip" {
                return Err(ConditionError::Malformed);
            }
            let network: IpNet = object
                .get("value")
                .and_then(Value::as_str)
                .ok_or(ConditionError::Malformed)?
                .parse()
                .map_err(|_| ConditionError::Malformed)?;
            let Some(ip) = context.ip.as_deref() else {
                return Ok(false);
            };
            let ip: IpAddr = ip.parse().map_err(|_| ConditionError::Malformed)?;
            Ok(network.contains(&ip))
        }
        _ => Err(ConditionError::Unknown),
    }
}

fn args(object: &serde_json::Map<String, Value>) -> Result<&Vec<Value>, ConditionError> {
    object
        .get("args")
        .and_then(Value::as_array)
        .ok_or(ConditionError::Malformed)
}

fn field_name(object: &serde_json::Map<String, Value>) -> Result<&str, ConditionError> {
    let field = object
        .get("field")
        .and_then(Value::as_str)
        .ok_or(ConditionError::Malformed)?;
    match field {
        "zone" | "mfa" | "ip" | "request_id" | "break_glass" | "evaluated_at" => Ok(field),
        _ => Err(ConditionError::Unknown),
    }
}

fn field_value(
    object: &serde_json::Map<String, Value>,
    context: &DecisionContext,
    evaluated_at: i64,
) -> Result<Option<Value>, ConditionError> {
    Ok(match field_name(object)? {
        "zone" => context.zone.clone().map(Value::String),
        "mfa" => Some(Value::Bool(context.mfa)),
        "ip" => context.ip.clone().map(Value::String),
        "request_id" => context.request_id.clone().map(Value::String),
        "break_glass" => Some(Value::Bool(context.break_glass)),
        "evaluated_at" => Some(Value::from(evaluated_at)),
        _ => unreachable!(),
    })
}

fn ensure_same_type(actual: Option<&Value>, expected: &Value) -> Result<(), ConditionError> {
    let Some(actual) = actual else {
        return Ok(());
    };
    let same = matches!(
        (actual, expected),
        (Value::Bool(_), Value::Bool(_))
            | (Value::String(_), Value::String(_))
            | (Value::Number(_), Value::Number(_))
    );
    if same {
        Ok(())
    } else {
        Err(ConditionError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> DecisionContext {
        DecisionContext {
            zone: Some("internal".to_string()),
            mfa: true,
            ip: Some("10.1.2.3".to_string()),
            request_id: Some("req_1".to_string()),
            break_glass: false,
        }
    }

    #[test]
    fn typed_ast_matches_all_supported_context_shapes() {
        let value = serde_json::json!({"v":1,"op":"and","args":[
            {"op":"eq","field":"zone","value":"internal"},
            {"op":"eq","field":"mfa","value":true},
            {"op":"ip_in_cidr","field":"ip","value":"10.0.0.0/8"},
            {"op":"between","field":"evaluated_at","value":[99,101]}
        ]});
        assert_eq!(evaluate(&value, &context(), 100), Ok(true));
    }

    #[test]
    fn unknown_operator_and_wrong_type_are_not_false_matches() {
        let unknown = serde_json::json!({"v":1,"op":"regex","field":"zone","value":".*"});
        assert_eq!(
            evaluate(&unknown, &context(), 100),
            Err(ConditionError::Unknown)
        );
        let malformed = serde_json::json!({"v":1,"op":"eq","field":"mfa","value":"true"});
        assert_eq!(
            evaluate(&malformed, &context(), 100),
            Err(ConditionError::Malformed)
        );
    }

    #[test]
    fn well_formed_non_match_is_an_ordinary_false() {
        let value = serde_json::json!({"v":1,"op":"eq","field":"zone","value":"external"});
        assert_eq!(evaluate(&value, &context(), 100), Ok(false));
    }

    #[test]
    fn closed_ast_rejects_extra_keys_and_nested_versions() {
        let extra = serde_json::json!({"v":1,"op":"eq","field":"mfa","value":true,"extra":1});
        assert_eq!(validate(&extra), Err(ConditionError::Malformed));

        let nested_version = serde_json::json!({
            "v":1,
            "op":"and",
            "args":[{"v":1,"op":"present","field":"ip"}]
        });
        assert_eq!(validate(&nested_version), Err(ConditionError::Malformed));
    }

    #[test]
    fn closed_ast_rejects_wrong_field_types_and_excessive_depth() {
        let wrong_type = serde_json::json!({"v":1,"op":"eq","field":"mfa","value":"true"});
        assert_eq!(validate(&wrong_type), Err(ConditionError::Malformed));

        let mut nested = serde_json::json!({"op":"present","field":"ip"});
        for _ in 0..=MAX_DEPTH {
            nested = serde_json::json!({"op":"not","args":[nested]});
        }
        nested
            .as_object_mut()
            .unwrap()
            .insert("v".into(), Value::from(1));
        assert_eq!(validate(&nested), Err(ConditionError::Malformed));
    }
}

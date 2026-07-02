//! Tuple import/export helpers shared by the JSON API and the SSO console.
//!
//! The canonical import/export shape is the Zanzibar triple only:
//! `object, relation, subject`. Row ids and timestamps are generated on import. CSV accepts an
//! optional `object,relation,subject` header and supports standard quoted fields. JSON accepts
//! either `[{...}]` or `{ "tuples": [{...}] }`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::store::{Store, StoreError, Tuple};
use crate::{now_nanos, now_secs};

/// Guardrail for a single request/import form. This keeps accidental giant pastes out of the hot
/// handler path while still being comfortably above the console's browse cap.
pub const MAX_IMPORT_ROWS: usize = 5_000;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TupleInput {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub subject: String,
}

impl TupleInput {
    fn from_tuple(t: &Tuple) -> Self {
        TupleInput {
            object: t.object.clone(),
            relation: t.relation.clone(),
            subject: t.subject.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportReport {
    pub ok: bool,
    pub total: usize,
    pub written: usize,
    pub skipped: usize,
}

#[derive(Debug, Deserialize)]
struct ImportEnvelope {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tuples: Option<Vec<TupleInput>>,
}

pub fn parse_import_value(value: &Value) -> Result<Vec<TupleInput>, String> {
    match value {
        Value::Array(_) => parse_json_rows(value.clone()),
        Value::Object(_) => {
            let env: ImportEnvelope = serde_json::from_value(value.clone())
                .map_err(|e| format!("invalid import envelope: {e}"))?;
            if let Some(rows) = env.tuples {
                return validate_rows(rows);
            }
            let Some(content) = env.content else {
                return Err(
                    "import body must be an array, {\"tuples\":[...]}, or {\"format\",\"content\"}"
                        .to_string(),
                );
            };
            parse_import_text(env.format.as_deref().unwrap_or("json"), &content)
        }
        _ => Err("import body must be a JSON array or object".to_string()),
    }
}

pub fn parse_import_text(format: &str, content: &str) -> Result<Vec<TupleInput>, String> {
    match format.trim().to_ascii_lowercase().as_str() {
        "json" => {
            let value: Value =
                serde_json::from_str(content).map_err(|e| format!("invalid JSON import: {e}"))?;
            parse_import_value(&value)
        }
        "csv" => parse_csv(content),
        other => Err(format!(
            "unsupported import format {other:?} (use json or csv)"
        )),
    }
}

pub async fn write_import(
    store: &dyn Store,
    rows: &[TupleInput],
) -> Result<ImportReport, StoreError> {
    let mut written = 0usize;
    let now = now_secs();
    for (i, row) in rows.iter().enumerate() {
        let tuple = Tuple {
            id: format!("tup_{}_{}", now_nanos(), i),
            object: row.object.clone(),
            relation: row.relation.clone(),
            subject: row.subject.clone(),
            created_at: now,
        };
        if store.add_tuple(&tuple).await? {
            written += 1;
        }
    }
    Ok(ImportReport {
        ok: true,
        total: rows.len(),
        written,
        skipped: rows.len().saturating_sub(written),
    })
}

pub fn export_rows(tuples: &[Tuple]) -> Vec<TupleInput> {
    tuples.iter().map(TupleInput::from_tuple).collect()
}

pub fn export_json(tuples: &[Tuple]) -> String {
    serde_json::to_string_pretty(&json!({ "tuples": export_rows(tuples) }))
        .expect("tuple export serializes")
}

pub fn export_csv(tuples: &[Tuple]) -> String {
    let mut out = String::from("object,relation,subject\n");
    for row in export_rows(tuples) {
        out.push_str(&csv_field(&row.object));
        out.push(',');
        out.push_str(&csv_field(&row.relation));
        out.push(',');
        out.push_str(&csv_field(&row.subject));
        out.push('\n');
    }
    out
}

fn parse_json_rows(value: Value) -> Result<Vec<TupleInput>, String> {
    let rows: Vec<TupleInput> =
        serde_json::from_value(value).map_err(|e| format!("invalid JSON tuple rows: {e}"))?;
    validate_rows(rows)
}

fn validate_rows(rows: Vec<TupleInput>) -> Result<Vec<TupleInput>, String> {
    if rows.len() > MAX_IMPORT_ROWS {
        return Err(format!(
            "import contains {} rows; maximum is {}",
            rows.len(),
            MAX_IMPORT_ROWS
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, row)| validate_row(row, i + 1))
        .collect()
}

fn validate_row(row: TupleInput, row_number: usize) -> Result<TupleInput, String> {
    let object = row.object.trim();
    let relation = row.relation.trim();
    let subject = row.subject.trim();
    if object.is_empty() || relation.is_empty() || subject.is_empty() {
        return Err(format!(
            "row {row_number}: object, relation and subject are required"
        ));
    }
    for (label, value) in [
        ("object", object),
        ("relation", relation),
        ("subject", subject),
    ] {
        if value.split_whitespace().count() != 1 {
            return Err(format!(
                "row {row_number}: {label} must not contain whitespace"
            ));
        }
    }
    Ok(TupleInput {
        object: object.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    })
}

fn parse_csv(content: &str) -> Result<Vec<TupleInput>, String> {
    let mut rows = Vec::new();
    let mut saw_data = false;
    for (line_idx, raw_line) in content.lines().enumerate() {
        let line_number = line_idx + 1;
        if raw_line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(raw_line)
            .map_err(|e| format!("line {line_number}: invalid CSV: {e}"))?;
        if fields.len() != 3 {
            return Err(format!(
                "line {line_number}: expected 3 CSV fields, got {}",
                fields.len()
            ));
        }
        if !saw_data
            && fields[0].trim().eq_ignore_ascii_case("object")
            && fields[1].trim().eq_ignore_ascii_case("relation")
            && fields[2].trim().eq_ignore_ascii_case("subject")
        {
            saw_data = true;
            continue;
        }
        saw_data = true;
        rows.push(validate_row(
            TupleInput {
                object: fields[0].clone(),
                relation: fields[1].clone(),
                subject: fields[2].clone(),
            },
            line_number,
        )?);
    }
    if rows.len() > MAX_IMPORT_ROWS {
        return Err(format!(
            "import contains {} rows; maximum is {}",
            rows.len(),
            MAX_IMPORT_ROWS
        ));
    }
    Ok(rows)
}

fn parse_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(field.trim().to_string());
                field.clear();
            }
            _ => field.push(ch),
        }
    }

    if in_quotes {
        return Err("unclosed quoted field".to_string());
    }
    fields.push(field.trim().to_string());
    Ok(fields)
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_import_accepts_header_and_quotes() {
        let rows = parse_import_text(
            "csv",
            "object,relation,subject\n\"doc,one\",viewer,\"group:eng#member\"\n",
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![TupleInput {
                object: "doc,one".to_string(),
                relation: "viewer".to_string(),
                subject: "group:eng#member".to_string(),
            }]
        );
    }

    #[test]
    fn json_import_accepts_array_and_envelope() {
        let rows = parse_import_text(
            "json",
            r#"[{"object":"doc:a","relation":"viewer","subject":"user:w33d"}]"#,
        )
        .unwrap();
        assert_eq!(rows[0].object, "doc:a");

        let rows = parse_import_text(
            "json",
            r#"{"tuples":[{"object":"doc:b","relation":"editor","subject":"user:zed"}]}"#,
        )
        .unwrap();
        assert_eq!(rows[0].relation, "editor");
    }

    #[test]
    fn import_rejects_whitespace_inside_tokens() {
        let err = parse_import_text(
            "json",
            r#"[{"object":"doc:a","relation":"view er","subject":"user:w33d"}]"#,
        )
        .unwrap_err();
        assert!(err.contains("relation must not contain whitespace"));
    }

    #[test]
    fn csv_export_quotes_commas() {
        let tuples = vec![Tuple {
            id: "t1".to_string(),
            object: "doc,one".to_string(),
            relation: "viewer".to_string(),
            subject: "user:w33d".to_string(),
            created_at: 1,
        }];
        assert_eq!(
            export_csv(&tuples),
            "object,relation,subject\n\"doc,one\",viewer,user:w33d\n"
        );
    }
}

//! Shared value-minimization assertions for serialized engine boundaries.

use serde_json::Value;

/// Stable, path-free reasons returned by the serialized-output boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinimizationViolation {
    /// A response claimed that a secret value was returned.
    ValueReturned,
    /// A response used a field reserved for value-bearing data.
    ForbiddenField,
}

/// Fields that must never appear in model, API, audit, evidence, or diagnostic
/// JSON emitted by the Rust engine.
pub const FORBIDDEN_OUTPUT_FIELDS: &[&str] = &[
    "value",
    "values",
    "secret_value",
    "secret_values",
    "secret_literal",
    "literal",
    "plaintext",
    "plain_text",
    "raw_secret",
    "raw_value",
    "raw_name",
    "owner",
    "owner_ref",
    "classification",
    "secret_class",
    "secret_name",
    "backend_path",
    "source_path",
    "request_body",
    "env",
    "environment",
    "token",
    "cookie",
    "connector_output",
    "permit_payload",
];

/// Validate a serialized value without ever returning its path or content.
pub fn enforce_value_free_json(value: &Value) -> Result<(), MinimizationViolation> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if key == "value_returned" && nested != &Value::Bool(false) {
                    return Err(MinimizationViolation::ValueReturned);
                }
                if FORBIDDEN_OUTPUT_FIELDS.contains(&key.as_str()) {
                    return Err(MinimizationViolation::ForbiddenField);
                }
                enforce_value_free_json(nested)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                enforce_value_free_json(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Check a rendered boundary against supplied canaries. The return value
/// carries no literal, offset, or surrounding content.
pub fn excludes_literals(rendered: &str, literals: &[&str]) -> bool {
    literals
        .iter()
        .all(|literal| literal.is_empty() || !rendered.contains(literal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialized_boundary_is_recursive_and_path_free() {
        assert!(enforce_value_free_json(&json!({
            "result": [{"secret_ref": "sec_fixture", "value_returned": false}]
        }))
        .is_ok());
        assert_eq!(
            enforce_value_free_json(&json!({"nested": {"value": "canary"}})),
            Err(MinimizationViolation::ForbiddenField)
        );
        assert_eq!(
            enforce_value_free_json(&json!({"nested": {"value_returned": true}})),
            Err(MinimizationViolation::ValueReturned)
        );
    }

    #[test]
    fn literal_assertion_returns_only_a_boolean() {
        assert!(excludes_literals("stable metadata", &["secret-canary"]));
        assert!(!excludes_literals(
            "prefix secret-canary suffix",
            &["secret-canary"]
        ));
    }
}

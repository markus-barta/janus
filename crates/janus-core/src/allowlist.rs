//! Allowlist enforcement (the "soft" layer).
//!
//! The **hard** allowlist is the backend identity scope: a Bitwarden user
//! granted access to one collection, or a 1P Connect token scoped to one
//! vault. That is enforced by the backend itself, returning 403 on
//! out-of-scope reads.
//!
//! This module enforces the **soft** layer: even within the in-scope
//! container, an item must bear the allowlist marker (custom field
//! `llm-ok = true` by default). Re-checked on every [`check`] call —
//! never cached.

use crate::error::JanusError;
use crate::types::{FieldKind, JanusItem};

/// Configuration for the allowlist marker.
#[derive(Debug, Clone)]
pub struct AllowlistConfig {
    /// Custom-field name that signals "this item may be read by LLM."
    /// Default: `"llm-ok"`. Should rarely be changed.
    pub marker_field: String,
    /// Required value for the marker field. Default: `"true"`.
    pub marker_value: String,
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            marker_field: "llm-ok".to_string(),
            marker_value: "true".to_string(),
        }
    }
}

/// Re-check the allowlist marker on a fully-fetched item.
///
/// Returns [`JanusError::AllowlistDenied`] if the marker field is absent
/// or carries an unexpected value.
pub fn check(item: &JanusItem, cfg: &AllowlistConfig) -> Result<(), JanusError> {
    let marker = item
        .fields
        .iter()
        .find(|f| f.name == cfg.marker_field)
        .and_then(|f| f.value.as_deref());

    match marker {
        Some(v) if v == cfg.marker_value => Ok(()),
        _ => Err(JanusError::AllowlistDenied {
            item_id: item.id.0.clone(),
            reason: format!(
                "missing or wrong allowlist marker `{}`",
                cfg.marker_field
            ),
        }),
    }
}

/// Redact concealed fields unless `reveal` is `true`.
///
/// Mutates the item in place; the result is what gets returned to the
/// LLM. Pair every `reveal = true` call with a separate audit event at
/// elevated severity.
pub fn redact(item: &mut JanusItem, reveal: bool) {
    if reveal {
        return;
    }
    for f in &mut item.fields {
        if f.kind == FieldKind::Concealed {
            f.value = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ItemId, JanusField};

    fn item_with(fields: Vec<JanusField>) -> JanusItem {
        JanusItem {
            id: ItemId("test".into()),
            title: "test".into(),
            fields,
            allowlisted: true,
        }
    }

    fn field(name: &str, kind: FieldKind, val: Option<&str>) -> JanusField {
        JanusField {
            name: name.into(),
            kind,
            value: val.map(|v| v.to_string()),
        }
    }

    #[test]
    fn allows_when_marker_set() {
        let item = item_with(vec![field("llm-ok", FieldKind::Text, Some("true"))]);
        assert!(check(&item, &AllowlistConfig::default()).is_ok());
    }

    #[test]
    fn denies_when_marker_missing() {
        let item = item_with(vec![]);
        assert!(check(&item, &AllowlistConfig::default()).is_err());
    }

    #[test]
    fn denies_when_marker_wrong_value() {
        let item = item_with(vec![field("llm-ok", FieldKind::Text, Some("nope"))]);
        assert!(check(&item, &AllowlistConfig::default()).is_err());
    }

    #[test]
    fn redact_removes_concealed_by_default() {
        let mut item = item_with(vec![
            field("password", FieldKind::Concealed, Some("hunter2")),
            field("username", FieldKind::Text, Some("alice")),
        ]);
        redact(&mut item, false);
        assert!(item.fields[0].value.is_none());
        assert!(item.fields[1].value.is_some());
    }

    #[test]
    fn redact_preserves_concealed_when_reveal_true() {
        let mut item = item_with(vec![field(
            "password",
            FieldKind::Concealed,
            Some("hunter2"),
        )]);
        redact(&mut item, true);
        assert!(item.fields[0].value.is_some());
    }
}

//! Janus-domain types.
//!
//! Adapters MUST map their backend DTOs into these. Nothing
//! backend-shaped should appear in this module — except [`ItemId`],
//! which is deliberately opaque.
//!
//! **Note on secret protection (v0):** field values are plain `String`.
//! The redaction story relies on [`crate::allowlist::redact`] stripping
//! concealed values to `None` BEFORE serialization. A future hardening
//! pass (see guideline `architecture-v0` §13.6) can wrap concealed
//! values in `secrecy::SecretString` with an explicit serializer to add
//! `Debug`-leak protection — for v0 that's deferred to keep the
//! scaffold simple.

use serde::{Deserialize, Serialize};

/// Opaque backend item identifier. Adapters decide how this is parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ItemId(pub String);

/// Lightweight summary of an item — returned by
/// [`super::VaultBackend::list_items`]. Concealed values are NEVER
/// included here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemOverview {
    /// Backend-assigned item identifier.
    pub id: ItemId,
    /// Item title (e.g. "openai-api-key (prod)").
    pub title: String,
    /// Whether the item bears the soft-allowlist marker. Computed by the
    /// adapter, re-checked at [`super::VaultBackend::get_item`] time
    /// (defense-in-depth).
    pub allowlisted: bool,
}

/// Kind of a field. Determines redaction default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Plain text — username, hostname, notes. Default-visible.
    Text,
    /// Concealed — password, API key, token. Default-redacted.
    Concealed,
    /// URL.
    Url,
    /// Email.
    Email,
}

/// A single field on an item. Use [`crate::allowlist::redact`] to strip
/// concealed values to `None` before returning to the LLM (unless
/// explicit reveal was requested).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JanusField {
    /// Field name (e.g. "username", "password", "llm-ok").
    pub name: String,
    /// Field kind — drives redaction.
    pub kind: FieldKind,
    /// Field value. `None` after redaction of a concealed field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Full item, with field values possibly populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JanusItem {
    /// Backend-assigned item identifier.
    pub id: ItemId,
    /// Item title.
    pub title: String,
    /// All fields on the item.
    pub fields: Vec<JanusField>,
    /// Whether the item bears the soft-allowlist marker (re-checked at
    /// read time).
    pub allowlisted: bool,
}

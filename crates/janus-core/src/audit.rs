//! Audit event schema and emitter trait.
//!
//! Schema is **action- and actor-generic from day one** so Janus-Forge
//! can write to the same stream without a future migration.
//! See PAIMOS guideline `architecture-v0 §7` for the canonical schema.

use serde::{Deserialize, Serialize};

/// Stable identifier for the schema version.
pub const SCHEMA_VERSION: &str = "1";

/// Which Janus actor produced the event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Actor {
    /// Read broker (this crate's primary consumer).
    JanusWarden,
    /// Rotation broker (future).
    JanusForge,
    /// Manual admin action via CLI.
    Admin,
}

/// What happened.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read a vault item (Janus-Warden's primary action).
    Read,
    /// Rotate a credential (Janus-Forge, future).
    Rotate,
    /// Revoke a credential (Janus-Forge, future).
    Revoke,
    /// Create a new credential (Janus-Forge, future).
    Create,
    /// Backend health / liveness check.
    Health,
}

/// Outcome of the action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Action completed successfully.
    Ok,
    /// Backend returned 4xx/5xx — hard-allowlist breach or upstream
    /// failure. Should only happen on misconfiguration.
    DeniedBackend,
    /// Soft-allowlist check failed (item exists but lacks marker).
    DeniedAllowlist,
    /// Other error (transport, parse, internal).
    Error,
}

/// A single audit event. Serialized one-per-line as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version — bumped if the schema changes incompatibly.
    pub schema_version: &'static str,
    /// ISO-8601 timestamp set by the emitter.
    pub ts: String,
    /// Which Janus actor produced this event.
    pub actor: Actor,
    /// Instance identifier of the actor (e.g. `warden-prod-01`).
    pub actor_instance: String,
    /// What action was attempted.
    pub action: Action,
    /// Outcome of the action.
    pub outcome: Outcome,
    /// Backend-assigned item id (the only backend-shaped field in the schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id_backend: Option<String>,
    /// Human-readable item title (no concealed values).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_title: Option<String>,
    /// Handle of the vault/collection the item was read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_handle: Option<String>,
    /// Names of fields whose values were returned (concealed values are
    /// listed by name only; values are never logged).
    #[serde(default)]
    pub fields_returned: Vec<String>,
    /// True iff this read returned concealed values verbatim
    /// (`reveal_concealed=true`).
    pub concealed_revealed: bool,
    /// MCP tool name that handled this call.
    pub tool_name: String,
    /// Optional MCP session identifier for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_session_id: Option<String>,
    /// SHA-256 of the last user prompt — gives correlation without
    /// leaking the prompt content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
    /// Identity of the caller (e.g. `claude-code/mba`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_principal: Option<String>,
    /// Backend name (e.g. `vaultwarden`, `1password`).
    pub backend: String,
    /// Wall-clock duration of the action in milliseconds.
    pub duration_ms: u64,
}

/// Audit sink. Production: SIEM. Tests: in-memory `Vec<AuditEvent>`.
pub trait AuditSink: Send + Sync {
    /// Emit a single audit event. Implementations MUST be non-blocking
    /// or have bounded blocking time.
    fn emit(&self, event: AuditEvent);
}

/// Default sink — writes JSON Lines to `tracing::info!` under target
/// `janus.audit`. Pair with a `tracing-subscriber` JSON formatter and
/// forward to your SIEM.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn emit(&self, event: AuditEvent) {
        match serde_json::to_string(&event) {
            Ok(j) => tracing::info!(target: "janus.audit", "{}", j),
            Err(e) => tracing::error!(target: "janus.audit", "serialize-fail: {}", e),
        }
    }
}

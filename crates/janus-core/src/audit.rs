//! Audit event schema and emitter trait.
//!
//! Schema is **action- and actor-generic from day one** so Janus-Forge
//! can write to the same stream without a future migration.
//! See PAIMOS `JANUS-1 §7` for the canonical schema.

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
    Read,
    Rotate,
    Revoke,
    Create,
    Health,
}

/// Outcome of the action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    /// Backend returned 4xx/5xx — hard-allowlist breach or upstream
    /// failure. Should only happen on misconfiguration.
    DeniedBackend,
    /// Soft-allowlist check failed (item exists but lacks marker).
    DeniedAllowlist,
    /// Other error.
    Error,
}

/// A single audit event. Serialized one-per-line as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: &'static str,
    pub ts: String,
    pub actor: Actor,
    pub actor_instance: String,
    pub action: Action,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_handle: Option<String>,
    #[serde(default)]
    pub fields_returned: Vec<String>,
    pub concealed_revealed: bool,
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_principal: Option<String>,
    pub backend: String,
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

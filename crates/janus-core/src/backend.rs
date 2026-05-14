//! The single trait every Janus backend adapter implements.
//!
//! Deliberately read-only. Janus-Forge (future) will define a separate
//! `WritableVaultBackend` trait — code-path isolation is a security
//! feature, not friction.

use async_trait::async_trait;

use crate::error::JanusError;
use crate::types::{ItemId, ItemOverview, JanusItem};

/// Health snapshot returned by [`VaultBackend::health`].
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Static name of the backend (e.g. `"vaultwarden"`, `"1password"`).
    pub backend_name: &'static str,
    /// True if the backend is reachable and auth is valid.
    pub ok: bool,
    /// Human-readable detail (e.g. version, hostname, last-error).
    pub detail: String,
}

/// Read-only vault backend.
#[async_trait]
pub trait VaultBackend: Send + Sync {
    /// Liveness + auth check.
    async fn health(&self) -> Result<HealthStatus, JanusError>;

    /// Enumerate items the backend identity can see. Concealed field
    /// values are NOT populated in the overview.
    async fn list_items(&self) -> Result<Vec<ItemOverview>, JanusError>;

    /// Fetch a single item by [`ItemId`]. Concealed values are populated
    /// here; redaction happens in [`crate::allowlist::redact`], not in
    /// the backend.
    async fn get_item(&self, id: &ItemId) -> Result<JanusItem, JanusError>;
}

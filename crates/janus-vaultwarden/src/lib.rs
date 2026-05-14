//! Vaultwarden / Bitwarden adapter for Janus.
//!
//! Implements [`janus_core::VaultBackend`] against the Bitwarden REST API.
//! Compatible with Vaultwarden (the Rust reimplementation) and the
//! Bitwarden.com hosted service.
//!
//! See PAIMOS `JANUS-1 §3–§5` for the surface contract.

#![forbid(unsafe_code)]

pub mod client;
pub mod mapping;

use async_trait::async_trait;
use janus_core::backend::{HealthStatus, VaultBackend};
use janus_core::error::JanusError;
use janus_core::types::{ItemId, ItemOverview, JanusItem};
use secrecy::SecretString;

/// Configuration for the Vaultwarden adapter.
#[derive(Debug, Clone)]
pub struct VaultwardenConfig {
    /// Base URL of the Vaultwarden instance (e.g. `https://vw.example.com`).
    pub base_url: url::Url,
    /// OAuth2 client_id (resolved from env at startup; never from disk).
    pub client_id: String,
    /// OAuth2 client_secret (resolved from env at startup; never from disk).
    pub client_secret: SecretString,
    /// Collection ID that the API user is scoped to — the **hard
    /// allowlist** container. Items outside this collection are not
    /// visible to this identity by Bitwarden's permission model.
    pub collection_id: String,
}

/// Vaultwarden / Bitwarden REST adapter.
pub struct VaultwardenBackend {
    _cfg: VaultwardenConfig,
    // TODO (JANUS-1): reqwest::Client with retry, auth refresh, timeouts.
}

impl VaultwardenBackend {
    /// Build a new adapter. Does NOT validate connectivity — call
    /// [`VaultBackend::health`] at startup for that.
    pub fn new(cfg: VaultwardenConfig) -> Self {
        Self { _cfg: cfg }
    }
}

#[async_trait]
impl VaultBackend for VaultwardenBackend {
    async fn health(&self) -> Result<HealthStatus, JanusError> {
        // TODO (JANUS-1): GET /api/version + verify token still valid.
        unimplemented!("janus-vaultwarden::health")
    }

    async fn list_items(&self) -> Result<Vec<ItemOverview>, JanusError> {
        // TODO (JANUS-1): GET /api/ciphers filtered to our collection,
        //                 map via `mapping::dto_to_overview`.
        unimplemented!("janus-vaultwarden::list_items")
    }

    async fn get_item(&self, _id: &ItemId) -> Result<JanusItem, JanusError> {
        // TODO (JANUS-1): GET /api/ciphers/{id}, map via
        //                 `mapping::dto_to_item`.
        unimplemented!("janus-vaultwarden::get_item")
    }
}

//! Error types.

use thiserror::Error;

/// Top-level error for Janus operations.
#[derive(Error, Debug)]
pub enum JanusError {
    /// Backend returned an unexpected response or transport failed.
    #[error("backend error: {0}")]
    Backend(String),

    /// Soft-allowlist check failed.
    #[error("allowlist denied for item {item_id}: {reason}")]
    AllowlistDenied {
        item_id: String,
        reason: String,
    },

    /// Backend reported the item does not exist (or the identity cannot
    /// see it — distinguishing 404 from 403 is a backend concern).
    #[error("item not found: {0}")]
    NotFound(String),

    /// Authentication / authorization failure.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Misconfiguration discovered at startup or first call.
    #[error("configuration error: {0}")]
    Config(String),

    /// Network / I/O failure.
    #[error("transport: {0}")]
    Transport(String),
}

//! Janus core — Janus-domain types, the [`VaultBackend`] trait, and the
//! allowlist / audit logic.
//!
//! This crate is **intentionally backend-agnostic**. It MUST NOT depend on
//! `reqwest`, `1password`, `bitwarden`, or any other backend-specific
//! crate. Adapters live in sibling crates and implement [`VaultBackend`].
//!
//! See PAIMOS guideline `architecture-v0` for the engineering design doc.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod allowlist;
pub mod audit;
pub mod backend;
pub mod error;
pub mod types;

pub use backend::{HealthStatus, VaultBackend};
pub use error::JanusError;
pub use types::{FieldKind, ItemId, ItemOverview, JanusField, JanusItem};

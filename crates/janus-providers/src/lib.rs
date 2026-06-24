//! # janus-providers — backend implementations of `janus-core::SecretStore`
//!
//! Vendor-neutral by construction: the **manifest (`secretspec.toml`) is the
//! constant allowlist** across all tiers; only the provider changes per
//! deployment (architecture-v1 §backend, goal 9 — key-custody-pluggable):
//!
//! | Tier | Provider | Ticket |
//! |---|---|---|
//! | Self-host / NixOS (default) | **age / agenix** | JANUS-21 |
//! | Cross-tier manifest/allowlist | **secretspec** | JANUS-12 |
//! | Big-corp fleet | OpenBao | — |
//! | Laptop / hobbyist | OS keyring | — |
//!
//! TODO: one module per provider, each behind the `SecretStore` trait. age is
//! the self-host default, **not** the enterprise ceiling — the model must allow
//! HSM/KMS/OpenBao-class custody later.

#![forbid(unsafe_code)]

pub mod secretspec;

pub use secretspec::SecretspecStore;

//! # janus-core — the secret-handling engine (greenfield, Rust)
//!
//! Implements the core model from PPM JANUS `guideline/architecture-v1`:
//! opaque, non-authorizing [`SecretRef`]s; opaque, single-use [`UsePermit`]s;
//! the backend-pluggable `SecretStore`; and the policy + audit-as-evidence
//! model. The deployed Go REST service in `../../go-envelope` is the oversight
//! **envelope** only — it brokers no secret values. This crate is the **engine**
//! the envelope has been waiting for.
//!
//! ## Backlog tickets this crate covers
//! - **JANUS-14** — core async `SecretStore`
//! - **JANUS-28** — approved-use execution (the only path a value may leave Janus)
//!
//! Nothing here is implemented yet; the types below are sketches that anchor the
//! implementation session to the spec's vocabulary.

// Skeleton crate: the placeholder fields are unused until the engine lands.
#![allow(dead_code)]

/// Opaque, non-authorizing reference to a declared secret.
///
/// A `SecretRef` names a secret that exists in the manifest allowlist but grants
/// no access to its value. Safe to log, persist, and hand to an AI surface
/// (architecture-v1 goal 6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretRef(String);

/// Opaque, single-use, short-lived approval for exactly one narrow use.
///
/// A `UsePermit` authorizes one use path — built-in connector, managed command
/// profile, or non-LLM provider path — bound to a principal chain. It is never
/// the value, and copying it outside its binding must fail (architecture-v1
/// goal 6, §threat-model).
#[derive(Clone, Debug)]
pub struct UsePermit(String);

/// Backend-pluggable secret store. Concrete backends (age, secretspec, OpenBao,
/// OS keyring) live in the `janus-providers` crate behind this trait so that no
/// single vendor — including secretspec itself — can capture the core
/// (architecture-v1 goal 8).
///
/// TODO(JANUS-14): make this `async` (tokio + async-trait), add the
/// resolve / use / rotate surface, and wire the audit sink such that
/// secret-bearing actions fail closed when audit cannot be written.
pub trait SecretStore {
    // Intentionally empty — see architecture-v1 §3 for the target surface.
}

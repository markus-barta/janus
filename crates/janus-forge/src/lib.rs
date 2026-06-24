//! # janus-forge — the rotation / write broker (admin + script facing)
//!
//! Vulcan's forge: **makes and rotates** secrets. Write-side, deliberately
//! **not MCP** and **not LLM-driven** (architecture-v1: Warden guards read,
//! Forge makes/rotates). Rotation decisions consult the consumer registry so an
//! unknown consumer blocks one-click rotation (goal 5); `SecretStore::rotate` is
//! the backend value-change primitive, but the user-visible operation is the
//! broker-level lifecycle: plan → prepare → rotate → validate → reload.
//!
//! ## Backlog
//! - **JANUS-219** — Janus-Forge: issue + rotate `pharos-beacon` agent tokens
//!   (the first real Forge consumer)

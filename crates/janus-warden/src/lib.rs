//! # janus-warden — the reference-only MCP surface (read side)
//!
//! The AI-facing face of Janus. **Reference-only**: it serves [`SecretRef`]s and
//! brokers `UsePermit`s but never literals, and the model never chooses where a
//! secret goes (architecture-v1 goals 6–7). Transport is **MCP**; the deployed
//! Go envelope exposes REST instead — closing that gap is the point of this
//! crate.
//!
//! ## Backlog
//! - **JANUS-22** — reference-only MCP warden
//!
//! TODO: depend on the official Rust MCP SDK (`rmcp`) and `janus-core`; expose
//! the descriptor catalog + permit-request tools with prompt-injection-safe
//! handles only.
//!
//! [`SecretRef`]: ../janus_core/struct.SecretRef.html

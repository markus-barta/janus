//! Janus-Warden — MCP server entry point.
//!
//! See PAIMOS `JANUS-1` for the engineering design doc.
//!
//! This is **scaffold only**. The MCP SDK crate is unselected (see
//! `JANUS-1 §13.1`); refusing to serve until that decision lands keeps
//! the build green without committing to a transport we haven't audited.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    tracing::info!(
        "janus-warden starting (v{}) — scaffold-only build",
        env!("CARGO_PKG_VERSION")
    );

    // Production wiring (TODO, JANUS-1 §13):
    //   1. Load config from env:
    //      JANUS_VW_BASE_URL, JANUS_VW_CLIENT_ID, JANUS_VW_CLIENT_SECRET,
    //      JANUS_VW_COLLECTION_ID, JANUS_AUDIT_SINK, JANUS_ALLOWLIST_FIELD.
    //   2. Build `VaultwardenBackend` boxed as `dyn VaultBackend`.
    //   3. backend.health().await — refuse to serve on failure.
    //   4. Register MCP tools: `list_secrets`, `read_secret`, `health`.
    //   5. Run the MCP server over stdio.
    //
    // Per-tool handler shape:
    //   * call backend
    //   * on get_item: re-check `janus_core::allowlist::check`
    //   * redact via `janus_core::allowlist::redact` unless `reveal=true`
    //   * emit `AuditEvent` (action-generic schema)
    //   * return Janus-domain types serialized as JSON

    anyhow::bail!(
        "scaffold only — see PAIMOS JANUS-1 §13 for open questions \
         that must resolve before this binary is wired"
    )
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,janus=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .init();
}

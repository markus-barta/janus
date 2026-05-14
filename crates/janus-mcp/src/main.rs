//! Janus-Warden — MCP server entry point.
//!
//! See PAIMOS guideline `architecture-v0` for the engineering design doc.
//!
//! ## v0 scaffold posture
//!
//! The `rmcp` types are exercised end-to-end (`ServerHandler` impl, three
//! tool registrations, stdio transport boot), but every tool call
//! currently returns a "scaffold only — backend not wired" message. The
//! binary CAN run and CAN serve MCP — it just refuses to read any vault
//! item until the `janus-vaultwarden` adapter is implemented.
//!
//! Note: API surface tracks `rmcp` `1.7.0`. If field names have drifted,
//! cross-check against the SDK README before adjusting the impl below —
//! the *intent* is the source of truth, not the exact symbol names.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::Result;
use rmcp::{
    model::{
        CallToolRequestParam, CallToolResult, Content, Implementation,
        ListToolsResult, PaginatedRequestParam, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::stdio,
    ServerHandler, ServiceExt,
};
use serde_json::json;
use tracing_subscriber::EnvFilter;

/// The Janus-Warden MCP server state. Holds (eventually) an
/// `Arc<dyn VaultBackend>`; today, nothing.
#[derive(Clone, Default)]
struct Warden {
    // TODO (architecture-v0): once janus-vaultwarden is implemented, hold
    //                         `backend: Arc<dyn janus_core::VaultBackend>`
    //                         here and inject it via `Warden::new`.
}

impl ServerHandler for Warden {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "janus-warden".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            instructions: Some(
                "Janus-Warden — read-only broker between an LLM and a \
                 credential vault, under tag-based allowlist control. See \
                 PAIMOS · JANUS · guideline architecture-v0."
                    .into(),
            ),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::Error> {
        // Tool descriptions are STATIC + code-reviewed. This is the
        // structural defense against tool-description poisoning
        // (architecture-v0 §9). Do not derive descriptions from
        // doc-comments or runtime config.
        let tools = vec![
            tool(
                "list_secrets",
                "List vault items that bear the allowlist marker (`llm-ok`). Read-only. \
                 Returns minimal overview: id, title, allowlisted flag. Concealed values \
                 are never included in this response.",
                json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
            ),
            tool(
                "read_secret",
                "Fetch a single allowlisted vault item by id. Concealed fields (passwords, \
                 API keys, tokens) are redacted unless `reveal_concealed = true` is passed, \
                 which is audited at elevated severity. Returns 'denied_allowlist' if the \
                 item exists but lacks the `llm-ok` marker.",
                json!({
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Backend item id (opaque to the LLM)."
                        },
                        "reveal_concealed": {
                            "type": "boolean",
                            "default": false,
                            "description": "If true, return concealed values verbatim. AUDITED."
                        }
                    },
                    "required": ["id"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "health",
                "Backend liveness + auth check. No parameters. Returns backend name, \
                 reachability, and last successful check time.",
                json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
            ),
        ];
        Ok(ListToolsResult { tools, next_cursor: None })
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::Error> {
        // TODO (architecture-v0 §6): dispatch by `req.name` to the
        //   backend, then re-check `janus_core::allowlist::check`, then
        //   redact via `janus_core::allowlist::redact`, then emit an
        //   AuditEvent, then return the Janus-domain JSON.
        //
        // Until then: log the attempt and return an explicit
        // scaffold-only error response so callers know the tool is
        // registered but unimplemented.
        tracing::warn!(
            target: "janus.audit",
            tool = %req.name,
            "tool call refused — scaffold only, backend not wired"
        );
        Ok(CallToolResult::success(vec![Content::text(format!(
            "ERROR: scaffold only — tool `{}` is registered but the \
             Vaultwarden backend is unimplemented. See PAIMOS guideline \
             architecture-v0 §13 for open questions blocking full wiring.",
            req.name
        ))]))
    }
}

/// Helper to build a `Tool` from a static description + JSON schema.
/// Keeps `list_tools` readable.
fn tool(name: &str, description: &str, schema: serde_json::Value) -> Tool {
    Tool {
        name: name.into(),
        description: Some(description.into()),
        input_schema: Arc::new(
            schema
                .as_object()
                .expect("tool schema must be a JSON object")
                .clone(),
        ),
        annotations: None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    tracing::info!(
        "janus-warden starting (v{}) — scaffold (backend not wired)",
        env!("CARGO_PKG_VERSION")
    );

    let warden = Warden::default();

    // serve() takes ownership; .waiting() blocks until the transport
    // closes. Stdio transport will keep the server alive as long as the
    // client (LLM host) has the pipe open.
    let server = warden.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}

fn init_tracing() {
    // CRITICAL: stdio transport uses STDOUT for the MCP protocol. All
    // logs MUST go to stderr or the wire format gets corrupted.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,janus=debug,rmcp=warn"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .init();
}

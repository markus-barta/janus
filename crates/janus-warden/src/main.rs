//! Janus-Warden MCP stdio server.
//!
//! This binary is intentionally thin: `rmcp` handles transport, while
//! `janus-warden`'s SDK-agnostic dispatcher owns tool names, schemas,
//! validation, and broker calls. Logs go to stderr so stdout stays reserved for
//! the MCP protocol.

#![forbid(unsafe_code)]

use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use janus_core::{
    AuditWrite, Destination, EgressMode, ExecutorRef, Principal, PrincipalChain, PrincipalId,
    PrincipalKind, ProfilePolicy, ScopeRef, SecretBroker, SecretDescriptor, SecretStore,
    TrustLevel, UseProfile,
};
use janus_providers::SecretspecStore;
use janus_warden::{tool_definitions, WardenRuntime};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::stdio,
    ErrorData, ServerHandler, ServiceExt,
};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

type Runtime = WardenRuntime<SecretspecStore, AuditWrite>;

/// `rmcp` server state.
struct McpWarden {
    runtime: Arc<Mutex<Runtime>>,
    principal: PrincipalChain,
}

impl ServerHandler for McpWarden {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info = Implementation::new("janus-warden", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "Janus-Warden exposes reference-only secret metadata and opaque use permits. \
             It never exposes raw secret values, raw resolve tools, or model-selected \
             destinations."
                .into(),
        );
        info
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools: tool_definitions()
                .iter()
                .map(|definition| {
                    let schema = serde_json::from_str::<Value>(definition.input_schema)
                        .expect("static Warden tool schema should be valid JSON");
                    let schema = schema
                        .as_object()
                        .expect("static Warden tool schema should be a JSON object")
                        .clone();
                    Tool::new(definition.name, definition.description, Arc::new(schema))
                })
                .collect(),
        })
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = req
            .arguments
            .map(Value::Object)
            .unwrap_or_else(|| Value::Object(Default::default()));
        let response = self
            .runtime
            .lock()
            .await
            .call_tool_json(req.name.as_ref(), args, &self.principal, SystemTime::now())
            .await;
        let response_value =
            serde_json::to_value(&response).expect("Warden tool response should serialize");
        if response.ok {
            Ok(CallToolResult::structured(response_value))
        } else {
            Ok(CallToolResult::structured_error(response_value))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let runtime = build_runtime_from_env().await?;
    let principal = principal_from_env()?;
    let server = McpWarden {
        runtime: Arc::new(Mutex::new(runtime)),
        principal,
    };

    tracing::info!("janus-warden MCP stdio server starting");
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

async fn build_runtime_from_env() -> Result<Runtime> {
    let manifest = required_env("JANUS_WARDEN_SECRETSPEC_FILE")?;
    let profile = env::var("JANUS_WARDEN_SECRETSPEC_PROFILE").unwrap_or_else(|_| "default".into());
    let provider_uri = required_env("JANUS_WARDEN_SECRETSPEC_PROVIDER_URI")?;
    let store = SecretspecStore::load_from(manifest, profile, provider_uri)
        .context("failed to load JANUS_WARDEN_SECRETSPEC_* backend")?;
    let descriptors = store
        .list()
        .await
        .context("failed to list secretspec manifest descriptors during Warden boot")?;
    let policy = policy_from_env(&descriptors)?;
    Ok(WardenRuntime::new(SecretBroker::new(
        store,
        policy,
        AuditWrite::accepting(),
    )))
}

fn policy_from_env(descriptors: &[SecretDescriptor]) -> Result<ProfilePolicy> {
    let Ok(destination) = env::var("JANUS_WARDEN_DESTINATION") else {
        tracing::warn!(
            "JANUS_WARDEN_DESTINATION unset; request_use will be default-deny, list/describe/health remain available"
        );
        return Ok(ProfilePolicy::default());
    };

    let executor = ExecutorRef::new(executor_id_from_env()?)?;
    let destination = Destination::new(destination)?;
    let ttl = env::var("JANUS_WARDEN_PERMIT_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(300);
    let mut profiles = Vec::new();
    for descriptor in descriptors {
        for profile_id in &descriptor.allowed_uses {
            profiles.push(UseProfile {
                id: profile_id.clone(),
                secret_ref: descriptor.secret_ref.clone(),
                executor: executor.clone(),
                destination: destination.clone(),
                egress: EgressMode::Connector,
                trust_level: TrustLevel::L2,
                ttl: Duration::from_secs(ttl),
                single_use: true,
                enabled: true,
            });
        }
    }
    Ok(ProfilePolicy::new(profiles))
}

fn principal_from_env() -> Result<PrincipalChain> {
    Ok(PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new(executor_id_from_env()?)?,
        ),
        ScopeRef::new(env::var("JANUS_WARDEN_SCOPE").unwrap_or_else(|_| "janus/default".into()))?,
    ))
}

fn executor_id_from_env() -> Result<String> {
    Ok(env::var("JANUS_WARDEN_EXECUTOR").unwrap_or_else(|_| "warden-stdio".into()))
}

fn required_env(key: &'static str) -> Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,janus_warden=debug,rmcp=warn"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .init();
}

//! Janus-Warden MCP stdio server.
//!
//! This binary is intentionally thin: `rmcp` handles transport, while
//! `janus-warden`'s SDK-agnostic dispatcher owns tool names, schemas,
//! validation, and broker calls. Logs go to stderr so stdout stays reserved for
//! the MCP protocol.

#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use janus_core::{
    AuditWrite, Destination, EgressMode, ExecutorRef, Principal, PrincipalChain, PrincipalId,
    PrincipalKind, ProfilePolicy, ScopeRef, SecretBroker, SecretDescriptor, SecretStore,
    TrustLevel, UseProfile,
};
use janus_provider_age::AgeSecretStore;
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

type Runtime = WardenRuntime<WardenStore, AuditWrite>;

enum WardenStore {
    Secretspec(SecretspecStore),
    Age(AgeSecretStore),
}

#[async_trait::async_trait]
impl SecretStore for WardenStore {
    fn capabilities(&self) -> janus_core::StoreCapabilities {
        match self {
            Self::Secretspec(store) => store.capabilities(),
            Self::Age(store) => store.capabilities(),
        }
    }

    async fn health(&self) -> janus_core::JanusResult<janus_core::HealthStatus> {
        match self {
            Self::Secretspec(store) => store.health().await,
            Self::Age(store) => store.health().await,
        }
    }

    async fn list(&self) -> janus_core::JanusResult<Vec<SecretDescriptor>> {
        match self {
            Self::Secretspec(store) => store.list().await,
            Self::Age(store) => store.list().await,
        }
    }

    async fn get(
        &self,
        name: &janus_core::SecretName,
    ) -> janus_core::JanusResult<janus_core::SecretValue> {
        match self {
            Self::Secretspec(store) => store.get(name).await,
            Self::Age(store) => store.get(name).await,
        }
    }

    async fn set(
        &mut self,
        name: &janus_core::SecretName,
        value: janus_core::SecretValue,
    ) -> janus_core::JanusResult<()> {
        match self {
            Self::Secretspec(store) => store.set(name, value).await,
            Self::Age(store) => store.set(name, value).await,
        }
    }

    async fn rotate(
        &mut self,
        name: &janus_core::SecretName,
        spec: &janus_core::RotationSpec,
    ) -> janus_core::JanusResult<janus_core::RotationOutcome> {
        match self {
            Self::Secretspec(store) => store.rotate(name, spec).await,
            Self::Age(store) => store.rotate(name, spec).await,
        }
    }

    async fn delete(&mut self, name: &janus_core::SecretName) -> janus_core::JanusResult<()> {
        match self {
            Self::Secretspec(store) => store.delete(name).await,
            Self::Age(store) => store.delete(name).await,
        }
    }
}

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
    let store = load_store_from_env()?;
    let descriptors = store
        .list()
        .await
        .context("failed to list backend manifest descriptors during Warden boot")?;
    let policy = policy_from_env(&descriptors)?;
    Ok(WardenRuntime::new(SecretBroker::new(
        store,
        policy,
        AuditWrite::accepting(),
    )))
}

fn load_store_from_env() -> Result<WardenStore> {
    match env::var("JANUS_WARDEN_BACKEND")
        .unwrap_or_else(|_| "secretspec".into())
        .as_str()
    {
        "secretspec" => load_secretspec_store().map(WardenStore::Secretspec),
        "age" => load_age_store().map(WardenStore::Age),
        other => anyhow::bail!("unsupported JANUS_WARDEN_BACKEND {other}"),
    }
}

fn load_secretspec_store() -> Result<SecretspecStore> {
    let manifest = required_env("JANUS_WARDEN_SECRETSPEC_FILE")?;
    let profile = env::var("JANUS_WARDEN_SECRETSPEC_PROFILE").unwrap_or_else(|_| "default".into());
    let provider_uri = required_env("JANUS_WARDEN_SECRETSPEC_PROVIDER_URI")?;
    SecretspecStore::load_from(manifest, profile, provider_uri)
        .context("failed to load JANUS_WARDEN_SECRETSPEC_* backend")
}

fn load_age_store() -> Result<AgeSecretStore> {
    let manifest = env::var("JANUS_WARDEN_AGE_MANIFEST_FILE")
        .or_else(|_| env::var("JANUS_WARDEN_SECRETSPEC_FILE"))
        .context("JANUS_WARDEN_AGE_MANIFEST_FILE or JANUS_WARDEN_SECRETSPEC_FILE is required")?;
    let profile = env::var("JANUS_WARDEN_AGE_PROFILE")
        .or_else(|_| env::var("JANUS_WARDEN_SECRETSPEC_PROFILE"))
        .unwrap_or_else(|_| "default".into());
    let store_dir =
        env::var("JANUS_WARDEN_AGE_STORE_DIR").unwrap_or_else(|_| "/var/lib/janus/secrets".into());
    let identity_files = age_identity_files_from_env()?;
    let recipients = age_recipients_from_env()?;
    AgeSecretStore::load_from_secretspec_manifest(
        manifest,
        profile,
        store_dir,
        identity_files,
        recipients,
    )
    .context("failed to load JANUS_WARDEN_BACKEND=age backend")
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

fn age_identity_files_from_env() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if let Ok(value) = env::var("JANUS_WARDEN_AGE_IDENTITY_FILE") {
        files.push(PathBuf::from(value));
    }
    if let Ok(value) = env::var("JANUS_WARDEN_AGE_IDENTITY_FILES") {
        files.extend(
            value
                .split(':')
                .filter(|part| !part.trim().is_empty())
                .map(PathBuf::from),
        );
    }
    if files.is_empty() {
        anyhow::bail!(
            "JANUS_WARDEN_AGE_IDENTITY_FILE or JANUS_WARDEN_AGE_IDENTITY_FILES is required"
        );
    }
    Ok(files)
}

fn age_recipients_from_env() -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    if let Ok(value) = env::var("JANUS_WARDEN_AGE_RECIPIENT") {
        recipients.push(value);
    }
    if let Ok(path) = env::var("JANUS_WARDEN_AGE_RECIPIENTS_FILE") {
        recipients.extend(read_recipient_file(Path::new(&path))?);
    }
    if recipients.is_empty() {
        anyhow::bail!("JANUS_WARDEN_AGE_RECIPIENT or JANUS_WARDEN_AGE_RECIPIENTS_FILE is required");
    }
    Ok(recipients)
}

fn read_recipient_file(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path).context("failed to read age recipients file")?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
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

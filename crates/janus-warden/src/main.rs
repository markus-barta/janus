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
    AuditWrite, Destination, EgressMode, ExecutorRef, NamespaceId, Principal, PrincipalChain,
    PrincipalId, PrincipalKind, ProfilePolicy, ReleaseAdmission, ScopePathV1, ScopeRef,
    SecretBroker, SecretDescriptor, SecretMetadataOverlay, SecretStore, TrustLevel, UseProfile,
    WorkloadId,
};
use janus_local::{
    enforce_migration_ready_from_env, enforce_release_admission_from_env,
    enforce_scope_transfer_ready_from_env, FilePermitRegistry, NoopPermitStore, PermitStore,
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

type Runtime = WardenRuntime<WardenStore, AuditWrite, RuntimePermitStore>;

enum WardenStore {
    Secretspec(SecretspecStore),
    Age(AgeSecretStore),
}

enum RuntimePermitStore {
    Noop(NoopPermitStore),
    File(FilePermitRegistry),
}

impl PermitStore for RuntimePermitStore {
    fn store(&self, permit: &janus_core::UsePermit) -> janus_core::JanusResult<()> {
        match self {
            Self::Noop(store) => store.store(permit),
            Self::File(store) => store.store(permit),
        }
    }
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
    let principal = principal_from_env()?;
    let release = enforce_release_admission_from_env(&principal)
        .context("release admission denied Warden startup")?;
    enforce_migration_ready_from_env().context("migration state denied Warden startup")?;
    enforce_scope_transfer_ready_from_env()
        .context("scope transfer state denied Warden startup")?;
    let runtime = build_runtime_from_env(release).await?;
    let server = McpWarden {
        runtime: Arc::new(Mutex::new(runtime)),
        principal,
    };

    tracing::info!("janus-warden MCP stdio server starting");
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

async fn build_runtime_from_env(release: ReleaseAdmission) -> Result<Runtime> {
    let store = load_store_from_env()?;
    let descriptors = store
        .list()
        .await
        .context("failed to list backend manifest descriptors during Warden boot")?;
    let policy = policy_from_env(&descriptors)?;
    let permits = permit_store_from_env()?;
    Ok(WardenRuntime::with_permit_store(
        SecretBroker::new(store, policy, AuditWrite::accepting()),
        permits,
    )
    .with_release_admission(release))
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
    let metadata = metadata_overlay_from_env(&[
        "JANUS_WARDEN_SECRETSPEC_METADATA_FILE",
        "JANUS_WARDEN_METADATA_FILE",
        "JANUS_METADATA_FILE",
    ])?;
    SecretspecStore::load_from_with_metadata(
        manifest,
        profile,
        provider_uri,
        scope_from_env()?,
        metadata.as_ref(),
    )
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
    let metadata = metadata_overlay_from_env(&[
        "JANUS_WARDEN_AGE_METADATA_FILE",
        "JANUS_WARDEN_METADATA_FILE",
        "JANUS_METADATA_FILE",
    ])?;
    AgeSecretStore::load_from_secretspec_manifest_with_metadata(
        manifest,
        profile,
        store_dir,
        identity_files,
        recipients,
        scope_from_env()?,
        metadata.as_ref(),
    )
    .context("failed to load JANUS_WARDEN_BACKEND=age backend")
}

fn metadata_overlay_from_env(keys: &[&'static str]) -> Result<Option<SecretMetadataOverlay>> {
    for key in keys {
        if let Ok(path) = env::var(key) {
            return SecretMetadataOverlay::load_toml_file(path)
                .map(Some)
                .with_context(|| format!("failed to load {key}"));
        }
    }
    Ok(None)
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
                scope: descriptor.scope.clone(),
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

fn permit_store_from_env() -> Result<RuntimePermitStore> {
    let Some(dir) = optional_env_first(&["JANUS_WARDEN_PERMIT_DIR", "JANUS_PERMIT_DIR"])? else {
        return Ok(RuntimePermitStore::Noop(NoopPermitStore));
    };
    Ok(RuntimePermitStore::File(FilePermitRegistry::new(dir)))
}

fn principal_from_env() -> Result<PrincipalChain> {
    let mut principal = PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new(executor_id_from_env()?)?,
        ),
        scope_from_env()?,
    );
    principal.agent = agent_principal_from_env()?;
    principal.human = optional_principal_from_env(PrincipalKind::Human, "JANUS_WARDEN_HUMAN")?;
    principal.workload =
        optional_principal_from_env(PrincipalKind::Workload, "JANUS_WARDEN_WORKLOAD")?;
    principal.admin = optional_principal_from_env(PrincipalKind::Admin, "JANUS_WARDEN_ADMIN")?;
    Ok(principal)
}

fn executor_id_from_env() -> Result<String> {
    Ok(env::var("JANUS_WARDEN_EXECUTOR").unwrap_or_else(|_| "warden-stdio".into()))
}

fn scope_from_env() -> Result<ScopeRef> {
    let mut scope = ScopePathV1::for_repository(
        required_env_first(&[
            "JANUS_WARDEN_SCOPE_ORGANIZATION",
            "JANUS_SCOPE_ORGANIZATION",
        ])?,
        required_env_first(&["JANUS_WARDEN_SCOPE_PROJECT", "JANUS_SCOPE_PROJECT"])?,
        required_env_first(&["JANUS_WARDEN_SCOPE_REPOSITORY", "JANUS_SCOPE_REPOSITORY"])?,
        required_env_first(&["JANUS_WARDEN_SCOPE_ENVIRONMENT", "JANUS_SCOPE_ENVIRONMENT"])?,
    )?;
    if let Some(namespace) =
        optional_env_first(&["JANUS_WARDEN_SCOPE_NAMESPACE", "JANUS_SCOPE_NAMESPACE"])?
    {
        scope = scope.with_namespace(NamespaceId::new(namespace)?);
    }
    if let Some(workload) =
        optional_env_first(&["JANUS_WARDEN_SCOPE_WORKLOAD", "JANUS_SCOPE_WORKLOAD"])?
    {
        scope = scope.with_workload(WorkloadId::new(workload)?)?;
    }
    Ok(scope.scope_ref())
}

fn agent_principal_from_env() -> Result<Option<Principal>> {
    let session = optional_env("JANUS_WARDEN_AGENT_SESSION")?;
    let model = optional_env("JANUS_WARDEN_AGENT_MODEL")?;
    let Some(id) = agent_principal_id(session, model) else {
        return Ok(None);
    };
    Ok(Some(Principal::new(
        PrincipalKind::AgentSession,
        PrincipalId::new(id)?,
    )))
}

fn agent_principal_id(session: Option<String>, model: Option<String>) -> Option<String> {
    match (session, model) {
        (Some(session), Some(model)) => Some(format!("session:{session},model:{model}")),
        (Some(session), None) => Some(format!("session:{session}")),
        (None, Some(model)) => Some(format!("model:{model}")),
        (None, None) => None,
    }
}

fn optional_principal_from_env(
    kind: PrincipalKind,
    key: &'static str,
) -> Result<Option<Principal>> {
    optional_env(key)?
        .map(|value| Ok(Principal::new(kind, PrincipalId::new(value)?)))
        .transpose()
}

fn optional_env(key: &'static str) -> Result<Option<String>> {
    match env::var(key) {
        Ok(value) => {
            if value.trim().is_empty() || value.trim().len() != value.len() {
                anyhow::bail!("{key} must be non-empty and must not have surrounding whitespace");
            }
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read {key}")),
    }
}

fn optional_env_first(keys: &[&'static str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = optional_env(key)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn required_env_first(keys: &[&'static str]) -> Result<String> {
    optional_env_first(keys)?.with_context(|| format!("{} is required", keys.join(" or ")))
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

#[cfg(test)]
mod tests {
    use std::env;
    use std::sync::Mutex;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const PRINCIPAL_ENV_KEYS: &[&str] = &[
        "JANUS_WARDEN_EXECUTOR",
        "JANUS_WARDEN_SCOPE_ORGANIZATION",
        "JANUS_WARDEN_SCOPE_PROJECT",
        "JANUS_WARDEN_SCOPE_REPOSITORY",
        "JANUS_WARDEN_SCOPE_ENVIRONMENT",
        "JANUS_WARDEN_SCOPE_NAMESPACE",
        "JANUS_WARDEN_SCOPE_WORKLOAD",
        "JANUS_SCOPE_ORGANIZATION",
        "JANUS_SCOPE_PROJECT",
        "JANUS_SCOPE_REPOSITORY",
        "JANUS_SCOPE_ENVIRONMENT",
        "JANUS_SCOPE_NAMESPACE",
        "JANUS_SCOPE_WORKLOAD",
        "JANUS_WARDEN_AGENT_SESSION",
        "JANUS_WARDEN_AGENT_MODEL",
        "JANUS_WARDEN_HUMAN",
        "JANUS_WARDEN_WORKLOAD",
        "JANUS_WARDEN_ADMIN",
    ];

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    fn set_required_scope() -> ScopeRef {
        env::set_var("JANUS_WARDEN_SCOPE_ORGANIZATION", "fixture-org");
        env::set_var("JANUS_WARDEN_SCOPE_PROJECT", "janus");
        env::set_var("JANUS_WARDEN_SCOPE_REPOSITORY", "janus");
        env::set_var("JANUS_WARDEN_SCOPE_ENVIRONMENT", "dev");
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    impl EnvGuard {
        fn clear_principal_env() -> Self {
            let saved = PRINCIPAL_ENV_KEYS
                .iter()
                .map(|key| (*key, env::var(key).ok()))
                .collect();
            for key in PRINCIPAL_ENV_KEYS {
                env::remove_var(key);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn principal_env_requires_explicit_scope() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear_principal_env();

        let error = principal_from_env().unwrap_err().to_string();
        assert!(error.contains("JANUS_WARDEN_SCOPE_ORGANIZATION"));
    }

    #[test]
    fn principal_env_builds_full_local_identity_chain() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear_principal_env();
        let scope = set_required_scope();
        env::set_var("JANUS_WARDEN_EXECUTOR", "warden-stdio");
        env::set_var("JANUS_WARDEN_AGENT_SESSION", "agent-session-1");
        env::set_var("JANUS_WARDEN_AGENT_MODEL", "codex");
        env::set_var("JANUS_WARDEN_HUMAN", "human-markus");
        env::set_var("JANUS_WARDEN_WORKLOAD", "stdio-mcp-client");
        env::set_var("JANUS_WARDEN_ADMIN", "admin-break-glass");

        let principal = principal_from_env().unwrap();

        assert_eq!(
            principal.binding_key(),
            format!("executor:warden-stdio|scope:{}|human:human-markus|agent:session:agent-session-1,model:codex|workload:stdio-mcp-client|admin:admin-break-glass", scope.as_str())
        );
    }

    #[test]
    fn namespace_and_workload_refine_the_exact_scope() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear_principal_env();
        set_required_scope();
        env::set_var("JANUS_WARDEN_SCOPE_NAMESPACE", "runtime");
        env::set_var("JANUS_WARDEN_SCOPE_WORKLOAD", "warden");

        let principal = principal_from_env().unwrap();

        let expected = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .with_namespace(NamespaceId::new("runtime").unwrap())
            .with_workload(WorkloadId::new("warden").unwrap())
            .unwrap()
            .scope_ref();
        assert_eq!(principal.scope, expected);
    }

    #[test]
    fn principal_env_rejects_trimmed_identity_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear_principal_env();
        set_required_scope();
        env::set_var("JANUS_WARDEN_AGENT_SESSION", " agent-session-1 ");

        let err = principal_from_env().unwrap_err().to_string();

        assert!(err.contains("JANUS_WARDEN_AGENT_SESSION"));
        assert!(err.contains("must not have surrounding whitespace"));
    }
}

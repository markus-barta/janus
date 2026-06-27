//! # janusd — the Janus daemon
//!
//! Wires `janus-core` + `janus-warden` + `janus-forge` into the serving binary
//! that will supersede the Go envelope's serving role at `vault.barta.cm`.
//! The deployed service is still `../../go-envelope`; this binary is growing
//! narrow engine execution surfaces behind value-free broker contracts.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use janus_core::{
    ApprovalGrant, AuditSink, AuditWrite, BlastRadius, ClassPermitPolicy, ConsumerDescriptor,
    ConsumerKind, ConsumerRef, ConsumerRegistry, Destination, EgressMode, Environment, ExecutorRef,
    JanusError, OwnerRef, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId,
    ProfilePolicy, Purpose, ReloadMethod, SafeLabel, ScopeRef, SecretBroker, SecretDescriptor,
    SecretMetadataOverlay, SecretName, SecretRef, SecretStore, TrustLevel, UsePermit, UseProfile,
    UseRequest, ValidationProbe,
};
use janus_executor::{
    ApprovedUseExecutor, ManagedCommandProfile, ManagedCommandProfileSpec, ManagedCommandRequest,
    ManagedCommandRuntimeLimits,
};
use janus_forge::{
    ConsumerRotationHooks, GeneratedAlphabet, GeneratedRotationBroker, GeneratedValuePolicy,
    RotationApproval,
};
use janus_local::{
    ApprovalRegistry as SharedApprovalRegistry, FileApprovalRegistry, FilePermitRegistry,
    PermitRegistry as SharedPermitRegistry, PermitStore as SharedPermitStore,
};
use janus_provider_age::AgeSecretStore;
use serde::Deserialize;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 30;
const MAX_APPROVAL_TTL_SECONDS: u64 = 3600;

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::ForgeRotateGenerated(config) => run_forge_rotate_generated(config).await,
        Command::RunManaged(config) => run_managed_command(config).await,
        Command::Approve(command) => run_approve(command).await,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Help,
    ForgeRotateGenerated(ForgeRotateGeneratedConfig),
    RunManaged(RunManagedCommandConfig),
    Approve(ApproveCommand),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ApproveCommand {
    Issue(ApproveIssueConfig),
    Permit(ApprovePermitConfig),
    List,
    Revoke(ApproveRevokeConfig),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForgeRotateGeneratedConfig {
    secret: SecretName,
    reason: SafeLabel,
    consumer_ref: ConsumerRef,
    validation_probe: ValidationProbe,
    reload: ReloadMethod,
    alphabet: GeneratedAlphabet,
    length: usize,
    hook_manifest: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunManagedCommandConfig {
    profile_id: ProfileId,
    permit: PermitToken,
    requested_args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApproveIssueConfig {
    secret_ref: SecretRef,
    profile_id: ProfileId,
    purpose: Purpose,
    reason: SafeLabel,
    egress: EgressMode,
    expires_in: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApprovePermitConfig {
    approval: ApprovalToken,
    permit_ttl: Option<Duration>,
    revoke_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApproveRevokeConfig {
    approval: ApprovalToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApprovedPermitIssueOutcome {
    permit_id: String,
    approval_id: String,
    secret_ref: String,
    profile_id: String,
    executor: String,
    destination: String,
    approval_revoked: bool,
    value_returned: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct PermitToken(String);

impl PermitToken {
    fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty()
            || value.trim().len() != value.len()
            || !value.starts_with("use_")
            || value.len() <= "use_".len()
        {
            anyhow::bail!("invalid --permit token");
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PermitToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PermitToken").field(&"<redacted>").finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ApprovalToken(String);

impl ApprovalToken {
    fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty()
            || value.trim().len() != value.len()
            || !value.starts_with("appr_")
            || value.len() <= "appr_".len()
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            anyhow::bail!("invalid --approval token");
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApprovalToken").field(&"<redacted>").finish()
    }
}

impl Default for ForgeRotateGeneratedConfig {
    fn default() -> Self {
        Self {
            secret: SecretName::new("UNSET").expect("static secret name"),
            reason: SafeLabel::new("UNSET").expect("static reason"),
            consumer_ref: ConsumerRef::new("consumer.unset").expect("static consumer ref"),
            validation_probe: ValidationProbe::new("unset").expect("static probe"),
            reload: ReloadMethod::None,
            alphabet: GeneratedAlphabet::UrlSafe,
            length: 48,
            hook_manifest: None,
        }
    }
}

async fn run_forge_rotate_generated(config: ForgeRotateGeneratedConfig) -> Result<()> {
    let store = load_age_store_from_env()?;
    let hook_manifest = hook_manifest_path(config.hook_manifest.as_deref())?;
    let hooks = ManifestRotationHooks::load(&hook_manifest)?;
    let descriptors = store
        .list()
        .await
        .context("failed to list age manifest descriptors")?;
    let descriptor = descriptors
        .into_iter()
        .find(|descriptor| descriptor.name == config.secret)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret.as_str().to_string(),
        })?;
    let secret_ref = descriptor.secret_ref.clone();
    let registry = ConsumerRegistry::new(vec![ConsumerDescriptor {
        consumer_ref: config.consumer_ref.clone(),
        secret_ref: secret_ref.clone(),
        kind: ConsumerKind::ManagedCommand,
        owner: OwnerRef::new("janusd-forge")?,
        environment: Environment::new("admin")?,
        reload: config.reload.clone(),
        validation: vec![config.validation_probe.clone()],
        supports_dual_value: false,
        blast_radius: BlastRadius::new("single generated secret rotation")?,
        declared: true,
    }]);
    let approval = RotationApproval::new(secret_ref, config.reason.clone());
    let policy = GeneratedValuePolicy::new(config.alphabet, config.length)?;
    let principal = forge_principal_from_env()?;
    let mut broker =
        GeneratedRotationBroker::new(store, registry, janus_core::AuditWrite::accepting(), hooks);
    let outcome = broker
        .rotate_generated(&config.secret, &policy, &approval, &principal)
        .await?;

    println!(
        "janusd forge rotate-generated ok secret_ref={} phase={:?} reason_code={} value_returned={}",
        outcome.secret_ref.as_str(),
        outcome.phase,
        outcome.reason_code,
        outcome.value_returned
    );
    Ok(())
}

async fn run_managed_command(config: RunManagedCommandConfig) -> Result<()> {
    let manifest_path = run_profile_manifest_path()?;
    let profiles = ManagedCommandProfileCatalog::load(&manifest_path)?;
    let permits = FilePermitRegistry::new(run_permit_registry_dir()?);
    let store = load_age_store_from_env()?;
    let executor = ApprovedUseExecutor::new(SecretBroker::new(
        store,
        ProfilePolicy::default(),
        AuditWrite::accepting(),
    ));
    let principal = run_principal_from_env()?;
    let mut runner = ProfileManifestManagedCommandRunner {
        profiles,
        permits,
        executor,
        principal,
        clock: SystemManagedCommandClock,
    };
    let outcome = run_managed_command_with(&config, &mut runner).await?;
    emit_run_managed_outcome(&outcome);
    Ok(())
}

async fn run_approve(command: ApproveCommand) -> Result<()> {
    let registry = FileApprovalRegistry::new(approval_registry_dir()?);
    match command {
        ApproveCommand::Issue(config) => {
            let manifest_path = run_profile_manifest_path()?;
            let profiles = ManagedCommandProfileCatalog::load(&manifest_path)?;
            let store = load_age_store_from_env()?;
            let descriptors = store
                .list()
                .await
                .context("failed to list age manifest descriptors for approval issue")?;
            let approval =
                build_approval_grant(&config, &profiles, &descriptors, SystemTime::now())?;
            SharedApprovalRegistry::store(&registry, &approval)?;
            emit_approve_issue_outcome(&approval);
        }
        ApproveCommand::Permit(config) => {
            let permits = FilePermitRegistry::new(run_permit_registry_dir()?);
            let store = load_age_store_from_env()?;
            let principal = run_principal_from_env()?;
            let outcome = issue_approved_permit_with(
                &config,
                &registry,
                &permits,
                store,
                &principal,
                SystemTime::now(),
            )
            .await?;
            emit_approve_permit_outcome(&outcome);
        }
        ApproveCommand::List => {
            let approvals = SharedApprovalRegistry::list(&registry)?;
            emit_approve_list_outcome(&approvals);
        }
        ApproveCommand::Revoke(config) => {
            SharedApprovalRegistry::revoke(&registry, config.approval.as_str())?;
            emit_approve_revoke_outcome(&config.approval);
        }
    }
    Ok(())
}

async fn issue_approved_permit_with<S, R, P>(
    config: &ApprovePermitConfig,
    approvals: &R,
    permits: &P,
    store: S,
    principal: &PrincipalChain,
    now: SystemTime,
) -> Result<ApprovedPermitIssueOutcome>
where
    S: SecretStore,
    R: SharedApprovalRegistry,
    P: SharedPermitStore,
{
    let approval = approvals.get(config.approval.as_str())?;
    let ttl = permit_ttl_for_approval(&approval, config.permit_ttl, now)?;
    let profile = use_profile_for_approval(&approval, ttl);
    let request = use_request_for_approval(&approval);
    let mut broker = SecretBroker::new(
        store,
        ProfilePolicy::new(vec![profile]),
        AuditWrite::accepting(),
    );
    let permit = broker
        .request_use_with_approval(&request, principal, now, Some(&approval))
        .await?;
    if permit.approval().is_none() {
        return Err(JanusError::policy_denied(
            "approval_not_required",
            "stored approval did not bind to this permit path",
        )
        .into());
    }
    permits.store(&permit)?;
    if config.revoke_approval {
        approvals.revoke(config.approval.as_str())?;
    }
    Ok(ApprovedPermitIssueOutcome {
        permit_id: permit.id().as_str().to_string(),
        approval_id: approval.id().as_str().to_string(),
        secret_ref: permit.secret_ref().as_str().to_string(),
        profile_id: permit.profile_id().as_str().to_string(),
        executor: permit.executor().as_str().to_string(),
        destination: permit.destination().as_str().to_string(),
        approval_revoked: config.revoke_approval,
        value_returned: false,
    })
}

fn permit_ttl_for_approval(
    approval: &ApprovalGrant,
    requested_ttl: Option<Duration>,
    now: SystemTime,
) -> Result<Duration> {
    let expires_at = approval_expires_at(approval)?;
    let remaining = expires_at.duration_since(now).map_err(|_| {
        JanusError::approval_invalid("approval_expired", "approval grant is expired")
    })?;
    if remaining.is_zero() {
        return Err(
            JanusError::approval_invalid("approval_expired", "approval grant is expired").into(),
        );
    }
    let class_policy = ClassPermitPolicy::for_class(approval.scope().class);
    let class_limit = class_policy.max_ttl();
    let default_ttl = class_limit
        .map(|max_ttl| remaining.min(max_ttl))
        .unwrap_or(remaining);
    let ttl = requested_ttl.unwrap_or(default_ttl);
    if ttl.is_zero() {
        anyhow::bail!("permit ttl must be greater than zero");
    }
    if ttl > remaining {
        anyhow::bail!("permit ttl exceeds approval remaining lifetime");
    }
    if let Some(max_ttl) = class_limit {
        if ttl > max_ttl {
            anyhow::bail!("permit ttl exceeds secret class limit");
        }
    }
    Ok(ttl)
}

fn approval_expires_at(approval: &ApprovalGrant) -> Result<SystemTime> {
    let snapshot = approval.snapshot();
    if snapshot.expires_at_subsec_nanos >= 1_000_000_000 {
        return Err(JanusError::approval_invalid(
            "denied_malformed_approval",
            "approval registry entry is malformed",
        )
        .into());
    }
    Ok(UNIX_EPOCH
        + Duration::new(
            snapshot.expires_at_unix_secs,
            snapshot.expires_at_subsec_nanos,
        ))
}

fn use_profile_for_approval(approval: &ApprovalGrant, ttl: Duration) -> UseProfile {
    let scope = approval.scope();
    UseProfile {
        id: scope.profile_id.clone(),
        secret_ref: scope.secret_ref.clone(),
        executor: scope.executor.clone(),
        destination: scope.destination.clone(),
        egress: scope.egress,
        trust_level: TrustLevel::L2,
        ttl,
        single_use: true,
        enabled: true,
    }
}

fn use_request_for_approval(approval: &ApprovalGrant) -> UseRequest {
    let scope = approval.scope();
    UseRequest {
        secret_ref: scope.secret_ref.clone(),
        profile_id: scope.profile_id.clone(),
        destination: scope.destination.clone(),
        purpose: scope.purpose.clone(),
    }
}

fn build_approval_grant(
    config: &ApproveIssueConfig,
    profiles: &ManagedCommandProfileCatalog,
    descriptors: &[SecretDescriptor],
    now: SystemTime,
) -> Result<ApprovalGrant> {
    let profile = profiles
        .profile(&config.profile_id)
        .context("managed command profile not found")?;
    if profile.secret_ref() != &config.secret_ref {
        anyhow::bail!("approval profile does not match the requested secret ref");
    }
    let descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.secret_ref == config.secret_ref)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret_ref.as_str().to_string(),
        })?;
    if !descriptor
        .allowed_uses
        .iter()
        .any(|profile_id| profile_id == &config.profile_id)
    {
        anyhow::bail!("approval profile is not allowed by secret metadata");
    }
    if let Some((reason_code, detail)) = descriptor.normal_use_denial() {
        return Err(JanusError::policy_denied(reason_code, detail).into());
    }
    let class = descriptor
        .classification
        .expect("normal_use_denial guarantees classification is present");
    let use_profile = UseProfile {
        id: profile.profile_id().clone(),
        secret_ref: profile.secret_ref().clone(),
        executor: profile.executor().clone(),
        destination: profile.destination().clone(),
        egress: config.egress,
        trust_level: TrustLevel::L2,
        ttl: config.expires_in,
        single_use: true,
        enabled: true,
    };
    let request = UseRequest {
        secret_ref: config.secret_ref.clone(),
        profile_id: config.profile_id.clone(),
        destination: profile.destination().clone(),
        purpose: config.purpose.clone(),
    };
    Ok(ApprovalGrant::for_request(
        &request,
        &use_profile,
        class,
        now + config.expires_in,
        config.reason.clone(),
    ))
}

fn emit_approve_issue_outcome(approval: &ApprovalGrant) {
    let snapshot = approval.snapshot();
    println!(
        "janusd approve issue ok approval_id={} secret_ref={} profile_id={} class={} egress={} expires_at_unix_secs={} value_returned=false",
        snapshot.approval_id,
        snapshot.secret_ref,
        snapshot.profile_id,
        snapshot.class,
        snapshot.egress,
        snapshot.expires_at_unix_secs
    );
}

fn emit_approve_permit_outcome(outcome: &ApprovedPermitIssueOutcome) {
    println!(
        "janusd approve permit ok permit_id={} approval_id={} secret_ref={} profile_id={} executor={} destination={} approval_revoked={} value_returned={}",
        outcome.permit_id,
        outcome.approval_id,
        outcome.secret_ref,
        outcome.profile_id,
        outcome.executor,
        outcome.destination,
        outcome.approval_revoked,
        outcome.value_returned
    );
}

fn emit_approve_list_outcome(approvals: &[ApprovalGrant]) {
    println!(
        "janusd approve list count={} value_returned=false",
        approvals.len()
    );
    for approval in approvals {
        let snapshot = approval.snapshot();
        println!(
            "approval_id={} secret_ref={} profile_id={} class={} egress={} expires_at_unix_secs={} value_returned=false",
            snapshot.approval_id,
            snapshot.secret_ref,
            snapshot.profile_id,
            snapshot.class,
            snapshot.egress,
            snapshot.expires_at_unix_secs
        );
    }
}

fn emit_approve_revoke_outcome(approval: &ApprovalToken) {
    println!(
        "janusd approve revoke ok approval_id={} value_returned=false",
        approval.as_str()
    );
}

async fn run_managed_command_with<R>(
    config: &RunManagedCommandConfig,
    runner: &mut R,
) -> Result<ManagedCommandCliOutcome>
where
    R: ManagedCommandRunner + Send,
{
    runner.run(config).await
}

#[async_trait]
trait ManagedCommandRunner {
    async fn run(&mut self, config: &RunManagedCommandConfig) -> Result<ManagedCommandCliOutcome>;
}

trait ManagedCommandPermitRegistry {
    fn resolve(&self, token: &PermitToken) -> Result<UsePermit>;
}

impl ManagedCommandPermitRegistry for FilePermitRegistry {
    fn resolve(&self, token: &PermitToken) -> Result<UsePermit> {
        Ok(SharedPermitRegistry::take(self, token.as_str())?)
    }
}

#[async_trait]
trait ManagedCommandExecutor {
    async fn run(
        &mut self,
        profile: &ManagedCommandProfile,
        permit: &UsePermit,
        principal: &PrincipalChain,
        requested_args: Vec<String>,
        now: SystemTime,
    ) -> Result<ManagedCommandCliOutcome>;
}

#[async_trait]
impl<S, A> ManagedCommandExecutor for ApprovedUseExecutor<S, A>
where
    S: SecretStore + Send,
    A: AuditSink + Send,
{
    async fn run(
        &mut self,
        profile: &ManagedCommandProfile,
        permit: &UsePermit,
        principal: &PrincipalChain,
        requested_args: Vec<String>,
        now: SystemTime,
    ) -> Result<ManagedCommandCliOutcome> {
        let outcome = self
            .run_managed_command(ManagedCommandRequest {
                profile,
                permit,
                principal,
                requested_args,
                now,
            })
            .await?;
        Ok(outcome.into())
    }
}

trait ManagedCommandClock {
    fn now(&self) -> SystemTime;
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemManagedCommandClock;

impl ManagedCommandClock for SystemManagedCommandClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct ProfileManifestManagedCommandRunner<R, E, C = SystemManagedCommandClock> {
    profiles: ManagedCommandProfileCatalog,
    permits: R,
    executor: E,
    principal: PrincipalChain,
    clock: C,
}

#[async_trait]
impl<R, E, C> ManagedCommandRunner for ProfileManifestManagedCommandRunner<R, E, C>
where
    R: ManagedCommandPermitRegistry + Send,
    E: ManagedCommandExecutor + Send,
    C: ManagedCommandClock + Send,
{
    async fn run(&mut self, config: &RunManagedCommandConfig) -> Result<ManagedCommandCliOutcome> {
        let profile = self
            .profiles
            .profile(&config.profile_id)
            .context("managed command profile not found")?;
        if profile.allowed_args() != config.requested_args.as_slice() {
            anyhow::bail!("janusd run command arguments do not match the reviewed profile");
        }
        let permit = self.permits.resolve(&config.permit)?;
        self.executor
            .run(
                profile,
                &permit,
                &self.principal,
                config.requested_args.clone(),
                self.clock.now(),
            )
            .await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedCommandCliOutcome {
    stdout: String,
    stderr: String,
    exit_success: bool,
    exit_code: Option<i32>,
    reason_code: &'static str,
    value_returned: bool,
}

impl From<janus_executor::ManagedCommandOutcome> for ManagedCommandCliOutcome {
    fn from(outcome: janus_executor::ManagedCommandOutcome) -> Self {
        Self {
            stdout: outcome.output.stdout,
            stderr: outcome.output.stderr,
            exit_success: outcome.output.exit_success,
            exit_code: outcome.output.exit_code,
            reason_code: outcome.output.reason_code,
            value_returned: outcome.value_returned || outcome.output.value_returned,
        }
    }
}

fn emit_run_managed_outcome(outcome: &ManagedCommandCliOutcome) {
    print!("{}", outcome.stdout);
    eprint!("{}", outcome.stderr);
    eprintln!(
        "janusd run completed exit_success={} exit_code={:?} reason_code={} value_returned={}",
        outcome.exit_success, outcome.exit_code, outcome.reason_code, outcome.value_returned
    );
}

#[derive(Clone, Debug)]
struct ManagedCommandProfileCatalog {
    profiles: Vec<ManagedCommandProfile>,
}

impl ManagedCommandProfileCatalog {
    fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read managed command profile manifest {}",
                path.display()
            )
        })?;
        Self::parse(&contents)
    }

    fn parse(contents: &str) -> Result<Self> {
        let parsed = toml::from_str::<ManagedCommandProfileCatalogToml>(contents)
            .context("failed to parse managed command profile manifest")?;
        let mut ids = BTreeSet::new();
        let mut profiles = Vec::new();
        for profile in parsed.profiles {
            let profile = profile.into_profile()?;
            if !ids.insert(profile.profile_id().as_str().to_string()) {
                anyhow::bail!("duplicate managed command profile id");
            }
            profiles.push(profile);
        }
        if profiles.is_empty() {
            anyhow::bail!("managed command profile manifest has no profiles");
        }
        Ok(Self { profiles })
    }

    fn profile(&self, profile_id: &ProfileId) -> Option<&ManagedCommandProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.profile_id() == profile_id)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedCommandProfileCatalogToml {
    profiles: Vec<ManagedCommandProfileToml>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedCommandProfileToml {
    id: String,
    secret_ref: String,
    executor: String,
    destination: String,
    env: String,
    binary: PathBuf,
    allowed_args: Vec<String>,
    #[serde(default = "default_run_timeout_seconds")]
    timeout_seconds: u64,
    #[serde(default = "default_run_max_output_bytes")]
    max_stdout_bytes: usize,
    #[serde(default = "default_run_max_output_bytes")]
    max_stderr_bytes: usize,
    consumer: ManagedCommandConsumerToml,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedCommandConsumerToml {
    consumer_ref: String,
    #[serde(default = "default_managed_command_kind")]
    kind: String,
    owner: String,
    environment: String,
    #[serde(default = "default_reload_method")]
    reload: String,
    #[serde(default)]
    validation: Vec<String>,
    #[serde(default)]
    supports_dual_value: bool,
    blast_radius: String,
}

impl ManagedCommandProfileToml {
    fn into_profile(self) -> Result<ManagedCommandProfile> {
        if self.consumer.kind != "managed_command" {
            anyhow::bail!("managed command profile consumer kind must be managed_command");
        }
        let secret_ref = SecretRef::new(self.secret_ref)?;
        let consumer = ConsumerDescriptor {
            consumer_ref: ConsumerRef::new(self.consumer.consumer_ref)?,
            secret_ref: secret_ref.clone(),
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new(self.consumer.owner)?,
            environment: Environment::new(self.consumer.environment)?,
            reload: parse_reload_method(&self.consumer.reload)?,
            validation: self
                .consumer
                .validation
                .into_iter()
                .map(ValidationProbe::new)
                .collect::<janus_core::JanusResult<_>>()?,
            supports_dual_value: self.consumer.supports_dual_value,
            blast_radius: BlastRadius::new(self.consumer.blast_radius)?,
            declared: true,
        };
        Ok(ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id: ProfileId::new(self.id)?,
            secret_ref,
            executor: ExecutorRef::new(self.executor)?,
            destination: Destination::new(self.destination)?,
            env_name: SafeLabel::new(self.env)?,
            binary: self.binary,
            allowed_args: self.allowed_args,
            runtime_limits: ManagedCommandRuntimeLimits {
                timeout: Duration::from_secs(self.timeout_seconds),
                max_stdout_bytes: self.max_stdout_bytes,
                max_stderr_bytes: self.max_stderr_bytes,
            },
            consumer,
        })?)
    }
}

fn default_run_timeout_seconds() -> u64 {
    30
}

fn default_run_max_output_bytes() -> usize {
    64 * 1024
}

fn default_managed_command_kind() -> String {
    "managed_command".to_string()
}

fn default_reload_method() -> String {
    "none".to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HookCommand {
    program: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HookManifest {
    #[serde(default)]
    validation: BTreeMap<String, HookCommand>,
    #[serde(default)]
    reload: ReloadHookManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReloadHookManifest {
    #[serde(default)]
    restart_service: BTreeMap<String, HookCommand>,
    #[serde(default)]
    signal: BTreeMap<String, HookCommand>,
    #[serde(default)]
    exec_hook: BTreeMap<String, HookCommand>,
    #[serde(default)]
    connector_action: BTreeMap<String, HookCommand>,
}

struct ManifestRotationHooks {
    manifest: HookManifest,
}

impl ManifestRotationHooks {
    fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read hook manifest {}", path.display()))?;
        let manifest = HookManifest::parse(&contents).context("failed to parse hook manifest")?;
        Ok(Self { manifest })
    }
}

impl HookManifest {
    fn parse(contents: &str) -> Result<Self> {
        let manifest = toml::from_str::<Self>(contents)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        for command in self.validation.values() {
            command.validate()?;
        }
        for command in self.reload.restart_service.values() {
            command.validate()?;
        }
        for command in self.reload.signal.values() {
            command.validate()?;
        }
        for command in self.reload.exec_hook.values() {
            command.validate()?;
        }
        for command in self.reload.connector_action.values() {
            command.validate()?;
        }
        Ok(())
    }
}

impl HookCommand {
    fn validate(&self) -> Result<()> {
        if !self.program.is_absolute() {
            anyhow::bail!("hook program must be an absolute path");
        }
        if matches!(self.timeout_seconds, Some(0)) {
            anyhow::bail!("hook timeout must be greater than zero");
        }
        Ok(())
    }
}

#[async_trait]
impl ConsumerRotationHooks for ManifestRotationHooks {
    async fn validate(&mut self, probe: &ValidationProbe) -> janus_core::JanusResult<()> {
        let command = self
            .manifest
            .validation
            .get(probe.as_str())
            .ok_or_else(|| {
                JanusError::policy_denied(
                    "validation_hook_missing",
                    "no reviewed command is declared for the validation probe",
                )
            })?;
        run_hook_command(HookRun {
            command,
            kind: "validation",
            label: probe.as_str(),
            consumer: None,
            missing_reason: "validation_hook_missing",
            failed_reason: "validation_hook_failed",
            timeout_reason: "validation_hook_timeout",
        })
        .await
    }

    async fn reload(
        &mut self,
        consumer: &ConsumerRef,
        method: &ReloadMethod,
    ) -> janus_core::JanusResult<()> {
        let Some((label, command)) = self.manifest.reload_command(method) else {
            return Err(JanusError::policy_denied(
                "reload_hook_missing",
                "no reviewed command is declared for the reload method",
            ));
        };
        run_hook_command(HookRun {
            command,
            kind: "reload",
            label,
            consumer: Some(consumer),
            missing_reason: "reload_hook_missing",
            failed_reason: "reload_hook_failed",
            timeout_reason: "reload_hook_timeout",
        })
        .await
    }
}

impl HookManifest {
    fn reload_command(&self, method: &ReloadMethod) -> Option<(&str, &HookCommand)> {
        match method {
            ReloadMethod::None => None,
            ReloadMethod::RestartService { service } => self
                .reload
                .restart_service
                .get_key_value(service.as_str())
                .map(|(label, command)| (label.as_str(), command)),
            ReloadMethod::Signal { signal } => self
                .reload
                .signal
                .get_key_value(signal.as_str())
                .map(|(label, command)| (label.as_str(), command)),
            ReloadMethod::ExecHook { hook } => self
                .reload
                .exec_hook
                .get_key_value(hook.as_str())
                .map(|(label, command)| (label.as_str(), command)),
            ReloadMethod::ConnectorAction { action } => self
                .reload
                .connector_action
                .get_key_value(action.as_str())
                .map(|(label, command)| (label.as_str(), command)),
            ReloadMethod::Manual | ReloadMethod::Unsupported => None,
        }
    }
}

struct HookRun<'a> {
    command: &'a HookCommand,
    kind: &'static str,
    label: &'a str,
    consumer: Option<&'a ConsumerRef>,
    missing_reason: &'static str,
    failed_reason: &'static str,
    timeout_reason: &'static str,
}

async fn run_hook_command(run: HookRun<'_>) -> janus_core::JanusResult<()> {
    if !run.command.program.is_absolute() {
        return Err(JanusError::policy_denied(
            run.missing_reason,
            "hook command is not reviewed as an absolute program path",
        ));
    }
    let timeout_duration = Duration::from_secs(
        run.command
            .timeout_seconds
            .unwrap_or(DEFAULT_HOOK_TIMEOUT_SECONDS),
    );
    let mut child = TokioCommand::new(&run.command.program);
    child
        .args(&run.command.args)
        .env_clear()
        .env("JANUS_HOOK_KIND", run.kind)
        .env("JANUS_HOOK_LABEL", run.label)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(consumer) = run.consumer {
        child.env("JANUS_HOOK_CONSUMER_REF", consumer.as_str());
    }
    let mut child = child.spawn().map_err(|_| {
        JanusError::policy_denied(run.failed_reason, "reviewed hook command failed to start")
    })?;
    let status = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            return Err(JanusError::policy_denied(
                run.failed_reason,
                "reviewed hook command failed while waiting",
            ))
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(JanusError::policy_denied(
                run.timeout_reason,
                "reviewed hook command timed out",
            ));
        }
    };
    if status.success() {
        Ok(())
    } else {
        Err(JanusError::policy_denied(
            run.failed_reason,
            "reviewed hook command exited unsuccessfully",
        ))
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() || args == ["--help"] || args == ["help"] {
        return Ok(Command::Help);
    }
    match args.as_slice() {
        [forge, rotate, rest @ ..] if forge == "forge" && rotate == "rotate-generated" => {
            parse_forge_rotate_generated(rest.iter().cloned()).map(Command::ForgeRotateGenerated)
        }
        [run, rest @ ..] if run == "run" => {
            parse_run_managed(rest.iter().cloned()).map(Command::RunManaged)
        }
        [approve, issue, rest @ ..] if approve == "approve" && issue == "issue" => {
            parse_approve_issue(rest.iter().cloned())
                .map(ApproveCommand::Issue)
                .map(Command::Approve)
        }
        [approve, permit, rest @ ..] if approve == "approve" && permit == "permit" => {
            parse_approve_permit(rest.iter().cloned())
                .map(ApproveCommand::Permit)
                .map(Command::Approve)
        }
        [approve, list] if approve == "approve" && list == "list" => {
            Ok(Command::Approve(ApproveCommand::List))
        }
        [approve, revoke, rest @ ..] if approve == "approve" && revoke == "revoke" => {
            parse_approve_revoke(rest.iter().cloned())
                .map(ApproveCommand::Revoke)
                .map(Command::Approve)
        }
        _ => anyhow::bail!("unsupported janusd command; run `janusd --help`"),
    }
}

fn parse_approve_issue(args: impl IntoIterator<Item = String>) -> Result<ApproveIssueConfig> {
    let mut secret_ref = None;
    let mut profile_id = None;
    let mut purpose = None;
    let mut reason = None;
    let mut egress = None;
    let mut expires_in = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--secret-ref" => {
                if secret_ref
                    .replace(SecretRef::new(required_arg("--secret-ref", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--secret-ref may only be provided once");
                }
            }
            "--profile" => {
                if profile_id
                    .replace(ProfileId::new(required_arg("--profile", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--profile may only be provided once");
                }
            }
            "--purpose" => {
                if purpose
                    .replace(Purpose::new(required_arg("--purpose", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--purpose may only be provided once");
                }
            }
            "--reason" => {
                if reason
                    .replace(SafeLabel::new(required_arg("--reason", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--reason may only be provided once");
                }
            }
            "--egress" => {
                if egress
                    .replace(EgressMode::parse(&required_arg("--egress", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--egress may only be provided once");
                }
            }
            "--expires-in-seconds" => {
                if expires_in
                    .replace(parse_approval_ttl(&required_arg(
                        "--expires-in-seconds",
                        args.next(),
                    )?)?)
                    .is_some()
                {
                    anyhow::bail!("--expires-in-seconds may only be provided once");
                }
            }
            "--secret" | "--value" | "--raw-value" | "--permit" => {
                anyhow::bail!("approve issue accepts only value-free approval scope fields")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd approve flag"),
            _ => anyhow::bail!("unsupported janusd approve argument"),
        }
    }

    Ok(ApproveIssueConfig {
        secret_ref: secret_ref.context("--secret-ref is required")?,
        profile_id: profile_id.context("--profile is required")?,
        purpose: purpose.context("--purpose is required")?,
        reason: reason.context("--reason is required")?,
        egress: egress.context("--egress is required")?,
        expires_in: expires_in.context("--expires-in-seconds is required")?,
    })
}

fn parse_approve_permit(args: impl IntoIterator<Item = String>) -> Result<ApprovePermitConfig> {
    let mut approval = None;
    let mut permit_ttl = None;
    let mut revoke_approval = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--approval" => {
                if approval
                    .replace(ApprovalToken::new(required_arg(
                        "--approval",
                        args.next(),
                    )?)?)
                    .is_some()
                {
                    anyhow::bail!("--approval may only be provided once");
                }
            }
            "--permit-ttl-seconds" => {
                if permit_ttl
                    .replace(parse_positive_duration(
                        "--permit-ttl-seconds",
                        &required_arg("--permit-ttl-seconds", args.next())?,
                    )?)
                    .is_some()
                {
                    anyhow::bail!("--permit-ttl-seconds may only be provided once");
                }
            }
            "--revoke-approval" => {
                if revoke_approval {
                    anyhow::bail!("--revoke-approval may only be provided once");
                }
                revoke_approval = true;
            }
            "--secret" | "--secret-ref" | "--value" | "--raw-value" | "--profile" => {
                anyhow::bail!("approve permit accepts only an approval id and permit controls")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd approve flag"),
            _ => anyhow::bail!("unsupported janusd approve argument"),
        }
    }
    Ok(ApprovePermitConfig {
        approval: approval.context("--approval is required")?,
        permit_ttl,
        revoke_approval,
    })
}

fn parse_approve_revoke(args: impl IntoIterator<Item = String>) -> Result<ApproveRevokeConfig> {
    let mut approval = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--approval" => {
                if approval
                    .replace(ApprovalToken::new(required_arg(
                        "--approval",
                        args.next(),
                    )?)?)
                    .is_some()
                {
                    anyhow::bail!("--approval may only be provided once");
                }
            }
            "--value" | "--secret" | "--secret-ref" => {
                anyhow::bail!("approve revoke accepts only an approval id")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd approve flag"),
            _ => anyhow::bail!("unsupported janusd approve argument"),
        }
    }
    Ok(ApproveRevokeConfig {
        approval: approval.context("--approval is required")?,
    })
}

fn parse_approval_ttl(value: &str) -> Result<Duration> {
    let seconds = value
        .parse::<u64>()
        .context("invalid --expires-in-seconds")?;
    if seconds == 0 || seconds > MAX_APPROVAL_TTL_SECONDS {
        anyhow::bail!("approval expiry must be between 1 and 3600 seconds");
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_positive_duration(flag: &'static str, value: &str) -> Result<Duration> {
    let seconds = value
        .parse::<u64>()
        .with_context(|| format!("invalid {flag}"))?;
    if seconds == 0 {
        anyhow::bail!("{flag} must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_run_managed(args: impl IntoIterator<Item = String>) -> Result<RunManagedCommandConfig> {
    let mut profile_id = None;
    let mut permit = None;
    let mut requested_args = Vec::new();
    let mut saw_separator = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                if profile_id
                    .replace(ProfileId::new(required_arg("--profile", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--profile may only be provided once");
                }
            }
            "--permit" => {
                if permit
                    .replace(PermitToken::new(required_arg("--permit", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--permit may only be provided once");
                }
            }
            "--" => {
                saw_separator = true;
                requested_args.extend(args);
                break;
            }
            "--secret" | "--secret-ref" | "--value" | "--env" | "--binary" | "--destination"
            | "--executor" => {
                anyhow::bail!("run policy fields come from the reviewed profile")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd run flag"),
            _ => anyhow::bail!("janusd run command arguments must follow --"),
        }
    }

    let Some(profile_id) = profile_id else {
        anyhow::bail!("--profile is required");
    };
    let Some(permit) = permit else {
        anyhow::bail!("--permit is required");
    };
    if !saw_separator {
        anyhow::bail!("janusd run requires -- before command arguments");
    }

    Ok(RunManagedCommandConfig {
        profile_id,
        permit,
        requested_args,
    })
}

fn parse_forge_rotate_generated(
    args: impl IntoIterator<Item = String>,
) -> Result<ForgeRotateGeneratedConfig> {
    let mut config = ForgeRotateGeneratedConfig::default();
    let mut secret_set = false;
    let mut reason_set = false;
    let mut consumer_set = false;
    let mut validation_set = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--secret" => {
                config.secret = SecretName::new(required_arg("--secret", args.next())?)?;
                secret_set = true;
            }
            "--reason" => {
                config.reason = SafeLabel::new(required_arg("--reason", args.next())?)?;
                reason_set = true;
            }
            "--consumer-ref" => {
                config.consumer_ref =
                    ConsumerRef::new(required_arg("--consumer-ref", args.next())?)?;
                consumer_set = true;
            }
            "--validation" => {
                config.validation_probe =
                    ValidationProbe::new(required_arg("--validation", args.next())?)?;
                validation_set = true;
            }
            "--reload" => {
                config.reload = parse_reload_method(&required_arg("--reload", args.next())?)?;
            }
            "--hook-manifest" => {
                config.hook_manifest =
                    Some(PathBuf::from(required_arg("--hook-manifest", args.next())?));
            }
            "--alphabet" => {
                config.alphabet = parse_alphabet(&required_arg("--alphabet", args.next())?)?;
            }
            "--length" => {
                let value = required_arg("--length", args.next())?;
                config.length = value.parse::<usize>().context("invalid --length")?;
            }
            "--allow-noop-hooks" => {
                anyhow::bail!("--allow-noop-hooks was removed; use --hook-manifest")
            }
            "--value" | "--generated-value" => {
                anyhow::bail!(
                    "{arg} is intentionally unsupported; Forge generates values internally"
                )
            }
            other if other.starts_with('-') => {
                anyhow::bail!("unsupported forge rotate-generated flag")
            }
            _ => anyhow::bail!("unsupported forge rotate-generated argument"),
        }
    }
    if !secret_set {
        anyhow::bail!("--secret is required");
    }
    if !reason_set {
        anyhow::bail!("--reason is required");
    }
    if !consumer_set {
        anyhow::bail!("--consumer-ref is required");
    }
    if !validation_set {
        anyhow::bail!("--validation is required");
    }
    GeneratedValuePolicy::new(config.alphabet, config.length)?;
    Ok(config)
}

fn parse_alphabet(value: &str) -> Result<GeneratedAlphabet> {
    match value {
        "url-safe" => Ok(GeneratedAlphabet::UrlSafe),
        "alphanumeric" => Ok(GeneratedAlphabet::Alphanumeric),
        "hex" => Ok(GeneratedAlphabet::Hex),
        _ => anyhow::bail!("unsupported generated alphabet"),
    }
}

fn parse_reload_method(value: &str) -> Result<ReloadMethod> {
    if value == "none" {
        return Ok(ReloadMethod::None);
    }
    let Some((kind, label)) = value.split_once(':') else {
        anyhow::bail!("unsupported reload method");
    };
    match kind {
        "restart-service" => Ok(ReloadMethod::RestartService {
            service: SafeLabel::new(label)?,
        }),
        "signal" => Ok(ReloadMethod::Signal {
            signal: SafeLabel::new(label)?,
        }),
        "exec-hook" => Ok(ReloadMethod::ExecHook {
            hook: SafeLabel::new(label)?,
        }),
        "connector-action" => Ok(ReloadMethod::ConnectorAction {
            action: SafeLabel::new(label)?,
        }),
        _ => anyhow::bail!("unsupported reload method"),
    }
}

fn required_arg(flag: &'static str, value: Option<String>) -> Result<String> {
    value.with_context(|| format!("{flag} requires a value"))
}

fn hook_manifest_path(configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_path_buf());
    }
    env::var("JANUS_FORGE_HOOK_MANIFEST")
        .map(PathBuf::from)
        .context("--hook-manifest or JANUS_FORGE_HOOK_MANIFEST is required")
}

fn run_profile_manifest_path() -> Result<PathBuf> {
    env_first(&[
        "JANUS_RUN_PROFILE_MANIFEST",
        "JANUS_MANAGED_PROFILE_MANIFEST",
    ])
    .map(PathBuf::from)
    .context("JANUS_RUN_PROFILE_MANIFEST is required")
}

fn run_permit_registry_dir() -> Result<PathBuf> {
    env_first(&["JANUS_RUN_PERMIT_DIR", "JANUS_PERMIT_DIR"])
        .map(PathBuf::from)
        .context("JANUS_RUN_PERMIT_DIR is required")
}

fn approval_registry_dir() -> Result<PathBuf> {
    env_first(&["JANUS_APPROVAL_DIR", "JANUS_RUN_APPROVAL_DIR"])
        .map(PathBuf::from)
        .context("JANUS_APPROVAL_DIR is required")
}

fn run_principal_from_env() -> Result<PrincipalChain> {
    let executor = env_first(&["JANUS_RUN_EXECUTOR", "JANUS_WARDEN_EXECUTOR"])
        .unwrap_or_else(|| "warden-stdio".to_string());
    let scope = env_first(&["JANUS_RUN_SCOPE", "JANUS_WARDEN_SCOPE"])
        .unwrap_or_else(|| "janus/default".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        ScopeRef::new(scope)?,
    ))
}

fn load_age_store_from_env() -> Result<AgeSecretStore> {
    let manifest = env_first(&[
        "JANUS_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_SECRETSPEC_FILE",
    ])
    .context("JANUS_AGE_MANIFEST_FILE is required")?;
    let profile = env_first(&["JANUS_AGE_PROFILE", "JANUS_WARDEN_AGE_PROFILE"])
        .unwrap_or_else(|| "default".to_string());
    let store_dir = env_first(&["JANUS_AGE_STORE_DIR", "JANUS_WARDEN_AGE_STORE_DIR"])
        .unwrap_or_else(|| "/var/lib/janus/secrets".to_string());
    let identity_files = age_identity_files_from_env()?;
    let recipients = age_recipients_from_env()?;
    let metadata = metadata_overlay_from_env(&[
        "JANUS_AGE_METADATA_FILE",
        "JANUS_WARDEN_AGE_METADATA_FILE",
        "JANUS_METADATA_FILE",
    ])?;
    AgeSecretStore::load_from_secretspec_manifest_with_metadata(
        manifest,
        profile,
        store_dir,
        identity_files,
        recipients,
        metadata.as_ref(),
    )
    .context("failed to load age backend for janusd")
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

fn age_identity_files_from_env() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for key in ["JANUS_AGE_IDENTITY_FILE", "JANUS_WARDEN_AGE_IDENTITY_FILE"] {
        if let Ok(value) = env::var(key) {
            files.push(PathBuf::from(value));
        }
    }
    for key in [
        "JANUS_AGE_IDENTITY_FILES",
        "JANUS_WARDEN_AGE_IDENTITY_FILES",
    ] {
        if let Ok(value) = env::var(key) {
            files.extend(
                value
                    .split(':')
                    .filter(|part| !part.trim().is_empty())
                    .map(PathBuf::from),
            );
        }
    }
    if files.is_empty() {
        anyhow::bail!("JANUS_AGE_IDENTITY_FILE or JANUS_AGE_IDENTITY_FILES is required");
    }
    Ok(files)
}

fn age_recipients_from_env() -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    for key in ["JANUS_AGE_RECIPIENT", "JANUS_WARDEN_AGE_RECIPIENT"] {
        if let Ok(value) = env::var(key) {
            recipients.push(value);
        }
    }
    for key in [
        "JANUS_AGE_RECIPIENTS_FILE",
        "JANUS_WARDEN_AGE_RECIPIENTS_FILE",
    ] {
        if let Ok(path) = env::var(key) {
            recipients.extend(read_recipient_file(Path::new(&path))?);
        }
    }
    if recipients.is_empty() {
        anyhow::bail!("JANUS_AGE_RECIPIENT or JANUS_AGE_RECIPIENTS_FILE is required");
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

fn forge_principal_from_env() -> Result<PrincipalChain> {
    let executor = env::var("JANUS_FORGE_EXECUTOR").unwrap_or_else(|_| "forge-cli".to_string());
    let scope = env::var("JANUS_FORGE_SCOPE").unwrap_or_else(|_| "janus/default".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        ScopeRef::new(scope)?,
    ))
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env::var(key).ok())
}

fn print_usage() {
    eprintln!(
        "janusd\n\nCommands:\n  run --profile PROFILE --permit use_... -- ARG...\n  approve issue --secret-ref REF --profile PROFILE --purpose PURPOSE --reason REASON \\\n    --egress connector|sandboxed|proxy_enforced|hook_guarded|declared_only \\\n    --expires-in-seconds SECONDS\n  approve permit --approval appr_... [--permit-ttl-seconds SECONDS] [--revoke-approval]\n  approve list\n  approve revoke --approval appr_...\n  forge rotate-generated --secret NAME --reason REASON --consumer-ref REF \\\n    --validation PROBE --hook-manifest PATH [--reload METHOD] \\\n    [--alphabet url-safe|alphanumeric|hex] [--length N]\n\njanusd run loads reviewed profiles from JANUS_RUN_PROFILE_MANIFEST and permits from JANUS_RUN_PERMIT_DIR.\njanusd approve loads reviewed profiles from JANUS_RUN_PROFILE_MANIFEST, backend metadata from JANUS_AGE_* / JANUS_WARDEN_AGE_*, approvals from JANUS_APPROVAL_DIR, and permits from JANUS_RUN_PERMIT_DIR.\nReload methods: none, restart-service:LABEL, signal:LABEL, exec-hook:LABEL, connector-action:LABEL.\nForge generates replacement values internally; no --value argument exists."
    );
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::SystemTime;

    #[cfg(unix)]
    use janus_core::{
        AuditWrite, Destination, EgressMode, ExecutorRef, ManifestCatalog, ProjectId, Purpose,
        SecretClass, SecretLifecycle, SecretMeta, SecretRef, TrustLevel, UseProfile, UseRequest,
    };
    #[cfg(unix)]
    use janus_mock::MockStore;

    use super::*;

    fn parse_ok(args: &[&str]) -> ForgeRotateGeneratedConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::ForgeRotateGenerated(config) => config,
            Command::Help => panic!("expected forge config"),
            Command::RunManaged(_) => panic!("expected forge config"),
            Command::Approve(_) => panic!("expected forge config"),
        }
    }

    fn parse_run_ok(args: &[&str]) -> RunManagedCommandConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::RunManaged(config) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected run config"),
            Command::Help => panic!("expected run config"),
            Command::Approve(_) => panic!("expected run config"),
        }
    }

    fn parse_approve_issue_ok(args: &[&str]) -> ApproveIssueConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Issue(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve issue config"),
            Command::RunManaged(_) => panic!("expected approve issue config"),
            Command::Approve(_) => panic!("expected approve issue config"),
            Command::Help => panic!("expected approve issue config"),
        }
    }

    fn parse_approve_permit_ok(args: &[&str]) -> ApprovePermitConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Permit(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve permit config"),
            Command::RunManaged(_) => panic!("expected approve permit config"),
            Command::Approve(_) => panic!("expected approve permit config"),
            Command::Help => panic!("expected approve permit config"),
        }
    }

    fn parse_approve_revoke_ok(args: &[&str]) -> ApproveRevokeConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Revoke(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve revoke config"),
            Command::RunManaged(_) => panic!("expected approve revoke config"),
            Command::Approve(_) => panic!("expected approve revoke config"),
            Command::Help => panic!("expected approve revoke config"),
        }
    }

    #[test]
    fn parses_run_profile_permit_and_separator_args_without_exposing_permit_debug() {
        let config = parse_run_ok(&[
            "run",
            "--profile",
            "profile.canary",
            "--permit",
            "use_abc123",
            "--",
            "release",
            "upload",
        ]);

        assert_eq!(config.profile_id.as_str(), "profile.canary");
        assert_eq!(config.permit.as_str(), "use_abc123");
        assert_eq!(config.requested_args, vec!["release", "upload"]);
        assert!(!format!("{config:?}").contains("use_abc123"));
    }

    #[test]
    fn parses_approve_issue_and_revoke_without_literal_inputs() {
        let config = parse_approve_issue_ok(&[
            "approve",
            "issue",
            "--secret-ref",
            "sec_fixture",
            "--profile",
            "profile.canary",
            "--purpose",
            "emergency deploy",
            "--reason",
            "JANUS-229 approval",
            "--egress",
            "proxy_enforced",
            "--expires-in-seconds",
            "120",
        ]);

        assert_eq!(config.secret_ref.as_str(), "sec_fixture");
        assert_eq!(config.profile_id.as_str(), "profile.canary");
        assert_eq!(config.purpose.as_str(), "emergency deploy");
        assert_eq!(config.reason.as_str(), "JANUS-229 approval");
        assert_eq!(config.egress, EgressMode::ProxyEnforced);
        assert_eq!(config.expires_in, Duration::from_secs(120));

        let revoke = parse_approve_revoke_ok(&["approve", "revoke", "--approval", "appr_abc123"]);
        assert_eq!(revoke.approval.as_str(), "appr_abc123");
        assert!(!format!("{revoke:?}").contains("appr_abc123"));

        let permit = parse_approve_permit_ok(&[
            "approve",
            "permit",
            "--approval",
            "appr_abc123",
            "--permit-ttl-seconds",
            "30",
            "--revoke-approval",
        ]);
        assert_eq!(permit.approval.as_str(), "appr_abc123");
        assert_eq!(permit.permit_ttl, Some(Duration::from_secs(30)));
        assert!(permit.revoke_approval);
        assert!(!format!("{permit:?}").contains("appr_abc123"));
    }

    #[test]
    fn approve_issue_rejects_literals_and_invalid_ttl_without_echoing_values() {
        let err = parse_args(
            [
                "approve",
                "issue",
                "--secret-ref",
                "sec_fixture",
                "--profile",
                "profile.canary",
                "--purpose",
                "emergency deploy",
                "--reason",
                "JANUS-229",
                "--egress",
                "connector",
                "--value",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("value-free"));
        assert!(!err.to_string().contains("do-not-echo-me"));

        let err = parse_args(
            [
                "approve",
                "issue",
                "--secret-ref",
                "sec_fixture",
                "--profile",
                "profile.canary",
                "--purpose",
                "emergency deploy",
                "--reason",
                "JANUS-229",
                "--egress",
                "connector",
                "--expires-in-seconds",
                "0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval expiry"));
    }

    #[test]
    fn approve_permit_rejects_literals_and_invalid_ttl_without_echoing_values() {
        let err = parse_args(
            [
                "approve",
                "permit",
                "--approval",
                "appr_abc123",
                "--value",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval id"));
        assert!(!err.to_string().contains("do-not-echo-me"));

        let err = parse_args(
            [
                "approve",
                "permit",
                "--approval",
                "appr_abc123",
                "--permit-ttl-seconds",
                "0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--permit-ttl-seconds"));
    }

    #[test]
    fn run_rejects_policy_fields_and_literal_args_without_echoing_values() {
        let err = parse_args(
            [
                "run",
                "--profile",
                "profile.canary",
                "--permit",
                "use_abc123",
                "--secret-ref",
                "sec_do_not_echo",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("profile"));
        assert!(!err.to_string().contains("sec_do_not_echo"));

        let err = parse_args(
            [
                "run",
                "--profile",
                "profile.canary",
                "--permit",
                "use_abc123",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--"));
        assert!(!err.to_string().contains("do-not-echo-me"));

        let err = parse_args(
            [
                "run",
                "--profile",
                "profile.canary",
                "--permit",
                "not-a-permit",
                "--",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--permit"));
        assert!(!err.to_string().contains("not-a-permit"));
    }

    fn toml_string(value: &str) -> String {
        format!("{value:?}")
    }

    fn toml_string_array(values: &[String]) -> String {
        format!(
            "[{}]",
            values
                .iter()
                .map(|value| toml_string(value))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn managed_profile_toml(secret_ref: &SecretRef, allowed_args: &[String]) -> String {
        format!(
            r#"
                [[profiles]]
                id = "profile.canary"
                secret_ref = {}
                executor = "janus-run@fixture"
                destination = "fixture-destination"
                env = "GITHUB_TOKEN"
                binary = "/bin/sh"
                allowed_args = {}
                timeout_seconds = 30
                max_stdout_bytes = 65536
                max_stderr_bytes = 65536

                [profiles.consumer]
                consumer_ref = "consumer.fixture_run"
                kind = "managed_command"
                owner = "janusd-test"
                environment = "test"
                reload = "none"
                validation = ["fixture-run"]
                supports_dual_value = false
                blast_radius = "fixture"
            "#,
            toml_string(secret_ref.as_str()),
            toml_string_array(allowed_args),
        )
    }

    #[test]
    fn managed_profile_manifest_parses_reviewed_command_contract() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let allowed_args = vec!["release".to_string(), "upload".to_string()];
        let catalog =
            ManagedCommandProfileCatalog::parse(&managed_profile_toml(&secret_ref, &allowed_args))
                .unwrap();
        let profile = catalog
            .profile(&ProfileId::new("profile.canary").unwrap())
            .unwrap();

        assert_eq!(profile.secret_ref(), &secret_ref);
        assert_eq!(profile.executor().as_str(), "janus-run@fixture");
        assert_eq!(profile.destination().as_str(), "fixture-destination");
        assert_eq!(profile.env_name().as_str(), "GITHUB_TOKEN");
        assert_eq!(profile.binary(), &PathBuf::from("/bin/sh"));
        assert_eq!(profile.allowed_args(), allowed_args.as_slice());
        assert_eq!(profile.consumer_ref().as_str(), "consumer.fixture_run");
        assert_eq!(profile.runtime_limits().timeout, Duration::from_secs(30));
        assert_eq!(profile.runtime_limits().max_stdout_bytes, 65536);
        assert_eq!(profile.runtime_limits().max_stderr_bytes, 65536);
    }

    #[test]
    fn approve_issue_builds_exact_grant_from_profile_and_metadata() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let profiles = ManagedCommandProfileCatalog::parse(&managed_profile_toml(
            &secret_ref,
            &["release".to_string(), "upload".to_string()],
        ))
        .unwrap();
        let descriptors = vec![SecretDescriptor {
            name: SecretName::new("CANARY").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::BreakGlass),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id.clone()],
            present: true,
        }];
        let config = ApproveIssueConfig {
            secret_ref: secret_ref.clone(),
            profile_id: profile_id.clone(),
            purpose: Purpose::new("emergency deploy").unwrap(),
            reason: SafeLabel::new("approved fixture").unwrap(),
            egress: EgressMode::ProxyEnforced,
            expires_in: Duration::from_secs(120),
        };

        let approval =
            build_approval_grant(&config, &profiles, &descriptors, SystemTime::UNIX_EPOCH).unwrap();
        let snapshot = approval.snapshot();

        assert!(snapshot.approval_id.starts_with("appr_"));
        assert_eq!(snapshot.secret_ref, secret_ref.as_str());
        assert_eq!(snapshot.profile_id, profile_id.as_str());
        assert_eq!(snapshot.executor, "janus-run@fixture");
        assert_eq!(snapshot.destination, "fixture-destination");
        assert_eq!(snapshot.class, "break_glass");
        assert_eq!(snapshot.egress, "proxy_enforced");
        assert_eq!(snapshot.purpose, "emergency deploy");
        assert_eq!(snapshot.expires_at_unix_secs, 120);
        assert_eq!(snapshot.reason, "approved fixture");
        assert!(!format!("{approval:?}").contains(&snapshot.approval_id));
    }

    #[cfg(unix)]
    #[test]
    fn approve_permit_ttl_is_limited_by_approval_and_class() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let approval = fixture_approval(
            &secret_ref,
            &profile_id,
            SecretClass::BreakGlass,
            EgressMode::Connector,
            SystemTime::UNIX_EPOCH + Duration::from_secs(120),
        );

        assert_eq!(
            permit_ttl_for_approval(
                &approval,
                None,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .unwrap(),
            Duration::from_secs(60)
        );

        let err = permit_ttl_for_approval(
            &approval,
            Some(Duration::from_secs(61)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("class limit"));

        let err = permit_ttl_for_approval(
            &approval,
            Some(Duration::from_secs(120)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("remaining lifetime"));

        let err = permit_ttl_for_approval(
            &approval,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(120),
        )
        .unwrap_err();
        assert!(err.to_string().contains("approval_expired"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn approve_permit_issues_registry_permit_from_stored_approval_and_revokes() {
        let approval_dir = tempfile::tempdir().unwrap();
        let permit_dir = tempfile::tempdir().unwrap();
        let approvals = FileApprovalRegistry::new(approval_dir.path());
        let permits = FilePermitRegistry::new(permit_dir.path());
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let approval = fixture_approval(
            &secret_ref,
            &profile_id,
            SecretClass::BreakGlass,
            EgressMode::Connector,
            SystemTime::UNIX_EPOCH + Duration::from_secs(120),
        );
        SharedApprovalRegistry::store(&approvals, &approval).unwrap();

        let outcome = issue_approved_permit_with(
            &ApprovePermitConfig {
                approval: ApprovalToken::new(approval.id().as_str()).unwrap(),
                permit_ttl: Some(Duration::from_secs(30)),
                revoke_approval: true,
            },
            &approvals,
            &permits,
            fixture_store_with_class(&secret_ref, &name, &profile_id, SecretClass::BreakGlass),
            &fixture_principal(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(outcome.approval_id, approval.id().as_str());
        assert_eq!(outcome.secret_ref, secret_ref.as_str());
        assert_eq!(outcome.profile_id, profile_id.as_str());
        assert_eq!(outcome.executor, "janus-run@fixture");
        assert_eq!(outcome.destination, "fixture-destination");
        assert!(outcome.approval_revoked);
        assert!(!outcome.value_returned);

        let permit = SharedPermitRegistry::take(&permits, &outcome.permit_id).unwrap();
        assert_eq!(permit.secret_ref(), &secret_ref);
        assert_eq!(permit.profile_id(), &profile_id);
        assert_eq!(permit.executor().as_str(), "janus-run@fixture");
        assert_eq!(permit.destination().as_str(), "fixture-destination");
        assert_eq!(
            permit.remaining_ttl_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            Duration::from_secs(30)
        );
        assert!(permit.approval().is_some());

        let err = SharedApprovalRegistry::get(&approvals, approval.id().as_str()).unwrap_err();
        assert!(matches!(
            err,
            JanusError::ApprovalInvalid {
                reason_code: "denied_unknown_approval",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn approve_permit_rejects_approval_when_policy_does_not_need_it() {
        let approval_dir = tempfile::tempdir().unwrap();
        let permit_dir = tempfile::tempdir().unwrap();
        let approvals = FileApprovalRegistry::new(approval_dir.path());
        let permits = FilePermitRegistry::new(permit_dir.path());
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let approval = fixture_approval(
            &secret_ref,
            &profile_id,
            SecretClass::HighValue,
            EgressMode::Connector,
            SystemTime::UNIX_EPOCH + Duration::from_secs(120),
        );
        SharedApprovalRegistry::store(&approvals, &approval).unwrap();

        let err = issue_approved_permit_with(
            &ApprovePermitConfig {
                approval: ApprovalToken::new(approval.id().as_str()).unwrap(),
                permit_ttl: Some(Duration::from_secs(30)),
                revoke_approval: true,
            },
            &approvals,
            &permits,
            fixture_store_with_class(&secret_ref, &name, &profile_id, SecretClass::HighValue),
            &fixture_principal(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        let err = err.downcast_ref::<JanusError>().unwrap();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_not_required",
                ..
            }
        ));
        assert!(SharedApprovalRegistry::get(&approvals, approval.id().as_str()).is_ok());
        assert_eq!(std::fs::read_dir(permit_dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn managed_profile_manifest_rejects_unknown_fields_and_duplicates() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let allowed_args = vec!["release".to_string(), "upload".to_string()];
        let mut with_unknown = managed_profile_toml(&secret_ref, &allowed_args);
        with_unknown.push_str("\nunreviewed = true\n");
        let err = ManagedCommandProfileCatalog::parse(&with_unknown).unwrap_err();
        assert!(err.to_string().contains("parse"));

        let duplicate = format!(
            "{}\n{}",
            managed_profile_toml(&secret_ref, &allowed_args),
            managed_profile_toml(&secret_ref, &allowed_args)
        );
        let err = ManagedCommandProfileCatalog::parse(&duplicate).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[tokio::test]
    async fn profile_manifest_runner_rejects_unreviewed_args_before_permit_lookup() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let allowed_args = vec!["release".to_string(), "upload".to_string()];
        let profiles =
            ManagedCommandProfileCatalog::parse(&managed_profile_toml(&secret_ref, &allowed_args))
                .unwrap();
        let mut runner = ProfileManifestManagedCommandRunner {
            profiles,
            permits: PermitLookupMustNotRun,
            executor: ExecutorMustNotRun,
            principal: fixture_principal(),
            clock: FixedManagedCommandClock(SystemTime::UNIX_EPOCH),
        };
        let err = run_managed_command_with(
            &RunManagedCommandConfig {
                profile_id: ProfileId::new("profile.canary").unwrap(),
                permit: PermitToken::new("use_abc123").unwrap(),
                requested_args: vec!["release".to_string(), "delete".to_string()],
            },
            &mut runner,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("reviewed profile"));
        assert!(!err.to_string().contains("use_abc123"));
    }

    struct PermitLookupMustNotRun;

    impl ManagedCommandPermitRegistry for PermitLookupMustNotRun {
        fn resolve(&self, _token: &PermitToken) -> Result<UsePermit> {
            panic!("permit lookup should not run for unreviewed command arguments")
        }
    }

    struct PermitLookupReached;

    impl ManagedCommandPermitRegistry for PermitLookupReached {
        fn resolve(&self, _token: &PermitToken) -> Result<UsePermit> {
            anyhow::bail!("fixture permit registry reached")
        }
    }

    struct ExecutorMustNotRun;

    #[async_trait]
    impl ManagedCommandExecutor for ExecutorMustNotRun {
        async fn run(
            &mut self,
            _profile: &ManagedCommandProfile,
            _permit: &UsePermit,
            _principal: &PrincipalChain,
            _requested_args: Vec<String>,
            _now: SystemTime,
        ) -> Result<ManagedCommandCliOutcome> {
            panic!("managed command executor should not run")
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FixedManagedCommandClock(SystemTime);

    impl ManagedCommandClock for FixedManagedCommandClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn fixture_principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("janus-run@fixture").unwrap(),
            ),
            ScopeRef::new("janus/dev").unwrap(),
        )
    }

    #[tokio::test]
    async fn profile_manifest_runner_resolves_permit_after_reviewed_args() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let allowed_args = vec!["release".to_string(), "upload".to_string()];
        let profiles =
            ManagedCommandProfileCatalog::parse(&managed_profile_toml(&secret_ref, &allowed_args))
                .unwrap();
        let mut runner = ProfileManifestManagedCommandRunner {
            profiles,
            permits: PermitLookupReached,
            executor: ExecutorMustNotRun,
            principal: fixture_principal(),
            clock: FixedManagedCommandClock(SystemTime::UNIX_EPOCH),
        };
        let err = run_managed_command_with(
            &RunManagedCommandConfig {
                profile_id: ProfileId::new("profile.canary").unwrap(),
                permit: PermitToken::new("use_abc123").unwrap(),
                requested_args: allowed_args,
            },
            &mut runner,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("permit registry reached"));
        assert!(!err.to_string().contains("use_abc123"));
    }

    #[cfg(unix)]
    #[derive(Clone, Debug, Default)]
    struct InMemoryPermitRegistry {
        permits: BTreeMap<String, UsePermit>,
    }

    #[cfg(unix)]
    impl InMemoryPermitRegistry {
        fn insert(&mut self, permit: UsePermit) -> PermitToken {
            let token = PermitToken::new(permit.id().as_str()).unwrap();
            self.permits.insert(token.as_str().to_string(), permit);
            token
        }
    }

    #[cfg(unix)]
    impl ManagedCommandPermitRegistry for InMemoryPermitRegistry {
        fn resolve(&self, token: &PermitToken) -> Result<UsePermit> {
            self.permits
                .get(token.as_str())
                .cloned()
                .context("fixture permit not found")
        }
    }

    #[cfg(unix)]
    type FixtureProfileManifestRunner = ProfileManifestManagedCommandRunner<
        InMemoryPermitRegistry,
        ApprovedUseExecutor<MockStore, AuditWrite>,
        FixedManagedCommandClock,
    >;

    #[cfg(unix)]
    struct FixtureManagedCommandHarness {
        runner: FixtureProfileManifestRunner,
        permit_token: PermitToken,
        profile_id: ProfileId,
        requested_args: Vec<String>,
    }

    #[cfg(unix)]
    impl FixtureManagedCommandHarness {
        async fn new(allowed_args: Vec<String>) -> Self {
            let project = ProjectId::new("janus").unwrap();
            let name = SecretName::new("CANARY").unwrap();
            let secret_ref = SecretRef::for_manifest_entry(&project, &name);
            let profile_id = ProfileId::new("profile.canary").unwrap();
            let executor_ref = ExecutorRef::new("janus-run@fixture").unwrap();
            let destination = Destination::new("fixture-destination").unwrap();
            let catalog = ManifestCatalog::new(vec![SecretMeta {
                secret_ref: secret_ref.clone(),
                name: name.clone(),
                label: SafeLabel::new("Canary token").unwrap(),
                scope: ScopeRef::new("janus/dev").unwrap(),
                owner: Some(OwnerRef::new("infra").unwrap()),
                classification: Some(SecretClass::Normal),
                lifecycle: SecretLifecycle::Active,
                required: true,
                trust_level: TrustLevel::L1,
                allowed_uses: vec![profile_id.clone()],
            }])
            .unwrap();
            let store = MockStore::new(catalog)
                .with_value(name, b"expected-canary".to_vec())
                .unwrap();
            let use_profile = UseProfile {
                id: profile_id.clone(),
                secret_ref: secret_ref.clone(),
                executor: executor_ref.clone(),
                destination: destination.clone(),
                egress: EgressMode::Connector,
                trust_level: TrustLevel::L2,
                ttl: Duration::from_secs(60),
                single_use: true,
                enabled: true,
            };
            let principal = fixture_principal();
            let mut broker = janus_core::SecretBroker::new(
                store,
                janus_core::ProfilePolicy::new(vec![use_profile]),
                AuditWrite::accepting(),
            );
            let permit = broker
                .request_use(
                    &UseRequest {
                        secret_ref: secret_ref.clone(),
                        profile_id: profile_id.clone(),
                        destination: destination.clone(),
                        purpose: Purpose::new("fixture run").unwrap(),
                    },
                    &principal,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .unwrap();
            let profile_catalog = ManagedCommandProfileCatalog::parse(&managed_profile_toml(
                &secret_ref,
                &allowed_args,
            ))
            .unwrap();
            let profile = profile_catalog.profile(&profile_id).unwrap().clone();
            let requested_args = profile.allowed_args().to_vec();
            let mut permits = InMemoryPermitRegistry::default();
            let permit_token = permits.insert(permit);

            Self {
                runner: ProfileManifestManagedCommandRunner {
                    profiles: profile_catalog,
                    permits,
                    executor: ApprovedUseExecutor::new(broker),
                    principal,
                    clock: FixedManagedCommandClock(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                    ),
                },
                permit_token,
                profile_id,
                requested_args,
            }
        }

        fn config(&self) -> RunManagedCommandConfig {
            RunManagedCommandConfig {
                profile_id: self.profile_id.clone(),
                permit: self.permit_token.clone(),
                requested_args: self.requested_args.clone(),
            }
        }

        fn runner_mut(&mut self) -> &mut FixtureProfileManifestRunner {
            &mut self.runner
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_command_fixture_path_calls_executor_and_redacts_output() {
        let mut harness = FixtureManagedCommandHarness::new(vec![
            "-c".to_string(),
            "printf 'stdout:%s' \"$GITHUB_TOKEN\"; printf 'stderr:%s' \"$GITHUB_TOKEN\" >&2"
                .to_string(),
        ])
        .await;
        let config = harness.config();

        let outcome = run_managed_command_with(&config, harness.runner_mut())
            .await
            .unwrap();

        assert_eq!(outcome.stdout, "stdout:[REDACTED]");
        assert_eq!(outcome.stderr, "stderr:[REDACTED]");
        assert!(outcome.exit_success);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.reason_code, "ok");
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn warden_file_registry_handoff_smoke_runs_janusd_command() {
        let permit_dir = tempfile::tempdir().unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let executor_ref = ExecutorRef::new("janus-run@fixture").unwrap();
        let destination = Destination::new("fixture-destination").unwrap();
        let principal = fixture_principal();
        let use_profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            executor: executor_ref,
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let mut warden = janus_warden::WardenRuntime::with_permit_store(
            janus_core::SecretBroker::new(
                fixture_store(&secret_ref, &name, &profile_id),
                janus_core::ProfilePolicy::new(vec![use_profile]),
                AuditWrite::accepting(),
            ),
            FilePermitRegistry::new(permit_dir.path()),
        );
        let permit = warden
            .request_use(
                janus_warden::RequestUseArgs {
                    secret_ref: secret_ref.clone(),
                    profile_id: profile_id.clone(),
                    purpose: Purpose::new("fixture handoff").unwrap(),
                },
                &principal,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();

        let allowed_args = vec![
            "-c".to_string(),
            "printf 'handoff:%s' \"$GITHUB_TOKEN\"".to_string(),
        ];
        let profiles =
            ManagedCommandProfileCatalog::parse(&managed_profile_toml(&secret_ref, &allowed_args))
                .unwrap();
        let mut runner = ProfileManifestManagedCommandRunner {
            profiles,
            permits: FilePermitRegistry::new(permit_dir.path()),
            executor: ApprovedUseExecutor::new(janus_core::SecretBroker::new(
                fixture_store(&secret_ref, &name, &profile_id),
                janus_core::ProfilePolicy::default(),
                AuditWrite::accepting(),
            )),
            principal,
            clock: FixedManagedCommandClock(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        };
        let config = RunManagedCommandConfig {
            profile_id,
            permit: PermitToken::new(permit.permit_id.clone()).unwrap(),
            requested_args: allowed_args,
        };

        let outcome = run_managed_command_with(&config, &mut runner)
            .await
            .unwrap();

        assert_eq!(outcome.stdout, "handoff:[REDACTED]");
        assert_eq!(outcome.stderr, "");
        assert!(outcome.exit_success);
        assert_eq!(outcome.reason_code, "ok");
        assert!(!outcome.value_returned);
        assert!(matches!(
            janus_local::PermitRegistry::take(
                &FilePermitRegistry::new(permit_dir.path()),
                &permit.permit_id,
            ),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_unknown_permit",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_command_fixture_path_rejects_wrong_permit_before_execution() {
        let marker =
            std::env::temp_dir().join(format!("janusd-run-fixture-{}", std::process::id()));
        let mut harness = FixtureManagedCommandHarness::new(vec![
            "-c".to_string(),
            "printf spawned > \"$1\"".to_string(),
            "janusd-fixture".to_string(),
            marker.to_string_lossy().into_owned(),
        ])
        .await;
        let mut config = harness.config();
        config.permit = PermitToken::new("use_wrongfixture").unwrap();

        let err = run_managed_command_with(&config, harness.runner_mut())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("permit"));
        assert!(!marker.exists());
        let _ = std::fs::remove_file(marker);
    }

    #[cfg(unix)]
    fn fixture_store(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
    ) -> MockStore {
        fixture_store_with_class(secret_ref, name, profile_id, SecretClass::Normal)
    }

    #[cfg(unix)]
    fn fixture_store_with_class(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
    ) -> MockStore {
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(class),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id.clone()],
        }])
        .unwrap();
        MockStore::new(catalog)
            .with_value(name.clone(), b"expected-canary".to_vec())
            .unwrap()
    }

    #[cfg(unix)]
    fn fixture_approval(
        secret_ref: &SecretRef,
        profile_id: &ProfileId,
        class: SecretClass,
        egress: EgressMode,
        expires_at: SystemTime,
    ) -> ApprovalGrant {
        let profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("janus-run@fixture").unwrap(),
            destination: Destination::new("fixture-destination").unwrap(),
            egress,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            secret_ref: secret_ref.clone(),
            profile_id: profile_id.clone(),
            destination: Destination::new("fixture-destination").unwrap(),
            purpose: Purpose::new("emergency deploy").unwrap(),
        };
        ApprovalGrant::for_request(
            &request,
            &profile,
            class,
            expires_at,
            SafeLabel::new("fixture approval").unwrap(),
        )
    }

    #[test]
    fn parses_forge_rotate_generated_without_secret_literals() {
        let config = parse_ok(&[
            "forge",
            "rotate-generated",
            "--secret",
            "CANARY",
            "--reason",
            "JANUS-21 planned rotation",
            "--consumer-ref",
            "consumer.deploy",
            "--validation",
            "deploy-smoke",
            "--reload",
            "exec-hook:reload deploy",
            "--hook-manifest",
            "/etc/janus/forge-hooks.toml",
            "--alphabet",
            "hex",
            "--length",
            "32",
        ]);
        assert_eq!(config.secret.as_str(), "CANARY");
        assert_eq!(config.reason.as_str(), "JANUS-21 planned rotation");
        assert_eq!(config.consumer_ref.as_str(), "consumer.deploy");
        assert_eq!(config.validation_probe.as_str(), "deploy-smoke");
        assert_eq!(
            config.reload,
            ReloadMethod::ExecHook {
                hook: SafeLabel::new("reload deploy").unwrap()
            }
        );
        assert_eq!(
            config.hook_manifest,
            Some(PathBuf::from("/etc/janus/forge-hooks.toml"))
        );
        assert_eq!(config.alphabet, GeneratedAlphabet::Hex);
        assert_eq!(config.length, 32);
    }

    #[test]
    fn rejects_literal_replacement_values() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--value",
                "do-not-accept-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(!err.to_string().contains("do-not-accept-me"));
    }

    #[test]
    fn requires_approval_reason_and_rejects_noop_flag() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--reason"));

        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--allow-noop-hooks",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("removed"));
    }

    #[test]
    fn rejects_invalid_generation_policy() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--length",
                "0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("generated_value_length"));
    }

    #[test]
    fn rejects_unknown_literal_arguments_without_echoing_them() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(!err.to_string().contains("do-not-echo-me"));
    }

    #[test]
    fn rejects_unknown_flags_without_echoing_values() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--unknown=do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(!err.to_string().contains("do-not-echo-me"));
    }

    #[test]
    fn parses_hook_manifest_with_reviewed_absolute_commands() {
        let manifest = HookManifest::parse(
            r#"
                [validation."deploy-smoke"]
                program = "/usr/bin/true"
                args = ["--version"]
                timeout_seconds = 5

                [reload.exec_hook."reload deploy"]
                program = "/usr/bin/true"
            "#,
        )
        .unwrap();

        assert!(manifest.validation.contains_key("deploy-smoke"));
        assert!(manifest
            .reload_command(&ReloadMethod::ExecHook {
                hook: SafeLabel::new("reload deploy").unwrap()
            })
            .is_some());
    }

    #[test]
    fn hook_manifest_rejects_relative_programs() {
        let err = HookManifest::parse(
            r#"
                [validation."deploy-smoke"]
                program = "true"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[tokio::test]
    async fn hook_manifest_runs_validation_without_capturing_output() {
        let mut hooks = ManifestRotationHooks {
            manifest: HookManifest::parse(
                r#"
                    [validation."deploy-smoke"]
                    program = "/usr/bin/true"
                "#,
            )
            .unwrap(),
        };

        hooks
            .validate(&ValidationProbe::new("deploy-smoke").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_validation_hook_fails_closed() {
        let mut hooks = ManifestRotationHooks {
            manifest: HookManifest::default(),
        };

        let err = hooks
            .validate(&ValidationProbe::new("deploy-smoke").unwrap())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("validation_hook_missing"));
    }
}

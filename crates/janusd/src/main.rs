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
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use janus_core::{
    ApprovalGrant, AuditAction, AuditEvent, AuditOutcome, AuditSink, AuditWrite, BlastRadius,
    ClassPermitPolicy, ConsumerDescriptor, ConsumerKind, ConsumerRef, ConsumerRegistry,
    Destination, EgressMode, Environment, ExecutorRef, JanusError, LifecycleTransitionPolicy,
    OwnerRef, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy,
    Purpose, ReloadMethod, RotationOutcome, SafeLabel, ScopeRef, SecretAgeEvidence, SecretBroker,
    SecretDescriptor, SecretLifecycle, SecretMeta, SecretMetadataOverlay, SecretName, SecretRef,
    SecretStore, SecretTombstoneRequest, Severity, StaleSecretPolicy, StaleSecretReportRow,
    StaleSecretReporter, TombstonePolicy, TrustLevel, UsePermit, UseProfile, UseRequest,
    ValidationProbe,
};
use janus_executor::{
    ApprovedUseExecutor, EnvFileHashSidecarFormat, EnvFileHashSidecarSpec, EnvFilePlan,
    EnvFileProfile, EnvFileProfileSpec, EnvFileRequest, ManagedCommandPlan, ManagedCommandProfile,
    ManagedCommandProfileSpec, ManagedCommandRequest, ManagedCommandRuntimeLimits,
};
use janus_forge::{
    ConsumerRotationHooks, GeneratedAlphabet, GeneratedRotationBroker, GeneratedValuePolicy,
    RotationApproval,
};
use janus_local::{
    ApprovalRegistry as SharedApprovalRegistry, FileApprovalRegistry,
    FileLifecycleEvidenceRegistry, FilePermitRegistry, FileTombstoneRegistry,
    LifecycleEvidenceRegistry as SharedLifecycleEvidenceRegistry,
    PermitRegistry as SharedPermitRegistry, PermitStore as SharedPermitStore,
    TombstoneRegistry as SharedTombstoneRegistry,
};
use janus_provider_age::AgeSecretStore;
use serde::Deserialize;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 30;
const MAX_APPROVAL_TTL_SECONDS: u64 = 3600;
const DEFAULT_STALE_AFTER_DAYS: u64 = 90;
const DEFAULT_MISSING_EVIDENCE_AFTER_DAYS: u64 = 7;
const METADATA_ENV_KEYS: &[&str] = &[
    "JANUS_AGE_METADATA_FILE",
    "JANUS_WARDEN_AGE_METADATA_FILE",
    "JANUS_METADATA_FILE",
];

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::ForgeRotateGenerated(config) => run_forge_rotate_generated(config).await,
        Command::RunManagedPreflight(config) => run_managed_command_preflight(config).await,
        Command::RunManaged(config) => run_managed_command(config).await,
        Command::EnvFilePreflight(config) => run_env_file_preflight(config).await,
        Command::EnvFile(config) => run_env_file(config).await,
        Command::Approve(command) => run_approve(command).await,
        Command::LifecycleTransition(config) => run_lifecycle_transition(config).await,
        Command::LifecycleStaleReport(config) => run_lifecycle_stale_report(config).await,
        Command::LifecycleDestroyRecord(config) => run_lifecycle_destroy_record(config).await,
        Command::LifecycleDestroyFinalize(config) => run_lifecycle_destroy_finalize(config).await,
        Command::LifecycleDestroyReconcile(config) => run_lifecycle_destroy_reconcile(config).await,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Help,
    ForgeRotateGenerated(ForgeRotateGeneratedConfig),
    RunManagedPreflight(RunManagedPreflightConfig),
    RunManaged(RunManagedCommandConfig),
    EnvFilePreflight(EnvFilePreflightConfig),
    EnvFile(EnvFileConfig),
    Approve(ApproveCommand),
    LifecycleTransition(LifecycleTransitionConfig),
    LifecycleStaleReport(LifecycleStaleReportConfig),
    LifecycleDestroyRecord(LifecycleDestroyRecordConfig),
    LifecycleDestroyFinalize(LifecycleDestroyFinalizeConfig),
    LifecycleDestroyReconcile(LifecycleDestroyReconcileConfig),
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
struct RunManagedPreflightConfig {
    profile_id: ProfileId,
    requested_args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvFileConfig {
    profile_id: ProfileId,
    permit: PermitToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvFilePreflightConfig {
    profile_id: ProfileId,
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
struct LifecycleTransitionConfig {
    secret_ref: SecretRef,
    to: SecretLifecycle,
    reason: SafeLabel,
    metadata_file: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleStaleReportConfig {
    evidence_file: Option<PathBuf>,
    stale_after: Duration,
    missing_evidence_after: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyRecordConfig {
    secret_ref: SecretRef,
    reason: SafeLabel,
    retain_for: Duration,
    metadata_file: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyFinalizeConfig {
    secret_ref: SecretRef,
    metadata_file: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyReconcileConfig {
    metadata_file: Option<PathBuf>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleTransitionCliOutcome {
    secret_ref: String,
    from: &'static str,
    to: &'static str,
    reason_code: &'static str,
    value_returned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyRecordCliOutcome {
    secret_ref: String,
    from: &'static str,
    to: &'static str,
    reason_code: &'static str,
    retain_until_unix_secs: u64,
    value_returned: bool,
    provider_deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyFinalizeCliOutcome {
    secret_ref: String,
    from: &'static str,
    to: &'static str,
    reason_code: &'static str,
    metadata_finalized: bool,
    value_returned: bool,
    provider_deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleDestroyReconcileRow {
    secret_ref: SecretRef,
    metadata_lifecycle: String,
    tombstone_state: &'static str,
    status: &'static str,
    reason_code: &'static str,
    action_required: bool,
    action: &'static str,
    value_returned: bool,
    provider_deleted: bool,
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
    let lifecycle_evidence = FileLifecycleEvidenceRegistry::new(lifecycle_evidence_registry_dir());
    record_rotation_evidence(&outcome, &lifecycle_evidence, SystemTime::now())?;

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
    let lifecycle_evidence = FileLifecycleEvidenceRegistry::new(lifecycle_evidence_registry_dir());
    record_managed_command_evidence(&outcome, &lifecycle_evidence, SystemTime::now())?;
    emit_run_managed_outcome(&outcome);
    Ok(())
}

async fn run_managed_command_preflight(config: RunManagedPreflightConfig) -> Result<()> {
    let manifest_path = run_profile_manifest_path()?;
    let profiles = ManagedCommandProfileCatalog::load(&manifest_path)?;
    let outcome = run_managed_command_preflight_with(&config, &profiles)?;
    emit_run_managed_preflight_outcome(&outcome);
    Ok(())
}

async fn run_env_file(config: EnvFileConfig) -> Result<()> {
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
    let mut runner = ProfileManifestEnvFileRunner {
        profiles,
        permits,
        executor,
        principal,
        clock: SystemManagedCommandClock,
    };
    let outcome = run_env_file_with(&config, &mut runner).await?;
    let lifecycle_evidence = FileLifecycleEvidenceRegistry::new(lifecycle_evidence_registry_dir());
    record_secret_use_evidence(&outcome.secret_ref, &lifecycle_evidence, SystemTime::now())?;
    emit_env_file_outcome(&outcome);
    Ok(())
}

async fn run_env_file_preflight(config: EnvFilePreflightConfig) -> Result<()> {
    let manifest_path = run_profile_manifest_path()?;
    let profiles = ManagedCommandProfileCatalog::load(&manifest_path)?;
    let outcome = run_env_file_preflight_with(&config, &profiles)?;
    emit_env_file_preflight_outcome(&outcome);
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

async fn run_lifecycle_transition(config: LifecycleTransitionConfig) -> Result<()> {
    let metadata_file =
        lifecycle_metadata_file_path(config.metadata_file.as_deref(), METADATA_ENV_KEYS)?;
    let store = load_age_store_from_env_with_metadata_path(Some(&metadata_file))?;
    let principal = lifecycle_principal_from_env()?;
    let mut audit = AuditWrite::accepting();
    let outcome =
        apply_lifecycle_transition_with(&config, &metadata_file, store, &principal, &mut audit)
            .await?;
    emit_lifecycle_transition_outcome(&outcome);
    Ok(())
}

async fn run_lifecycle_stale_report(config: LifecycleStaleReportConfig) -> Result<()> {
    let store = load_age_store_from_env()?;
    let principal = lifecycle_principal_from_env()?;
    let registry = FileLifecycleEvidenceRegistry::new(lifecycle_evidence_registry_dir());
    let evidence = load_stale_evidence_sources(&registry, config.evidence_file.as_deref())?;
    let mut audit = AuditWrite::accepting();
    let rows = build_lifecycle_stale_report_with(
        &config,
        store,
        &evidence,
        &principal,
        &mut audit,
        SystemTime::now(),
    )
    .await?;
    emit_lifecycle_stale_report(&rows);
    Ok(())
}

async fn run_lifecycle_destroy_record(config: LifecycleDestroyRecordConfig) -> Result<()> {
    let store = load_age_store_from_env_with_metadata_path(config.metadata_file.as_deref())?;
    let principal = lifecycle_principal_from_env()?;
    let registry = FileTombstoneRegistry::new(lifecycle_tombstone_registry_dir());
    let mut audit = AuditWrite::accepting();
    let outcome = record_lifecycle_destroy_with(
        &config,
        store,
        &registry,
        &principal,
        &mut audit,
        SystemTime::now(),
    )
    .await?;
    emit_lifecycle_destroy_record_outcome(&outcome);
    Ok(())
}

async fn run_lifecycle_destroy_finalize(config: LifecycleDestroyFinalizeConfig) -> Result<()> {
    let metadata_file =
        lifecycle_metadata_file_path(config.metadata_file.as_deref(), METADATA_ENV_KEYS)?;
    let store = load_age_store_from_env_with_metadata_path(Some(&metadata_file))?;
    let principal = lifecycle_principal_from_env()?;
    let registry = FileTombstoneRegistry::new(lifecycle_tombstone_registry_dir());
    let mut audit = AuditWrite::accepting();
    let outcome = finalize_lifecycle_destroy_with(
        &config,
        &metadata_file,
        store,
        &registry,
        &principal,
        &mut audit,
    )
    .await?;
    emit_lifecycle_destroy_finalize_outcome(&outcome);
    Ok(())
}

async fn run_lifecycle_destroy_reconcile(config: LifecycleDestroyReconcileConfig) -> Result<()> {
    let store = load_age_store_from_env_with_metadata_path(config.metadata_file.as_deref())?;
    let principal = lifecycle_principal_from_env()?;
    let registry = FileTombstoneRegistry::new(lifecycle_tombstone_registry_dir());
    let mut audit = AuditWrite::accepting();
    let rows =
        build_lifecycle_destroy_reconcile_with(store, &registry, &principal, &mut audit).await?;
    emit_lifecycle_destroy_reconcile_report(&rows);
    Ok(())
}

async fn build_lifecycle_stale_report_with<S, A>(
    config: &LifecycleStaleReportConfig,
    store: S,
    evidence: &BTreeMap<SecretRef, SecretAgeEvidence>,
    principal: &PrincipalChain,
    audit: &mut A,
    now: SystemTime,
) -> Result<Vec<StaleSecretReportRow>>
where
    S: SecretStore,
    A: AuditSink,
{
    let descriptors = store
        .list()
        .await
        .context("failed to list descriptors for lifecycle stale report")?;
    let policy = StaleSecretPolicy::new(config.stale_after, config.missing_evidence_after);
    StaleSecretReporter::new(policy)
        .report(&descriptors, evidence, now, principal, audit)
        .map_err(Into::into)
}

async fn record_lifecycle_destroy_with<S, R, A>(
    config: &LifecycleDestroyRecordConfig,
    store: S,
    registry: &R,
    principal: &PrincipalChain,
    audit: &mut A,
    now: SystemTime,
) -> Result<LifecycleDestroyRecordCliOutcome>
where
    S: SecretStore,
    R: SharedTombstoneRegistry,
    A: AuditSink,
{
    let descriptors = store
        .list()
        .await
        .context("failed to list descriptors for lifecycle destroy-record")?;
    let descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.secret_ref == config.secret_ref)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret_ref.as_str().to_string(),
        })?;
    let retain_until = now
        .checked_add(config.retain_for)
        .context("destroy-record retention window is too large")?;
    let request = SecretTombstoneRequest::new(
        config.secret_ref.clone(),
        config.reason.clone(),
        now,
        retain_until,
    );
    let tombstone = TombstonePolicy::record(descriptor, request, principal, audit)?;
    SharedTombstoneRegistry::record(registry, &tombstone, principal)?;

    Ok(LifecycleDestroyRecordCliOutcome {
        secret_ref: tombstone.secret_ref().as_str().to_string(),
        from: tombstone.from().as_str(),
        to: tombstone.to().as_str(),
        reason_code: "tombstone_recorded",
        retain_until_unix_secs: unix_seconds(tombstone.retain_until()),
        value_returned: false,
        provider_deleted: false,
    })
}

async fn build_lifecycle_destroy_reconcile_with<S, R, A>(
    store: S,
    registry: &R,
    principal: &PrincipalChain,
    audit: &mut A,
) -> Result<Vec<LifecycleDestroyReconcileRow>>
where
    S: SecretStore,
    R: SharedTombstoneRegistry,
    A: AuditSink,
{
    let descriptors = store
        .list()
        .await
        .context("failed to list descriptors for lifecycle destroy-reconcile")?;
    let tombstones = registry
        .list()
        .context("failed to list destroy tombstones for reconcile report")?;
    let descriptor_by_ref = descriptors
        .iter()
        .map(|descriptor| (descriptor.secret_ref.clone(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let tombstone_by_ref = tombstones
        .iter()
        .map(|tombstone| (tombstone.secret_ref.clone(), tombstone))
        .collect::<BTreeMap<_, _>>();

    let mut rows = Vec::new();
    for descriptor in &descriptors {
        let tombstone = tombstone_by_ref.get(&descriptor.secret_ref);
        if let Some(row) = reconcile_descriptor_tombstone(descriptor, tombstone.is_some()) {
            audit_destroy_reconcile_row(&row, principal, audit)?;
            rows.push(row);
        }
    }
    for tombstone in &tombstones {
        if !descriptor_by_ref.contains_key(&tombstone.secret_ref) {
            let row = LifecycleDestroyReconcileRow {
                secret_ref: tombstone.secret_ref.clone(),
                metadata_lifecycle: "missing".to_string(),
                tombstone_state: "present",
                status: "drift",
                reason_code: "destroy_tombstone_metadata_missing",
                action_required: true,
                action: "investigate_orphan_tombstone",
                value_returned: false,
                provider_deleted: false,
            };
            audit_destroy_reconcile_row(&row, principal, audit)?;
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| left.secret_ref.as_str().cmp(right.secret_ref.as_str()));
    Ok(rows)
}

fn reconcile_descriptor_tombstone(
    descriptor: &SecretDescriptor,
    tombstone_present: bool,
) -> Option<LifecycleDestroyReconcileRow> {
    let metadata_lifecycle = descriptor.lifecycle.as_str().to_string();
    let tombstone_state = if tombstone_present {
        "present"
    } else {
        "missing"
    };
    let (status, reason_code, action_required, action) =
        match (descriptor.lifecycle, tombstone_present) {
            (SecretLifecycle::PendingDelete, true) => (
                "needs_finalize",
                "destroy_tombstone_pending_finalize",
                true,
                "run_destroy_finalize",
            ),
            (SecretLifecycle::Destroyed, true) => {
                ("ok", "destroy_tombstone_reconcile_ok", false, "none")
            }
            (SecretLifecycle::Destroyed, false) => (
                "drift",
                "destroyed_missing_tombstone",
                true,
                "restore_tombstone_or_investigate",
            ),
            (lifecycle, true)
                if lifecycle != SecretLifecycle::PendingDelete
                    && lifecycle != SecretLifecycle::Destroyed =>
            {
                (
                    "drift",
                    "destroy_tombstone_lifecycle_mismatch",
                    true,
                    "investigate_destroy_lifecycle",
                )
            }
            _ => return None,
        };

    Some(LifecycleDestroyReconcileRow {
        secret_ref: descriptor.secret_ref.clone(),
        metadata_lifecycle,
        tombstone_state,
        status,
        reason_code,
        action_required,
        action,
        value_returned: false,
        provider_deleted: false,
    })
}

fn audit_destroy_reconcile_row<A>(
    row: &LifecycleDestroyReconcileRow,
    principal: &PrincipalChain,
    audit: &mut A,
) -> Result<()>
where
    A: AuditSink,
{
    let severity = if row.action_required {
        Severity::High
    } else {
        Severity::Notice
    };
    audit.record(AuditEvent::new(
        AuditAction::SecretLifecycle,
        AuditOutcome::Allowed,
        row.reason_code,
        severity,
        Some(row.secret_ref.clone()),
        principal,
    ))?;
    Ok(())
}

async fn finalize_lifecycle_destroy_with<S, R, A>(
    config: &LifecycleDestroyFinalizeConfig,
    metadata_file: &Path,
    store: S,
    registry: &R,
    principal: &PrincipalChain,
    audit: &mut A,
) -> Result<LifecycleDestroyFinalizeCliOutcome>
where
    S: SecretStore,
    R: SharedTombstoneRegistry,
    A: AuditSink,
{
    let descriptors = store
        .list()
        .await
        .context("failed to list descriptors for lifecycle destroy-finalize")?;
    let descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.secret_ref == config.secret_ref)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret_ref.as_str().to_string(),
        })?;
    let tombstone = SharedTombstoneRegistry::get(registry, &config.secret_ref)
        .context("destroy tombstone is required before metadata finalization")?;

    if descriptor.lifecycle == SecretLifecycle::Destroyed {
        audit.record(
            AuditEvent::new(
                AuditAction::SecretLifecycle,
                AuditOutcome::Allowed,
                "destroy_metadata_already_finalized",
                Severity::Notice,
                Some(config.secret_ref.clone()),
                principal,
            )
            .with_evidence(tombstone.reason.clone()),
        )?;
        return Ok(LifecycleDestroyFinalizeCliOutcome {
            secret_ref: config.secret_ref.as_str().to_string(),
            from: SecretLifecycle::Destroyed.as_str(),
            to: SecretLifecycle::Destroyed.as_str(),
            reason_code: "destroy_metadata_already_finalized",
            metadata_finalized: false,
            value_returned: false,
            provider_deleted: false,
        });
    }

    if descriptor.lifecycle != SecretLifecycle::PendingDelete {
        audit.record(
            AuditEvent::new(
                AuditAction::SecretLifecycle,
                AuditOutcome::Denied,
                "denied_destroy_finalize_requires_pending_delete",
                Severity::High,
                Some(config.secret_ref.clone()),
                principal,
            )
            .with_evidence(tombstone.reason.clone()),
        )?;
        return Err(JanusError::policy_denied(
            "denied_destroy_finalize_requires_pending_delete",
            "destroy metadata finalization requires pending_delete lifecycle",
        )
        .into());
    }

    audit.record(
        AuditEvent::new(
            AuditAction::SecretLifecycle,
            AuditOutcome::Allowed,
            "destroy_metadata_finalized",
            Severity::Critical,
            Some(config.secret_ref.clone()),
            principal,
        )
        .with_evidence(tombstone.reason.clone()),
    )?;

    let mut overlay = SecretMetadataOverlay::load_toml_file(metadata_file)
        .with_context(|| "failed to load lifecycle metadata overlay")?;
    overlay.set_secret_lifecycle(descriptor.name.clone(), SecretLifecycle::Destroyed);
    let mut metadata_entries = descriptors
        .iter()
        .map(secret_meta_from_descriptor)
        .collect::<Vec<_>>();
    overlay
        .apply_to_entries(&mut metadata_entries)
        .context("lifecycle metadata overlay no longer matches manifest")?;
    write_metadata_overlay_atomic(metadata_file, &overlay.to_toml_string()?)?;

    Ok(LifecycleDestroyFinalizeCliOutcome {
        secret_ref: config.secret_ref.as_str().to_string(),
        from: SecretLifecycle::PendingDelete.as_str(),
        to: SecretLifecycle::Destroyed.as_str(),
        reason_code: "destroy_metadata_finalized",
        metadata_finalized: true,
        value_returned: false,
        provider_deleted: false,
    })
}

async fn apply_lifecycle_transition_with<S, A>(
    config: &LifecycleTransitionConfig,
    metadata_file: &Path,
    store: S,
    principal: &PrincipalChain,
    audit: &mut A,
) -> Result<LifecycleTransitionCliOutcome>
where
    S: SecretStore,
    A: AuditSink,
{
    let descriptors = store
        .list()
        .await
        .context("failed to list descriptors for lifecycle transition")?;
    let descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.secret_ref == config.secret_ref)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret_ref.as_str().to_string(),
        })?;
    let transition = LifecycleTransitionPolicy::transition(
        descriptor,
        config.to,
        config.reason.clone(),
        principal,
        audit,
    )?;

    let mut overlay = SecretMetadataOverlay::load_toml_file(metadata_file)
        .with_context(|| "failed to load lifecycle metadata overlay")?;
    overlay.set_secret_lifecycle(descriptor.name.clone(), transition.to());
    let mut metadata_entries = descriptors
        .iter()
        .map(secret_meta_from_descriptor)
        .collect::<Vec<_>>();
    overlay
        .apply_to_entries(&mut metadata_entries)
        .context("lifecycle metadata overlay no longer matches manifest")?;
    write_metadata_overlay_atomic(metadata_file, &overlay.to_toml_string()?)?;

    Ok(LifecycleTransitionCliOutcome {
        secret_ref: transition.secret_ref().as_str().to_string(),
        from: transition.from().as_str(),
        to: transition.to().as_str(),
        reason_code: "lifecycle_transition_ok",
        value_returned: false,
    })
}

fn secret_meta_from_descriptor(descriptor: &SecretDescriptor) -> SecretMeta {
    SecretMeta {
        secret_ref: descriptor.secret_ref.clone(),
        name: descriptor.name.clone(),
        label: descriptor.label.clone(),
        scope: descriptor.scope.clone(),
        owner: descriptor.owner.clone(),
        classification: descriptor.classification,
        lifecycle: descriptor.lifecycle,
        required: descriptor.required,
        trust_level: descriptor.trust_level,
        allowed_uses: descriptor.allowed_uses.clone(),
    }
}

fn emit_lifecycle_transition_outcome(outcome: &LifecycleTransitionCliOutcome) {
    println!(
        "janusd lifecycle transition ok secret_ref={} from={} to={} reason_code={} value_returned={}",
        outcome.secret_ref,
        outcome.from,
        outcome.to,
        outcome.reason_code,
        outcome.value_returned
    );
}

fn emit_lifecycle_stale_report(rows: &[StaleSecretReportRow]) {
    for row in rows {
        let owner = row
            .owner
            .as_ref()
            .map(OwnerRef::as_str)
            .unwrap_or("unassigned");
        let age = row
            .last_activity_age_seconds
            .map(|age| age.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "janusd lifecycle stale-report secret_ref={} status={} reason_code={} action_required={} action={} owner={} lifecycle={} age_seconds={} value_returned={}",
            row.secret_ref.as_str(),
            row.status.as_str(),
            row.reason_code,
            row.action_required,
            row.action,
            owner,
            row.lifecycle.as_str(),
            age,
            row.value_returned
        );
    }
}

fn emit_lifecycle_destroy_record_outcome(outcome: &LifecycleDestroyRecordCliOutcome) {
    println!(
        "janusd lifecycle destroy-record ok secret_ref={} from={} to={} reason_code={} retain_until_unix_secs={} value_returned={} provider_deleted={}",
        outcome.secret_ref,
        outcome.from,
        outcome.to,
        outcome.reason_code,
        outcome.retain_until_unix_secs,
        outcome.value_returned,
        outcome.provider_deleted
    );
}

fn emit_lifecycle_destroy_finalize_outcome(outcome: &LifecycleDestroyFinalizeCliOutcome) {
    println!(
        "janusd lifecycle destroy-finalize ok secret_ref={} from={} to={} reason_code={} metadata_finalized={} value_returned={} provider_deleted={}",
        outcome.secret_ref,
        outcome.from,
        outcome.to,
        outcome.reason_code,
        outcome.metadata_finalized,
        outcome.value_returned,
        outcome.provider_deleted
    );
}

fn emit_lifecycle_destroy_reconcile_report(rows: &[LifecycleDestroyReconcileRow]) {
    for row in rows {
        println!(
            "janusd lifecycle destroy-reconcile secret_ref={} status={} reason_code={} action_required={} action={} metadata_lifecycle={} tombstone={} value_returned={} provider_deleted={}",
            row.secret_ref.as_str(),
            row.status,
            row.reason_code,
            row.action_required,
            row.action,
            row.metadata_lifecycle,
            row.tombstone_state,
            row.value_returned,
            row.provider_deleted
        );
    }
}

fn record_managed_command_evidence<R>(
    outcome: &ManagedCommandCliOutcome,
    registry: &R,
    at: SystemTime,
) -> Result<()>
where
    R: SharedLifecycleEvidenceRegistry,
{
    record_secret_use_evidence(&outcome.secret_ref, registry, at)
}

fn record_secret_use_evidence<R>(secret_ref: &SecretRef, registry: &R, at: SystemTime) -> Result<()>
where
    R: SharedLifecycleEvidenceRegistry,
{
    registry.record_used(secret_ref, at)?;
    Ok(())
}

fn record_rotation_evidence<R>(
    outcome: &RotationOutcome,
    registry: &R,
    at: SystemTime,
) -> Result<()>
where
    R: SharedLifecycleEvidenceRegistry,
{
    registry.record_rotated(&outcome.secret_ref, at)?;
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
        .profile_binding(&config.profile_id)
        .context("approved-use profile not found")?;
    if profile.secret_ref != config.secret_ref {
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
        id: config.profile_id.clone(),
        secret_ref: profile.secret_ref.clone(),
        executor: profile.executor.clone(),
        destination: profile.destination.clone(),
        egress: config.egress,
        trust_level: TrustLevel::L2,
        ttl: config.expires_in,
        single_use: true,
        enabled: true,
    };
    let request = UseRequest {
        secret_ref: config.secret_ref.clone(),
        profile_id: config.profile_id.clone(),
        destination: profile.destination.clone(),
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

fn run_managed_command_preflight_with(
    config: &RunManagedPreflightConfig,
    profiles: &ManagedCommandProfileCatalog,
) -> Result<ManagedCommandPlan> {
    let profile = profiles
        .profile(&config.profile_id)
        .context("managed command profile not found")?;
    Ok(profile.preflight_command(&config.requested_args)?)
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

async fn run_env_file_with<R>(config: &EnvFileConfig, runner: &mut R) -> Result<EnvFileCliOutcome>
where
    R: EnvFileRunner + Send,
{
    runner.run(config).await
}

fn run_env_file_preflight_with(
    config: &EnvFilePreflightConfig,
    profiles: &ManagedCommandProfileCatalog,
) -> Result<EnvFileCliOutcome> {
    let profile = profiles
        .env_file_profile(&config.profile_id)
        .context("env-file profile not found")?;
    Ok(EnvFileCliOutcome::from_plan(
        profile.preflight_target()?,
        "ok",
    ))
}

#[async_trait]
trait EnvFileRunner {
    async fn run(&mut self, config: &EnvFileConfig) -> Result<EnvFileCliOutcome>;
}

#[async_trait]
trait EnvFileExecutor {
    async fn render(
        &mut self,
        profile: &EnvFileProfile,
        permit: &UsePermit,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> Result<EnvFileCliOutcome>;
}

#[async_trait]
impl<S, A> EnvFileExecutor for ApprovedUseExecutor<S, A>
where
    S: SecretStore + Send,
    A: AuditSink + Send,
{
    async fn render(
        &mut self,
        profile: &EnvFileProfile,
        permit: &UsePermit,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> Result<EnvFileCliOutcome> {
        let outcome = self
            .render_env_file(EnvFileRequest {
                profile,
                permit,
                principal,
                now,
            })
            .await?;
        Ok(outcome.into())
    }
}

struct ProfileManifestEnvFileRunner<R, E, C = SystemManagedCommandClock> {
    profiles: ManagedCommandProfileCatalog,
    permits: R,
    executor: E,
    principal: PrincipalChain,
    clock: C,
}

#[async_trait]
impl<R, E, C> EnvFileRunner for ProfileManifestEnvFileRunner<R, E, C>
where
    R: ManagedCommandPermitRegistry + Send,
    E: EnvFileExecutor + Send,
    C: ManagedCommandClock + Send,
{
    async fn run(&mut self, config: &EnvFileConfig) -> Result<EnvFileCliOutcome> {
        let profile = self
            .profiles
            .env_file_profile(&config.profile_id)
            .context("env-file profile not found")?;
        let permit = self.permits.resolve(&config.permit)?;
        self.executor
            .render(profile, &permit, &self.principal, self.clock.now())
            .await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedCommandCliOutcome {
    secret_ref: SecretRef,
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
            secret_ref: outcome.plan.secret_ref,
            stdout: outcome.output.stdout,
            stderr: outcome.output.stderr,
            exit_success: outcome.output.exit_success,
            exit_code: outcome.output.exit_code,
            reason_code: outcome.output.reason_code,
            value_returned: outcome.value_returned || outcome.output.value_returned,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvFileCliOutcome {
    secret_ref: SecretRef,
    profile_id: ProfileId,
    output_path: PathBuf,
    hash_output_path: Option<PathBuf>,
    hash_format: Option<&'static str>,
    consumer_ref: ConsumerRef,
    reason_code: &'static str,
    value_returned: bool,
}

impl From<janus_executor::EnvFileOutcome> for EnvFileCliOutcome {
    fn from(outcome: janus_executor::EnvFileOutcome) -> Self {
        let value_returned = outcome.value_returned || outcome.plan.value_returned;
        Self::from_plan(outcome.plan, outcome.reason_code).with_value_returned(value_returned)
    }
}

impl EnvFileCliOutcome {
    fn from_plan(plan: EnvFilePlan, reason_code: &'static str) -> Self {
        Self {
            secret_ref: plan.secret_ref,
            profile_id: plan.profile_id,
            output_path: plan.output_path,
            hash_output_path: plan
                .hash_sidecar
                .as_ref()
                .map(|sidecar| sidecar.output_path.clone()),
            hash_format: plan
                .hash_sidecar
                .as_ref()
                .map(|sidecar| sidecar.format.as_str()),
            consumer_ref: plan.consumer_ref,
            reason_code,
            value_returned: plan.value_returned,
        }
    }

    fn with_value_returned(mut self, value_returned: bool) -> Self {
        self.value_returned = value_returned;
        self
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

fn emit_run_managed_preflight_outcome(outcome: &ManagedCommandPlan) {
    println!(
        "janusd run preflight ok secret_ref={} profile_id={} executor={} destination={} binary={} args_count={} timeout_seconds={} max_stdout_bytes={} max_stderr_bytes={} consumer_ref={} reason_code=ok value_returned={}",
        outcome.secret_ref.as_str(),
        outcome.profile_id.as_str(),
        outcome.executor.as_str(),
        outcome.destination.as_str(),
        outcome.binary.display(),
        outcome.args.len(),
        outcome.runtime_limits.timeout.as_secs(),
        outcome.runtime_limits.max_stdout_bytes,
        outcome.runtime_limits.max_stderr_bytes,
        outcome.consumer_ref.as_str(),
        outcome.value_returned
    );
}

fn emit_env_file_outcome(outcome: &EnvFileCliOutcome) {
    println!(
        "janusd env-file ok secret_ref={} profile_id={} output_path={} hash_output_path={} hash_format={} consumer_ref={} reason_code={} value_returned={}",
        outcome.secret_ref.as_str(),
        outcome.profile_id.as_str(),
        outcome.output_path.display(),
        optional_path(outcome.hash_output_path.as_deref()),
        outcome.hash_format.unwrap_or("none"),
        outcome.consumer_ref.as_str(),
        outcome.reason_code,
        outcome.value_returned
    );
}

fn emit_env_file_preflight_outcome(outcome: &EnvFileCliOutcome) {
    println!(
        "janusd env-file preflight ok secret_ref={} profile_id={} output_path={} hash_output_path={} hash_format={} consumer_ref={} reason_code={} value_returned={}",
        outcome.secret_ref.as_str(),
        outcome.profile_id.as_str(),
        outcome.output_path.display(),
        optional_path(outcome.hash_output_path.as_deref()),
        outcome.hash_format.unwrap_or("none"),
        outcome.consumer_ref.as_str(),
        outcome.reason_code,
        outcome.value_returned
    );
}

fn optional_path(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string())
}

#[derive(Clone, Debug)]
struct ManagedCommandProfileCatalog {
    profiles: Vec<ManagedCommandProfile>,
    env_file_profiles: Vec<EnvFileProfile>,
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
                anyhow::bail!("duplicate approved-use profile id");
            }
            profiles.push(profile);
        }
        let mut env_file_profiles = Vec::new();
        for profile in parsed.env_files {
            let profile = profile.into_profile()?;
            if !ids.insert(profile.profile_id().as_str().to_string()) {
                anyhow::bail!("duplicate approved-use profile id");
            }
            env_file_profiles.push(profile);
        }
        if profiles.is_empty() && env_file_profiles.is_empty() {
            anyhow::bail!("approved-use profile manifest has no profiles");
        }
        Ok(Self {
            profiles,
            env_file_profiles,
        })
    }

    fn profile(&self, profile_id: &ProfileId) -> Option<&ManagedCommandProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.profile_id() == profile_id)
    }

    fn env_file_profile(&self, profile_id: &ProfileId) -> Option<&EnvFileProfile> {
        self.env_file_profiles
            .iter()
            .find(|profile| profile.profile_id() == profile_id)
    }

    fn profile_binding(&self, profile_id: &ProfileId) -> Option<ApprovedUseProfileBinding> {
        if let Some(profile) = self.profile(profile_id) {
            return Some(ApprovedUseProfileBinding {
                secret_ref: profile.secret_ref().clone(),
                executor: profile.executor().clone(),
                destination: profile.destination().clone(),
            });
        }
        self.env_file_profile(profile_id)
            .map(|profile| ApprovedUseProfileBinding {
                secret_ref: profile.secret_ref().clone(),
                executor: profile.executor().clone(),
                destination: profile.destination().clone(),
            })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedCommandProfileCatalogToml {
    #[serde(default)]
    profiles: Vec<ManagedCommandProfileToml>,
    #[serde(default)]
    env_files: Vec<EnvFileProfileToml>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApprovedUseProfileBinding {
    secret_ref: SecretRef,
    executor: ExecutorRef,
    destination: Destination,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnvFileProfileToml {
    id: String,
    secret_ref: String,
    executor: String,
    destination: String,
    env: String,
    output: PathBuf,
    hash_sidecar: Option<EnvFileHashSidecarToml>,
    consumer: EnvFileConsumerToml,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnvFileHashSidecarToml {
    format: String,
    subject: String,
    output: PathBuf,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnvFileConsumerToml {
    consumer_ref: String,
    #[serde(default = "default_env_file_kind")]
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

impl EnvFileProfileToml {
    fn into_profile(self) -> Result<EnvFileProfile> {
        let secret_ref = SecretRef::new(self.secret_ref)?;
        let consumer = ConsumerDescriptor {
            consumer_ref: ConsumerRef::new(self.consumer.consumer_ref)?,
            secret_ref: secret_ref.clone(),
            kind: parse_env_file_consumer_kind(&self.consumer.kind)?,
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
        Ok(EnvFileProfile::new(EnvFileProfileSpec {
            profile_id: ProfileId::new(self.id)?,
            secret_ref,
            executor: ExecutorRef::new(self.executor)?,
            destination: Destination::new(self.destination)?,
            env_name: SafeLabel::new(self.env)?,
            output_path: self.output,
            hash_sidecar: self
                .hash_sidecar
                .map(|sidecar| -> Result<EnvFileHashSidecarSpec> {
                    Ok(EnvFileHashSidecarSpec {
                        format: parse_env_file_hash_sidecar_format(&sidecar.format)?,
                        subject: SafeLabel::new(sidecar.subject)?,
                        output_path: sidecar.output,
                    })
                })
                .transpose()?,
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

fn default_env_file_kind() -> String {
    "service".to_string()
}

fn default_reload_method() -> String {
    "none".to_string()
}

fn parse_env_file_consumer_kind(value: &str) -> Result<ConsumerKind> {
    match value {
        "service" => Ok(ConsumerKind::Service),
        "ci_job" => Ok(ConsumerKind::CiJob),
        "dev_shell" => Ok(ConsumerKind::DevShell),
        "connector" => Ok(ConsumerKind::Connector),
        "human_workflow" => Ok(ConsumerKind::HumanWorkflow),
        "managed_command" => anyhow::bail!("env-file consumer kind must not be managed_command"),
        _ => anyhow::bail!("unsupported env-file consumer kind"),
    }
}

fn parse_env_file_hash_sidecar_format(value: &str) -> Result<EnvFileHashSidecarFormat> {
    match value {
        "pharos-beacon-token-hashes-v1" => Ok(EnvFileHashSidecarFormat::PharosBeaconTokenHashesV1),
        _ => anyhow::bail!("unsupported env-file hash sidecar format"),
    }
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
        [run, preflight, rest @ ..] if run == "run" && preflight == "preflight" => {
            parse_run_managed_preflight(rest.iter().cloned()).map(Command::RunManagedPreflight)
        }
        [run, rest @ ..] if run == "run" => {
            parse_run_managed(rest.iter().cloned()).map(Command::RunManaged)
        }
        [env_file, preflight, rest @ ..] if env_file == "env-file" && preflight == "preflight" => {
            parse_env_file_preflight(rest.iter().cloned()).map(Command::EnvFilePreflight)
        }
        [env_file, rest @ ..] if env_file == "env-file" => {
            parse_env_file(rest.iter().cloned()).map(Command::EnvFile)
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
        [lifecycle, transition, rest @ ..]
            if lifecycle == "lifecycle" && transition == "transition" =>
        {
            parse_lifecycle_transition(rest.iter().cloned()).map(Command::LifecycleTransition)
        }
        [lifecycle, stale_report, rest @ ..]
            if lifecycle == "lifecycle" && stale_report == "stale-report" =>
        {
            parse_lifecycle_stale_report(rest.iter().cloned()).map(Command::LifecycleStaleReport)
        }
        [lifecycle, destroy_record, rest @ ..]
            if lifecycle == "lifecycle" && destroy_record == "destroy-record" =>
        {
            parse_lifecycle_destroy_record(rest.iter().cloned())
                .map(Command::LifecycleDestroyRecord)
        }
        [lifecycle, destroy_finalize, rest @ ..]
            if lifecycle == "lifecycle" && destroy_finalize == "destroy-finalize" =>
        {
            parse_lifecycle_destroy_finalize(rest.iter().cloned())
                .map(Command::LifecycleDestroyFinalize)
        }
        [lifecycle, destroy_reconcile, rest @ ..]
            if lifecycle == "lifecycle" && destroy_reconcile == "destroy-reconcile" =>
        {
            parse_lifecycle_destroy_reconcile(rest.iter().cloned())
                .map(Command::LifecycleDestroyReconcile)
        }
        _ => anyhow::bail!("unsupported janusd command; run `janusd --help`"),
    }
}

fn parse_lifecycle_transition(
    args: impl IntoIterator<Item = String>,
) -> Result<LifecycleTransitionConfig> {
    let mut secret_ref = None;
    let mut to = None;
    let mut reason = None;
    let mut metadata_file = None;
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
            "--to" => {
                if to
                    .replace(SecretLifecycle::parse(&required_arg("--to", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--to may only be provided once");
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
            "--metadata-file" => {
                if metadata_file
                    .replace(PathBuf::from(required_arg("--metadata-file", args.next())?))
                    .is_some()
                {
                    anyhow::bail!("--metadata-file may only be provided once");
                }
            }
            "--secret" | "--name" | "--value" | "--raw-value" | "--owner" | "--classification" => {
                anyhow::bail!("lifecycle transition accepts only value-free lifecycle fields")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd lifecycle flag"),
            _ => anyhow::bail!("unsupported janusd lifecycle argument"),
        }
    }

    Ok(LifecycleTransitionConfig {
        secret_ref: secret_ref.context("--secret-ref is required")?,
        to: to.context("--to is required")?,
        reason: reason.context("--reason is required")?,
        metadata_file,
    })
}

fn parse_lifecycle_stale_report(
    args: impl IntoIterator<Item = String>,
) -> Result<LifecycleStaleReportConfig> {
    let mut evidence_file = None;
    let mut stale_after = Duration::from_secs(DEFAULT_STALE_AFTER_DAYS * 24 * 60 * 60);
    let mut missing_evidence_after =
        Duration::from_secs(DEFAULT_MISSING_EVIDENCE_AFTER_DAYS * 24 * 60 * 60);
    let mut stale_after_set = false;
    let mut missing_evidence_after_set = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--evidence-file" => {
                if evidence_file
                    .replace(PathBuf::from(required_arg("--evidence-file", args.next())?))
                    .is_some()
                {
                    anyhow::bail!("--evidence-file may only be provided once");
                }
            }
            "--stale-after-days" => {
                if stale_after_set {
                    anyhow::bail!("--stale-after-days may only be provided once");
                }
                stale_after = parse_positive_days(
                    "--stale-after-days",
                    &required_arg("--stale-after-days", args.next())?,
                )?;
                stale_after_set = true;
            }
            "--missing-evidence-after-days" => {
                if missing_evidence_after_set {
                    anyhow::bail!("--missing-evidence-after-days may only be provided once");
                }
                missing_evidence_after = parse_positive_days(
                    "--missing-evidence-after-days",
                    &required_arg("--missing-evidence-after-days", args.next())?,
                )?;
                missing_evidence_after_set = true;
            }
            "--secret" | "--secret-ref" | "--name" | "--value" | "--raw-value" => {
                anyhow::bail!("lifecycle stale-report accepts only value-free report controls")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd lifecycle flag"),
            _ => anyhow::bail!("unsupported janusd lifecycle argument"),
        }
    }

    Ok(LifecycleStaleReportConfig {
        evidence_file,
        stale_after,
        missing_evidence_after,
    })
}

fn parse_lifecycle_destroy_record(
    args: impl IntoIterator<Item = String>,
) -> Result<LifecycleDestroyRecordConfig> {
    let mut secret_ref = None;
    let mut reason = None;
    let mut retain_for = None;
    let mut metadata_file = None;
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
            "--reason" => {
                if reason
                    .replace(SafeLabel::new(required_arg("--reason", args.next())?)?)
                    .is_some()
                {
                    anyhow::bail!("--reason may only be provided once");
                }
            }
            "--retain-for-days" => {
                if retain_for
                    .replace(parse_positive_days(
                        "--retain-for-days",
                        &required_arg("--retain-for-days", args.next())?,
                    )?)
                    .is_some()
                {
                    anyhow::bail!("--retain-for-days may only be provided once");
                }
            }
            "--metadata-file" => {
                if metadata_file
                    .replace(PathBuf::from(required_arg("--metadata-file", args.next())?))
                    .is_some()
                {
                    anyhow::bail!("--metadata-file may only be provided once");
                }
            }
            "--secret" | "--name" | "--value" | "--raw-value" | "--to" | "--delete"
            | "--provider-delete" => {
                anyhow::bail!(
                    "lifecycle destroy-record accepts only value-free tombstone evidence fields"
                )
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd lifecycle flag"),
            _ => anyhow::bail!("unsupported janusd lifecycle argument"),
        }
    }

    Ok(LifecycleDestroyRecordConfig {
        secret_ref: secret_ref.context("--secret-ref is required")?,
        reason: reason.context("--reason is required")?,
        retain_for: retain_for.context("--retain-for-days is required")?,
        metadata_file,
    })
}

fn parse_lifecycle_destroy_finalize(
    args: impl IntoIterator<Item = String>,
) -> Result<LifecycleDestroyFinalizeConfig> {
    let mut secret_ref = None;
    let mut metadata_file = None;
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
            "--metadata-file" => {
                if metadata_file
                    .replace(PathBuf::from(required_arg("--metadata-file", args.next())?))
                    .is_some()
                {
                    anyhow::bail!("--metadata-file may only be provided once");
                }
            }
            "--secret" | "--name" | "--value" | "--raw-value" | "--reason" | "--to"
            | "--delete" | "--provider-delete" => {
                anyhow::bail!(
                    "lifecycle destroy-finalize accepts only value-free finalization controls"
                )
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd lifecycle flag"),
            _ => anyhow::bail!("unsupported janusd lifecycle argument"),
        }
    }

    Ok(LifecycleDestroyFinalizeConfig {
        secret_ref: secret_ref.context("--secret-ref is required")?,
        metadata_file,
    })
}

fn parse_lifecycle_destroy_reconcile(
    args: impl IntoIterator<Item = String>,
) -> Result<LifecycleDestroyReconcileConfig> {
    let mut metadata_file = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--metadata-file" => {
                if metadata_file
                    .replace(PathBuf::from(required_arg("--metadata-file", args.next())?))
                    .is_some()
                {
                    anyhow::bail!("--metadata-file may only be provided once");
                }
            }
            "--secret" | "--secret-ref" | "--name" | "--value" | "--raw-value" | "--reason"
            | "--to" | "--delete" | "--provider-delete" => {
                anyhow::bail!("lifecycle destroy-reconcile accepts only value-free report controls")
            }
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd lifecycle flag"),
            _ => anyhow::bail!("unsupported janusd lifecycle argument"),
        }
    }

    Ok(LifecycleDestroyReconcileConfig { metadata_file })
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

fn parse_positive_days(flag: &'static str, value: &str) -> Result<Duration> {
    let days = value
        .parse::<u64>()
        .with_context(|| format!("invalid {flag}"))?;
    if days == 0 {
        anyhow::bail!("{flag} must be greater than zero");
    }
    let seconds = days
        .checked_mul(24 * 60 * 60)
        .with_context(|| format!("{flag} is too large"))?;
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

fn parse_run_managed_preflight(
    args: impl IntoIterator<Item = String>,
) -> Result<RunManagedPreflightConfig> {
    let mut profile_id = None;
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
            "--" => {
                saw_separator = true;
                requested_args.extend(args);
                break;
            }
            "--permit" => anyhow::bail!("run preflight does not accept a permit"),
            "--secret" | "--secret-ref" | "--value" | "--env" | "--binary" | "--destination"
            | "--executor" => {
                anyhow::bail!("run preflight policy fields come from the reviewed profile")
            }
            other if other.starts_with('-') => {
                anyhow::bail!("unsupported janusd run preflight flag")
            }
            _ => anyhow::bail!("janusd run preflight command arguments must follow --"),
        }
    }

    let Some(profile_id) = profile_id else {
        anyhow::bail!("--profile is required");
    };
    if !saw_separator {
        anyhow::bail!("janusd run preflight requires -- before command arguments");
    }

    Ok(RunManagedPreflightConfig {
        profile_id,
        requested_args,
    })
}

fn parse_env_file(args: impl IntoIterator<Item = String>) -> Result<EnvFileConfig> {
    let mut profile_id = None;
    let mut permit = None;
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
            "--secret" | "--secret-ref" | "--value" | "--raw-value" | "--env" | "--output"
            | "--destination" | "--executor" | "--binary" => {
                anyhow::bail!("env-file policy fields come from the reviewed profile")
            }
            "--" => anyhow::bail!("janusd env-file does not accept command arguments"),
            other if other.starts_with('-') => anyhow::bail!("unsupported janusd env-file flag"),
            _ => anyhow::bail!("unsupported janusd env-file argument"),
        }
    }

    Ok(EnvFileConfig {
        profile_id: profile_id.context("--profile is required")?,
        permit: permit.context("--permit is required")?,
    })
}

fn parse_env_file_preflight(
    args: impl IntoIterator<Item = String>,
) -> Result<EnvFilePreflightConfig> {
    let mut profile_id = None;
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
            "--permit" => anyhow::bail!("janusd env-file preflight does not accept permits"),
            "--secret" | "--secret-ref" | "--value" | "--raw-value" | "--env" | "--output"
            | "--destination" | "--executor" | "--binary" => {
                anyhow::bail!("env-file preflight policy fields come from the reviewed profile")
            }
            "--" => anyhow::bail!("janusd env-file preflight does not accept command arguments"),
            other if other.starts_with('-') => {
                anyhow::bail!("unsupported janusd env-file preflight flag")
            }
            _ => anyhow::bail!("unsupported janusd env-file preflight argument"),
        }
    }

    Ok(EnvFilePreflightConfig {
        profile_id: profile_id.context("--profile is required")?,
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

fn lifecycle_evidence_registry_dir() -> PathBuf {
    env_first(&["JANUS_LIFECYCLE_EVIDENCE_DIR", "JANUS_STALE_EVIDENCE_DIR"])
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/janus/lifecycle-evidence"))
}

fn lifecycle_tombstone_registry_dir() -> PathBuf {
    env_first(&["JANUS_LIFECYCLE_TOMBSTONE_DIR", "JANUS_TOMBSTONE_DIR"])
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/janus/tombstones"))
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
    load_age_store_from_env_with_metadata_path(None)
}

fn load_age_store_from_env_with_metadata_path(
    metadata_file: Option<&Path>,
) -> Result<AgeSecretStore> {
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
    let metadata = if let Some(path) = metadata_file {
        Some(
            SecretMetadataOverlay::load_toml_file(path)
                .context("failed to load lifecycle metadata overlay")?,
        )
    } else {
        metadata_overlay_from_env(METADATA_ENV_KEYS)?
    };
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

fn lifecycle_metadata_file_path(
    configured: Option<&Path>,
    env_keys: &[&'static str],
) -> Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_path_buf());
    }
    env_first(env_keys)
        .map(PathBuf::from)
        .context("JANUS_AGE_METADATA_FILE, JANUS_WARDEN_AGE_METADATA_FILE, or JANUS_METADATA_FILE is required for lifecycle transition")
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

fn write_metadata_overlay_atomic(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("failed to create metadata overlay directory")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("metadata overlay path must include a file name")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .context("failed to create temporary metadata overlay")?;
        file.write_all(contents.as_bytes())
            .context("failed to write temporary metadata overlay")?;
        file.write_all(b"\n")
            .context("failed to finish temporary metadata overlay")?;
        file.flush()
            .context("failed to flush temporary metadata overlay")?;
        file.sync_all()
            .context("failed to sync temporary metadata overlay")?;
        fs::rename(&temp_path, path).context("failed to replace metadata overlay atomically")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn load_stale_evidence_sources<R>(
    registry: &R,
    manual_path: Option<&Path>,
) -> Result<BTreeMap<SecretRef, SecretAgeEvidence>>
where
    R: SharedLifecycleEvidenceRegistry,
{
    let mut evidence = BTreeMap::new();
    merge_stale_evidence(&mut evidence, registry.list()?);
    merge_stale_evidence(
        &mut evidence,
        load_stale_evidence(manual_path)?.into_values(),
    );
    Ok(evidence)
}

fn merge_stale_evidence<I>(target: &mut BTreeMap<SecretRef, SecretAgeEvidence>, records: I)
where
    I: IntoIterator<Item = SecretAgeEvidence>,
{
    for record in records {
        target
            .entry(record.secret_ref.clone())
            .and_modify(|existing| merge_stale_evidence_record(existing, &record))
            .or_insert(record);
    }
}

fn merge_stale_evidence_record(existing: &mut SecretAgeEvidence, incoming: &SecretAgeEvidence) {
    existing.declared_at = match (existing.declared_at, incoming.declared_at) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };
    existing.last_used_at = max_optional_time(existing.last_used_at, incoming.last_used_at);
    existing.last_rotated_at =
        max_optional_time(existing.last_rotated_at, incoming.last_rotated_at);
}

fn max_optional_time(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<SystemTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left >= right { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn load_stale_evidence(path: Option<&Path>) -> Result<BTreeMap<SecretRef, SecretAgeEvidence>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let contents = fs::read_to_string(path).context("failed to read lifecycle evidence file")?;
    let parsed: LifecycleStaleEvidenceToml =
        toml::from_str(&contents).context("failed to parse lifecycle evidence file")?;
    let mut evidence = BTreeMap::new();
    for entry in parsed.secrets {
        let secret_ref = SecretRef::new(entry.secret_ref)?;
        let record = SecretAgeEvidence {
            secret_ref: secret_ref.clone(),
            declared_at: entry.declared_at_unix_secs.map(unix_time),
            last_used_at: entry.last_used_at_unix_secs.map(unix_time),
            last_rotated_at: entry.last_rotated_at_unix_secs.map(unix_time),
        };
        if evidence.insert(secret_ref.clone(), record).is_some() {
            anyhow::bail!(
                "duplicate lifecycle evidence entry for {}",
                secret_ref.as_str()
            );
        }
    }
    Ok(evidence)
}

fn unix_time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleStaleEvidenceToml {
    #[serde(default)]
    secrets: Vec<LifecycleStaleEvidenceEntryToml>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleStaleEvidenceEntryToml {
    secret_ref: String,
    declared_at_unix_secs: Option<u64>,
    last_used_at_unix_secs: Option<u64>,
    last_rotated_at_unix_secs: Option<u64>,
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

fn lifecycle_principal_from_env() -> Result<PrincipalChain> {
    let executor =
        env::var("JANUS_LIFECYCLE_EXECUTOR").unwrap_or_else(|_| "janusd-lifecycle".to_string());
    let scope = env::var("JANUS_LIFECYCLE_SCOPE").unwrap_or_else(|_| "janus/default".to_string());
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
        "janusd\n\nCommands:\n  run --profile PROFILE --permit use_... -- ARG...\n  env-file preflight --profile PROFILE\n  env-file --profile PROFILE --permit use_...\n  approve issue --secret-ref REF --profile PROFILE --purpose PURPOSE --reason REASON \\\n    --egress connector|sandboxed|proxy_enforced|hook_guarded|declared_only \\\n    --expires-in-seconds SECONDS\n  approve permit --approval appr_... [--permit-ttl-seconds SECONDS] [--revoke-approval]\n  approve list\n  approve revoke --approval appr_...\n  lifecycle transition --secret-ref REF --to STATE --reason REASON [--metadata-file PATH]\n  lifecycle stale-report [--evidence-file PATH] [--stale-after-days N] [--missing-evidence-after-days N]\n  lifecycle destroy-record --secret-ref REF --reason REASON --retain-for-days N [--metadata-file PATH]\n  lifecycle destroy-finalize --secret-ref REF [--metadata-file PATH]\n  lifecycle destroy-reconcile [--metadata-file PATH]\n  forge rotate-generated --secret NAME --reason REASON --consumer-ref REF \\\n    --validation PROBE --hook-manifest PATH [--reload METHOD] \\\n    [--alphabet url-safe|alphanumeric|hex] [--length N]\n\njanusd run loads reviewed profiles from JANUS_RUN_PROFILE_MANIFEST and permits from JANUS_RUN_PERMIT_DIR.\njanusd env-file preflight checks the reviewed env-file profile and target path without a permit, backend, or secret read.\njanusd env-file writes a reviewed private env file from JANUS_RUN_PROFILE_MANIFEST; callers cannot choose env name, output path, executor, destination, or value.\njanusd approve loads reviewed profiles from JANUS_RUN_PROFILE_MANIFEST, backend metadata from JANUS_AGE_* / JANUS_WARDEN_AGE_*, approvals from JANUS_APPROVAL_DIR, and permits from JANUS_RUN_PERMIT_DIR.\njanusd lifecycle transition updates the configured metadata overlay only; it never deletes provider values.\njanusd lifecycle stale-report emits value-free admin rows and never reads secret values.\njanusd lifecycle destroy-record writes a value-free tombstone only; it never deletes provider values.\njanusd lifecycle destroy-finalize requires a tombstone and writes destroyed metadata only; it never deletes provider values.\njanusd lifecycle destroy-reconcile reads metadata and tombstones only; it never deletes provider values.\nReload methods: none, restart-service:LABEL, signal:LABEL, exec-hook:LABEL, connector-action:LABEL.\nForge generates replacement values internally; no --value argument exists."
    );
    eprintln!(
        "\nManaged command preflight:\n  run preflight --profile PROFILE -- ARG...\n\nThis validates the reviewed profile, exact argv, and executable without a permit, backend, or secret read."
    );
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::time::SystemTime;

    #[cfg(unix)]
    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef,
        ManifestCatalog, ProjectId, Purpose, SecretClass, SecretLifecycle, SecretMeta, SecretRef,
        StaleSecretStatus, TrustLevel, UseProfile, UseRequest,
    };
    #[cfg(unix)]
    use janus_mock::MockStore;

    use super::*;

    fn parse_ok(args: &[&str]) -> ForgeRotateGeneratedConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::ForgeRotateGenerated(config) => config,
            Command::Help => panic!("expected forge config"),
            Command::RunManagedPreflight(_) => panic!("expected forge config"),
            Command::RunManaged(_) => panic!("expected forge config"),
            Command::EnvFilePreflight(_) => panic!("expected forge config"),
            Command::EnvFile(_) => panic!("expected forge config"),
            Command::Approve(_) => panic!("expected forge config"),
            Command::LifecycleTransition(_) => panic!("expected forge config"),
            Command::LifecycleStaleReport(_) => panic!("expected forge config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected forge config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected forge config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected forge config"),
        }
    }

    fn parse_run_ok(args: &[&str]) -> RunManagedCommandConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::RunManaged(config) => config,
            Command::RunManagedPreflight(_) => panic!("expected run config"),
            Command::ForgeRotateGenerated(_) => panic!("expected run config"),
            Command::EnvFilePreflight(_) => panic!("expected run config"),
            Command::EnvFile(_) => panic!("expected run config"),
            Command::Help => panic!("expected run config"),
            Command::Approve(_) => panic!("expected run config"),
            Command::LifecycleTransition(_) => panic!("expected run config"),
            Command::LifecycleStaleReport(_) => panic!("expected run config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected run config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected run config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected run config"),
        }
    }

    fn parse_run_preflight_ok(args: &[&str]) -> RunManagedPreflightConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::RunManagedPreflight(config) => config,
            _ => panic!("expected run preflight config"),
        }
    }

    fn parse_env_file_ok(args: &[&str]) -> EnvFileConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::EnvFile(config) => config,
            Command::EnvFilePreflight(_) => panic!("expected env-file config"),
            Command::ForgeRotateGenerated(_) => panic!("expected env-file config"),
            Command::RunManagedPreflight(_) => panic!("expected env-file config"),
            Command::RunManaged(_) => panic!("expected env-file config"),
            Command::Approve(_) => panic!("expected env-file config"),
            Command::Help => panic!("expected env-file config"),
            Command::LifecycleTransition(_) => panic!("expected env-file config"),
            Command::LifecycleStaleReport(_) => panic!("expected env-file config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected env-file config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected env-file config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected env-file config"),
        }
    }

    fn parse_env_file_preflight_ok(args: &[&str]) -> EnvFilePreflightConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::EnvFilePreflight(config) => config,
            Command::EnvFile(_) => panic!("expected env-file preflight config"),
            Command::ForgeRotateGenerated(_) => panic!("expected env-file preflight config"),
            Command::RunManagedPreflight(_) => panic!("expected env-file preflight config"),
            Command::RunManaged(_) => panic!("expected env-file preflight config"),
            Command::Approve(_) => panic!("expected env-file preflight config"),
            Command::Help => panic!("expected env-file preflight config"),
            Command::LifecycleTransition(_) => panic!("expected env-file preflight config"),
            Command::LifecycleStaleReport(_) => panic!("expected env-file preflight config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected env-file preflight config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected env-file preflight config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected env-file preflight config"),
        }
    }

    fn parse_approve_issue_ok(args: &[&str]) -> ApproveIssueConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Issue(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve issue config"),
            Command::RunManagedPreflight(_) => panic!("expected approve issue config"),
            Command::RunManaged(_) => panic!("expected approve issue config"),
            Command::EnvFilePreflight(_) => panic!("expected approve issue config"),
            Command::EnvFile(_) => panic!("expected approve issue config"),
            Command::Approve(_) => panic!("expected approve issue config"),
            Command::Help => panic!("expected approve issue config"),
            Command::LifecycleTransition(_) => panic!("expected approve issue config"),
            Command::LifecycleStaleReport(_) => panic!("expected approve issue config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected approve issue config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected approve issue config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected approve issue config"),
        }
    }

    fn parse_approve_permit_ok(args: &[&str]) -> ApprovePermitConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Permit(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve permit config"),
            Command::RunManagedPreflight(_) => panic!("expected approve permit config"),
            Command::RunManaged(_) => panic!("expected approve permit config"),
            Command::EnvFilePreflight(_) => panic!("expected approve permit config"),
            Command::EnvFile(_) => panic!("expected approve permit config"),
            Command::Approve(_) => panic!("expected approve permit config"),
            Command::Help => panic!("expected approve permit config"),
            Command::LifecycleTransition(_) => panic!("expected approve permit config"),
            Command::LifecycleStaleReport(_) => panic!("expected approve permit config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected approve permit config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected approve permit config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected approve permit config"),
        }
    }

    fn parse_approve_revoke_ok(args: &[&str]) -> ApproveRevokeConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::Approve(ApproveCommand::Revoke(config)) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected approve revoke config"),
            Command::RunManagedPreflight(_) => panic!("expected approve revoke config"),
            Command::RunManaged(_) => panic!("expected approve revoke config"),
            Command::EnvFilePreflight(_) => panic!("expected approve revoke config"),
            Command::EnvFile(_) => panic!("expected approve revoke config"),
            Command::Approve(_) => panic!("expected approve revoke config"),
            Command::Help => panic!("expected approve revoke config"),
            Command::LifecycleTransition(_) => panic!("expected approve revoke config"),
            Command::LifecycleStaleReport(_) => panic!("expected approve revoke config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected approve revoke config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected approve revoke config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected approve revoke config"),
        }
    }

    fn parse_lifecycle_transition_ok(args: &[&str]) -> LifecycleTransitionConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::LifecycleTransition(config) => config,
            Command::ForgeRotateGenerated(_) => panic!("expected lifecycle config"),
            Command::RunManagedPreflight(_) => panic!("expected lifecycle config"),
            Command::RunManaged(_) => panic!("expected lifecycle config"),
            Command::EnvFilePreflight(_) => panic!("expected lifecycle config"),
            Command::EnvFile(_) => panic!("expected lifecycle config"),
            Command::Approve(_) => panic!("expected lifecycle config"),
            Command::Help => panic!("expected lifecycle config"),
            Command::LifecycleStaleReport(_) => panic!("expected lifecycle config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected lifecycle config"),
            Command::LifecycleDestroyFinalize(_) => panic!("expected lifecycle config"),
            Command::LifecycleDestroyReconcile(_) => panic!("expected lifecycle config"),
        }
    }

    fn parse_lifecycle_stale_report_ok(args: &[&str]) -> LifecycleStaleReportConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::LifecycleStaleReport(config) => config,
            Command::LifecycleTransition(_) => panic!("expected lifecycle stale-report config"),
            Command::ForgeRotateGenerated(_) => panic!("expected lifecycle stale-report config"),
            Command::RunManagedPreflight(_) => {
                panic!("expected lifecycle stale-report config")
            }
            Command::RunManaged(_) => panic!("expected lifecycle stale-report config"),
            Command::EnvFilePreflight(_) => panic!("expected lifecycle stale-report config"),
            Command::EnvFile(_) => panic!("expected lifecycle stale-report config"),
            Command::Approve(_) => panic!("expected lifecycle stale-report config"),
            Command::Help => panic!("expected lifecycle stale-report config"),
            Command::LifecycleDestroyRecord(_) => panic!("expected lifecycle stale-report config"),
            Command::LifecycleDestroyFinalize(_) => {
                panic!("expected lifecycle stale-report config")
            }
            Command::LifecycleDestroyReconcile(_) => {
                panic!("expected lifecycle stale-report config")
            }
        }
    }

    fn parse_lifecycle_destroy_record_ok(args: &[&str]) -> LifecycleDestroyRecordConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::LifecycleDestroyRecord(config) => config,
            Command::LifecycleTransition(_) => panic!("expected lifecycle destroy-record config"),
            Command::LifecycleStaleReport(_) => {
                panic!("expected lifecycle destroy-record config")
            }
            Command::ForgeRotateGenerated(_) => panic!("expected lifecycle destroy-record config"),
            Command::RunManagedPreflight(_) => {
                panic!("expected lifecycle destroy-record config")
            }
            Command::RunManaged(_) => panic!("expected lifecycle destroy-record config"),
            Command::EnvFilePreflight(_) => panic!("expected lifecycle destroy-record config"),
            Command::EnvFile(_) => panic!("expected lifecycle destroy-record config"),
            Command::Approve(_) => panic!("expected lifecycle destroy-record config"),
            Command::Help => panic!("expected lifecycle destroy-record config"),
            Command::LifecycleDestroyFinalize(_) => {
                panic!("expected lifecycle destroy-record config")
            }
            Command::LifecycleDestroyReconcile(_) => {
                panic!("expected lifecycle destroy-record config")
            }
        }
    }

    fn parse_lifecycle_destroy_finalize_ok(args: &[&str]) -> LifecycleDestroyFinalizeConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::LifecycleDestroyFinalize(config) => config,
            Command::LifecycleTransition(_) => panic!("expected lifecycle destroy-finalize config"),
            Command::LifecycleStaleReport(_) => {
                panic!("expected lifecycle destroy-finalize config")
            }
            Command::LifecycleDestroyRecord(_) => {
                panic!("expected lifecycle destroy-finalize config")
            }
            Command::ForgeRotateGenerated(_) => {
                panic!("expected lifecycle destroy-finalize config")
            }
            Command::RunManagedPreflight(_) => {
                panic!("expected lifecycle destroy-finalize config")
            }
            Command::RunManaged(_) => panic!("expected lifecycle destroy-finalize config"),
            Command::EnvFilePreflight(_) => panic!("expected lifecycle destroy-finalize config"),
            Command::EnvFile(_) => panic!("expected lifecycle destroy-finalize config"),
            Command::Approve(_) => panic!("expected lifecycle destroy-finalize config"),
            Command::Help => panic!("expected lifecycle destroy-finalize config"),
            Command::LifecycleDestroyReconcile(_) => {
                panic!("expected lifecycle destroy-finalize config")
            }
        }
    }

    fn parse_lifecycle_destroy_reconcile_ok(args: &[&str]) -> LifecycleDestroyReconcileConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::LifecycleDestroyReconcile(config) => config,
            Command::LifecycleTransition(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::LifecycleStaleReport(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::LifecycleDestroyRecord(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::LifecycleDestroyFinalize(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::ForgeRotateGenerated(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::RunManagedPreflight(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::RunManaged(_) => panic!("expected lifecycle destroy-reconcile config"),
            Command::EnvFilePreflight(_) => {
                panic!("expected lifecycle destroy-reconcile config")
            }
            Command::EnvFile(_) => panic!("expected lifecycle destroy-reconcile config"),
            Command::Approve(_) => panic!("expected lifecycle destroy-reconcile config"),
            Command::Help => panic!("expected lifecycle destroy-reconcile config"),
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
    fn parses_run_preflight_without_permit_or_policy_overrides() {
        let config = parse_run_preflight_ok(&[
            "run",
            "preflight",
            "--profile",
            "profile.canary",
            "--",
            "deploy",
            "hsb0",
        ]);

        assert_eq!(config.profile_id.as_str(), "profile.canary");
        assert_eq!(config.requested_args, ["deploy", "hsb0"]);

        let err = parse_args(
            [
                "run",
                "preflight",
                "--profile",
                "profile.canary",
                "--permit",
                "use_abc123",
                "--",
                "deploy",
                "hsb0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not accept a permit"));
        assert!(!err.to_string().contains("use_abc123"));

        for flag in [
            "--secret-ref",
            "--value",
            "--env",
            "--binary",
            "--destination",
            "--executor",
        ] {
            let err = parse_args(
                [
                    "run",
                    "preflight",
                    "--profile",
                    "profile.canary",
                    flag,
                    "unreviewed",
                    "--",
                    "deploy",
                    "hsb0",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .unwrap_err();
            assert!(err.to_string().contains("reviewed profile"));
            assert!(!err.to_string().contains("unreviewed"));
        }
    }

    #[test]
    fn parses_env_file_profile_and_rejects_unreviewed_fields() {
        let config = parse_env_file_ok(&[
            "env-file",
            "--profile",
            "profile.service_env",
            "--permit",
            "use_abc123",
        ]);

        assert_eq!(config.profile_id.as_str(), "profile.service_env");
        assert_eq!(config.permit.as_str(), "use_abc123");
        assert!(!format!("{config:?}").contains("use_abc123"));

        for flag in [
            "--secret-ref",
            "--value",
            "--raw-value",
            "--env",
            "--output",
            "--destination",
            "--executor",
            "--binary",
        ] {
            let err = parse_args(
                [
                    "env-file",
                    "--profile",
                    "profile.service_env",
                    "--permit",
                    "use_abc123",
                    flag,
                    "unreviewed",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .unwrap_err();
            assert!(err.to_string().contains("reviewed profile"));
            assert!(!err.to_string().contains("use_abc123"));
        }

        let err = parse_args(
            [
                "env-file",
                "--profile",
                "profile.service_env",
                "--permit",
                "use_abc123",
                "--",
                "echo",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not accept"));
        assert!(!err.to_string().contains("use_abc123"));
    }

    #[test]
    fn parses_env_file_preflight_without_permit_or_policy_fields() {
        let config = parse_env_file_preflight_ok(&[
            "env-file",
            "preflight",
            "--profile",
            "profile.service_env",
        ]);

        assert_eq!(config.profile_id.as_str(), "profile.service_env");

        let err = parse_args(
            [
                "env-file",
                "preflight",
                "--profile",
                "profile.service_env",
                "--permit",
                "use_abc123",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not accept permits"));
        assert!(!err.to_string().contains("use_abc123"));

        for flag in [
            "--secret-ref",
            "--value",
            "--raw-value",
            "--env",
            "--output",
            "--destination",
            "--executor",
            "--binary",
        ] {
            let err = parse_args(
                [
                    "env-file",
                    "preflight",
                    "--profile",
                    "profile.service_env",
                    flag,
                    "unreviewed",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .unwrap_err();
            assert!(err.to_string().contains("reviewed profile"));
            assert!(!err.to_string().contains("unreviewed"));
        }
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
    fn parses_lifecycle_transition_without_literal_inputs() {
        let config = parse_lifecycle_transition_ok(&[
            "lifecycle",
            "transition",
            "--secret-ref",
            "sec_fixture",
            "--to",
            "disabled",
            "--reason",
            "reviewed disable",
            "--metadata-file",
            "/tmp/janus-metadata.toml",
        ]);

        assert_eq!(config.secret_ref.as_str(), "sec_fixture");
        assert_eq!(config.to, SecretLifecycle::Disabled);
        assert_eq!(config.reason.as_str(), "reviewed disable");
        assert_eq!(
            config.metadata_file,
            Some(PathBuf::from("/tmp/janus-metadata.toml"))
        );

        let err = parse_args(
            [
                "lifecycle",
                "transition",
                "--secret-ref",
                "sec_fixture",
                "--to",
                "disabled",
                "--reason",
                "reviewed disable",
                "--value",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("value-free"));
        assert!(!err.to_string().contains("do-not-echo-me"));
    }

    #[test]
    fn lifecycle_transition_requires_metadata_configuration() {
        let err = lifecycle_metadata_file_path(None, &[]).unwrap_err();
        assert!(err.to_string().contains("METADATA"));
    }

    #[test]
    fn parses_lifecycle_stale_report_without_literal_inputs() {
        let config = parse_lifecycle_stale_report_ok(&[
            "lifecycle",
            "stale-report",
            "--evidence-file",
            "/tmp/janus-stale-evidence.toml",
            "--stale-after-days",
            "30",
            "--missing-evidence-after-days",
            "3",
        ]);

        assert_eq!(
            config.evidence_file,
            Some(PathBuf::from("/tmp/janus-stale-evidence.toml"))
        );
        assert_eq!(config.stale_after, Duration::from_secs(30 * 24 * 60 * 60));
        assert_eq!(
            config.missing_evidence_after,
            Duration::from_secs(3 * 24 * 60 * 60)
        );

        let err = parse_args(
            [
                "lifecycle",
                "stale-report",
                "--evidence-file",
                "/tmp/janus-stale-evidence.toml",
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
            ["lifecycle", "stale-report", "--stale-after-days", "0"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--stale-after-days"));
    }

    #[test]
    fn parses_lifecycle_destroy_record_without_literal_inputs() {
        let config = parse_lifecycle_destroy_record_ok(&[
            "lifecycle",
            "destroy-record",
            "--secret-ref",
            "sec_fixture",
            "--reason",
            "reviewed destroy record",
            "--retain-for-days",
            "365",
            "--metadata-file",
            "/tmp/janus-metadata.toml",
        ]);

        assert_eq!(config.secret_ref.as_str(), "sec_fixture");
        assert_eq!(config.reason.as_str(), "reviewed destroy record");
        assert_eq!(config.retain_for, Duration::from_secs(365 * 24 * 60 * 60));
        assert_eq!(
            config.metadata_file,
            Some(PathBuf::from("/tmp/janus-metadata.toml"))
        );

        let err = parse_args(
            [
                "lifecycle",
                "destroy-record",
                "--secret-ref",
                "sec_fixture",
                "--reason",
                "reviewed destroy record",
                "--retain-for-days",
                "365",
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
                "lifecycle",
                "destroy-record",
                "--secret-ref",
                "sec_fixture",
                "--reason",
                "reviewed destroy record",
                "--retain-for-days",
                "0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--retain-for-days"));
    }

    #[test]
    fn parses_lifecycle_destroy_finalize_without_literal_inputs() {
        let config = parse_lifecycle_destroy_finalize_ok(&[
            "lifecycle",
            "destroy-finalize",
            "--secret-ref",
            "sec_fixture",
            "--metadata-file",
            "/tmp/janus-metadata.toml",
        ]);

        assert_eq!(config.secret_ref.as_str(), "sec_fixture");
        assert_eq!(
            config.metadata_file,
            Some(PathBuf::from("/tmp/janus-metadata.toml"))
        );

        let err = parse_args(
            [
                "lifecycle",
                "destroy-finalize",
                "--secret-ref",
                "sec_fixture",
                "--metadata-file",
                "/tmp/janus-metadata.toml",
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
                "lifecycle",
                "destroy-finalize",
                "--secret-ref",
                "sec_fixture",
                "--reason",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("value-free"));
        assert!(!err.to_string().contains("do-not-echo-me"));
    }

    #[test]
    fn parses_lifecycle_destroy_reconcile_without_literal_inputs() {
        let config = parse_lifecycle_destroy_reconcile_ok(&[
            "lifecycle",
            "destroy-reconcile",
            "--metadata-file",
            "/tmp/janus-metadata.toml",
        ]);

        assert_eq!(
            config.metadata_file,
            Some(PathBuf::from("/tmp/janus-metadata.toml"))
        );

        let err = parse_args(
            [
                "lifecycle",
                "destroy-reconcile",
                "--metadata-file",
                "/tmp/janus-metadata.toml",
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
                "lifecycle",
                "destroy-reconcile",
                "--secret-ref",
                "sec_do_not_echo",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("value-free"));
        assert!(!err.to_string().contains("sec_do_not_echo"));
    }

    #[test]
    fn lifecycle_stale_evidence_loads_opaque_refs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.toml");
        std::fs::write(
            &path,
            r#"
            [[secrets]]
            secret_ref = "sec_fixture"
            declared_at_unix_secs = 10
            last_used_at_unix_secs = 20
            last_rotated_at_unix_secs = 30
            "#,
        )
        .unwrap();

        let evidence = load_stale_evidence(Some(&path)).unwrap();
        let record = evidence
            .get(&SecretRef::new("sec_fixture").unwrap())
            .unwrap();

        assert_eq!(record.secret_ref.as_str(), "sec_fixture");
        assert_eq!(
            record.declared_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
        );
        assert_eq!(
            record.last_used_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20))
        );
        assert_eq!(
            record.last_rotated_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(30))
        );
    }

    #[test]
    fn lifecycle_stale_evidence_merges_registry_and_manual_sources() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(dir.path().join("registry"));
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        registry
            .record_declared(
                &secret_ref,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            )
            .unwrap();
        registry
            .record_used(
                &secret_ref,
                SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            )
            .unwrap();
        let manual = dir.path().join("manual.toml");
        std::fs::write(
            &manual,
            r#"
            [[secrets]]
            secret_ref = "sec_fixture"
            declared_at_unix_secs = 5
            last_used_at_unix_secs = 15
            last_rotated_at_unix_secs = 30
            "#,
        )
        .unwrap();

        let evidence = load_stale_evidence_sources(&registry, Some(&manual)).unwrap();
        let record = evidence.get(&secret_ref).unwrap();

        assert_eq!(
            record.declared_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(5))
        );
        assert_eq!(
            record.last_used_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20))
        );
        assert_eq!(
            record.last_rotated_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(30))
        );
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

    fn true_program() -> &'static str {
        [
            "/usr/bin/true",
            "/run/current-system/sw/bin/true",
            "/bin/true",
        ]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .expect("test platform provides an absolute true binary")
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

    fn env_file_profile_toml(secret_ref: &SecretRef, output_path: &Path) -> String {
        format!(
            r#"
                [[env_files]]
                id = "profile.service_env"
                secret_ref = {}
                executor = "janus-run@fixture"
                destination = "fixture-service"
                env = "SERVICE_TOKEN"
                output = {}

                [env_files.consumer]
                consumer_ref = "consumer.fixture_service"
                kind = "service"
                owner = "janusd-test"
                environment = "test"
                reload = "restart-service:fixture-service"
                validation = ["fixture-service-health"]
                supports_dual_value = false
                blast_radius = "fixture-service"
            "#,
            toml_string(secret_ref.as_str()),
            toml_string(output_path.to_string_lossy().as_ref()),
        )
    }

    fn env_file_profile_with_hash_sidecar_toml(
        secret_ref: &SecretRef,
        output_path: &Path,
        hash_output_path: &Path,
    ) -> String {
        format!(
            r#"
                [[env_files]]
                id = "profile.service_env"
                secret_ref = {}
                executor = "janus-run@fixture"
                destination = "fixture-service"
                env = "SERVICE_TOKEN"
                output = {}

                [env_files.hash_sidecar]
                format = "pharos-beacon-token-hashes-v1"
                subject = "ares"
                output = {}

                [env_files.consumer]
                consumer_ref = "consumer.fixture_service"
                kind = "service"
                owner = "janusd-test"
                environment = "test"
                reload = "restart-service:fixture-service"
                validation = ["fixture-service-health"]
                supports_dual_value = false
                blast_radius = "fixture-service"
            "#,
            toml_string(secret_ref.as_str()),
            toml_string(output_path.to_string_lossy().as_ref()),
            toml_string(hash_output_path.to_string_lossy().as_ref()),
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
    fn env_file_profile_manifest_parses_reviewed_service_contract() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let output_path = PathBuf::from("/run/janus/env/fixture.env");
        let catalog =
            ManagedCommandProfileCatalog::parse(&env_file_profile_toml(&secret_ref, &output_path))
                .unwrap();
        let profile = catalog
            .env_file_profile(&ProfileId::new("profile.service_env").unwrap())
            .unwrap();

        assert_eq!(profile.secret_ref(), &secret_ref);
        assert_eq!(profile.executor().as_str(), "janus-run@fixture");
        assert_eq!(profile.destination().as_str(), "fixture-service");
        assert_eq!(profile.env_name().as_str(), "SERVICE_TOKEN");
        assert_eq!(profile.output_path(), output_path.as_path());
        assert_eq!(profile.consumer_ref().as_str(), "consumer.fixture_service");
        assert_eq!(profile.consumer().kind, ConsumerKind::Service);
        assert_eq!(profile.consumer().owner.as_str(), "janusd-test");
        assert_eq!(
            profile.consumer().blast_radius,
            BlastRadius::new("fixture-service").unwrap()
        );
    }

    #[test]
    fn env_file_profile_manifest_parses_reviewed_hash_sidecar_contract() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let output_path = PathBuf::from("/run/janus/env/fixture.env");
        let hash_output_path = PathBuf::from("/run/janus/env/fixture-token-hash.json");
        let catalog = ManagedCommandProfileCatalog::parse(
            &env_file_profile_with_hash_sidecar_toml(&secret_ref, &output_path, &hash_output_path),
        )
        .unwrap();
        let profile = catalog
            .env_file_profile(&ProfileId::new("profile.service_env").unwrap())
            .unwrap();
        let sidecar = profile.hash_sidecar().expect("hash sidecar");

        assert_eq!(
            sidecar.format(),
            EnvFileHashSidecarFormat::PharosBeaconTokenHashesV1
        );
        assert_eq!(sidecar.subject().as_str(), "ares");
        assert_eq!(sidecar.output_path(), hash_output_path.as_path());
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

    #[test]
    fn approve_issue_builds_exact_grant_from_env_file_profile_and_metadata() {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.service_env").unwrap();
        let profiles = ManagedCommandProfileCatalog::parse(&env_file_profile_toml(
            &secret_ref,
            &PathBuf::from("/run/janus/env/fixture.env"),
        ))
        .unwrap();
        let descriptors = vec![SecretDescriptor {
            name: SecretName::new("CANARY").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id.clone()],
            present: true,
        }];
        let config = ApproveIssueConfig {
            secret_ref: secret_ref.clone(),
            profile_id: profile_id.clone(),
            purpose: Purpose::new("fixture service env").unwrap(),
            reason: SafeLabel::new("approved fixture").unwrap(),
            egress: EgressMode::Connector,
            expires_in: Duration::from_secs(120),
        };

        let approval =
            build_approval_grant(&config, &profiles, &descriptors, SystemTime::UNIX_EPOCH).unwrap();
        let snapshot = approval.snapshot();

        assert_eq!(snapshot.secret_ref, secret_ref.as_str());
        assert_eq!(snapshot.profile_id, profile_id.as_str());
        assert_eq!(snapshot.executor, "janus-run@fixture");
        assert_eq!(snapshot.destination, "fixture-service");
        assert_eq!(snapshot.class, "normal");
        assert_eq!(snapshot.egress, "connector");
        assert_eq!(snapshot.purpose, "fixture service env");
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

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_transition_persists_overlay_patch() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_file = dir.path().join("metadata.toml");
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "active"
            "#,
        )
        .unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let config = LifecycleTransitionConfig {
            secret_ref: secret_ref.clone(),
            to: SecretLifecycle::Disabled,
            reason: SafeLabel::new("reviewed disable").unwrap(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut audit = AuditWrite::accepting();

        let outcome = apply_lifecycle_transition_with(
            &config,
            &metadata_file,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                SecretLifecycle::Active,
            ),
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap();

        assert_eq!(outcome.secret_ref, secret_ref.as_str());
        assert_eq!(outcome.from, "active");
        assert_eq!(outcome.to, "disabled");
        assert_eq!(outcome.reason_code, "lifecycle_transition_ok");
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));
        let overlay = SecretMetadataOverlay::load_toml_file(&metadata_file).unwrap();
        let mut entries = vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id],
        }];
        overlay.apply_to_entries(&mut entries).unwrap();
        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Disabled);
        assert_eq!(audit.events().len(), 1);
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::SecretLifecycle);
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "lifecycle_transition_ok");
        assert_eq!(event.evidence.as_ref(), Some(&config.reason));
        assert!(!event.value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_transition_denials_leave_overlay_unchanged() {
        for (from, to, expected_reason) in [
            (
                SecretLifecycle::Active,
                SecretLifecycle::Active,
                "denied_lifecycle_transition_noop",
            ),
            (
                SecretLifecycle::Disabled,
                SecretLifecycle::Active,
                "denied_lifecycle_transition_unsupported",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let metadata_file = dir.path().join("metadata.toml");
            std::fs::write(
                &metadata_file,
                format!(
                    r#"
                    [defaults]
                    owner = "infra"
                    classification = "normal"
                    lifecycle = "active"

                    [[secrets]]
                    name = "CANARY"
                    lifecycle = "{}"
                    "#,
                    from.as_str()
                ),
            )
            .unwrap();
            let before = std::fs::read_to_string(&metadata_file).unwrap();
            let project = ProjectId::new("janus").unwrap();
            let name = SecretName::new("CANARY").unwrap();
            let secret_ref = SecretRef::for_manifest_entry(&project, &name);
            let profile_id = ProfileId::new("profile.canary").unwrap();
            let config = LifecycleTransitionConfig {
                secret_ref: secret_ref.clone(),
                to,
                reason: SafeLabel::new("reviewed lifecycle attempt").unwrap(),
                metadata_file: Some(metadata_file.clone()),
            };
            let mut audit = AuditWrite::accepting();

            let err = apply_lifecycle_transition_with(
                &config,
                &metadata_file,
                fixture_store_with_class_and_lifecycle(
                    &secret_ref,
                    &name,
                    &profile_id,
                    SecretClass::Normal,
                    from,
                ),
                &fixture_principal(),
                &mut audit,
            )
            .await
            .unwrap_err();

            let janus_err = err.downcast_ref::<JanusError>().unwrap();
            assert!(matches!(
                janus_err,
                JanusError::PolicyDenied { reason_code, .. } if *reason_code == expected_reason
            ));
            assert_eq!(std::fs::read_to_string(&metadata_file).unwrap(), before);
            assert_eq!(audit.events().len(), 1);
            let event = &audit.events()[0];
            assert_eq!(event.action, AuditAction::SecretLifecycle);
            assert_eq!(event.outcome, AuditOutcome::Denied);
            assert_eq!(event.reason_code, expected_reason);
            assert!(!event.value_returned);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_record_writes_tombstone_without_provider_delete() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path());
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy record").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: None,
        };
        let mut audit = AuditWrite::accepting();

        let outcome = record_lifecycle_destroy_with(
            &config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
            now,
        )
        .await
        .unwrap();

        assert_eq!(outcome.secret_ref, secret_ref.as_str());
        assert_eq!(outcome.from, "pending_delete");
        assert_eq!(outcome.to, "destroyed");
        assert_eq!(outcome.reason_code, "tombstone_recorded");
        assert_eq!(outcome.retain_until_unix_secs, 24 * 60 * 60 + 10);
        assert!(!outcome.value_returned);
        assert!(!outcome.provider_deleted);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let records = janus_local::TombstoneRegistry::list(&registry).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].secret_ref, secret_ref);
        assert_eq!(records[0].reason.as_str(), "reviewed destroy record");
        assert_eq!(records[0].destroyed_at, now);
        assert_eq!(
            records[0].retain_until,
            SystemTime::UNIX_EPOCH + Duration::from_secs(24 * 60 * 60 + 10)
        );
        assert_eq!(
            records[0].principal_binding,
            "executor:janus-run@fixture|scope:janus/dev"
        );
        assert_eq!(audit.events().len(), 1);
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::SecretLifecycle);
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "tombstone_recorded");
        assert_eq!(event.evidence.as_ref(), Some(&config.reason));
        assert!(!event.value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_record_requires_pending_delete() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path());
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy attempt").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: None,
        };
        let mut audit = AuditWrite::accepting();

        let err = record_lifecycle_destroy_with(
            &config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::Disabled,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .await
        .unwrap_err();

        let janus_err = err.downcast_ref::<JanusError>().unwrap();
        assert!(matches!(
            janus_err,
            JanusError::PolicyDenied {
                reason_code: "denied_destroy_requires_pending_delete",
                ..
            }
        ));
        assert_eq!(
            janus_local::TombstoneRegistry::list(&registry)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(audit.events().len(), 1);
        assert_eq!(audit.events()[0].outcome, AuditOutcome::Denied);
        assert_eq!(
            audit.events()[0].reason_code,
            "denied_destroy_requires_pending_delete"
        );
        assert!(!audit.events()[0].value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_finalize_marks_overlay_destroyed_without_provider_delete() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        let metadata_file = dir.path().join("metadata.toml");
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "pending_delete"
            "#,
        )
        .unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let record_config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy record").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: None,
        };
        let mut record_audit = AuditWrite::accepting();
        record_lifecycle_destroy_with(
            &record_config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut record_audit,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .await
        .unwrap();
        let config = LifecycleDestroyFinalizeConfig {
            secret_ref: secret_ref.clone(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut audit = AuditWrite::accepting();

        let outcome = finalize_lifecycle_destroy_with(
            &config,
            &metadata_file,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap();

        assert_eq!(outcome.secret_ref, secret_ref.as_str());
        assert_eq!(outcome.from, "pending_delete");
        assert_eq!(outcome.to, "destroyed");
        assert_eq!(outcome.reason_code, "destroy_metadata_finalized");
        assert!(outcome.metadata_finalized);
        assert!(!outcome.value_returned);
        assert!(!outcome.provider_deleted);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let overlay = SecretMetadataOverlay::load_toml_file(&metadata_file).unwrap();
        let mut entries = vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id],
        }];
        overlay.apply_to_entries(&mut entries).unwrap();
        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Destroyed);

        assert_eq!(audit.events().len(), 1);
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::SecretLifecycle);
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "destroy_metadata_finalized");
        assert_eq!(event.evidence.as_ref(), Some(&record_config.reason));
        assert!(!event.value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_finalize_is_retry_safe_when_already_destroyed() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        let metadata_file = dir.path().join("metadata.toml");
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            lifecycle = "destroyed"
            "#,
        )
        .unwrap();
        let before = std::fs::read_to_string(&metadata_file).unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let record_config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy record").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: None,
        };
        let mut record_audit = AuditWrite::accepting();
        record_lifecycle_destroy_with(
            &record_config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut record_audit,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .await
        .unwrap();
        let config = LifecycleDestroyFinalizeConfig {
            secret_ref: secret_ref.clone(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut audit = AuditWrite::accepting();

        let outcome = finalize_lifecycle_destroy_with(
            &config,
            &metadata_file,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::Destroyed,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap();

        assert_eq!(outcome.from, "destroyed");
        assert_eq!(outcome.to, "destroyed");
        assert_eq!(outcome.reason_code, "destroy_metadata_already_finalized");
        assert!(!outcome.metadata_finalized);
        assert!(!outcome.value_returned);
        assert!(!outcome.provider_deleted);
        assert_eq!(std::fs::read_to_string(&metadata_file).unwrap(), before);
        assert_eq!(audit.events().len(), 1);
        assert_eq!(audit.events()[0].outcome, AuditOutcome::Allowed);
        assert_eq!(
            audit.events()[0].reason_code,
            "destroy_metadata_already_finalized"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_finalize_requires_tombstone_before_overlay_write() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        let metadata_file = dir.path().join("metadata.toml");
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            lifecycle = "pending_delete"
            "#,
        )
        .unwrap();
        let before = std::fs::read_to_string(&metadata_file).unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let config = LifecycleDestroyFinalizeConfig {
            secret_ref: secret_ref.clone(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut audit = AuditWrite::accepting();

        let err = finalize_lifecycle_destroy_with(
            &config,
            &metadata_file,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("tombstone"));
        assert_eq!(std::fs::read_to_string(&metadata_file).unwrap(), before);
        assert_eq!(audit.events().len(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_finalize_denies_non_pending_lifecycle_without_overlay_write() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        let metadata_file = dir.path().join("metadata.toml");
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            lifecycle = "disabled"
            "#,
        )
        .unwrap();
        let before = std::fs::read_to_string(&metadata_file).unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let record_config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy record").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: None,
        };
        let mut record_audit = AuditWrite::accepting();
        record_lifecycle_destroy_with(
            &record_config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::PendingDelete,
            ),
            &registry,
            &fixture_principal(),
            &mut record_audit,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .await
        .unwrap();
        let config = LifecycleDestroyFinalizeConfig {
            secret_ref: secret_ref.clone(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut audit = AuditWrite::accepting();

        let err = finalize_lifecycle_destroy_with(
            &config,
            &metadata_file,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::Disabled,
            ),
            &registry,
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap_err();

        let janus_err = err.downcast_ref::<JanusError>().unwrap();
        assert!(matches!(
            janus_err,
            JanusError::PolicyDenied {
                reason_code: "denied_destroy_finalize_requires_pending_delete",
                ..
            }
        ));
        assert_eq!(std::fs::read_to_string(&metadata_file).unwrap(), before);
        assert_eq!(audit.events().len(), 1);
        assert_eq!(audit.events()[0].outcome, AuditOutcome::Denied);
        assert_eq!(
            audit.events()[0].reason_code,
            "denied_destroy_finalize_requires_pending_delete"
        );
        assert!(!audit.events()[0].value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_reconcile_reports_tombstone_metadata_drift() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        let project = ProjectId::new("janus").unwrap();
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let pending_name = SecretName::new("PENDING").unwrap();
        let pending_ref = SecretRef::for_manifest_entry(&project, &pending_name);
        let destroyed_missing_name = SecretName::new("DESTROYED_MISSING").unwrap();
        let destroyed_missing_ref =
            SecretRef::for_manifest_entry(&project, &destroyed_missing_name);
        let active_name = SecretName::new("ACTIVE_WITH_TOMBSTONE").unwrap();
        let active_ref = SecretRef::for_manifest_entry(&project, &active_name);
        let ok_name = SecretName::new("DESTROYED_OK").unwrap();
        let ok_ref = SecretRef::for_manifest_entry(&project, &ok_name);
        let healthy_name = SecretName::new("ACTIVE_OK").unwrap();
        let healthy_ref = SecretRef::for_manifest_entry(&project, &healthy_name);
        let orphan_name = SecretName::new("ORPHAN").unwrap();
        let orphan_ref = SecretRef::for_manifest_entry(&project, &orphan_name);

        for (name, secret_ref) in [
            (&pending_name, &pending_ref),
            (&active_name, &active_ref),
            (&ok_name, &ok_ref),
            (&orphan_name, &orphan_ref),
        ] {
            let config = LifecycleDestroyRecordConfig {
                secret_ref: secret_ref.clone(),
                reason: SafeLabel::new("reviewed destroy record").unwrap(),
                retain_for: Duration::from_secs(24 * 60 * 60),
                metadata_file: None,
            };
            let mut audit = AuditWrite::accepting();
            record_lifecycle_destroy_with(
                &config,
                fixture_store_with_class_and_lifecycle(
                    secret_ref,
                    name,
                    &profile_id,
                    SecretClass::Normal,
                    SecretLifecycle::PendingDelete,
                ),
                &registry,
                &fixture_principal(),
                &mut audit,
                SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            )
            .await
            .unwrap();
        }

        let store = fixture_store_with_lifecycle_entries(&[
            (
                pending_ref.clone(),
                pending_name.clone(),
                SecretLifecycle::PendingDelete,
            ),
            (
                destroyed_missing_ref.clone(),
                destroyed_missing_name.clone(),
                SecretLifecycle::Destroyed,
            ),
            (
                active_ref.clone(),
                active_name.clone(),
                SecretLifecycle::Active,
            ),
            (ok_ref.clone(), ok_name.clone(), SecretLifecycle::Destroyed),
            (
                healthy_ref.clone(),
                healthy_name.clone(),
                SecretLifecycle::Active,
            ),
        ]);
        let mut audit = AuditWrite::accepting();

        let rows = build_lifecycle_destroy_reconcile_with(
            store,
            &registry,
            &fixture_principal(),
            &mut audit,
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 5);
        let by_ref = rows
            .iter()
            .map(|row| (row.secret_ref.as_str().to_string(), row))
            .collect::<BTreeMap<_, _>>();
        assert!(!by_ref.contains_key(healthy_ref.as_str()));

        let pending = by_ref.get(pending_ref.as_str()).unwrap();
        assert_eq!(pending.status, "needs_finalize");
        assert_eq!(pending.reason_code, "destroy_tombstone_pending_finalize");
        assert_eq!(pending.action, "run_destroy_finalize");
        assert_eq!(pending.metadata_lifecycle, "pending_delete");
        assert_eq!(pending.tombstone_state, "present");
        assert!(pending.action_required);

        let destroyed_missing = by_ref.get(destroyed_missing_ref.as_str()).unwrap();
        assert_eq!(destroyed_missing.status, "drift");
        assert_eq!(destroyed_missing.reason_code, "destroyed_missing_tombstone");
        assert_eq!(destroyed_missing.action, "restore_tombstone_or_investigate");
        assert_eq!(destroyed_missing.metadata_lifecycle, "destroyed");
        assert_eq!(destroyed_missing.tombstone_state, "missing");
        assert!(destroyed_missing.action_required);

        let active = by_ref.get(active_ref.as_str()).unwrap();
        assert_eq!(active.status, "drift");
        assert_eq!(active.reason_code, "destroy_tombstone_lifecycle_mismatch");
        assert_eq!(active.action, "investigate_destroy_lifecycle");
        assert_eq!(active.metadata_lifecycle, "active");
        assert_eq!(active.tombstone_state, "present");
        assert!(active.action_required);

        let ok = by_ref.get(ok_ref.as_str()).unwrap();
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.reason_code, "destroy_tombstone_reconcile_ok");
        assert_eq!(ok.action, "none");
        assert_eq!(ok.metadata_lifecycle, "destroyed");
        assert_eq!(ok.tombstone_state, "present");
        assert!(!ok.action_required);

        let orphan = by_ref.get(orphan_ref.as_str()).unwrap();
        assert_eq!(orphan.status, "drift");
        assert_eq!(orphan.reason_code, "destroy_tombstone_metadata_missing");
        assert_eq!(orphan.action, "investigate_orphan_tombstone");
        assert_eq!(orphan.metadata_lifecycle, "missing");
        assert_eq!(orphan.tombstone_state, "present");
        assert!(orphan.action_required);

        for row in &rows {
            assert!(!row.value_returned);
            assert!(!row.provider_deleted);
            assert!(!format!("{row:?}").contains("expected-canary"));
        }
        assert_eq!(audit.events().len(), rows.len());
        for event in audit.events() {
            assert_eq!(event.action, AuditAction::SecretLifecycle);
            assert_eq!(event.outcome, AuditOutcome::Allowed);
            assert!(!event.value_returned);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_destroy_smoke_walks_metadata_only_operator_flow() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_file = dir.path().join("metadata.toml");
        let registry = FileTombstoneRegistry::new(dir.path().join("tombstones"));
        std::fs::write(
            &metadata_file,
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "active"
            "#,
        )
        .unwrap();
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let principal = fixture_principal();

        let disable_config = LifecycleTransitionConfig {
            secret_ref: secret_ref.clone(),
            to: SecretLifecycle::Disabled,
            reason: SafeLabel::new("reviewed disable").unwrap(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut disable_audit = AuditWrite::accepting();
        let disable = apply_lifecycle_transition_with(
            &disable_config,
            &metadata_file,
            fixture_store_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            &principal,
            &mut disable_audit,
        )
        .await
        .unwrap();

        assert_eq!(disable.from, "active");
        assert_eq!(disable.to, "disabled");
        assert_eq!(disable.reason_code, "lifecycle_transition_ok");
        assert!(!disable.value_returned);
        assert_eq!(
            fixture_lifecycle_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            SecretLifecycle::Disabled
        );

        let pending_config = LifecycleTransitionConfig {
            secret_ref: secret_ref.clone(),
            to: SecretLifecycle::PendingDelete,
            reason: SafeLabel::new("reviewed pending delete").unwrap(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut pending_audit = AuditWrite::accepting();
        let pending = apply_lifecycle_transition_with(
            &pending_config,
            &metadata_file,
            fixture_store_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            &principal,
            &mut pending_audit,
        )
        .await
        .unwrap();

        assert_eq!(pending.from, "disabled");
        assert_eq!(pending.to, "pending_delete");
        assert_eq!(pending.reason_code, "lifecycle_transition_ok");
        assert!(!pending.value_returned);
        assert_eq!(
            fixture_lifecycle_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            SecretLifecycle::PendingDelete
        );

        let record_config = LifecycleDestroyRecordConfig {
            secret_ref: secret_ref.clone(),
            reason: SafeLabel::new("reviewed destroy record").unwrap(),
            retain_for: Duration::from_secs(24 * 60 * 60),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut record_audit = AuditWrite::accepting();
        let record = record_lifecycle_destroy_with(
            &record_config,
            fixture_store_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            &registry,
            &principal,
            &mut record_audit,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(record.from, "pending_delete");
        assert_eq!(record.to, "destroyed");
        assert_eq!(record.reason_code, "tombstone_recorded");
        assert!(!record.value_returned);
        assert!(!record.provider_deleted);
        let tombstones = janus_local::TombstoneRegistry::list(&registry).unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].secret_ref, secret_ref);
        assert_eq!(tombstones[0].reason.as_str(), "reviewed destroy record");

        let finalize_config = LifecycleDestroyFinalizeConfig {
            secret_ref: secret_ref.clone(),
            metadata_file: Some(metadata_file.clone()),
        };
        let mut finalize_audit = AuditWrite::accepting();
        let finalized = finalize_lifecycle_destroy_with(
            &finalize_config,
            &metadata_file,
            fixture_store_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            &registry,
            &principal,
            &mut finalize_audit,
        )
        .await
        .unwrap();

        assert_eq!(finalized.from, "pending_delete");
        assert_eq!(finalized.to, "destroyed");
        assert_eq!(finalized.reason_code, "destroy_metadata_finalized");
        assert!(finalized.metadata_finalized);
        assert!(!finalized.value_returned);
        assert!(!finalized.provider_deleted);
        assert_eq!(
            fixture_lifecycle_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            SecretLifecycle::Destroyed
        );

        let mut reconcile_audit = AuditWrite::accepting();
        let rows = build_lifecycle_destroy_reconcile_with(
            fixture_store_from_metadata_overlay(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::HighValue,
                &metadata_file,
            ),
            &registry,
            &principal,
            &mut reconcile_audit,
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].secret_ref, secret_ref);
        assert_eq!(rows[0].status, "ok");
        assert_eq!(rows[0].reason_code, "destroy_tombstone_reconcile_ok");
        assert_eq!(rows[0].metadata_lifecycle, "destroyed");
        assert_eq!(rows[0].tombstone_state, "present");
        assert_eq!(rows[0].action, "none");
        assert!(!rows[0].action_required);
        assert!(!rows[0].value_returned);
        assert!(!rows[0].provider_deleted);

        assert!(
            !format!("{disable:?}{pending:?}{record:?}{finalized:?}{rows:?}")
                .contains("expected-canary")
        );
        assert_eq!(disable_audit.events().len(), 1);
        assert_eq!(pending_audit.events().len(), 1);
        assert_eq!(record_audit.events().len(), 1);
        assert_eq!(finalize_audit.events().len(), 1);
        assert_eq!(reconcile_audit.events().len(), 1);
        for event in disable_audit
            .events()
            .iter()
            .chain(pending_audit.events())
            .chain(record_audit.events())
            .chain(finalize_audit.events())
            .chain(reconcile_audit.events())
        {
            assert!(!event.value_returned);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_stale_report_reports_value_free_rows_and_audit() {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let config = LifecycleStaleReportConfig {
            evidence_file: None,
            stale_after: Duration::from_secs(60),
            missing_evidence_after: Duration::from_secs(30),
        };
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut evidence = BTreeMap::new();
        evidence.insert(
            secret_ref.clone(),
            SecretAgeEvidence::new(secret_ref.clone())
                .with_last_used_at(now - Duration::from_secs(61)),
        );
        let mut audit = AuditWrite::accepting();

        let rows = build_lifecycle_stale_report_with(
            &config,
            fixture_store_with_class_and_lifecycle(
                &secret_ref,
                &name,
                &profile_id,
                SecretClass::Normal,
                SecretLifecycle::Active,
            ),
            &evidence,
            &fixture_principal(),
            &mut audit,
            now,
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].secret_ref, secret_ref);
        assert_eq!(rows[0].status, StaleSecretStatus::Stale);
        assert_eq!(rows[0].reason_code, "stale_activity_age_exceeded");
        assert!(rows[0].action_required);
        assert_eq!(rows[0].action, "review_rotate_or_disable");
        assert_eq!(rows[0].last_activity_age_seconds, Some(61));
        assert!(!rows[0].value_returned);
        assert!(!format!("{rows:?}").contains("expected-canary"));
        assert_eq!(audit.events().len(), 1);
        assert_eq!(audit.events()[0].action, AuditAction::SecretStalenessReport);
        assert_eq!(audit.events()[0].reason_code, "stale_activity_age_exceeded");
        assert!(!audit.events()[0].value_returned);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_success_records_lifecycle_use_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(dir.path());
        let mut harness = FixtureManagedCommandHarness::new(vec![
            "-c".to_string(),
            "printf 'used:%s' \"$GITHUB_TOKEN\"".to_string(),
        ])
        .await;
        let config = harness.config();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(2);

        let outcome = run_managed_command_with(&config, harness.runner_mut())
            .await
            .unwrap();
        record_managed_command_evidence(&outcome, &registry, at).unwrap();

        let evidence = registry.list().unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].secret_ref, outcome.secret_ref);
        assert_eq!(evidence[0].last_used_at, Some(at));
        assert_eq!(evidence[0].last_rotated_at, None);
        assert!(!format!("{evidence:?}").contains("expected-canary"));
    }

    #[test]
    fn generated_rotation_success_records_lifecycle_rotation_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(dir.path());
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(30);
        let outcome = RotationOutcome::rotated(secret_ref.clone());

        record_rotation_evidence(&outcome, &registry, at).unwrap();

        let evidence = registry.list().unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].secret_ref, secret_ref);
        assert_eq!(evidence[0].last_used_at, None);
        assert_eq!(evidence[0].last_rotated_at, Some(at));
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

        let cross_kind_duplicate = format!(
            "{}\n{}",
            managed_profile_toml(&secret_ref, &allowed_args),
            env_file_profile_toml(&secret_ref, &PathBuf::from("/run/janus/env/fixture.env"))
                .replace("profile.service_env", "profile.canary")
        );
        let err = ManagedCommandProfileCatalog::parse(&cross_kind_duplicate).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[cfg(unix)]
    #[test]
    fn managed_command_preflight_uses_only_reviewed_manifest_and_filesystem_state() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("pharos-deploy");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).unwrap();
        let secret_ref = SecretRef::new("sec_pharos_deploy_hsb0").unwrap();
        let allowed_args = vec!["deploy".to_string(), "hsb0".to_string()];
        let manifest = managed_profile_toml(&secret_ref, &allowed_args).replace(
            "binary = \"/bin/sh\"",
            &format!(
                "binary = {}",
                toml_string(binary.to_string_lossy().as_ref())
            ),
        );
        let profiles = ManagedCommandProfileCatalog::parse(&manifest).unwrap();
        let config = RunManagedPreflightConfig {
            profile_id: ProfileId::new("profile.canary").unwrap(),
            requested_args: allowed_args,
        };

        let plan = run_managed_command_preflight_with(&config, &profiles).unwrap();

        assert_eq!(plan.binary, fs::canonicalize(&binary).unwrap());
        assert_eq!(plan.args, ["deploy", "hsb0"]);
        assert_eq!(plan.secret_ref, secret_ref);
        assert!(!plan.value_returned);

        fs::set_permissions(&plan.binary, fs::Permissions::from_mode(0o520)).unwrap();
        let err = run_managed_command_preflight_with(&config, &profiles).unwrap_err();
        assert!(err
            .to_string()
            .contains("must not be group or world writable"));
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
    type FixtureEnvFileRunner = ProfileManifestEnvFileRunner<
        InMemoryPermitRegistry,
        ApprovedUseExecutor<MockStore, AuditWrite>,
        FixedManagedCommandClock,
    >;

    #[cfg(unix)]
    struct FixtureEnvFileHarness {
        runner: FixtureEnvFileRunner,
        permit_token: PermitToken,
        profile_id: ProfileId,
        output_path: PathBuf,
        hash_output_path: Option<PathBuf>,
    }

    #[cfg(unix)]
    impl FixtureEnvFileHarness {
        async fn new(output_dir: &Path) -> Self {
            Self::new_with_optional_hash_sidecar(output_dir, false).await
        }

        async fn new_with_hash_sidecar(output_dir: &Path) -> Self {
            Self::new_with_optional_hash_sidecar(output_dir, true).await
        }

        async fn new_with_optional_hash_sidecar(
            output_dir: &Path,
            include_hash_sidecar: bool,
        ) -> Self {
            let project = ProjectId::new("janus").unwrap();
            let name = SecretName::new("CANARY").unwrap();
            let secret_ref = SecretRef::for_manifest_entry(&project, &name);
            let profile_id = ProfileId::new("profile.service_env").unwrap();
            let executor_ref = ExecutorRef::new("janus-run@fixture").unwrap();
            let destination = Destination::new("fixture-service").unwrap();
            let store = fixture_store(&secret_ref, &name, &profile_id);
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
                        destination,
                        purpose: Purpose::new("fixture service env").unwrap(),
                    },
                    &principal,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .unwrap();
            let output_path = output_dir.join("service.env");
            let hash_output_path =
                include_hash_sidecar.then(|| output_dir.join("service-token-hash.json"));
            let profile_toml = if let Some(hash_output_path) = &hash_output_path {
                env_file_profile_with_hash_sidecar_toml(&secret_ref, &output_path, hash_output_path)
            } else {
                env_file_profile_toml(&secret_ref, &output_path)
            };
            let profile_catalog = ManagedCommandProfileCatalog::parse(&profile_toml).unwrap();
            let mut permits = InMemoryPermitRegistry::default();
            let permit_token = permits.insert(permit);

            Self {
                runner: ProfileManifestEnvFileRunner {
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
                output_path,
                hash_output_path,
            }
        }

        fn config(&self) -> EnvFileConfig {
            EnvFileConfig {
                profile_id: self.profile_id.clone(),
                permit: self.permit_token.clone(),
            }
        }

        fn runner_mut(&mut self) -> &mut FixtureEnvFileRunner {
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
    #[tokio::test]
    async fn env_file_fixture_path_writes_private_file_and_records_lifecycle_evidence() {
        let output_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let evidence_dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(evidence_dir.path());
        let mut harness = FixtureEnvFileHarness::new(output_dir.path()).await;
        let config = harness.config();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(3);

        let outcome = run_env_file_with(&config, harness.runner_mut())
            .await
            .unwrap();
        record_secret_use_evidence(&outcome.secret_ref, &registry, at).unwrap();

        assert_eq!(outcome.output_path, harness.output_path);
        assert_eq!(outcome.reason_code, "ok");
        assert!(!outcome.value_returned);
        assert_eq!(
            std::fs::read_to_string(&outcome.output_path).unwrap(),
            "SERVICE_TOKEN=expected-canary\n"
        );
        let metadata = std::fs::symlink_metadata(&outcome.output_path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let evidence = registry.list().unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].secret_ref, outcome.secret_ref);
        assert_eq!(evidence[0].last_used_at, Some(at));
        assert_eq!(evidence[0].last_rotated_at, None);
        assert!(!format!("{evidence:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_fixture_path_writes_private_hash_sidecar() {
        let output_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let mut harness = FixtureEnvFileHarness::new_with_hash_sidecar(output_dir.path()).await;
        let config = harness.config();

        let outcome = run_env_file_with(&config, harness.runner_mut())
            .await
            .unwrap();
        let hash_output_path = harness.hash_output_path.as_ref().expect("hash sidecar");

        assert_eq!(
            outcome.hash_output_path.as_deref(),
            Some(hash_output_path.as_path())
        );
        assert_eq!(outcome.hash_format, Some("pharos-beacon-token-hashes-v1"));
        assert!(!outcome.value_returned);
        assert_eq!(
            std::fs::read_to_string(&outcome.output_path).unwrap(),
            "SERVICE_TOKEN=expected-canary\n"
        );
        let sidecar = std::fs::read_to_string(hash_output_path).unwrap();
        assert!(sidecar.contains("\"schema\": \"inspr.pharos.beacon-token-hashes.v1\""));
        assert!(sidecar.contains("\"name\": \"ares\""));
        assert!(!sidecar.contains("expected-canary"));
        let metadata = std::fs::symlink_metadata(hash_output_path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_preflight_fixture_path_checks_target_without_writing() {
        let output_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let harness = FixtureEnvFileHarness::new(output_dir.path()).await;
        let config = EnvFilePreflightConfig {
            profile_id: harness.profile_id.clone(),
        };

        let outcome = run_env_file_preflight_with(&config, &harness.runner.profiles).unwrap();

        assert_eq!(outcome.output_path, harness.output_path);
        assert_eq!(outcome.profile_id, harness.profile_id);
        assert_eq!(outcome.consumer_ref.as_str(), "consumer.fixture_service");
        assert_eq!(outcome.reason_code, "ok");
        assert!(!outcome.value_returned);
        assert!(!outcome.output_path.exists());
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_preflight_fixture_path_checks_hash_sidecar_without_writing() {
        let output_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let harness = FixtureEnvFileHarness::new_with_hash_sidecar(output_dir.path()).await;
        let config = EnvFilePreflightConfig {
            profile_id: harness.profile_id.clone(),
        };

        let outcome = run_env_file_preflight_with(&config, &harness.runner.profiles).unwrap();
        let hash_output_path = harness.hash_output_path.as_ref().expect("hash sidecar");

        assert_eq!(
            outcome.hash_output_path.as_deref(),
            Some(hash_output_path.as_path())
        );
        assert_eq!(outcome.hash_format, Some("pharos-beacon-token-hashes-v1"));
        assert!(!outcome.value_returned);
        assert!(!outcome.output_path.exists());
        assert!(!hash_output_path.exists());
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_fixture_path_rejects_wrong_permit_before_write() {
        let output_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let mut harness = FixtureEnvFileHarness::new(output_dir.path()).await;
        let mut config = harness.config();
        config.permit = PermitToken::new("use_wrongfixture").unwrap();

        let err = run_env_file_with(&config, harness.runner_mut())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("permit"));
        assert!(!err.to_string().contains("use_wrongfixture"));
        assert!(!harness.output_path.exists());
    }

    #[cfg(unix)]
    fn fixture_store(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
    ) -> MockStore {
        fixture_store_with_class_and_lifecycle(
            secret_ref,
            name,
            profile_id,
            SecretClass::Normal,
            SecretLifecycle::Active,
        )
    }

    #[cfg(unix)]
    fn fixture_store_with_class(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
    ) -> MockStore {
        fixture_store_with_class_and_lifecycle(
            secret_ref,
            name,
            profile_id,
            class,
            SecretLifecycle::Active,
        )
    }

    #[cfg(unix)]
    fn fixture_store_with_class_and_lifecycle(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
        lifecycle: SecretLifecycle,
    ) -> MockStore {
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(class),
            lifecycle,
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
    fn fixture_store_from_metadata_overlay(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
        metadata_file: &Path,
    ) -> MockStore {
        let entries = fixture_metadata_entries_from_overlay(
            secret_ref,
            name,
            profile_id,
            class,
            metadata_file,
        );
        MockStore::new(ManifestCatalog::new(entries).unwrap())
            .with_value(name.clone(), b"expected-canary".to_vec())
            .unwrap()
    }

    #[cfg(unix)]
    fn fixture_lifecycle_from_metadata_overlay(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
        metadata_file: &Path,
    ) -> SecretLifecycle {
        fixture_metadata_entries_from_overlay(secret_ref, name, profile_id, class, metadata_file)[0]
            .lifecycle
    }

    #[cfg(unix)]
    fn fixture_metadata_entries_from_overlay(
        secret_ref: &SecretRef,
        name: &SecretName,
        profile_id: &ProfileId,
        class: SecretClass,
        metadata_file: &Path,
    ) -> Vec<SecretMeta> {
        let mut entries = vec![SecretMeta {
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
        }];
        SecretMetadataOverlay::load_toml_file(metadata_file)
            .unwrap()
            .apply_to_entries(&mut entries)
            .unwrap();
        entries
    }

    #[cfg(unix)]
    fn fixture_store_with_lifecycle_entries(
        entries: &[(SecretRef, SecretName, SecretLifecycle)],
    ) -> MockStore {
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let catalog = ManifestCatalog::new(
            entries
                .iter()
                .map(|(secret_ref, name, lifecycle)| SecretMeta {
                    secret_ref: secret_ref.clone(),
                    name: name.clone(),
                    label: SafeLabel::new("Canary token").unwrap(),
                    scope: ScopeRef::new("janus/dev").unwrap(),
                    owner: Some(OwnerRef::new("infra").unwrap()),
                    classification: Some(SecretClass::Normal),
                    lifecycle: *lifecycle,
                    required: true,
                    trust_level: TrustLevel::L1,
                    allowed_uses: vec![profile_id.clone()],
                })
                .collect(),
        )
        .unwrap();
        MockStore::new(catalog)
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
        let manifest = format!(
            r#"
                [validation."deploy-smoke"]
                program = {}
            "#,
            toml_string(true_program()),
        );
        let mut hooks = ManifestRotationHooks {
            manifest: HookManifest::parse(&manifest).unwrap(),
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

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs2::FileExt;
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, ConsumerDescriptor, ConsumerRef, JanusError,
    LifecycleTransitionPolicy, OwnerRef, Principal, PrincipalChain, PrincipalId, PrincipalKind,
    ProfileId, ReleaseAdmission, ReloadMethod, SafeLabel, ScopeRef, SecretClass, SecretDescriptor,
    SecretLifecycle, SecretMetadataOverlay, SecretName, SecretRef, SecretStore,
    SecretTombstoneRequest, SecretValue, Severity, TombstonePolicy,
};
use janus_forge::{ConsumerRotationHooks, GeneratedAlphabet, GeneratedValuePolicy};
use janus_local::{FileTombstoneRegistry, JsonlAuditSink, TombstoneRegistry};
use janus_provider_age::{AgeQuarantineMaterial, AgeRollbackMaterial, AgeSecretStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PLAN_SCHEMA_VERSION: u8 = 1;
const JOURNAL_SCHEMA_VERSION: u8 = 1;
const MAX_PLAN_BYTES: usize = 64 * 1024;
const MAX_BINDING_FILE_BYTES: usize = 1024 * 1024;
const MAX_IMPORT_BYTES: usize = 64 * 1024;
const MAX_REVIEW_AGE: Duration = Duration::from_secs(366 * 24 * 60 * 60);
const MAX_ENTRY_JOURNALS: usize = 4096;
const REMOVAL_TOMBSTONE_RETAIN_SECONDS: u64 = 366 * 24 * 60 * 60;
const TOMBSTONE_DIR_ENV: &str = "JANUS_LIFECYCLE_TOMBSTONE_DIR";

#[path = "lifecycle_entry/web_transaction.rs"]
pub(super) mod web_transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryOperation {
    Preflight,
    Apply,
    Activate,
    Rollback,
    Status,
}

impl EntryOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Apply => "apply",
            Self::Activate => "activate",
            Self::Rollback => "rollback",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryCommand {
    operation: EntryOperation,
    plan: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct EntryPlanFile {
    schema_version: u8,
    operation_id: String,
    secret_ref: String,
    expected_scope_ref: String,
    expected_label: String,
    expected_owner: String,
    expected_classification: String,
    profile_id: String,
    consumer_ref: String,
    rotation_strategy: String,
    validation_probes: Vec<String>,
    reload_strategy: String,
    input_max_bytes: usize,
    preflight_max_age_seconds: u64,
    secretspec_manifest: PathBuf,
    secretspec_profile: String,
    age_store_dir: PathBuf,
    metadata_file: PathBuf,
    profile_manifest: PathBuf,
    hook_manifest: PathBuf,
    state_dir: PathBuf,
    audit_path: PathBuf,
    reviewed_by: String,
    reviewed_at_unix_secs: u64,
    activation_reason: String,
    source: EntrySource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum EntrySource {
    Generated { alphabet: String, length: usize },
    Import,
    Remove,
}

impl EntrySource {
    pub(super) fn mode(&self) -> &'static str {
        match self {
            Self::Generated { .. } => "generated",
            Self::Import => "import",
            Self::Remove => "remove",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct EntryPlan {
    file: EntryPlanFile,
    fingerprint: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum EntryPhase {
    Preflighted,
    Applying,
    Stored,
    Validated,
    Activating,
    Completed,
    Destroyed,
    RollingBack,
    RolledBack,
    Failed,
}

impl EntryPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Preflighted => "preflighted",
            Self::Applying => "applying",
            Self::Stored => "stored",
            Self::Validated => "validated",
            Self::Activating => "activating",
            Self::Completed => "completed",
            Self::Destroyed => "destroyed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EntryJournal {
    schema_version: u8,
    operation_id: String,
    plan_fingerprint: String,
    target_fingerprint: String,
    release_fingerprint: String,
    secret_ref: String,
    mode: String,
    #[serde(
        default = "default_create_operation_kind",
        skip_serializing_if = "is_create_operation_kind"
    )]
    operation_kind: String,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quarantine_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    purge_not_before_unix_secs: u64,
    phase: EntryPhase,
    preflighted_at_unix_secs: u64,
    created_by_operation: bool,
    reason_code: String,
    integrity_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EntryStatus {
    pub(super) operation_id: String,
    pub(super) secret_ref: String,
    pub(super) mode: String,
    pub(super) operation_kind: String,
    pub(super) generation: u64,
    pub(super) phase: EntryPhase,
    pub(super) reason_code: String,
    pub(super) value_returned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EntryJournalSummary {
    pub operation_id: String,
    pub secret_ref: SecretRef,
    pub operation_kind: String,
    pub generation: u64,
    pub phase: String,
    pub reason_code: String,
    pub preflighted_at_unix_secs: u64,
    pub release_matches: bool,
}

pub(super) struct EntryTransaction {
    plan: EntryPlan,
    release: ReleaseAdmission,
    principal: PrincipalChain,
    operation_kind: ManagedEntryOperationKind,
    generation_floor: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ManagedEntryOperationKind {
    Create,
    Replace,
    Remove,
}

impl ManagedEntryOperationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Replace => "replace",
            Self::Remove => "remove",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "create" => Ok(Self::Create),
            "replace" => Ok(Self::Replace),
            "remove" => Ok(Self::Remove),
            _ => anyhow::bail!(
                "lifecycle entry denied reason_code=entry_operation_kind_invalid value_returned=false"
            ),
        }
    }
}

struct BoundContext {
    store: AgeSecretStore,
    descriptor: SecretDescriptor,
    consumer: ConsumerDescriptor,
    hooks: super::ManifestRotationHooks,
    target_fingerprint: String,
}

#[derive(Clone, Copy)]
enum ExpectedPresence {
    Absent,
    Present,
    Either,
}

struct EntryLock {
    _file: File,
}

pub(super) fn is_lifecycle_entry_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "lifecycle-entry")
}

pub(super) async fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    if let Err(error) = run_inner(args, release).await {
        anyhow::bail!(
            "janusd-admin lifecycle-entry denied reason_code={} value_returned=false",
            stable_error_reason(&error)
        );
    }
    Ok(())
}

async fn run_inner(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let command = parse(args)?;
    if command.operation == EntryOperation::Apply {
        let plan = load_plan(&command.plan).context("entry plan denied")?;
        if matches!(plan.file.source, EntrySource::Import) && std::io::stdin().is_terminal() {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_import_tty_denied value_returned=false"
            );
        }
        let transaction = EntryTransaction::new(plan, release, entry_principal_from_env()?)?;
        let status = match transaction.plan.file.source {
            EntrySource::Import => {
                let stdin = std::io::stdin();
                transaction
                    .apply_import(&mut stdin.lock(), SystemTime::now())
                    .await
            }
            EntrySource::Generated { .. } => transaction.apply_generated(SystemTime::now()).await,
            EntrySource::Remove => anyhow::bail!(
                "lifecycle entry denied reason_code=entry_remove_cli_denied value_returned=false"
            ),
        }
        .context("lifecycle entry command failed closed")?;
        emit_status(command.operation, &status);
        return Ok(());
    }

    let transaction = EntryTransaction::load(&command.plan, release, entry_principal_from_env()?)
        .context("entry plan denied")?;
    let status = match command.operation {
        EntryOperation::Preflight => transaction.preflight(SystemTime::now()).await,
        EntryOperation::Activate => transaction.activate(SystemTime::now()).await,
        EntryOperation::Rollback => transaction.rollback().await,
        EntryOperation::Status => transaction.status().await,
        EntryOperation::Apply => unreachable!("apply handled above"),
    }
    .context("lifecycle entry command failed closed")?;
    emit_status(command.operation, &status);
    Ok(())
}

pub(super) fn stable_error_reason(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<JanusError>() {
            return match error {
                JanusError::PolicyDenied { reason_code, .. } => reason_code,
                JanusError::AuditUnavailable { .. } => "entry_audit_unavailable",
                JanusError::NotFound { .. } => "entry_target_missing",
                JanusError::NotInManifest { .. } => "entry_target_not_declared",
                JanusError::StoreUnavailable { .. } => "entry_store_unavailable",
                JanusError::InvalidIdentifier { .. } | JanusError::InvalidManifest { .. } => {
                    "entry_contract_invalid"
                }
                _ => "entry_transaction_denied",
            };
        }
    }
    const KNOWN: &[&str] = &[
        "entry_import_tty_denied",
        "entry_operation_replay",
        "entry_apply_phase_invalid",
        "entry_activation_phase_invalid",
        "entry_completed_rollback_denied",
        "entry_orphan_target_present",
        "entry_target_changed",
        "entry_preflight_stale",
        "entry_journal_binding_mismatch",
        "entry_journal_tampered",
        "entry_import_empty",
        "entry_import_oversize",
        "entry_import_trailing_data",
        "entry_removal_contract_invalid",
        "entry_removal_deadline_invalid",
        "entry_removal_finalize_phase_invalid",
        "entry_removal_purge_not_due",
        "entry_removal_value_denied",
        "entry_removal_activation_denied",
        "entry_removal_detach_boundary_crossed",
        "entry_removal_restore_unproven",
        "entry_removal_tombstone_conflict",
    ];
    let rendered = error.to_string();
    KNOWN
        .iter()
        .copied()
        .find(|reason| rendered.contains(reason))
        .unwrap_or("entry_transaction_denied")
}

fn parse(args: &[String]) -> Result<EntryCommand> {
    let [command, operation, plan_flag, plan] = args else {
        anyhow::bail!(
            "usage: janusd-admin lifecycle-entry preflight|apply|activate|rollback|status --plan PATH"
        );
    };
    if command != "lifecycle-entry" || plan_flag != "--plan" || plan.is_empty() {
        anyhow::bail!(
            "usage: janusd-admin lifecycle-entry preflight|apply|activate|rollback|status --plan PATH"
        );
    }
    let operation = match operation.as_str() {
        "preflight" => EntryOperation::Preflight,
        "apply" => EntryOperation::Apply,
        "activate" => EntryOperation::Activate,
        "rollback" => EntryOperation::Rollback,
        "status" => EntryOperation::Status,
        _ => anyhow::bail!("unsupported lifecycle entry operation"),
    };
    Ok(EntryCommand {
        operation,
        plan: PathBuf::from(plan),
    })
}

fn emit_status(operation: EntryOperation, status: &EntryStatus) {
    println!(
        "janusd-admin lifecycle-entry {} ok operation_id={} secret_ref={} mode={} phase={} reason_code={} value_returned={}",
        operation.as_str(),
        status.operation_id,
        status.secret_ref,
        status.mode,
        status.phase.as_str(),
        status.reason_code,
        status.value_returned,
    );
}

fn entry_principal_from_env() -> Result<PrincipalChain> {
    let executor = std::env::var("JANUS_LIFECYCLE_ENTRY_EXECUTOR")
        .unwrap_or_else(|_| "janusd-lifecycle-entry".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

impl EntryTransaction {
    fn load(path: &Path, release: ReleaseAdmission, principal: PrincipalChain) -> Result<Self> {
        Self::new(load_plan(path)?, release, principal)
    }

    pub(super) fn new(
        plan: EntryPlan,
        release: ReleaseAdmission,
        principal: PrincipalChain,
    ) -> Result<Self> {
        Self::new_managed(
            plan,
            release,
            principal,
            ManagedEntryOperationKind::Create,
            0,
        )
    }

    pub(super) fn new_managed(
        plan: EntryPlan,
        release: ReleaseAdmission,
        principal: PrincipalChain,
        operation_kind: ManagedEntryOperationKind,
        generation_floor: u64,
    ) -> Result<Self> {
        let expected_scope = ScopeRef::from_opaque(plan.file.expected_scope_ref.clone())?;
        if expected_scope != principal.scope {
            return Err(JanusError::policy_denied(
                "entry_scope_mismatch",
                "entry plan scope does not match the runtime principal",
            )
            .into());
        }
        if !release.allows_secret_use() {
            return Err(JanusError::policy_denied(
                "entry_release_denied",
                "release admission denied the entry transaction",
            )
            .into());
        }
        Ok(Self {
            plan,
            release,
            principal,
            operation_kind,
            generation_floor,
        })
    }

    pub(super) async fn preflight(&self, now: SystemTime) -> Result<EntryStatus> {
        let _lock = self.lock()?;
        if self.journal_path().exists() {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_operation_replay value_returned=false"
            );
        }
        let generation = self.next_generation()?;
        let context = self
            .bound_context(self.preflight_presence(), self.preflight_lifecycles())
            .await?;
        let mut audit = self.audit()?;
        self.audit_entry(
            &mut audit,
            AuditOutcome::Allowed,
            "entry_preflight_ok",
            Severity::Notice,
        )?;
        let journal = EntryJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id: self.plan.file.operation_id.clone(),
            plan_fingerprint: self.plan.fingerprint.clone(),
            target_fingerprint: context.target_fingerprint,
            release_fingerprint: release_fingerprint(&self.release),
            secret_ref: self.plan.file.secret_ref.clone(),
            mode: self.plan.file.source.mode().to_string(),
            operation_kind: self.operation_kind.as_str().to_string(),
            generation,
            rollback_id: None,
            quarantine_id: None,
            purge_not_before_unix_secs: 0,
            phase: EntryPhase::Preflighted,
            preflighted_at_unix_secs: unix_seconds(now)?,
            created_by_operation: false,
            reason_code: "entry_preflight_ok".to_string(),
            integrity_hash: String::new(),
        };
        self.write_journal(journal.clone())?;
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn apply_generated(&self, now: SystemTime) -> Result<EntryStatus> {
        let EntrySource::Generated { alphabet, length } = &self.plan.file.source else {
            anyhow::bail!("entry source mode mismatch");
        };
        let policy = GeneratedValuePolicy::new(parse_alphabet(alphabet)?, *length)?;
        self.apply_value_after_preflight(now, || Ok(policy.generate_value()))
            .await
    }

    pub(super) async fn apply_import<R>(
        &self,
        reader: &mut R,
        now: SystemTime,
    ) -> Result<EntryStatus>
    where
        R: Read,
    {
        if !matches!(self.plan.file.source, EntrySource::Import) {
            anyhow::bail!("entry source mode mismatch");
        }
        self.apply_value_after_preflight(now, || {
            read_import_value(reader, self.plan.file.input_max_bytes)
        })
        .await
    }

    pub(super) async fn apply_import_value(
        &self,
        value: SecretValue,
        now: SystemTime,
    ) -> Result<EntryStatus> {
        if !matches!(self.plan.file.source, EntrySource::Import) {
            anyhow::bail!("entry source mode mismatch");
        }
        if value.expose_bytes().is_empty() {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_import_empty value_returned=false"
            );
        }
        if value.expose_bytes().len() > self.plan.file.input_max_bytes {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_import_oversize value_returned=false"
            );
        }
        if matches!(value.expose_bytes().last(), Some(b'\n' | b'\r')) {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_import_trailing_data value_returned=false"
            );
        }
        self.apply_value_after_preflight(now, || Ok(value)).await
    }

    pub(super) async fn prepare_removal(
        &self,
        now: SystemTime,
        purge_not_before_unix_secs: u64,
    ) -> Result<EntryStatus> {
        if self.operation_kind != ManagedEntryOperationKind::Remove
            || !matches!(self.plan.file.source, EntrySource::Remove)
        {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_contract_invalid value_returned=false"
            );
        }
        let now_seconds = unix_seconds(now)?;
        if purge_not_before_unix_secs <= now_seconds {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_deadline_invalid value_returned=false"
            );
        }
        let _lock = self.lock()?;
        let mut journal = if self.journal_path().exists() {
            let existing = self.read_bound_journal()?;
            if existing.operation_kind != "remove"
                || existing.purge_not_before_unix_secs != purge_not_before_unix_secs
            {
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_operation_replay value_returned=false"
                );
            }
            match existing.phase {
                EntryPhase::Preflighted => existing,
                EntryPhase::Validated
                | EntryPhase::Activating
                | EntryPhase::Completed
                | EntryPhase::Destroyed => return Ok(status_from_journal(&existing)),
                _ => {
                    anyhow::bail!(
                        "lifecycle entry denied reason_code=entry_operation_replay value_returned=false"
                    );
                }
            }
        } else {
            let generation = self.next_generation()?;
            let context = self
                .bound_context(ExpectedPresence::Present, &[SecretLifecycle::Active])
                .await?;
            let journal = EntryJournal {
                schema_version: JOURNAL_SCHEMA_VERSION,
                operation_id: self.plan.file.operation_id.clone(),
                plan_fingerprint: self.plan.fingerprint.clone(),
                target_fingerprint: context.target_fingerprint.clone(),
                release_fingerprint: release_fingerprint(&self.release),
                secret_ref: self.plan.file.secret_ref.clone(),
                mode: "remove".to_string(),
                operation_kind: "remove".to_string(),
                generation,
                rollback_id: None,
                quarantine_id: None,
                purge_not_before_unix_secs,
                phase: EntryPhase::Preflighted,
                preflighted_at_unix_secs: now_seconds,
                created_by_operation: false,
                reason_code: "entry_removal_preflight_ok".to_string(),
                integrity_hash: String::new(),
            };
            self.write_journal(journal.clone())?;
            journal
        };
        let context = self
            .bound_context(
                ExpectedPresence::Present,
                &[SecretLifecycle::Active, SecretLifecycle::Disabled],
            )
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let mut audit = self.audit()?;
        if context.descriptor.lifecycle == SecretLifecycle::Active {
            LifecycleTransitionPolicy::transition(
                &context.descriptor,
                SecretLifecycle::Disabled,
                SafeLabel::new("managed service binding detached")?,
                &self.principal,
                &mut audit,
            )?;
            if let Err(error) =
                self.set_lifecycle(&context.descriptor.name, SecretLifecycle::Disabled)
            {
                journal.phase = EntryPhase::Failed;
                journal.reason_code = "entry_removal_revoke_failed".to_string();
                let _ = self.write_journal(journal);
                return Err(error);
            }
        }
        let disabled = self
            .bound_context(ExpectedPresence::Present, &[SecretLifecycle::Disabled])
            .await?;
        self.ensure_target_binding(&journal, &disabled)?;
        journal.phase = EntryPhase::Validated;
        journal.reason_code = "entry_removal_delivery_revoked".to_string();
        self.write_journal(journal.clone())?;
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn finalize_removal(
        &self,
        now: SystemTime,
        purge_not_before_unix_secs: u64,
    ) -> Result<EntryStatus> {
        if self.operation_kind != ManagedEntryOperationKind::Remove {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_contract_invalid value_returned=false"
            );
        }
        let _lock = self.lock()?;
        let mut journal = self.read_bound_journal()?;
        if journal.phase == EntryPhase::Completed {
            return Ok(status_from_journal(&journal));
        }
        if !matches!(
            journal.phase,
            EntryPhase::Validated | EntryPhase::Activating
        ) || journal.purge_not_before_unix_secs != purge_not_before_unix_secs
        {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_finalize_phase_invalid value_returned=false"
            );
        }
        let mut context = self
            .bound_context(
                ExpectedPresence::Either,
                &[SecretLifecycle::Disabled, SecretLifecycle::PendingDelete],
            )
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let quarantine_id = journal
            .quarantine_id
            .clone()
            .unwrap_or_else(|| deterministic_quarantine_id(&journal.operation_id));
        if journal.phase == EntryPhase::Validated {
            self.ensure_fresh(&journal, now)?;
            journal.quarantine_id = Some(quarantine_id.clone());
            journal.phase = EntryPhase::Activating;
            journal.reason_code = "entry_removal_quarantine_started".to_string();
            self.write_journal(journal.clone())?;
        }
        context
            .store
            .quarantine_with_id(
                &context.descriptor.name,
                quarantine_id,
                purge_not_before_unix_secs,
            )
            .await
            .context("entry removal quarantine denied")?;
        if context.descriptor.lifecycle == SecretLifecycle::Disabled {
            let mut audit = self.audit()?;
            LifecycleTransitionPolicy::transition(
                &context.descriptor,
                SecretLifecycle::PendingDelete,
                SafeLabel::new("managed service secret quarantined")?,
                &self.principal,
                &mut audit,
            )?;
            self.set_lifecycle(&context.descriptor.name, SecretLifecycle::PendingDelete)?;
        }
        let quarantined = self
            .bound_context(ExpectedPresence::Absent, &[SecretLifecycle::PendingDelete])
            .await?;
        self.ensure_target_binding(&journal, &quarantined)?;
        journal.phase = EntryPhase::Completed;
        journal.reason_code = "entry_removal_quarantined".to_string();
        self.write_journal(journal.clone())?;
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn purge_removal(&self, now: SystemTime) -> Result<EntryStatus> {
        if self.operation_kind != ManagedEntryOperationKind::Remove {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_contract_invalid value_returned=false"
            );
        }
        let _lock = self.lock()?;
        let mut journal = self.read_bound_journal()?;
        if journal.phase == EntryPhase::Destroyed {
            return Ok(status_from_journal(&journal));
        }
        if journal.phase != EntryPhase::Completed
            || unix_seconds(now)? < journal.purge_not_before_unix_secs
        {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_purge_not_due value_returned=false"
            );
        }
        let mut context = self
            .bound_context(ExpectedPresence::Absent, &[SecretLifecycle::PendingDelete])
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let quarantine = AgeQuarantineMaterial {
            secret_ref: self.secret_ref()?,
            quarantine_id: journal.quarantine_id.clone().ok_or_else(|| {
                JanusError::policy_denied(
                    "entry_removal_state_invalid",
                    "removal quarantine binding is missing",
                )
            })?,
            purge_not_before_unix_secs: journal.purge_not_before_unix_secs,
            value_returned: false,
        };
        self.record_removal_tombstone(&context.descriptor, journal.purge_not_before_unix_secs)?;
        context
            .store
            .purge_quarantine_if_due(&quarantine, now)
            .await
            .context("entry removal purge denied")?;
        self.set_lifecycle(&context.descriptor.name, SecretLifecycle::Destroyed)?;
        let destroyed = self
            .bound_context(ExpectedPresence::Absent, &[SecretLifecycle::Destroyed])
            .await?;
        self.ensure_target_binding(&journal, &destroyed)?;
        journal.phase = EntryPhase::Destroyed;
        journal.reason_code = "entry_removal_destroyed".to_string();
        self.write_journal(journal.clone())?;
        Ok(status_from_journal(&journal))
    }

    async fn apply_value_after_preflight<F>(
        &self,
        now: SystemTime,
        read_value: F,
    ) -> Result<EntryStatus>
    where
        F: FnOnce() -> Result<SecretValue>,
    {
        let _lock = self.lock()?;
        let mut journal = self.read_bound_journal()?;
        if journal.phase != EntryPhase::Preflighted {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_apply_phase_invalid value_returned=false"
            );
        }
        self.ensure_fresh(&journal, now)?;
        let mut context = self
            .bound_context(self.preflight_presence(), self.preflight_lifecycles())
            .await?;
        self.ensure_target_binding(&journal, &context)?;

        // Import bytes are read only after every value-free binding is valid.
        let value = read_value()?;
        if self.operation_kind == ManagedEntryOperationKind::Replace {
            journal.rollback_id = Some(replacement_rollback_id(
                &journal.operation_id,
                journal.generation,
            ));
        }
        journal.phase = EntryPhase::Applying;
        journal.reason_code = self.reason("entry_apply_started", "entry_replacement_started");
        self.write_journal(journal.clone())?;
        let mut audit = match self.audit() {
            Ok(audit) => audit,
            Err(error) => {
                journal.phase = EntryPhase::RolledBack;
                journal.reason_code = self.reason(
                    "entry_audit_unavailable_rolled_back",
                    "entry_replacement_audit_unavailable_rolled_back",
                );
                self.write_journal(journal)?;
                return Err(error);
            }
        };
        if let Err(error) = self.audit_entry(
            &mut audit,
            AuditOutcome::Allowed,
            if self.operation_kind == ManagedEntryOperationKind::Create {
                "entry_apply_started"
            } else {
                "entry_replacement_started"
            },
            Severity::High,
        ) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_audit_failed_rolled_back"),
            )
            .await?;
            return Err(error);
        }

        let store_result = match self.operation_kind {
            ManagedEntryOperationKind::Create => {
                context
                    .store
                    .create_if_absent(&context.descriptor.name, value)
                    .await
            }
            ManagedEntryOperationKind::Replace => {
                let rollback_id = journal.rollback_id.clone().ok_or_else(|| {
                    JanusError::policy_denied(
                        "entry_replacement_state_invalid",
                        "replacement rollback binding is missing",
                    )
                })?;
                context
                    .store
                    .prepare_generated_rotation_with_id(
                        &context.descriptor.name,
                        value,
                        rollback_id,
                    )
                    .await
                    .map(|_| janus_provider_age::AgeAdminOutcome {
                        action: "rotation.prepare",
                        changed: true,
                        present_secrets: 1,
                        recipient_count: context.store.recipient_count(),
                        value_returned: false,
                    })
            }
            ManagedEntryOperationKind::Remove => {
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_removal_value_denied value_returned=false"
                )
            }
        };
        if let Err(error) = store_result {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_store_failed_rolled_back"),
            )
            .await?;
            return Err(error.into());
        }
        journal.created_by_operation = self.operation_kind == ManagedEntryOperationKind::Create;
        journal.phase = EntryPhase::Stored;
        journal.reason_code = self.reason("entry_ciphertext_stored", "entry_replacement_staged");
        if let Err(error) = self.write_journal(journal.clone()) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_journal_failed_rolled_back"),
            )
            .await?;
            return Err(error);
        }

        for probe in &context.consumer.validation {
            if let Err(error) = context.hooks.validate(probe).await {
                let _ = self.audit_consumer(
                    &mut audit,
                    AuditAction::ConsumerValidate,
                    AuditOutcome::Denied,
                    "entry_validation_failed",
                    Severity::High,
                    &context.consumer.consumer_ref,
                );
                self.rollback_operation(
                    &mut context,
                    &mut journal,
                    &mut audit,
                    self.rollback_reason("entry_validation_failed_rolled_back"),
                )
                .await?;
                return Err(error.into());
            }
            if let Err(error) = self.audit_consumer(
                &mut audit,
                AuditAction::ConsumerValidate,
                AuditOutcome::Allowed,
                "entry_validation_ok",
                Severity::Notice,
                &context.consumer.consumer_ref,
            ) {
                self.rollback_operation(
                    &mut context,
                    &mut journal,
                    &mut audit,
                    self.rollback_reason("entry_audit_failed_rolled_back"),
                )
                .await?;
                return Err(error);
            }
        }
        journal.phase = EntryPhase::Validated;
        journal.reason_code = self.reason("entry_validation_ok", "entry_replacement_validated");
        if let Err(error) = self.write_journal(journal.clone()) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_journal_failed_rolled_back"),
            )
            .await?;
            return Err(error);
        }
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn activate(&self, now: SystemTime) -> Result<EntryStatus> {
        self.activate_bound(now, true).await
    }

    /// Complete lifecycle activation after the fixed host delivery path has
    /// already supplied fresh, current-generation reload and health evidence.
    /// This deliberately skips the local consumer hook so a managed service is
    /// never reloaded twice by two authorities.
    pub(super) async fn activate_after_external_verification(
        &self,
        now: SystemTime,
    ) -> Result<EntryStatus> {
        self.activate_bound(now, false).await
    }

    async fn activate_bound(&self, now: SystemTime, run_local_reload: bool) -> Result<EntryStatus> {
        if self.operation_kind == ManagedEntryOperationKind::Remove {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_activation_denied value_returned=false"
            );
        }
        let _lock = self.lock()?;
        let mut journal = self.read_bound_journal()?;
        if journal.phase != EntryPhase::Validated {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_activation_phase_invalid value_returned=false"
            );
        }
        self.ensure_fresh(&journal, now)?;
        let mut context = self
            .bound_context(
                ExpectedPresence::Present,
                if self.operation_kind == ManagedEntryOperationKind::Create {
                    &[SecretLifecycle::Draft]
                } else {
                    &[SecretLifecycle::Active]
                },
            )
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let mut audit = self.audit()?;
        journal.phase = EntryPhase::Activating;
        journal.reason_code = self.reason(
            "entry_activation_started",
            "entry_replacement_commit_started",
        );
        self.write_journal(journal.clone())?;

        if self.operation_kind == ManagedEntryOperationKind::Create {
            if let Err(error) = LifecycleTransitionPolicy::transition(
                &context.descriptor,
                SecretLifecycle::Active,
                SafeLabel::new(self.plan.file.activation_reason.clone())?,
                &self.principal,
                &mut audit,
            ) {
                self.rollback_operation(
                    &mut context,
                    &mut journal,
                    &mut audit,
                    "entry_activation_audit_failed_rolled_back",
                )
                .await?;
                return Err(error.into());
            }
            if let Err(error) =
                self.set_lifecycle(&context.descriptor.name, SecretLifecycle::Active)
            {
                self.rollback_operation(
                    &mut context,
                    &mut journal,
                    &mut audit,
                    "entry_activation_write_failed_rolled_back",
                )
                .await?;
                return Err(error);
            }
        } else if let Err(error) = self.audit_entry(
            &mut audit,
            AuditOutcome::Allowed,
            "entry_replacement_commit_started",
            Severity::High,
        ) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                "entry_replacement_audit_failed_rolled_back",
            )
            .await?;
            return Err(error);
        }

        let reload_result = if !run_local_reload || context.consumer.reload == ReloadMethod::None {
            Ok(())
        } else {
            context
                .hooks
                .reload(&context.consumer.consumer_ref, &context.consumer.reload)
                .await
        };
        if let Err(error) = reload_result {
            let _ = self.audit_consumer(
                &mut audit,
                AuditAction::ConsumerReload,
                AuditOutcome::Denied,
                "entry_reload_failed",
                Severity::High,
                &context.consumer.consumer_ref,
            );
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_reload_failed_rolled_back"),
            )
            .await?;
            return Err(error.into());
        }
        if let Err(error) = self.audit_consumer(
            &mut audit,
            AuditAction::ConsumerReload,
            AuditOutcome::Allowed,
            "entry_reload_ok",
            Severity::Notice,
            &context.consumer.consumer_ref,
        ) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_audit_failed_rolled_back"),
            )
            .await?;
            return Err(error);
        }

        journal.phase = EntryPhase::Completed;
        journal.reason_code = if self.operation_kind == ManagedEntryOperationKind::Replace {
            "entry_replacement_committed"
        } else if run_local_reload {
            "entry_activation_ok"
        } else {
            "entry_external_activation_ok"
        }
        .to_string();
        if let Err(error) = self.write_journal(journal.clone()) {
            self.rollback_operation(
                &mut context,
                &mut journal,
                &mut audit,
                self.rollback_reason("entry_journal_failed_rolled_back"),
            )
            .await?;
            return Err(error);
        }
        if self.operation_kind == ManagedEntryOperationKind::Replace {
            self.commit_replacement_cleanup(&mut context, &journal)
                .await?;
        }
        Ok(status_from_journal(&journal))
    }

    /// Read the exact staged value only for the reviewed host-encryption
    /// boundary. The caller receives a zeroizing `SecretValue`; no string,
    /// debug, log, or response representation is created.
    pub(super) async fn staged_value_for_host_delivery(&self) -> Result<janus_core::SecretValue> {
        if self.operation_kind == ManagedEntryOperationKind::Remove {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_value_denied value_returned=false"
            );
        }
        let _lock = self.lock()?;
        let journal = self.read_bound_journal()?;
        if journal.phase != EntryPhase::Validated {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_delivery_phase_invalid value_returned=false"
            );
        }
        let context = self
            .bound_context(
                ExpectedPresence::Present,
                if self.operation_kind == ManagedEntryOperationKind::Create {
                    &[SecretLifecycle::Draft]
                } else {
                    &[SecretLifecycle::Active]
                },
            )
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let mut audit = self.audit()?;
        self.audit_consumer(
            &mut audit,
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            "entry_host_delivery_read",
            Severity::High,
            &context.consumer.consumer_ref,
        )?;
        context
            .store
            .get(&context.descriptor.name)
            .await
            .context("entry host delivery read denied")
    }

    pub(super) async fn rollback(&self) -> Result<EntryStatus> {
        let _lock = self.lock()?;
        let mut journal = self.read_bound_journal()?;
        if journal.phase == EntryPhase::RolledBack {
            return Ok(status_from_journal(&journal));
        }
        if journal.phase == EntryPhase::Completed {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_completed_rollback_denied value_returned=false"
            );
        }
        let mut context = self
            .bound_context(
                ExpectedPresence::Either,
                if self.operation_kind == ManagedEntryOperationKind::Remove {
                    &[SecretLifecycle::Active, SecretLifecycle::Disabled]
                } else {
                    &[SecretLifecycle::Draft, SecretLifecycle::Active]
                },
            )
            .await?;
        self.ensure_target_binding(&journal, &context)?;
        let mut audit = self.audit()?;
        let reason = self.rollback_reason("entry_rollback_ok");
        self.rollback_operation(&mut context, &mut journal, &mut audit, reason)
            .await?;
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn finish_completed_cleanup(&self) -> Result<EntryStatus> {
        let _lock = self.lock()?;
        let journal = self.read_bound_journal()?;
        if journal.phase != EntryPhase::Completed {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_cleanup_phase_invalid value_returned=false"
            );
        }
        if self.operation_kind == ManagedEntryOperationKind::Replace {
            let mut context = self
                .bound_context(ExpectedPresence::Present, &[SecretLifecycle::Active])
                .await?;
            self.ensure_target_binding(&journal, &context)?;
            self.commit_replacement_cleanup(&mut context, &journal)
                .await?;
        }
        Ok(status_from_journal(&journal))
    }

    pub(super) async fn status(&self) -> Result<EntryStatus> {
        let _lock = self.lock()?;
        let journal = self.read_bound_journal()?;
        let (presence, lifecycles) = match journal.phase {
            EntryPhase::Preflighted => {
                if self.operation_kind == ManagedEntryOperationKind::Remove {
                    (
                        ExpectedPresence::Present,
                        vec![SecretLifecycle::Active, SecretLifecycle::Disabled],
                    )
                } else {
                    (
                        self.preflight_presence(),
                        self.preflight_lifecycles().to_vec(),
                    )
                }
            }
            EntryPhase::Applying | EntryPhase::Failed => (
                ExpectedPresence::Either,
                vec![SecretLifecycle::Draft, SecretLifecycle::Active],
            ),
            EntryPhase::Stored | EntryPhase::Validated => {
                if self.operation_kind == ManagedEntryOperationKind::Remove {
                    (ExpectedPresence::Present, vec![SecretLifecycle::Disabled])
                } else {
                    (
                        ExpectedPresence::Present,
                        vec![
                            if self.operation_kind == ManagedEntryOperationKind::Create {
                                SecretLifecycle::Draft
                            } else {
                                SecretLifecycle::Active
                            },
                        ],
                    )
                }
            }
            EntryPhase::Activating => {
                if self.operation_kind == ManagedEntryOperationKind::Remove {
                    (
                        ExpectedPresence::Either,
                        vec![SecretLifecycle::Disabled, SecretLifecycle::PendingDelete],
                    )
                } else {
                    (
                        ExpectedPresence::Present,
                        vec![SecretLifecycle::Draft, SecretLifecycle::Active],
                    )
                }
            }
            EntryPhase::Completed => {
                if self.operation_kind == ManagedEntryOperationKind::Remove {
                    (
                        ExpectedPresence::Absent,
                        vec![SecretLifecycle::PendingDelete],
                    )
                } else {
                    (ExpectedPresence::Present, vec![SecretLifecycle::Active])
                }
            }
            EntryPhase::Destroyed => (ExpectedPresence::Absent, vec![SecretLifecycle::Destroyed]),
            EntryPhase::RollingBack => (
                ExpectedPresence::Either,
                vec![SecretLifecycle::Draft, SecretLifecycle::Active],
            ),
            EntryPhase::RolledBack => match self.operation_kind {
                ManagedEntryOperationKind::Create => {
                    (ExpectedPresence::Absent, vec![SecretLifecycle::Draft])
                }
                ManagedEntryOperationKind::Replace | ManagedEntryOperationKind::Remove => {
                    (ExpectedPresence::Present, vec![SecretLifecycle::Active])
                }
            },
        };
        let context = self.bound_context(presence, &lifecycles).await?;
        self.ensure_target_binding(&journal, &context)?;
        Ok(status_from_journal(&journal))
    }

    async fn rollback_operation<A>(
        &self,
        context: &mut BoundContext,
        journal: &mut EntryJournal,
        audit: &mut A,
        reason_code: &'static str,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        match self.operation_kind {
            ManagedEntryOperationKind::Create => {
                self.rollback_created(context, journal, audit, reason_code)
                    .await
            }
            ManagedEntryOperationKind::Replace => {
                self.rollback_replacement(context, journal, audit, reason_code)
                    .await
            }
            ManagedEntryOperationKind::Remove => {
                self.rollback_removal(context, journal, audit, reason_code)
                    .await
            }
        }
    }

    async fn rollback_created<A>(
        &self,
        context: &mut BoundContext,
        journal: &mut EntryJournal,
        audit: &mut A,
        reason_code: &'static str,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        let may_delete = journal.created_by_operation || journal.phase == EntryPhase::Applying;
        journal.phase = EntryPhase::RollingBack;
        journal.reason_code = reason_code.to_string();
        let start_write_error = self.write_journal(journal.clone()).err();
        let audit_error = self
            .audit_entry(
                audit,
                AuditOutcome::Allowed,
                "entry_rollback_started",
                Severity::High,
            )
            .err();
        let descriptors = match context.store.list().await {
            Ok(descriptors) => descriptors,
            Err(error) => {
                journal.phase = EntryPhase::Failed;
                journal.reason_code = "entry_rollback_inspection_failed".to_string();
                let _ = self.write_journal(journal.clone());
                return Err(error.into());
            }
        };
        let descriptor = exact_descriptor(&descriptors, &self.secret_ref()?)?;
        if descriptor.present {
            if !may_delete {
                journal.phase = EntryPhase::Failed;
                journal.reason_code = "entry_orphan_target_present".to_string();
                let _ = self.write_journal(journal.clone());
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_orphan_target_present value_returned=false"
                );
            }
            if let Err(error) = context.store.delete(&descriptor.name).await {
                journal.phase = EntryPhase::Failed;
                journal.reason_code = "entry_rollback_delete_failed".to_string();
                self.write_journal(journal.clone())?;
                return Err(error.into());
            }
        }
        // The store snapshot may predate an activation write, so always restore
        // the reviewed metadata overlay to draft during recovery.
        if let Err(error) = self.set_lifecycle(&descriptor.name, SecretLifecycle::Draft) {
            journal.phase = EntryPhase::Failed;
            journal.reason_code = "entry_rollback_metadata_failed".to_string();
            let _ = self.write_journal(journal.clone());
            return Err(error);
        }
        journal.phase = EntryPhase::RolledBack;
        journal.reason_code = reason_code.to_string();
        self.write_journal(journal.clone())?;
        if let Some(error) = audit_error {
            return Err(error);
        }
        if let Some(error) = start_write_error {
            return Err(error);
        }
        Ok(())
    }

    async fn rollback_replacement<A>(
        &self,
        context: &mut BoundContext,
        journal: &mut EntryJournal,
        audit: &mut A,
        reason_code: &'static str,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        journal.phase = EntryPhase::RollingBack;
        journal.reason_code = reason_code.to_string();
        let start_write_error = self.write_journal(journal.clone()).err();
        let audit_error = self
            .audit_entry(
                audit,
                AuditOutcome::Allowed,
                "entry_replacement_rollback_started",
                Severity::High,
            )
            .err();
        if let Some(rollback_id) = journal.rollback_id.clone() {
            let rollback = AgeRollbackMaterial {
                secret_ref: self.secret_ref()?,
                rollback_id,
                value_returned: false,
            };
            if let Err(error) = context
                .store
                .rollback_generated_rotation_if_present(&rollback)
                .await
            {
                journal.phase = EntryPhase::Failed;
                journal.reason_code = "entry_replacement_rollback_failed".to_string();
                let _ = self.write_journal(journal.clone());
                return Err(error.into());
            }
        }
        let descriptors = context
            .store
            .list()
            .await
            .context("entry replacement rollback inspection denied")?;
        let descriptor = exact_descriptor(&descriptors, &self.secret_ref()?)?;
        if !descriptor.present || descriptor.lifecycle != SecretLifecycle::Active {
            journal.phase = EntryPhase::Failed;
            journal.reason_code = "entry_replacement_restore_invalid".to_string();
            let _ = self.write_journal(journal.clone());
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_replacement_restore_invalid value_returned=false"
            );
        }
        journal.phase = EntryPhase::RolledBack;
        journal.reason_code = reason_code.to_string();
        self.write_journal(journal.clone())?;
        if let Some(error) = audit_error {
            return Err(error);
        }
        if let Some(error) = start_write_error {
            return Err(error);
        }
        Ok(())
    }

    async fn rollback_removal<A>(
        &self,
        context: &mut BoundContext,
        journal: &mut EntryJournal,
        audit: &mut A,
        reason_code: &'static str,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        if journal.quarantine_id.is_some() || journal.phase == EntryPhase::Completed {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_detach_boundary_crossed value_returned=false"
            );
        }
        if !context.descriptor.present {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_removal_restore_unproven value_returned=false"
            );
        }
        self.audit_entry(
            audit,
            AuditOutcome::Allowed,
            "entry_removal_cancelled",
            Severity::High,
        )?;
        self.set_lifecycle(&context.descriptor.name, SecretLifecycle::Active)?;
        journal.phase = EntryPhase::RolledBack;
        journal.reason_code = reason_code.to_string();
        self.write_journal(journal.clone())?;
        Ok(())
    }

    async fn commit_replacement_cleanup(
        &self,
        context: &mut BoundContext,
        journal: &EntryJournal,
    ) -> Result<()> {
        let rollback_id = journal.rollback_id.clone().ok_or_else(|| {
            JanusError::policy_denied(
                "entry_replacement_state_invalid",
                "replacement rollback binding is missing",
            )
        })?;
        context
            .store
            .commit_generated_rotation_if_present(&AgeRollbackMaterial {
                secret_ref: self.secret_ref()?,
                rollback_id,
                value_returned: false,
            })
            .await
            .context("entry replacement cleanup denied")?;
        Ok(())
    }

    async fn bound_context(
        &self,
        expected_presence: ExpectedPresence,
        expected_lifecycles: &[SecretLifecycle],
    ) -> Result<BoundContext> {
        reject_symlink(&self.plan.file.age_store_dir)?;
        let metadata = SecretMetadataOverlay::load_toml_file(&self.plan.file.metadata_file)
            .context("entry metadata denied")?;
        let identities = super::age_identity_files_from_env()?;
        let recipients = super::age_recipients_from_env()?;
        let mut backend_binding = identities
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        backend_binding.extend(recipients.iter().cloned());
        let store = AgeSecretStore::load_from_secretspec_manifest_with_metadata(
            &self.plan.file.secretspec_manifest,
            self.plan.file.secretspec_profile.clone(),
            &self.plan.file.age_store_dir,
            identities,
            recipients,
            self.principal.scope.clone(),
            Some(&metadata),
        )
        .context("entry age backend denied")?;
        let descriptors = store
            .list()
            .await
            .context("entry descriptor lookup denied")?;
        let descriptor = exact_descriptor(&descriptors, &self.secret_ref()?)?.clone();
        self.validate_descriptor(&descriptor, expected_presence, expected_lifecycles)?;

        let profiles = super::ManagedCommandProfileCatalog::load(&self.plan.file.profile_manifest)
            .context("entry profile manifest denied")?;
        let profile_id = self.profile_id()?;
        let consumer = if let Some(profile) = profiles.profile(&profile_id) {
            profile.consumer().clone()
        } else if let Some(profile) = profiles.env_file_profile(&profile_id) {
            profile.consumer().clone()
        } else {
            return Err(JanusError::policy_denied(
                "entry_profile_missing",
                "entry profile is not declared",
            )
            .into());
        };
        self.validate_consumer(&descriptor, &consumer)?;

        let hooks = super::ManifestRotationHooks::load(&self.plan.file.hook_manifest)
            .context("entry hook manifest denied")?;
        for probe in &consumer.validation {
            if !hooks.manifest.validation.contains_key(probe.as_str()) {
                return Err(JanusError::policy_denied(
                    "entry_validation_hook_missing",
                    "entry validation hook is not reviewed",
                )
                .into());
            }
        }
        if consumer.reload != ReloadMethod::None
            && hooks.manifest.reload_command(&consumer.reload).is_none()
        {
            return Err(JanusError::policy_denied(
                "entry_reload_hook_missing",
                "entry reload hook is not reviewed",
            )
            .into());
        }
        let capabilities = store.capabilities();
        if !capabilities.write || !capabilities.delete {
            return Err(JanusError::policy_denied(
                "entry_backend_capability_missing",
                "entry backend cannot create and roll back material",
            )
            .into());
        }
        if matches!(self.plan.file.source, EntrySource::Generated { .. })
            && !capabilities.generated_rotate
        {
            return Err(JanusError::policy_denied(
                "entry_generation_capability_missing",
                "entry backend does not admit generated values",
            )
            .into());
        }

        let target_fingerprint =
            self.target_fingerprint(&descriptor, &consumer, &backend_binding)?;
        Ok(BoundContext {
            store,
            descriptor,
            consumer,
            hooks,
            target_fingerprint,
        })
    }

    fn validate_descriptor(
        &self,
        descriptor: &SecretDescriptor,
        expected_presence: ExpectedPresence,
        expected_lifecycles: &[SecretLifecycle],
    ) -> Result<()> {
        let expected_owner = OwnerRef::new(self.plan.file.expected_owner.clone())?;
        let expected_class = SecretClass::parse(&self.plan.file.expected_classification)?;
        if descriptor.scope != self.principal.scope
            || descriptor.label.as_str() != self.plan.file.expected_label
            || descriptor.owner.as_ref() != Some(&expected_owner)
            || descriptor.classification != Some(expected_class)
            || !descriptor.metadata_complete()
            || !expected_lifecycles.contains(&descriptor.lifecycle)
            || descriptor.allowed_uses != [self.profile_id()?]
        {
            return Err(JanusError::policy_denied(
                "entry_target_binding_mismatch",
                "entry target no longer matches the reviewed manifest binding",
            )
            .into());
        }
        let presence_matches = match expected_presence {
            ExpectedPresence::Absent => !descriptor.present,
            ExpectedPresence::Present => descriptor.present,
            ExpectedPresence::Either => true,
        };
        if !presence_matches {
            return Err(JanusError::policy_denied(
                "entry_target_presence_mismatch",
                "entry target presence does not match the transaction phase",
            )
            .into());
        }
        Ok(())
    }

    fn validate_consumer(
        &self,
        descriptor: &SecretDescriptor,
        consumer: &ConsumerDescriptor,
    ) -> Result<()> {
        let probes = consumer
            .validation
            .iter()
            .map(|probe| probe.as_str())
            .collect::<Vec<_>>();
        let expected_probes = self
            .plan
            .file
            .validation_probes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !consumer.declared
            || consumer.scope != self.principal.scope
            || consumer.secret_ref != descriptor.secret_ref
            || consumer.consumer_ref != self.consumer_ref()?
            || consumer.owner.as_str() != self.plan.file.expected_owner
            || probes != expected_probes
            || reload_label(&consumer.reload) != self.plan.file.reload_strategy
        {
            return Err(JanusError::policy_denied(
                "entry_consumer_binding_mismatch",
                "entry consumer no longer matches the reviewed profile binding",
            )
            .into());
        }
        Ok(())
    }

    fn preflight_presence(&self) -> ExpectedPresence {
        match self.operation_kind {
            ManagedEntryOperationKind::Create => ExpectedPresence::Absent,
            ManagedEntryOperationKind::Replace => ExpectedPresence::Present,
            ManagedEntryOperationKind::Remove => ExpectedPresence::Present,
        }
    }

    fn preflight_lifecycles(&self) -> &'static [SecretLifecycle] {
        match self.operation_kind {
            ManagedEntryOperationKind::Create => &[SecretLifecycle::Draft],
            ManagedEntryOperationKind::Replace => &[SecretLifecycle::Active],
            ManagedEntryOperationKind::Remove => &[SecretLifecycle::Active],
        }
    }

    fn next_generation(&self) -> Result<u64> {
        let mut maximum = 0_u64;
        let mut active_generation = self.generation_floor.max(1);
        for summary in scan_journal_summaries(
            &self.plan.file.state_dir,
            &self.release,
            MAX_ENTRY_JOURNALS,
            MAX_PLAN_BYTES,
        )? {
            if summary.secret_ref.as_str() != self.plan.file.secret_ref {
                continue;
            }
            if !summary.release_matches {
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_conflicting_release value_returned=false"
                );
            }
            if !matches!(
                summary.phase.as_str(),
                "completed" | "destroyed" | "rolled_back"
            ) {
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_conflicting_operation value_returned=false"
                );
            }
            maximum = maximum.max(summary.generation);
            if summary.phase == "completed"
                && matches!(summary.operation_kind.as_str(), "create" | "replace")
            {
                active_generation = active_generation.max(summary.generation);
            }
        }
        let next = match self.operation_kind {
            ManagedEntryOperationKind::Create => maximum
                .checked_add(1)
                .map(|generation| generation.max(self.generation_floor.max(1))),
            ManagedEntryOperationKind::Replace => {
                maximum.max(self.generation_floor.max(1)).checked_add(1)
            }
            // Removal targets the ciphertext generation that is actually
            // active. A newer failed replacement has a larger journal
            // generation but its rollback restored the most recent completed
            // create/replace generation.
            ManagedEntryOperationKind::Remove => Some(active_generation),
        };
        next.ok_or_else(|| {
            JanusError::policy_denied(
                "entry_generation_exhausted",
                "entry generation cannot advance",
            )
            .into()
        })
    }

    fn reason(&self, create: &'static str, replace: &'static str) -> String {
        match self.operation_kind {
            ManagedEntryOperationKind::Create => create,
            ManagedEntryOperationKind::Replace => replace,
            ManagedEntryOperationKind::Remove => "entry_removal_invalid",
        }
        .to_string()
    }

    fn rollback_reason(&self, create: &'static str) -> &'static str {
        if self.operation_kind == ManagedEntryOperationKind::Create {
            return create;
        }
        match create {
            "entry_store_failed_rolled_back" => "entry_replacement_store_failed_rolled_back",
            "entry_validation_failed_rolled_back" => {
                "entry_replacement_validation_failed_rolled_back"
            }
            "entry_reload_failed_rolled_back" => "entry_replacement_reload_failed_rolled_back",
            "entry_journal_failed_rolled_back" => "entry_replacement_journal_failed_rolled_back",
            "entry_audit_failed_rolled_back" => "entry_replacement_audit_failed_rolled_back",
            "entry_rollback_ok" => "entry_replacement_rollback_ok",
            _ => "entry_replacement_rolled_back",
        }
    }

    fn target_fingerprint(
        &self,
        descriptor: &SecretDescriptor,
        consumer: &ConsumerDescriptor,
        backend_binding: &[String],
    ) -> Result<String> {
        let manifest_hash = hash_file(&self.plan.file.secretspec_manifest)?;
        let profile_hash = hash_file(&self.plan.file.profile_manifest)?;
        let hook_hash = hash_file(&self.plan.file.hook_manifest)?;
        let mut fields = vec![
            "janus-entry-target-v1".to_string(),
            manifest_hash,
            profile_hash,
            hook_hash,
            descriptor.secret_ref.as_str().to_string(),
            descriptor.scope.as_str().to_string(),
            descriptor.label.as_str().to_string(),
            descriptor
                .owner
                .as_ref()
                .map(OwnerRef::as_str)
                .unwrap_or("")
                .to_string(),
            descriptor
                .classification
                .map(SecretClass::as_str)
                .unwrap_or("")
                .to_string(),
            self.plan.file.profile_id.clone(),
            consumer.consumer_ref.as_str().to_string(),
            consumer.owner.as_str().to_string(),
            reload_label(&consumer.reload),
        ];
        fields.extend(
            consumer
                .validation
                .iter()
                .map(|probe| probe.as_str().to_string()),
        );
        fields.extend(backend_binding.iter().cloned());
        Ok(hash_fields(&fields))
    }

    fn ensure_target_binding(&self, journal: &EntryJournal, context: &BoundContext) -> Result<()> {
        if journal.target_fingerprint != context.target_fingerprint {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_target_changed value_returned=false"
            );
        }
        Ok(())
    }

    fn ensure_fresh(&self, journal: &EntryJournal, now: SystemTime) -> Result<()> {
        let now = unix_seconds(now)?;
        let age = now
            .checked_sub(journal.preflighted_at_unix_secs)
            .ok_or_else(|| {
                JanusError::policy_denied(
                    "entry_preflight_clock_invalid",
                    "entry preflight evidence is in the future",
                )
            })?;
        if age > self.plan.file.preflight_max_age_seconds {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_preflight_stale value_returned=false"
            );
        }
        Ok(())
    }

    fn set_lifecycle(&self, name: &SecretName, lifecycle: SecretLifecycle) -> Result<()> {
        let mut overlay = SecretMetadataOverlay::load_toml_file(&self.plan.file.metadata_file)
            .context("entry metadata denied")?;
        overlay.set_secret_lifecycle(name.clone(), lifecycle);
        super::write_metadata_overlay_atomic(
            &self.plan.file.metadata_file,
            &overlay.to_toml_string()?,
        )
        .context("entry metadata update denied")
    }

    fn record_removal_tombstone(
        &self,
        descriptor: &SecretDescriptor,
        destroyed_at_unix_secs: u64,
    ) -> Result<()> {
        let registry = FileTombstoneRegistry::new(
            std::env::var(TOMBSTONE_DIR_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/lib/janus/tombstones")),
        );
        let reason = SafeLabel::new("managed service secret removed")?;
        let destroyed_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(destroyed_at_unix_secs))
            .context("entry removal tombstone time invalid")?;
        let retain_until = destroyed_at
            .checked_add(Duration::from_secs(REMOVAL_TOMBSTONE_RETAIN_SECONDS))
            .context("entry removal tombstone retention invalid")?;
        if let Some(existing) = registry
            .list()?
            .into_iter()
            .find(|record| record.secret_ref == descriptor.secret_ref)
        {
            if existing.reason != reason
                || existing.destroyed_at != destroyed_at
                || existing.retain_until != retain_until
            {
                anyhow::bail!(
                    "lifecycle entry denied reason_code=entry_removal_tombstone_conflict value_returned=false"
                );
            }
            return Ok(());
        }
        let mut audit = self.audit()?;
        let tombstone = TombstonePolicy::record(
            descriptor,
            SecretTombstoneRequest::new(
                descriptor.secret_ref.clone(),
                reason,
                destroyed_at,
                retain_until,
            ),
            &self.principal,
            &mut audit,
        )?;
        registry.record(&tombstone, &self.principal)?;
        Ok(())
    }

    fn audit(&self) -> Result<JsonlAuditSink> {
        JsonlAuditSink::open(self.plan.file.audit_path.clone()).context("entry audit unavailable")
    }

    fn audit_entry<A>(
        &self,
        audit: &mut A,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        audit.record(
            AuditEvent::new(
                match self.operation_kind {
                    ManagedEntryOperationKind::Create | ManagedEntryOperationKind::Remove => {
                        AuditAction::SecretLifecycle
                    }
                    ManagedEntryOperationKind::Replace => AuditAction::RotationLifecycle,
                },
                outcome,
                reason_code,
                severity,
                Some(self.secret_ref()?),
                &self.principal,
            )
            .with_evidence(SafeLabel::new(self.plan.file.operation_id.clone())?),
        )?;
        Ok(())
    }

    fn audit_consumer<A>(
        &self,
        audit: &mut A,
        action: AuditAction,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
        consumer: &ConsumerRef,
    ) -> Result<()>
    where
        A: AuditSink,
    {
        audit.record(
            AuditEvent::new(
                action,
                outcome,
                reason_code,
                severity,
                Some(self.secret_ref()?),
                &self.principal,
            )
            .with_evidence(SafeLabel::new(consumer.as_str())?),
        )?;
        Ok(())
    }

    fn lock(&self) -> Result<EntryLock> {
        ensure_private_dir(&self.plan.file.state_dir)?;
        let path = self
            .plan
            .file
            .state_dir
            .join(format!("{}.lock", self.plan.file.secret_ref));
        reject_symlink(&path)?;
        let file = private_open(&path, true, false)?;
        file.try_lock_exclusive().map_err(|_| {
            JanusError::policy_denied(
                "entry_operation_locked",
                "entry operation is already running",
            )
        })?;
        Ok(EntryLock { _file: file })
    }

    fn journal_path(&self) -> PathBuf {
        self.plan
            .file
            .state_dir
            .join(format!("{}.json", self.plan.file.operation_id))
    }

    fn read_bound_journal(&self) -> Result<EntryJournal> {
        let path = self.journal_path();
        let bytes = read_regular_bounded(&path, MAX_PLAN_BYTES, true)?;
        let journal: EntryJournal = serde_json::from_slice(&bytes).map_err(|_| {
            JanusError::policy_denied("entry_journal_invalid", "entry journal is invalid")
        })?;
        verify_journal(&journal)?;
        if journal.schema_version != JOURNAL_SCHEMA_VERSION
            || journal.operation_id != self.plan.file.operation_id
            || journal.plan_fingerprint != self.plan.fingerprint
            || journal.release_fingerprint != release_fingerprint(&self.release)
            || journal.secret_ref != self.plan.file.secret_ref
            || journal.mode != self.plan.file.source.mode()
            || journal.operation_kind != self.operation_kind.as_str()
            || self.generation_floor > 0 && journal.generation == 0
            || self.operation_kind == ManagedEntryOperationKind::Create
                && journal.rollback_id.is_some()
            || self.operation_kind == ManagedEntryOperationKind::Replace
                && journal.phase != EntryPhase::Preflighted
                && journal.rollback_id.is_none()
            || self.operation_kind != ManagedEntryOperationKind::Remove
                && (journal.quarantine_id.is_some() || journal.purge_not_before_unix_secs != 0)
            || self.operation_kind == ManagedEntryOperationKind::Remove
                && (journal.rollback_id.is_some()
                    || journal.purge_not_before_unix_secs == 0
                    || journal
                        .quarantine_id
                        .as_deref()
                        .is_some_and(|value| !valid_quarantine_id(value)))
        {
            anyhow::bail!(
                "lifecycle entry denied reason_code=entry_journal_binding_mismatch value_returned=false"
            );
        }
        Ok(journal)
    }

    fn write_journal(&self, mut journal: EntryJournal) -> Result<()> {
        journal.integrity_hash = journal_hash(&journal)?;
        let mut encoded = serde_json::to_vec_pretty(&journal).map_err(|_| {
            JanusError::policy_denied("entry_journal_invalid", "entry journal encoding failed")
        })?;
        encoded.push(b'\n');
        write_private_atomic(&self.journal_path(), &encoded)
    }

    fn secret_ref(&self) -> Result<SecretRef> {
        Ok(SecretRef::new(self.plan.file.secret_ref.clone())?)
    }

    fn profile_id(&self) -> Result<ProfileId> {
        Ok(ProfileId::new(self.plan.file.profile_id.clone())?)
    }

    fn consumer_ref(&self) -> Result<ConsumerRef> {
        Ok(ConsumerRef::new(self.plan.file.consumer_ref.clone())?)
    }
}

fn load_plan(path: &Path) -> Result<EntryPlan> {
    let bytes = read_regular_bounded(path, MAX_PLAN_BYTES, false)?;
    let file: EntryPlanFile = serde_json::from_slice(&bytes)
        .map_err(|_| JanusError::policy_denied("entry_plan_invalid", "entry plan is invalid"))?;
    validate_cli_operation_namespace(&file.operation_id)?;
    validate_plan(&file, SystemTime::now())?;
    Ok(EntryPlan {
        file,
        fingerprint: hex::encode(Sha256::digest(&bytes)),
    })
}

fn validate_cli_operation_namespace(operation_id: &str) -> Result<()> {
    if operation_id.starts_with("webtx_") {
        anyhow::bail!(
            "lifecycle entry denied reason_code=entry_operation_namespace_reserved value_returned=false"
        );
    }
    Ok(())
}

pub(super) fn validate_plan(plan: &EntryPlanFile, now: SystemTime) -> Result<()> {
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        anyhow::bail!("unsupported lifecycle entry plan version");
    }
    validate_operation_id(&plan.operation_id)?;
    SecretRef::new(plan.secret_ref.clone())?;
    ScopeRef::from_opaque(plan.expected_scope_ref.clone())?;
    SafeLabel::new(plan.expected_label.clone())?;
    OwnerRef::new(plan.expected_owner.clone())?;
    SecretClass::parse(&plan.expected_classification)?;
    ProfileId::new(plan.profile_id.clone())?;
    ConsumerRef::new(plan.consumer_ref.clone())?;
    SafeLabel::new(plan.reviewed_by.clone())?;
    SafeLabel::new(plan.activation_reason.clone())?;
    if plan.secretspec_profile.trim().is_empty()
        || plan.secretspec_profile.trim() != plan.secretspec_profile
    {
        anyhow::bail!("entry secretspec profile is invalid");
    }
    if plan.validation_probes.is_empty() || plan.validation_probes.len() > 32 {
        anyhow::bail!("entry validation probes are invalid");
    }
    let mut probes = BTreeSet::new();
    for probe in &plan.validation_probes {
        janus_core::ValidationProbe::new(probe.clone())?;
        if !probes.insert(probe) {
            anyhow::bail!("entry validation probes must be unique");
        }
    }
    super::parse_reload_method(&plan.reload_strategy)?;
    if plan.input_max_bytes == 0 || plan.input_max_bytes > MAX_IMPORT_BYTES {
        anyhow::bail!("entry input ceiling is invalid");
    }
    if plan.preflight_max_age_seconds == 0 || plan.preflight_max_age_seconds > 24 * 60 * 60 {
        anyhow::bail!("entry preflight age ceiling is invalid");
    }
    match &plan.source {
        EntrySource::Generated { alphabet, length } => {
            if plan.rotation_strategy != "generated" || *length > plan.input_max_bytes {
                anyhow::bail!("entry generated source binding is invalid");
            }
            GeneratedValuePolicy::new(parse_alphabet(alphabet)?, *length)?;
        }
        EntrySource::Import => {
            if plan.rotation_strategy != "import" {
                anyhow::bail!("entry import source binding is invalid");
            }
        }
        EntrySource::Remove => {}
    }
    let paths = [
        &plan.secretspec_manifest,
        &plan.age_store_dir,
        &plan.metadata_file,
        &plan.profile_manifest,
        &plan.hook_manifest,
        &plan.state_dir,
        &plan.audit_path,
    ];
    if paths.iter().any(|path| !path.is_absolute()) {
        anyhow::bail!("entry plan paths must be absolute");
    }
    let distinct = paths
        .iter()
        .map(|path| path.as_os_str())
        .collect::<BTreeSet<_>>();
    if distinct.len() != paths.len() {
        anyhow::bail!("entry plan paths must be distinct");
    }
    let audit_parent = plan
        .audit_path
        .parent()
        .context("entry audit path has no parent")?;
    for (left, right) in [
        (plan.age_store_dir.as_path(), plan.state_dir.as_path()),
        (plan.age_store_dir.as_path(), audit_parent),
        (plan.state_dir.as_path(), audit_parent),
    ] {
        if left.starts_with(right) || right.starts_with(left) {
            anyhow::bail!("entry data, state, and audit roots must not overlap");
        }
    }
    for reviewed_file in [
        &plan.secretspec_manifest,
        &plan.metadata_file,
        &plan.profile_manifest,
        &plan.hook_manifest,
    ] {
        if reviewed_file.starts_with(&plan.state_dir)
            || reviewed_file.starts_with(&plan.age_store_dir)
        {
            anyhow::bail!("entry reviewed files must be outside mutable transaction roots");
        }
    }
    let now = unix_seconds(now)?;
    let reviewed_age = now.checked_sub(plan.reviewed_at_unix_secs).ok_or_else(|| {
        JanusError::policy_denied(
            "entry_review_invalid",
            "entry plan review time is in the future",
        )
    })?;
    if reviewed_age > MAX_REVIEW_AGE.as_secs() {
        anyhow::bail!("entry plan review is stale");
    }
    Ok(())
}

fn parse_alphabet(value: &str) -> Result<GeneratedAlphabet> {
    match value {
        "url_safe" => Ok(GeneratedAlphabet::UrlSafe),
        "alphanumeric" => Ok(GeneratedAlphabet::Alphanumeric),
        "hex" => Ok(GeneratedAlphabet::Hex),
        _ => anyhow::bail!("unsupported generated alphabet"),
    }
}

fn reload_label(method: &ReloadMethod) -> String {
    match method {
        ReloadMethod::None => "none".to_string(),
        ReloadMethod::RestartService { service } => format!("restart-service:{}", service.as_str()),
        ReloadMethod::Signal { signal } => format!("signal:{}", signal.as_str()),
        ReloadMethod::ExecHook { hook } => format!("exec-hook:{}", hook.as_str()),
        ReloadMethod::ConnectorAction { action } => {
            format!("connector-action:{}", action.as_str())
        }
        ReloadMethod::Manual => "manual".to_string(),
        ReloadMethod::Unsupported => "unsupported".to_string(),
    }
}

fn exact_descriptor<'a>(
    descriptors: &'a [SecretDescriptor],
    secret_ref: &SecretRef,
) -> Result<&'a SecretDescriptor> {
    let matches = descriptors
        .iter()
        .filter(|descriptor| &descriptor.secret_ref == secret_ref)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(JanusError::policy_denied(
            "entry_target_not_unique",
            "entry target must resolve to exactly one manifest descriptor",
        )
        .into());
    }
    Ok(matches[0])
}

fn read_import_value<R>(reader: &mut R, limit: usize) -> Result<SecretValue>
where
    R: Read,
{
    let take_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::with_capacity(limit.min(4096));
    reader
        .take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            JanusError::policy_denied("entry_import_read_failed", "entry import stream failed")
        })?;
    if bytes.is_empty() {
        anyhow::bail!("lifecycle entry denied reason_code=entry_import_empty value_returned=false");
    }
    if bytes.len() > limit {
        anyhow::bail!(
            "lifecycle entry denied reason_code=entry_import_oversize value_returned=false"
        );
    }
    if matches!(bytes.last(), Some(b'\n' | b'\r')) {
        anyhow::bail!(
            "lifecycle entry denied reason_code=entry_import_trailing_data value_returned=false"
        );
    }
    Ok(SecretValue::new(bytes))
}

fn status_from_journal(journal: &EntryJournal) -> EntryStatus {
    EntryStatus {
        operation_id: journal.operation_id.clone(),
        secret_ref: journal.secret_ref.clone(),
        mode: journal.mode.clone(),
        operation_kind: journal.operation_kind.clone(),
        generation: journal.generation,
        phase: journal.phase,
        reason_code: journal.reason_code.clone(),
        value_returned: false,
    }
}

fn default_create_operation_kind() -> String {
    "create".to_string()
}

fn is_create_operation_kind(value: &str) -> bool {
    value == "create"
}

fn is_zero_generation(value: &u64) -> bool {
    *value == 0
}

fn replacement_rollback_id(operation_id: &str, generation: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"inspr.janus.lifecycle-entry-replacement-rollback.v1\0");
    hasher.update(operation_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("rb_webtx_{}", &digest[..32])
}

fn deterministic_quarantine_id(operation_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"inspr.janus.managed-removal-quarantine.v1\0");
    hasher.update(operation_id.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("qrn_{}", &digest[..24])
}

fn valid_quarantine_id(value: &str) -> bool {
    value.len() >= 12
        && value.len() <= 96
        && value.starts_with("qrn_")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn release_fingerprint(release: &ReleaseAdmission) -> String {
    hash_fields(&[
        "janus-entry-release-v1".to_string(),
        release.decision().as_str().to_string(),
        release.reason_code().to_string(),
        release.mode().as_str().to_string(),
        release.policy_id().unwrap_or("").to_string(),
        release.policy_version().unwrap_or_default().to_string(),
        release.channel().unwrap_or("").to_string(),
        release.artifact_id().unwrap_or("").to_string(),
    ])
}

fn journal_hash(journal: &EntryJournal) -> Result<String> {
    let mut unsigned = journal.clone();
    unsigned.integrity_hash.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| {
        JanusError::policy_denied("entry_journal_invalid", "entry journal encoding failed")
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn verify_journal(journal: &EntryJournal) -> Result<()> {
    if journal.integrity_hash != journal_hash(journal)? {
        anyhow::bail!(
            "lifecycle entry denied reason_code=entry_journal_tampered value_returned=false"
        );
    }
    Ok(())
}

pub(super) fn scan_journal_summaries(
    state_dir: &Path,
    release: &ReleaseAdmission,
    max_entries: usize,
    max_file_bytes: usize,
) -> Result<Vec<EntryJournalSummary>> {
    reject_symlink(state_dir)?;
    let metadata = fs::metadata(state_dir).map_err(|_| {
        JanusError::policy_denied(
            "entry_state_unavailable",
            "entry state directory is unavailable",
        )
    })?;
    if !metadata.is_dir() {
        anyhow::bail!("entry state path is not a directory");
    }
    ensure_private_mode(&metadata)?;

    let expected_release = release_fingerprint(release);
    let mut summaries = Vec::new();
    for entry in fs::read_dir(state_dir).map_err(|_| {
        JanusError::policy_denied(
            "entry_state_unavailable",
            "entry state directory is unavailable",
        )
    })? {
        let entry = entry.map_err(|_| {
            JanusError::policy_denied(
                "entry_state_unavailable",
                "entry state directory is unavailable",
            )
        })?;
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                JanusError::policy_denied(
                    "entry_journal_invalid",
                    "entry state contains an invalid name",
                )
            })?;
        if let Some(operation_id) = file_name.strip_suffix(".lock") {
            validate_operation_id(operation_id)?;
            let _ = read_regular_bounded(&path, max_file_bytes, true)?;
            continue;
        }
        let operation_id = file_name.strip_suffix(".json").ok_or_else(|| {
            JanusError::policy_denied(
                "entry_journal_invalid",
                "entry state contains an unsupported entry",
            )
        })?;
        validate_operation_id(operation_id)?;
        if summaries.len() >= max_entries {
            return Err(JanusError::policy_denied(
                "entry_journal_limit_exceeded",
                "entry journal count exceeds the reporting limit",
            )
            .into());
        }
        let bytes = read_regular_bounded(&path, max_file_bytes, true)?;
        let journal: EntryJournal = serde_json::from_slice(&bytes).map_err(|_| {
            JanusError::policy_denied("entry_journal_invalid", "entry journal is invalid")
        })?;
        verify_journal(&journal)?;
        if journal.schema_version != JOURNAL_SCHEMA_VERSION
            || journal.operation_id != operation_id
            || !matches!(journal.mode.as_str(), "generated" | "import" | "remove")
            || ManagedEntryOperationKind::parse(&journal.operation_kind).is_err()
            || (journal.operation_kind == "remove") != (journal.mode == "remove")
            || journal.operation_kind == "create" && journal.rollback_id.is_some()
            || journal.operation_kind == "replace"
                && journal.phase != EntryPhase::Preflighted
                && journal.rollback_id.is_none()
            || journal.operation_kind != "remove"
                && (journal.quarantine_id.is_some() || journal.purge_not_before_unix_secs != 0)
            || journal.operation_kind == "remove"
                && (journal.rollback_id.is_some()
                    || journal.generation == 0
                    || journal.purge_not_before_unix_secs == 0
                    || journal
                        .quarantine_id
                        .as_deref()
                        .is_some_and(|value| !valid_quarantine_id(value)))
        {
            return Err(JanusError::policy_denied(
                "entry_journal_binding_mismatch",
                "entry journal binding is invalid",
            )
            .into());
        }
        if let Some(rollback_id) = journal.rollback_id.as_deref() {
            validate_operation_id(rollback_id)?;
        }
        SafeLabel::new(journal.reason_code.clone())?;
        summaries.push(EntryJournalSummary {
            operation_id: journal.operation_id,
            secret_ref: SecretRef::new(journal.secret_ref)?,
            operation_kind: journal.operation_kind,
            generation: journal.generation,
            phase: journal.phase.as_str().to_string(),
            reason_code: journal.reason_code,
            preflighted_at_unix_secs: journal.preflighted_at_unix_secs,
            release_matches: journal.release_fingerprint == expected_release,
        });
    }
    summaries.sort_by(|left, right| {
        left.secret_ref
            .as_str()
            .cmp(right.secret_ref.as_str())
            .then_with(|| {
                left.preflighted_at_unix_secs
                    .cmp(&right.preflighted_at_unix_secs)
            })
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
    Ok(summaries)
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = read_regular_bounded(path, MAX_BINDING_FILE_BYTES, false)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn hash_fields(fields: &[String]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn read_regular_bounded(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|_| {
        JanusError::policy_denied("entry_file_unavailable", "entry file is unavailable")
    })?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        anyhow::bail!("entry file is not a bounded regular file");
    }
    if private {
        ensure_private_mode(&metadata)?;
    }
    fs::read(path).map_err(|_| {
        JanusError::policy_denied("entry_file_unavailable", "entry file is unavailable").into()
    })
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("entry path must not be a symlink")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => anyhow::bail!("entry path metadata is unavailable"),
    }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    let existed = path.exists();
    fs::create_dir_all(path).context("entry state directory unavailable")?;
    let metadata = fs::metadata(path).context("entry state directory unavailable")?;
    if !metadata.is_dir() {
        anyhow::bail!("entry state path is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if existed {
            ensure_private_mode(&metadata)?;
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .context("entry state directory permissions unavailable")?;
        }
    }
    Ok(())
}

fn ensure_private_mode(metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("entry private state permissions are too broad");
        }
    }
    Ok(())
}

fn private_open(path: &Path, create: bool, truncate: bool) -> Result<File> {
    let existed = path.exists();
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .context("entry private state unavailable")?;
    let metadata = file.metadata().context("entry private state unavailable")?;
    if !metadata.is_file() {
        anyhow::bail!("entry private state is not a regular file");
    }
    if existed {
        ensure_private_mode(&metadata)?;
    }
    Ok(file)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("entry journal has no private state directory")?;
    ensure_private_dir(parent)?;
    reject_symlink(path)?;
    if path.exists() {
        ensure_private_mode(&fs::metadata(path).context("entry journal unavailable")?)?;
    }
    let temp = parent.join(format!(
        ".entry-{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| -> Result<()> {
        let mut file = private_open(&temp, true, true)?;
        file.write_all(bytes)
            .context("entry journal write failed")?;
        file.flush().context("entry journal flush failed")?;
        file.sync_all()
            .context("entry journal persistence failed")?;
        drop(file);
        fs::rename(&temp, path).context("entry journal install failed")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("entry journal directory persistence failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_operation_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        anyhow::bail!("entry operation id is invalid");
    }
    Ok(())
}

fn unix_seconds(time: SystemTime) -> Result<u64> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JanusError::policy_denied("entry_clock_invalid", "entry clock is invalid"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    pub(super) fn sample_plan() -> EntryPlanFile {
        EntryPlanFile {
            schema_version: PLAN_SCHEMA_VERSION,
            operation_id: "entry-fixture".to_string(),
            secret_ref: "sec_fixture".to_string(),
            expected_scope_ref: format!("scp_{}", "0".repeat(40)),
            expected_label: "Entry fixture".to_string(),
            expected_owner: "fixture-owner".to_string(),
            expected_classification: "normal".to_string(),
            profile_id: "profile.FIXTURE".to_string(),
            consumer_ref: "consumer.fixture".to_string(),
            rotation_strategy: "generated".to_string(),
            validation_probes: vec!["fixture-valid".to_string()],
            reload_strategy: "none".to_string(),
            input_max_bytes: 4096,
            preflight_max_age_seconds: 900,
            secretspec_manifest: PathBuf::from("/fixture/secretspec.toml"),
            secretspec_profile: "default".to_string(),
            age_store_dir: PathBuf::from("/fixture/store"),
            metadata_file: PathBuf::from("/fixture/metadata.toml"),
            profile_manifest: PathBuf::from("/fixture/profiles.toml"),
            hook_manifest: PathBuf::from("/fixture/hooks.toml"),
            state_dir: PathBuf::from("/fixture/state"),
            audit_path: PathBuf::from("/fixture/audit/events.jsonl"),
            reviewed_by: "janus-security".to_string(),
            reviewed_at_unix_secs: unix_seconds(SystemTime::now()).unwrap(),
            activation_reason: "Reviewed fixture activation".to_string(),
            source: EntrySource::Generated {
                alphabet: "url_safe".to_string(),
                length: 48,
            },
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_only_the_narrow_reviewed_entry_surface() {
        for (name, expected) in [
            ("preflight", EntryOperation::Preflight),
            ("apply", EntryOperation::Apply),
            ("activate", EntryOperation::Activate),
            ("rollback", EntryOperation::Rollback),
            ("status", EntryOperation::Status),
        ] {
            let parsed = parse(&args(&[
                "lifecycle-entry",
                name,
                "--plan",
                "/etc/janus/entry.json",
            ]))
            .unwrap();
            assert_eq!(parsed.operation, expected);
        }
        for invalid in [
            args(&["lifecycle-entry", "apply"]),
            args(&["lifecycle-entry", "unknown", "--plan", "/tmp/plan"]),
            args(&["lifecycle-entry", "apply", "--value", "secret"]),
            args(&[
                "lifecycle-entry",
                "apply",
                "--plan",
                "/tmp/plan",
                "--secret-ref",
                "sec_override",
            ]),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn import_is_bounded_and_rejects_empty_or_trailing_delimiters() {
        let value = read_import_value(&mut Cursor::new(b"bounded-canary"), 32).unwrap();
        assert_eq!(value.expose_bytes(), b"bounded-canary");
        assert!(read_import_value(&mut Cursor::new(b""), 32).is_err());
        assert!(read_import_value(&mut Cursor::new(b"line\n"), 32).is_err());
        assert!(read_import_value(&mut Cursor::new(vec![b'x'; 33]), 32).is_err());
    }

    #[test]
    fn journal_integrity_detects_phase_and_binding_tamper() {
        let mut journal = EntryJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id: "entry-fixture".to_string(),
            plan_fingerprint: "plan".to_string(),
            target_fingerprint: "target".to_string(),
            release_fingerprint: "release".to_string(),
            secret_ref: "sec_fixture".to_string(),
            mode: "generated".to_string(),
            operation_kind: "create".to_string(),
            generation: 0,
            rollback_id: None,
            quarantine_id: None,
            purge_not_before_unix_secs: 0,
            phase: EntryPhase::Preflighted,
            preflighted_at_unix_secs: 1,
            created_by_operation: false,
            reason_code: "entry_preflight_ok".to_string(),
            integrity_hash: String::new(),
        };
        journal.integrity_hash = journal_hash(&journal).unwrap();
        verify_journal(&journal).unwrap();
        let legacy_shape = serde_json::to_string(&journal).unwrap();
        assert!(!legacy_shape.contains("operation_kind"));
        assert!(!legacy_shape.contains("generation"));
        assert!(!legacy_shape.contains("rollback_id"));
        assert!(!legacy_shape.contains("quarantine_id"));
        assert!(!legacy_shape.contains("purge_not_before_unix_secs"));
        let decoded: EntryJournal = serde_json::from_str(&legacy_shape).unwrap();
        assert_eq!(decoded.operation_kind, "create");
        assert_eq!(decoded.generation, 0);
        assert!(decoded.rollback_id.is_none());
        assert!(decoded.quarantine_id.is_none());
        assert_eq!(decoded.purge_not_before_unix_secs, 0);
        verify_journal(&decoded).unwrap();
        journal.phase = EntryPhase::Completed;
        assert!(verify_journal(&journal).is_err());
    }

    #[test]
    fn strict_plan_rejects_unknown_stale_and_incoherent_fields() {
        validate_plan(&sample_plan(), SystemTime::now()).unwrap();

        let mut unknown = serde_json::to_value(sample_plan()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("raw_value".to_string(), serde_json::json!("canary"));
        assert!(serde_json::from_value::<EntryPlanFile>(unknown).is_err());

        let mut mismatch = sample_plan();
        mismatch.rotation_strategy = "import".to_string();
        assert!(validate_plan(&mismatch, SystemTime::now()).is_err());

        let mut duplicate_probe = sample_plan();
        duplicate_probe
            .validation_probes
            .push("fixture-valid".to_string());
        assert!(validate_plan(&duplicate_probe, SystemTime::now()).is_err());

        let mut stale = sample_plan();
        stale.reviewed_at_unix_secs = stale
            .reviewed_at_unix_secs
            .saturating_sub(MAX_REVIEW_AGE.as_secs() + 1);
        assert!(validate_plan(&stale, SystemTime::now()).is_err());
    }

    #[test]
    fn operation_lock_rejects_a_concurrent_transaction() {
        let temporary = tempfile::tempdir().unwrap();
        let mut file = sample_plan();
        file.state_dir = temporary.path().join("state");
        let scope = ScopeRef::from_opaque(file.expected_scope_ref.clone()).unwrap();
        let transaction = EntryTransaction::new(
            EntryPlan {
                file,
                fingerprint: "fixture-plan".to_string(),
            },
            ReleaseAdmission::not_required(janus_core::ProductMode::SelfHosted),
            PrincipalChain::new(
                Principal::new(
                    PrincipalKind::Executor,
                    PrincipalId::new("entry-test").unwrap(),
                ),
                scope,
            ),
        )
        .unwrap();
        let held = transaction.lock().unwrap();
        assert!(transaction.lock().is_err());
        drop(held);
        transaction.lock().unwrap();
    }

    #[test]
    fn operation_ids_cannot_escape_private_state_directory() {
        for invalid in ["", "../escape", "a/b", "with space", "."] {
            assert!(validate_operation_id(invalid).is_err());
        }
        validate_operation_id("entry-fixture_1").unwrap();
        assert!(validate_cli_operation_namespace("webtx_0123456789").is_err());
        validate_cli_operation_namespace("entry-fixture_1").unwrap();
    }

    #[test]
    fn error_boundary_maps_untrusted_details_to_fixed_reason_codes() {
        let canary =
            anyhow::anyhow!("sensitive path and input SENSITIVE_ENTRY_ERROR_CANARY /private/value");
        let rendered = format!(
            "reason_code={} value_returned=false",
            stable_error_reason(&canary)
        );
        assert_eq!(
            rendered,
            "reason_code=entry_transaction_denied value_returned=false"
        );
        assert!(!rendered.contains("SENSITIVE_ENTRY_ERROR_CANARY"));
        assert!(!rendered.contains("/private/value"));

        let known = anyhow::anyhow!(
            "lifecycle entry denied reason_code=entry_import_oversize value_returned=false"
        );
        assert_eq!(stable_error_reason(&known), "entry_import_oversize");
    }
}

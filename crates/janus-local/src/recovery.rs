use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    RecoveryComponentKind, RecoveryDrillEvidenceInput, RecoveryDrillEvidenceV1,
    RecoveryDrillManifest, ReleaseAdmission, ReleaseAdmissionDecision, SafeLabel,
    SecretMetadataOverlay, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    audit::{lock_verified_audit_for_snapshot, VerifiedAuditLock},
    ApprovalRegistry, DelegationRegistry, FileApprovalRegistry, FileDelegationRegistry,
    FileLifecycleEvidenceRegistry, FileTombstoneRegistry, JsonlAuditSink,
};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REGISTRY_ENTRIES: usize = 100_000;
const MAX_REGISTRY_FILE_BYTES: u64 = 1024 * 1024;
const INVENTORY_VERSION: u8 = 1;
const JOURNAL_VERSION: u8 = 1;
const INVENTORY_FILE: &str = "inventory.json";
const PAYLOAD_DIR: &str = "payload";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "recovery-drill.lock";
const CONTENT_FILE: &str = "content";

/// Value-free recovery drill status for operator output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryDrillStatus {
    /// Reviewed operation id.
    pub operation_id: String,
    /// Durable workflow phase.
    pub phase: String,
    /// Exact opaque scope ref.
    pub scope_ref: String,
    /// Sealed bundle inventory fingerprint when available.
    pub bundle_fingerprint: String,
    /// Current immutable configuration-set fingerprint.
    pub config_fingerprint: String,
    /// Installed target fingerprint when available.
    pub target_fingerprint: String,
    /// Closed component count.
    pub component_count: u64,
    /// Sealed/restored regular files.
    pub file_count: u64,
    /// Sealed/restored aggregate bytes.
    pub total_bytes: u64,
    /// Permit records deliberately excluded.
    pub excluded_permit_count: u64,
    /// Continued target audit sequence, when postflight ran.
    pub audit_sequence: u64,
    /// Stable value-free reason code.
    pub reason_code: &'static str,
    /// Recovery operations never return values.
    pub value_returned: bool,
}

/// Filesystem paths needed by the provider-specific postflight check.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPostflightTarget {
    age_root: PathBuf,
    metadata_path: PathBuf,
    expected_ciphertext_files: u64,
}

impl RecoveryPostflightTarget {
    /// Restored Age ciphertext root.
    pub fn age_root(&self) -> &Path {
        &self.age_root
    }

    /// Restored metadata overlay file.
    pub fn metadata_path(&self) -> &Path {
        &self.metadata_path
    }

    /// Number of encrypted files the recoverability check must inspect.
    pub fn expected_ciphertext_files(&self) -> u64 {
        self.expected_ciphertext_files
    }
}

impl std::fmt::Debug for RecoveryPostflightTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryPostflightTarget")
            .field("paths", &"<redacted>")
            .field("expected_ciphertext_files", &self.expected_ciphertext_files)
            .finish()
    }
}

/// Offline runner for one sealed clean-state recovery drill.
pub struct RecoveryDrillRunner {
    manifest: RecoveryDrillManifest,
    plan_fingerprint: String,
    config_fingerprint: String,
    release: ReleaseAdmission,
    principal: PrincipalChain,
    reviewed_owner: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    Snapshotted,
    Preflighted,
    Restoring,
    Restored,
    Postflighting,
    Completed,
    RollingBack,
    RolledBack,
}

impl RecoveryPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Snapshotted => "snapshotted",
            Self::Preflighted => "preflighted",
            Self::Restoring => "restoring",
            Self::Restored => "restored",
            Self::Postflighting => "postflighting",
            Self::Completed => "completed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryJournal {
    version: u8,
    operation_id: String,
    plan_fingerprint: String,
    bundle_fingerprint: String,
    config_fingerprint: String,
    target_fingerprint: String,
    phase: RecoveryPhase,
    snapshotted_at_unix_secs: u64,
    preflighted_at_unix_secs: Option<u64>,
    completed_at_unix_secs: Option<u64>,
    component_count: u64,
    file_count: u64,
    total_bytes: u64,
    excluded_permit_count: u64,
    audit_sequence: Option<u64>,
    audit_hash: Option<String>,
    release_mode: String,
    release_policy_id: Option<String>,
    release_policy_version: Option<u64>,
    release_artifact_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleInventory {
    version: u8,
    operation_id: String,
    scope_ref: String,
    release_artifact: String,
    config_fingerprint: String,
    created_at_unix_secs: u64,
    created_at_subsec_nanos: u32,
    component_count: u64,
    file_count: u64,
    total_bytes: u64,
    excluded_permit_count: u64,
    entries: Vec<BundleEntry>,
    inventory_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleEntry {
    component: RecoveryComponentKind,
    relative_path: String,
    bytes: u64,
    fingerprint: String,
}

struct RecoveryLock(File);

impl Drop for RecoveryLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

struct WorkPaths {
    stage: PathBuf,
    previous: PathBuf,
    failed: PathBuf,
}

impl RecoveryDrillRunner {
    /// Load a strict reviewed manifest and current release/config bindings.
    pub fn load(
        manifest_path: &Path,
        release: ReleaseAdmission,
        principal: PrincipalChain,
    ) -> JanusResult<Self> {
        let text = read_reviewed_text(manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest = RecoveryDrillManifest::parse_json(&text)?;
        let plan_fingerprint = plan_fingerprint(&manifest)?;
        let config_fingerprint = validate_config_bindings(&manifest)?;
        let runner = Self {
            manifest,
            plan_fingerprint,
            config_fingerprint,
            release,
            principal,
            reviewed_owner: owner_id(manifest_path)?,
        };
        runner.validate_static_paths()?;
        runner.validate_release()?;
        if runner.principal.scope != runner.manifest.scope_ref() {
            return Err(recovery_denied(
                "recovery_scope_mismatch",
                "recovery principal scope does not match the reviewed manifest",
            ));
        }
        Ok(runner)
    }

    /// Exact reviewed manifest.
    pub fn manifest(&self) -> &RecoveryDrillManifest {
        &self.manifest
    }

    /// Require a runtime policy/descriptor input to be one exact reviewed binding.
    pub fn validate_bound_config_path(&self, path: &Path) -> JanusResult<()> {
        self.validate_config_unchanged()?;
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            recovery_denied(
                "recovery_config_unbound",
                "recovery runtime configuration is not an available reviewed file",
            )
        })?;
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !self
                .manifest
                .config_bindings()
                .iter()
                .any(|binding| binding.path() == path)
        {
            return Err(recovery_denied(
                "recovery_config_unbound",
                "recovery runtime configuration is not an exact reviewed binding",
            ));
        }
        Ok(())
    }

    /// Create a new private sealed snapshot bundle.
    pub fn snapshot(&self, now: SystemTime) -> JanusResult<RecoveryDrillStatus> {
        ensure_private_dir(self.manifest.state_root(), true)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        if self.read_journal()?.is_some() {
            return Err(recovery_denied(
                "recovery_snapshot_exists",
                "recovery snapshot is create-new and already exists",
            ));
        }
        if self.manifest.bundle_root().exists() {
            self.reject_orphan_work()?;
            let inventory = self.inspect_bundle(false)?;
            let journal = self.snapshot_journal(&inventory);
            self.write_journal(&journal)?;
            self.record_operation_audit(
                AuditOutcome::Allowed,
                "recovery_snapshot_recovered",
                Severity::High,
            )?;
            return Ok(self.status_from(&journal, "recovery_snapshot_recovered"));
        }
        self.recover_orphan_snapshot_stage()?;
        self.reject_orphan_work()?;
        self.validate_component_sources()?;
        let _source_audit = self.lock_and_validate_source_audit()?;
        let _age_lock = self.lock_age_source()?;

        self.record_operation_audit(
            AuditOutcome::Allowed,
            "recovery_snapshot_started",
            Severity::High,
        )?;

        let stage = self.snapshot_stage_path();
        create_private_dir(&stage)?;
        let payload = stage.join(PAYLOAD_DIR);
        create_private_dir(&payload)?;
        let mut entries = Vec::new();
        let mut total_bytes = 0_u64;
        for component in self.manifest.components() {
            snapshot_component(
                component.kind(),
                component.source_path(),
                &payload,
                &mut entries,
                &mut total_bytes,
                self.manifest.maximum_bundle_files(),
                self.manifest.maximum_bundle_bytes(),
            )?;
        }
        entries.sort();
        let excluded_permit_count = count_excluded_permits(
            self.manifest.permit_source_path(),
            self.manifest.maximum_bundle_files(),
        )?;
        let created = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| recovery_invalid("recovery clock is invalid"))?;
        let mut inventory = BundleInventory {
            version: INVENTORY_VERSION,
            operation_id: self.manifest.operation_id().to_string(),
            scope_ref: self.manifest.scope_ref().as_str().to_string(),
            release_artifact: self.manifest.release_artifact().to_string(),
            config_fingerprint: self.config_fingerprint.clone(),
            created_at_unix_secs: created.as_secs(),
            created_at_subsec_nanos: created.subsec_nanos(),
            component_count: RecoveryComponentKind::ALL.len() as u64,
            file_count: entries.len() as u64,
            total_bytes,
            excluded_permit_count,
            entries,
            inventory_fingerprint: String::new(),
        };
        inventory.inventory_fingerprint = inventory_fingerprint(&inventory)?;
        write_private_json_new(&stage.join(INVENTORY_FILE), &inventory)?;
        sync_dir(&stage)?;
        fs::rename(&stage, self.manifest.bundle_root()).map_err(|_| {
            recovery_denied(
                "recovery_snapshot_install_failed",
                "sealed recovery bundle could not be installed",
            )
        })?;
        sync_parent(self.manifest.bundle_root())?;

        let journal = self.snapshot_journal(&inventory);
        self.write_journal(&journal)?;
        self.record_operation_audit(
            AuditOutcome::Allowed,
            "recovery_snapshot_ok",
            Severity::High,
        )?;
        Ok(self.status_from(&journal, "recovery_snapshot_ok"))
    }

    /// Verify a sealed bundle and prepare an empty disposable target.
    pub fn preflight(&self, now: SystemTime) -> JanusResult<RecoveryDrillStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase != RecoveryPhase::Snapshotted {
            return Err(recovery_denied(
                "recovery_phase_invalid",
                "recovery preflight requires snapshotted state",
            ));
        }
        let inventory = self.inspect_bundle(true)?;
        if inventory.inventory_fingerprint != self.manifest.expected_bundle_fingerprint()
            || inventory.inventory_fingerprint != journal.bundle_fingerprint
        {
            return Err(recovery_denied(
                "recovery_bundle_mismatch",
                "sealed recovery bundle does not match the reviewed manifest",
            ));
        }
        ensure_private_dir(self.manifest.target_root(), true)?;
        ensure_empty_dir(self.manifest.target_root())?;
        self.reject_orphan_work()?;
        let required = inventory
            .total_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(self.manifest.minimum_free_bytes()))
            .ok_or_else(|| {
                recovery_denied(
                    "recovery_space_insufficient",
                    "recovery space requirement overflowed",
                )
            })?;
        let available = fs2::available_space(
            self.manifest
                .target_root()
                .parent()
                .unwrap_or_else(|| Path::new("/")),
        )
        .map_err(|_| {
            recovery_denied(
                "recovery_space_unavailable",
                "recovery free space could not be checked",
            )
        })?;
        if available < required {
            return Err(recovery_denied(
                "recovery_space_insufficient",
                "recovery requires more private staging space",
            ));
        }
        journal.phase = RecoveryPhase::Preflighted;
        journal.preflighted_at_unix_secs = Some(unix_seconds(now)?);
        journal.target_fingerprint = empty_tree_fingerprint();
        self.write_journal(&journal)?;
        self.record_operation_audit(
            AuditOutcome::Allowed,
            "recovery_preflight_ok",
            Severity::High,
        )?;
        Ok(self.status_from(&journal, "recovery_preflight_ok"))
    }

    /// Verify the sealed bundle and return paths for the provider preflight.
    pub fn prepare_preflight_provider_check(&self) -> JanusResult<RecoveryPostflightTarget> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        let journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase != RecoveryPhase::Snapshotted {
            return Err(recovery_denied(
                "recovery_phase_invalid",
                "recovery provider preflight requires snapshotted state",
            ));
        }
        let inventory = self.inspect_bundle(true)?;
        let payload = self.manifest.bundle_root().join(PAYLOAD_DIR);
        Ok(RecoveryPostflightTarget {
            age_root: target_component_path(&payload, RecoveryComponentKind::AgeCiphertext),
            metadata_path: target_component_path(&payload, RecoveryComponentKind::MetadataOverlay)
                .join(CONTENT_FILE),
            expected_ciphertext_files: inventory
                .entries
                .iter()
                .filter(|entry| entry.component == RecoveryComponentKind::AgeCiphertext)
                .count() as u64,
        })
    }

    /// Restore the sealed payload into the clean target using an atomic swap.
    pub fn restore(&self, now: SystemTime) -> JanusResult<RecoveryDrillStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        let inventory = self.inspect_bundle(true)?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase != RecoveryPhase::Preflighted {
            return Err(recovery_denied(
                "recovery_phase_invalid",
                "recovery restore requires preflighted state",
            ));
        }
        self.validate_preflight_age(&journal, now)?;
        ensure_private_dir(self.manifest.target_root(), false)?;
        ensure_empty_dir(self.manifest.target_root())?;
        let work = self.work_paths()?;
        reject_existing_path(&work.stage)?;
        reject_existing_path(&work.previous)?;
        reject_existing_path(&work.failed)?;

        journal.phase = RecoveryPhase::Restoring;
        self.write_journal(&journal)?;
        copy_tree_new(&self.manifest.bundle_root().join(PAYLOAD_DIR), &work.stage)?;
        let staged = inspect_payload_tree(&work.stage)?;
        validate_payload_against_inventory(&staged, &inventory)?;
        fs::rename(self.manifest.target_root(), &work.previous).map_err(|_| {
            recovery_denied(
                "recovery_restore_failed",
                "recovery could not preserve the empty target",
            )
        })?;
        if fs::rename(&work.stage, self.manifest.target_root()).is_err() {
            let _ = fs::rename(&work.previous, self.manifest.target_root());
            return Err(recovery_denied(
                "recovery_restore_failed",
                "recovery could not install staged state",
            ));
        }
        sync_parent(self.manifest.target_root())?;
        let installed = inspect_payload_tree(self.manifest.target_root())?;
        validate_payload_against_inventory(&installed, &inventory)?;
        journal.phase = RecoveryPhase::Restored;
        journal.target_fingerprint = payload_fingerprint(&installed);
        self.write_journal(&journal)?;
        self.record_operation_audit(AuditOutcome::Allowed, "recovery_restore_ok", Severity::High)?;
        Ok(self.status_from(&journal, "recovery_restore_ok"))
    }

    /// Verify generic restored state and return provider-specific check paths.
    pub fn prepare_postflight(&self) -> JanusResult<RecoveryPostflightTarget> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        let journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if !matches!(
            journal.phase,
            RecoveryPhase::Restored | RecoveryPhase::Postflighting
        ) {
            return Err(recovery_denied(
                "recovery_phase_invalid",
                "recovery postflight requires restored state",
            ));
        }
        let inventory = self.inspect_bundle(true)?;
        let installed = inspect_payload_tree(self.manifest.target_root())?;
        if journal.phase == RecoveryPhase::Restored {
            validate_payload_against_inventory(&installed, &inventory)?;
        }
        Ok(RecoveryPostflightTarget {
            age_root: target_component_path(
                self.manifest.target_root(),
                RecoveryComponentKind::AgeCiphertext,
            ),
            metadata_path: target_component_path(
                self.manifest.target_root(),
                RecoveryComponentKind::MetadataOverlay,
            )
            .join(CONTENT_FILE),
            expected_ciphertext_files: inventory
                .entries
                .iter()
                .filter(|entry| entry.component == RecoveryComponentKind::AgeCiphertext)
                .count() as u64,
        })
    }

    /// Complete semantic postflight after provider decryptability succeeds.
    pub fn postflight(
        &self,
        now: SystemTime,
        recoverable_ciphertext_files: u64,
    ) -> JanusResult<RecoveryDrillStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        self.validate_config_unchanged()?;
        let inventory = self.inspect_bundle(true)?;
        let expected_ciphertext_files = inventory
            .entries
            .iter()
            .filter(|entry| entry.component == RecoveryComponentKind::AgeCiphertext)
            .count() as u64;
        if recoverable_ciphertext_files != expected_ciphertext_files {
            return Err(recovery_denied(
                "recovery_provider_postflight_failed",
                "recovery provider check did not cover every encrypted payload",
            ));
        }
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == RecoveryPhase::Completed {
            self.validate_completed(&journal)?;
            return Ok(self.status_from(&journal, "recovery_already_completed"));
        }
        if !matches!(
            journal.phase,
            RecoveryPhase::Restored | RecoveryPhase::Postflighting
        ) {
            return Err(recovery_denied(
                "recovery_phase_invalid",
                "recovery postflight requires restored state",
            ));
        }

        if journal.phase == RecoveryPhase::Restored {
            let installed = inspect_payload_tree(self.manifest.target_root())?;
            validate_payload_against_inventory(&installed, &inventory)?;
            self.validate_production_state()?;
            journal.phase = RecoveryPhase::Postflighting;
            self.write_journal(&journal)?;
        }

        if journal.audit_sequence.is_none() || journal.audit_hash.is_none() {
            let target_audit =
                target_component_path(self.manifest.target_root(), RecoveryComponentKind::AuditLog)
                    .join(CONTENT_FILE);
            let mut audit = JsonlAuditSink::open(target_audit)?;
            audit.record(
                AuditEvent::new(
                    AuditAction::RecoveryDrill,
                    AuditOutcome::Allowed,
                    "recovery_drill_ok",
                    Severity::High,
                    None,
                    &self.principal,
                )
                .with_evidence(SafeLabel::new(format!(
                    "operation={};scope={}",
                    self.manifest.operation_id(),
                    self.manifest.scope_ref().as_str()
                ))?),
            )?;
            journal.audit_sequence = Some(audit.last_sequence());
            journal.audit_hash = Some(audit.last_event_hash().to_string());
            drop(audit);
            journal.target_fingerprint =
                payload_fingerprint(&inspect_payload_tree(self.manifest.target_root())?);
            self.write_journal(&journal)?;
        }

        self.record_operation_audit(
            AuditOutcome::Allowed,
            "recovery_postflight_ok",
            Severity::High,
        )?;
        let completed_at = now;
        let evidence = RecoveryDrillEvidenceV1::successful(
            &self.manifest,
            RecoveryDrillEvidenceInput {
                bundle_fingerprint: journal.bundle_fingerprint.clone(),
                config_fingerprint: journal.config_fingerprint.clone(),
                target_fingerprint: journal.target_fingerprint.clone(),
                file_count: journal.file_count,
                total_bytes: journal.total_bytes,
                excluded_permit_count: journal.excluded_permit_count,
                audit_sequence: journal.audit_sequence.ok_or_else(|| {
                    recovery_denied(
                        "recovery_postflight_failed",
                        "recovery audit sequence is missing",
                    )
                })?,
                audit_hash: journal.audit_hash.clone().ok_or_else(|| {
                    recovery_denied(
                        "recovery_postflight_failed",
                        "recovery audit hash is missing",
                    )
                })?,
                completed_at,
            },
        )?;
        write_private_json_atomic(self.manifest.evidence_path(), &evidence)?;
        evidence.validate_current(&self.manifest, now)?;
        journal.phase = RecoveryPhase::Completed;
        journal.completed_at_unix_secs = Some(unix_seconds(now)?);
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, "recovery_postflight_ok"))
    }

    /// Restore the verified empty target from any mutating drill phase.
    pub fn rollback(&self) -> JanusResult<RecoveryDrillStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == RecoveryPhase::RolledBack {
            ensure_private_dir(self.manifest.target_root(), false)?;
            ensure_empty_dir(self.manifest.target_root())?;
            return Ok(self.status_from(&journal, "recovery_already_rolled_back"));
        }
        journal.phase = RecoveryPhase::RollingBack;
        self.write_journal(&journal)?;
        let work = self.work_paths()?;
        cleanup_path(&work.stage)?;
        cleanup_path(&work.failed)?;
        if work.previous.exists() {
            if self.manifest.target_root().exists() {
                fs::rename(self.manifest.target_root(), &work.failed).map_err(|_| {
                    recovery_denied(
                        "recovery_rollback_failed",
                        "recovery rollback could not quarantine the drill target",
                    )
                })?;
            }
            fs::rename(&work.previous, self.manifest.target_root()).map_err(|_| {
                recovery_denied(
                    "recovery_rollback_failed",
                    "recovery rollback could not restore the empty target",
                )
            })?;
            cleanup_path(&work.failed)?;
        }
        ensure_private_dir(self.manifest.target_root(), false)?;
        ensure_empty_dir(self.manifest.target_root())?;
        if self.manifest.evidence_path().exists() {
            fs::remove_file(self.manifest.evidence_path()).map_err(|_| {
                recovery_denied(
                    "recovery_rollback_failed",
                    "recovery rollback could not remove drill evidence",
                )
            })?;
        }
        journal.phase = RecoveryPhase::RolledBack;
        journal.target_fingerprint = empty_tree_fingerprint();
        journal.audit_sequence = None;
        journal.audit_hash = None;
        journal.completed_at_unix_secs = None;
        self.write_journal(&journal)?;
        self.record_operation_audit(
            AuditOutcome::Allowed,
            "recovery_rollback_ok",
            Severity::Warning,
        )?;
        Ok(self.status_from(&journal, "recovery_rollback_ok"))
    }

    /// Inspect value-free current status without mutating drill state.
    pub fn status(&self) -> JanusResult<RecoveryDrillStatus> {
        match self.read_journal()? {
            Some(journal) => {
                self.validate_journal(&journal)?;
                if journal.phase == RecoveryPhase::Completed {
                    self.validate_completed(&journal)?;
                }
                Ok(self.status_from(&journal, "recovery_status_ok"))
            }
            None => Ok(RecoveryDrillStatus {
                operation_id: self.manifest.operation_id().to_string(),
                phase: "not_started".to_string(),
                scope_ref: self.manifest.scope_ref().as_str().to_string(),
                bundle_fingerprint: format!("sha256:{}", "0".repeat(64)),
                config_fingerprint: self.config_fingerprint.clone(),
                target_fingerprint: empty_tree_fingerprint(),
                component_count: RecoveryComponentKind::ALL.len() as u64,
                file_count: 0,
                total_bytes: 0,
                excluded_permit_count: 0,
                audit_sequence: 0,
                reason_code: "recovery_not_started",
                value_returned: false,
            }),
        }
    }

    fn validate_production_state(&self) -> JanusResult<()> {
        let metadata = target_component_path(
            self.manifest.target_root(),
            RecoveryComponentKind::MetadataOverlay,
        )
        .join(CONTENT_FILE);
        let metadata_text = read_private_text(&metadata, MAX_REGISTRY_FILE_BYTES)?;
        SecretMetadataOverlay::parse_toml(&metadata_text).map_err(|_| {
            recovery_denied(
                "recovery_metadata_invalid",
                "restored metadata overlay is invalid",
            )
        })?;

        let approvals = FileApprovalRegistry::new(target_component_path(
            self.manifest.target_root(),
            RecoveryComponentKind::Approvals,
        ));
        ApprovalRegistry::list(&approvals).map_err(|_| {
            recovery_denied(
                "recovery_approval_state_invalid",
                "restored approval state is invalid",
            )
        })?;
        let delegations = FileDelegationRegistry::new(target_component_path(
            self.manifest.target_root(),
            RecoveryComponentKind::Delegations,
        ));
        for entry in DelegationRegistry::list(&delegations).map_err(|_| {
            recovery_denied(
                "recovery_delegation_state_invalid",
                "restored delegation state is invalid",
            )
        })? {
            DelegationRegistry::get(&delegations, entry.delegation_id.as_str()).map_err(|_| {
                recovery_denied(
                    "recovery_delegation_state_invalid",
                    "restored delegation state is invalid",
                )
            })?;
        }
        FileLifecycleEvidenceRegistry::new(target_component_path(
            self.manifest.target_root(),
            RecoveryComponentKind::LifecycleEvidence,
        ))
        .list_existing_bounded(MAX_REGISTRY_ENTRIES, MAX_REGISTRY_FILE_BYTES)
        .map_err(|_| {
            recovery_denied(
                "recovery_lifecycle_state_invalid",
                "restored lifecycle evidence is invalid",
            )
        })?;
        FileTombstoneRegistry::new(target_component_path(
            self.manifest.target_root(),
            RecoveryComponentKind::Tombstones,
        ))
        .list_existing_bounded(MAX_REGISTRY_ENTRIES, MAX_REGISTRY_FILE_BYTES)
        .map_err(|_| {
            recovery_denied(
                "recovery_tombstone_state_invalid",
                "restored tombstone state is invalid",
            )
        })?;

        let restored_permits = self.manifest.target_root().join("permits");
        if restored_permits.exists() {
            return Err(recovery_denied(
                "recovery_permit_survived",
                "recovery target contains portable permit state",
            ));
        }
        Ok(())
    }

    fn validate_component_sources(&self) -> JanusResult<()> {
        for component in self.manifest.components() {
            if component.kind().is_file() {
                check_private_file(
                    component.source_path(),
                    self.manifest.maximum_bundle_bytes(),
                )?;
            } else {
                check_private_dir(component.source_path())?;
            }
            if matches!(
                component.kind(),
                RecoveryComponentKind::LifecycleEntry | RecoveryComponentKind::AdminState
            ) {
                reject_incomplete_journals(component.source_path())?;
            }
        }
        Ok(())
    }

    fn lock_and_validate_source_audit(&self) -> JanusResult<VerifiedAuditLock> {
        let path = self
            .manifest
            .components()
            .iter()
            .find(|component| component.kind() == RecoveryComponentKind::AuditLog)
            .expect("closed component set")
            .source_path();
        lock_verified_audit_for_snapshot(path).map_err(|_| {
            recovery_denied(
                "recovery_source_not_offline",
                "source audit is unavailable, active, or corrupt",
            )
        })
    }

    fn lock_age_source(&self) -> JanusResult<RecoveryLock> {
        let path = self
            .manifest
            .components()
            .iter()
            .find(|component| component.kind() == RecoveryComponentKind::AgeCiphertext)
            .expect("closed component set")
            .source_path()
            .join(".janus-age.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| {
            recovery_denied(
                "recovery_source_not_offline",
                "Age source maintenance lock is unavailable",
            )
        })?;
        set_file_private(&file)?;
        file.try_lock_exclusive().map_err(|_| {
            recovery_denied(
                "recovery_source_not_offline",
                "Age source is active during recovery snapshot",
            )
        })?;
        Ok(RecoveryLock(file))
    }

    fn inspect_bundle(&self, require_expected: bool) -> JanusResult<BundleInventory> {
        check_private_dir(self.manifest.bundle_root())?;
        let inventory: BundleInventory = read_private_json(
            &self.manifest.bundle_root().join(INVENTORY_FILE),
            MAX_INVENTORY_BYTES,
        )?;
        validate_inventory(&inventory, &self.manifest, &self.config_fingerprint)?;
        let actual = inspect_payload_tree(&self.manifest.bundle_root().join(PAYLOAD_DIR))?;
        validate_payload_against_inventory(&actual, &inventory)?;
        if require_expected
            && inventory.inventory_fingerprint != self.manifest.expected_bundle_fingerprint()
        {
            return Err(recovery_denied(
                "recovery_bundle_mismatch",
                "sealed recovery bundle does not match the reviewed manifest",
            ));
        }
        Ok(inventory)
    }

    fn validate_completed(&self, journal: &RecoveryJournal) -> JanusResult<()> {
        let evidence_text = read_private_text(self.manifest.evidence_path(), MAX_INVENTORY_BYTES)?;
        let evidence = RecoveryDrillEvidenceV1::parse_json(&evidence_text)?;
        evidence.validate_current(&self.manifest, SystemTime::now())?;
        let target = inspect_payload_tree(self.manifest.target_root())?;
        if payload_fingerprint(&target) != journal.target_fingerprint {
            return Err(recovery_denied(
                "recovery_terminal_state_mismatch",
                "completed recovery target does not match durable evidence",
            ));
        }
        Ok(())
    }

    fn validate_preflight_age(
        &self,
        journal: &RecoveryJournal,
        now: SystemTime,
    ) -> JanusResult<()> {
        let preflight = journal.preflighted_at_unix_secs.ok_or_else(|| {
            recovery_denied(
                "recovery_preflight_missing",
                "recovery preflight timestamp is missing",
            )
        })?;
        let age = unix_seconds(now)?.checked_sub(preflight).ok_or_else(|| {
            recovery_denied(
                "recovery_preflight_stale",
                "recovery clock moved behind preflight evidence",
            )
        })?;
        if age > self.manifest.preflight_max_age_seconds() {
            return Err(recovery_denied(
                "recovery_preflight_stale",
                "recovery preflight evidence is stale",
            ));
        }
        Ok(())
    }

    fn validate_release(&self) -> JanusResult<()> {
        if !self.release.allows_secret_use()
            || (self.release.mode().requires_trusted_release()
                && self.release.decision() != ReleaseAdmissionDecision::Trusted)
        {
            return Err(recovery_denied(
                "recovery_release_untrusted",
                "recovery drill requires an admitted runtime release",
            ));
        }
        if release_artifact(&self.release) != self.manifest.release_artifact() {
            return Err(recovery_denied(
                "recovery_release_mismatch",
                "recovery manifest does not match the admitted release",
            ));
        }
        Ok(())
    }

    fn validate_release_binding(&self, journal: &RecoveryJournal) -> JanusResult<()> {
        if journal.release_mode != self.release.mode().as_str()
            || journal.release_policy_id.as_deref() != self.release.policy_id()
            || journal.release_policy_version != self.release.policy_version()
            || journal.release_artifact_id.as_deref() != self.release.artifact_id()
        {
            return Err(recovery_denied(
                "recovery_release_changed",
                "release posture changed during recovery drill",
            ));
        }
        Ok(())
    }

    fn snapshot_journal(&self, inventory: &BundleInventory) -> RecoveryJournal {
        RecoveryJournal {
            version: JOURNAL_VERSION,
            operation_id: self.manifest.operation_id().to_string(),
            plan_fingerprint: self.plan_fingerprint.clone(),
            bundle_fingerprint: inventory.inventory_fingerprint.clone(),
            config_fingerprint: self.config_fingerprint.clone(),
            target_fingerprint: empty_tree_fingerprint(),
            phase: RecoveryPhase::Snapshotted,
            snapshotted_at_unix_secs: inventory.created_at_unix_secs,
            preflighted_at_unix_secs: None,
            completed_at_unix_secs: None,
            component_count: inventory.component_count,
            file_count: inventory.file_count,
            total_bytes: inventory.total_bytes,
            excluded_permit_count: inventory.excluded_permit_count,
            audit_sequence: None,
            audit_hash: None,
            release_mode: self.release.mode().as_str().to_string(),
            release_policy_id: self.release.policy_id().map(ToOwned::to_owned),
            release_policy_version: self.release.policy_version(),
            release_artifact_id: self.release.artifact_id().map(ToOwned::to_owned),
        }
    }

    fn validate_config_unchanged(&self) -> JanusResult<()> {
        if validate_config_bindings(&self.manifest)? != self.config_fingerprint {
            return Err(recovery_denied(
                "recovery_config_changed",
                "recovery configuration changed after runner load",
            ));
        }
        Ok(())
    }

    fn validate_static_paths(&self) -> JanusResult<()> {
        let mut paths = self
            .manifest
            .components()
            .iter()
            .map(|component| component.source_path().to_path_buf())
            .chain(
                self.manifest
                    .config_bindings()
                    .iter()
                    .map(|binding| binding.path().to_path_buf()),
            )
            .collect::<Vec<_>>();
        paths.extend([
            self.manifest.permit_source_path().to_path_buf(),
            self.manifest.bundle_root().to_path_buf(),
            self.manifest.target_root().to_path_buf(),
            self.manifest.state_root().to_path_buf(),
            self.manifest.operation_audit_path().to_path_buf(),
            self.manifest.evidence_path().to_path_buf(),
        ]);
        for path in &paths {
            if path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            {
                return Err(recovery_denied(
                    "recovery_path_invalid",
                    "recovery paths must be canonical absolute paths",
                ));
            }
        }
        let resolved = paths
            .iter()
            .map(|path| resolve_existing_prefix(path))
            .collect::<JanusResult<Vec<_>>>()?;
        for (index, left) in resolved.iter().enumerate() {
            for right in resolved.iter().skip(index + 1) {
                if left == right || left.starts_with(right) || right.starts_with(left) {
                    return Err(recovery_denied(
                        "recovery_path_overlap",
                        "recovery paths must be non-overlapping",
                    ));
                }
            }
        }
        for path in &paths {
            if owner_id_of_existing_prefix(path)? != self.reviewed_owner {
                return Err(recovery_denied(
                    "recovery_path_owner_mismatch",
                    "recovery paths must have one reviewed owner",
                ));
            }
        }
        for output in [
            self.manifest.bundle_root(),
            self.manifest.target_root(),
            self.manifest.state_root(),
            self.manifest.operation_audit_path(),
            self.manifest.evidence_path(),
        ] {
            let parent = output.parent().ok_or_else(|| {
                recovery_denied(
                    "recovery_path_invalid",
                    "recovery output requires a private parent",
                )
            })?;
            check_private_dir(parent)?;
        }
        Ok(())
    }

    fn validate_journal(&self, journal: &RecoveryJournal) -> JanusResult<()> {
        if journal.version != JOURNAL_VERSION
            || journal.operation_id != self.manifest.operation_id()
            || journal.plan_fingerprint != self.plan_fingerprint
            || journal.config_fingerprint != self.config_fingerprint
            || !valid_sha256(&journal.bundle_fingerprint)
            || !valid_sha256(&journal.target_fingerprint)
            || journal.component_count != RecoveryComponentKind::ALL.len() as u64
            || journal.file_count > self.manifest.maximum_bundle_files()
            || journal.total_bytes > self.manifest.maximum_bundle_bytes()
        {
            return Err(recovery_denied(
                "recovery_journal_invalid",
                "recovery journal does not match the reviewed operation",
            ));
        }
        self.validate_release_binding(journal)
    }

    fn record_operation_audit(
        &self,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
    ) -> JanusResult<()> {
        let mut audit = JsonlAuditSink::open(self.manifest.operation_audit_path())?;
        audit.record(
            AuditEvent::new(
                AuditAction::RecoveryDrill,
                outcome,
                reason_code,
                severity,
                None,
                &self.principal,
            )
            .with_evidence(SafeLabel::new(format!(
                "operation={};scope={}",
                self.manifest.operation_id(),
                self.manifest.scope_ref().as_str()
            ))?),
        )
    }

    fn acquire_lock(&self) -> JanusResult<RecoveryLock> {
        let path = self.manifest.state_root().join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| {
            recovery_denied(
                "recovery_lock_unavailable",
                "recovery maintenance lock is unavailable",
            )
        })?;
        set_file_private(&file)?;
        file.try_lock_exclusive().map_err(|_| {
            recovery_denied(
                "recovery_concurrent",
                "another recovery drill holds the maintenance lock",
            )
        })?;
        Ok(RecoveryLock(file))
    }

    fn read_journal(&self) -> JanusResult<Option<RecoveryJournal>> {
        let path = self.journal_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => read_private_json(&path, MAX_INVENTORY_BYTES).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(recovery_denied(
                "recovery_journal_unavailable",
                "recovery journal is unavailable",
            )),
        }
    }

    fn read_required_journal(&self) -> JanusResult<RecoveryJournal> {
        self.read_journal()?.ok_or_else(|| {
            recovery_denied(
                "recovery_snapshot_missing",
                "recovery requires a sealed snapshot journal",
            )
        })
    }

    fn write_journal(&self, journal: &RecoveryJournal) -> JanusResult<()> {
        write_private_json_atomic(&self.journal_path(), journal)
    }

    fn journal_path(&self) -> PathBuf {
        self.manifest.state_root().join(JOURNAL_FILE)
    }

    fn snapshot_stage_path(&self) -> PathBuf {
        self.manifest.state_root().join("snapshot-stage")
    }

    fn work_paths(&self) -> JanusResult<WorkPaths> {
        let parent = self.manifest.target_root().parent().ok_or_else(|| {
            recovery_denied(
                "recovery_path_invalid",
                "recovery target has no parent directory",
            )
        })?;
        let operation = self.manifest.operation_id();
        Ok(WorkPaths {
            stage: parent.join(format!(".janus-recovery-{operation}-stage")),
            previous: parent.join(format!(".janus-recovery-{operation}-previous")),
            failed: parent.join(format!(".janus-recovery-{operation}-failed")),
        })
    }

    fn reject_orphan_work(&self) -> JanusResult<()> {
        reject_existing_path(&self.snapshot_stage_path())?;
        let work = self.work_paths()?;
        reject_existing_path(&work.stage)?;
        reject_existing_path(&work.previous)?;
        reject_existing_path(&work.failed)
    }

    fn recover_orphan_snapshot_stage(&self) -> JanusResult<()> {
        let stage = self.snapshot_stage_path();
        match fs::symlink_metadata(&stage) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                Err(recovery_denied(
                    "recovery_orphan_work_state",
                    "recovery snapshot work state is not a private directory",
                ))
            }
            Ok(_) => {
                check_private_dir(&stage)?;
                cleanup_path(&stage)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(recovery_invalid(
                "recovery snapshot work state could not be inspected",
            )),
        }
    }

    fn status_from(
        &self,
        journal: &RecoveryJournal,
        reason_code: &'static str,
    ) -> RecoveryDrillStatus {
        RecoveryDrillStatus {
            operation_id: journal.operation_id.clone(),
            phase: journal.phase.as_str().to_string(),
            scope_ref: self.manifest.scope_ref().as_str().to_string(),
            bundle_fingerprint: journal.bundle_fingerprint.clone(),
            config_fingerprint: journal.config_fingerprint.clone(),
            target_fingerprint: journal.target_fingerprint.clone(),
            component_count: journal.component_count,
            file_count: journal.file_count,
            total_bytes: journal.total_bytes,
            excluded_permit_count: journal.excluded_permit_count,
            audit_sequence: journal.audit_sequence.unwrap_or(0),
            reason_code,
            value_returned: false,
        }
    }
}

/// Enforce optional startup freshness evidence when explicitly configured.
pub fn enforce_recovery_drill_freshness_from_env(
    release: &ReleaseAdmission,
    scope: &janus_core::ScopeRef,
) -> JanusResult<()> {
    let manifest_path =
        env::var_os("JANUS_RECOVERY_DRILL_MANIFEST").filter(|value| !value.is_empty());
    let evidence_path =
        env::var_os("JANUS_RECOVERY_DRILL_EVIDENCE").filter(|value| !value.is_empty());
    match (manifest_path, evidence_path) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(recovery_denied(
            "recovery_evidence_missing",
            "recovery freshness requires both manifest and evidence",
        )),
        (Some(manifest_path), Some(evidence_path)) => enforce_recovery_drill_freshness(
            Path::new(&manifest_path),
            Path::new(&evidence_path),
            release,
            scope,
            SystemTime::now(),
        ),
    }
}

/// Verify one exact current recovery-drill evidence record.
pub fn enforce_recovery_drill_freshness(
    manifest_path: &Path,
    evidence_path: &Path,
    release: &ReleaseAdmission,
    scope: &janus_core::ScopeRef,
    now: SystemTime,
) -> JanusResult<()> {
    let manifest_text = read_reviewed_text(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest = RecoveryDrillManifest::parse_json(&manifest_text)?;
    if &manifest.scope_ref() != scope || manifest.release_artifact() != release_artifact(release) {
        return Err(recovery_denied(
            "recovery_evidence_mismatch",
            "recovery freshness evidence does not match current runtime",
        ));
    }
    let config_fingerprint = validate_config_bindings(&manifest)?;
    let evidence_text = read_private_text(evidence_path, MAX_INVENTORY_BYTES)?;
    let evidence = RecoveryDrillEvidenceV1::parse_json(&evidence_text)?;
    if evidence.config_fingerprint != config_fingerprint {
        return Err(recovery_denied(
            "recovery_evidence_mismatch",
            "recovery freshness evidence does not match current configuration",
        ));
    }
    evidence.validate_current(&manifest, now)
}

fn snapshot_component(
    kind: RecoveryComponentKind,
    source: &Path,
    payload_root: &Path,
    entries: &mut Vec<BundleEntry>,
    total_bytes: &mut u64,
    max_files: u64,
    max_bytes: u64,
) -> JanusResult<()> {
    let destination = target_component_path(payload_root, kind);
    create_private_dir(&destination)?;
    if kind.is_file() {
        let target = destination.join(CONTENT_FILE);
        let (bytes, fingerprint) = copy_private_file(source, &target, max_bytes)?;
        push_entry(
            entries,
            total_bytes,
            BundleEntry {
                component: kind,
                relative_path: CONTENT_FILE.to_string(),
                bytes,
                fingerprint,
            },
            max_files,
            max_bytes,
        )?;
    } else {
        snapshot_directory(
            kind,
            source,
            source,
            &destination,
            entries,
            total_bytes,
            max_files,
            max_bytes,
        )?;
    }
    sync_dir(&destination)
}

#[allow(clippy::too_many_arguments)]
fn snapshot_directory(
    kind: RecoveryComponentKind,
    root: &Path,
    current: &Path,
    destination_root: &Path,
    entries: &mut Vec<BundleEntry>,
    total_bytes: &mut u64,
    max_files: u64,
    max_bytes: u64,
) -> JanusResult<()> {
    let mut children = fs::read_dir(current)
        .map_err(|_| recovery_invalid("recovery source directory is unavailable"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| recovery_invalid("recovery source directory is unavailable"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| recovery_invalid("recovery source entry name is invalid"))?;
        if forbidden_transient_name(name) {
            if name.ends_with(".lock") {
                continue;
            }
            return Err(recovery_denied(
                "recovery_source_incomplete",
                "recovery source contains transient state",
            ));
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| recovery_invalid("recovery source entry is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery source contains a symlink",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| recovery_invalid("recovery source entry escaped its component"))?;
        let destination = destination_root.join(relative);
        if metadata.is_dir() {
            check_private_dir(&path)?;
            create_private_dir(&destination)?;
            snapshot_directory(
                kind,
                root,
                &path,
                destination_root,
                entries,
                total_bytes,
                max_files,
                max_bytes,
            )?;
            sync_dir(&destination)?;
        } else if metadata.is_file() {
            check_private_file(&path, max_bytes)?;
            let (bytes, fingerprint) = copy_private_file(&path, &destination, max_bytes)?;
            let relative_path = relative_path_text(relative)?;
            push_entry(
                entries,
                total_bytes,
                BundleEntry {
                    component: kind,
                    relative_path,
                    bytes,
                    fingerprint,
                },
                max_files,
                max_bytes,
            )?;
        } else {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery source contains an unsupported file type",
            ));
        }
    }
    Ok(())
}

fn push_entry(
    entries: &mut Vec<BundleEntry>,
    total_bytes: &mut u64,
    entry: BundleEntry,
    max_files: u64,
    max_bytes: u64,
) -> JanusResult<()> {
    if entries.len() as u64 >= max_files {
        return Err(recovery_denied(
            "recovery_bundle_too_large",
            "recovery bundle file limit was exceeded",
        ));
    }
    *total_bytes = total_bytes.checked_add(entry.bytes).ok_or_else(|| {
        recovery_denied(
            "recovery_bundle_too_large",
            "recovery bundle byte count overflowed",
        )
    })?;
    if *total_bytes > max_bytes {
        return Err(recovery_denied(
            "recovery_bundle_too_large",
            "recovery bundle byte limit was exceeded",
        ));
    }
    entries.push(entry);
    Ok(())
}

fn validate_inventory(
    inventory: &BundleInventory,
    manifest: &RecoveryDrillManifest,
    config_fingerprint: &str,
) -> JanusResult<()> {
    let mut sorted = inventory.entries.clone();
    sorted.sort();
    let unique = sorted.iter().collect::<BTreeSet<_>>();
    if inventory.version != INVENTORY_VERSION
        || inventory.operation_id != manifest.operation_id()
        || inventory.scope_ref != manifest.scope_ref().as_str()
        || inventory.release_artifact != manifest.release_artifact()
        || inventory.config_fingerprint != config_fingerprint
        || inventory.component_count != RecoveryComponentKind::ALL.len() as u64
        || inventory.file_count != inventory.entries.len() as u64
        || inventory.file_count > manifest.maximum_bundle_files()
        || inventory.total_bytes > manifest.maximum_bundle_bytes()
        || sorted != inventory.entries
        || unique.len() != inventory.entries.len()
        || inventory.entries.iter().any(|entry| {
            !safe_relative_path(&entry.relative_path) || !valid_sha256(&entry.fingerprint)
        })
        || inventory.inventory_fingerprint != inventory_fingerprint(inventory)?
    {
        return Err(recovery_denied(
            "recovery_bundle_invalid",
            "sealed recovery bundle inventory is invalid",
        ));
    }
    let total = inventory
        .entries
        .iter()
        .try_fold(0_u64, |sum, entry| sum.checked_add(entry.bytes));
    if total != Some(inventory.total_bytes) {
        return Err(recovery_denied(
            "recovery_bundle_invalid",
            "sealed recovery bundle byte total is invalid",
        ));
    }
    Ok(())
}

fn inspect_payload_tree(root: &Path) -> JanusResult<Vec<BundleEntry>> {
    check_private_dir(root)?;
    let mut entries = Vec::new();
    for kind in RecoveryComponentKind::ALL {
        let component_root = target_component_path(root, kind);
        check_private_dir(&component_root)?;
        collect_payload_entries(kind, &component_root, &component_root, &mut entries)?;
    }
    entries.sort();
    Ok(entries)
}

fn collect_payload_entries(
    kind: RecoveryComponentKind,
    root: &Path,
    current: &Path,
    entries: &mut Vec<BundleEntry>,
) -> JanusResult<()> {
    let mut children = fs::read_dir(current)
        .map_err(|_| recovery_invalid("recovery payload directory is unavailable"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| recovery_invalid("recovery payload directory is unavailable"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| recovery_invalid("recovery payload entry is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery payload contains a symlink",
            ));
        }
        if metadata.is_dir() {
            check_private_dir(&path)?;
            collect_payload_entries(kind, root, &path, entries)?;
        } else if metadata.is_file() {
            check_private_file(&path, u64::MAX)?;
            let bytes = read_private_bytes(&path, u64::MAX)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| recovery_invalid("recovery payload escaped its component"))?;
            entries.push(BundleEntry {
                component: kind,
                relative_path: relative_path_text(relative)?,
                bytes: bytes.len() as u64,
                fingerprint: fingerprint_bytes(&bytes),
            });
        } else {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery payload contains an unsupported file type",
            ));
        }
    }
    Ok(())
}

fn validate_payload_against_inventory(
    actual: &[BundleEntry],
    inventory: &BundleInventory,
) -> JanusResult<()> {
    if actual != inventory.entries {
        return Err(recovery_denied(
            "recovery_bundle_tampered",
            "recovery payload does not match its sealed inventory",
        ));
    }
    Ok(())
}

fn inventory_fingerprint(inventory: &BundleInventory) -> JanusResult<String> {
    let mut canonical = BundleInventory {
        inventory_fingerprint: String::new(),
        ..inventory.clone()
    };
    canonical.entries.sort();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|_| recovery_invalid("recovery inventory could not be encoded"))?;
    Ok(fingerprint_domain("janus-recovery-inventory-v1", &bytes))
}

fn payload_fingerprint(entries: &[BundleEntry]) -> String {
    let bytes = serde_json::to_vec(entries).expect("recovery payload entries serialize");
    fingerprint_domain("janus-recovery-target-v1", &bytes)
}

fn empty_tree_fingerprint() -> String {
    payload_fingerprint(&[])
}

fn plan_fingerprint(manifest: &RecoveryDrillManifest) -> JanusResult<String> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|_| recovery_invalid("recovery manifest could not be encoded"))?;
    value["expected_bundle_fingerprint"] =
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| recovery_invalid("recovery manifest could not be encoded"))?;
    Ok(fingerprint_domain("janus-recovery-plan-v1", &bytes))
}

fn validate_config_bindings(manifest: &RecoveryDrillManifest) -> JanusResult<String> {
    let mut bindings = BTreeMap::new();
    for binding in manifest.config_bindings() {
        let bytes = read_reviewed_bytes(binding.path(), MAX_MANIFEST_BYTES)?;
        let fingerprint = fingerprint_bytes(&bytes);
        if fingerprint != binding.expected_fingerprint() {
            return Err(recovery_denied(
                "recovery_config_mismatch",
                "recovery configuration does not match the reviewed fingerprint",
            ));
        }
        bindings.insert(binding.name().to_string(), fingerprint);
    }
    let bytes = serde_json::to_vec(&bindings)
        .map_err(|_| recovery_invalid("recovery configuration could not be encoded"))?;
    Ok(fingerprint_domain("janus-recovery-config-v1", &bytes))
}

fn count_excluded_permits(path: &Path, max_files: u64) -> JanusResult<u64> {
    check_private_dir(path)?;
    let mut count = 0_u64;
    for entry in fs::read_dir(path)
        .map_err(|_| recovery_invalid("permit registry could not be inspected"))?
    {
        let path = entry
            .map_err(|_| recovery_invalid("permit registry could not be inspected"))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| recovery_invalid("permit registry entry is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(recovery_denied(
                "recovery_permit_state_invalid",
                "permit registry contains unsupported state",
            ));
        }
        check_private_file(&path, MAX_REGISTRY_FILE_BYTES)?;
        count = count.checked_add(1).ok_or_else(|| {
            recovery_denied(
                "recovery_bundle_too_large",
                "permit exclusion count overflowed",
            )
        })?;
        if count > max_files {
            return Err(recovery_denied(
                "recovery_bundle_too_large",
                "permit exclusion count exceeded the reviewed limit",
            ));
        }
    }
    Ok(count)
}

fn reject_incomplete_journals(root: &Path) -> JanusResult<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|_| recovery_invalid("admin state could not be inspected"))?
        {
            let path = entry
                .map_err(|_| recovery_invalid("admin state could not be inspected"))?
                .path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| recovery_invalid("admin state entry is unavailable"))?;
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if !metadata.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let bytes = read_private_bytes(&path, MAX_REGISTRY_FILE_BYTES)?;
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let Some(phase) = value.get("phase").and_then(|phase| phase.as_str()) else {
                continue;
            };
            if !matches!(phase, "completed" | "rolled_back" | "complete") {
                return Err(recovery_denied(
                    "recovery_source_incomplete",
                    "recovery source contains a non-terminal administration journal",
                ));
            }
        }
    }
    Ok(())
}

fn copy_tree_new(source: &Path, destination: &Path) -> JanusResult<()> {
    check_private_dir(source)?;
    create_private_dir(destination)?;
    let mut children = fs::read_dir(source)
        .map_err(|_| recovery_invalid("recovery payload could not be staged"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| recovery_invalid("recovery payload could not be staged"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let source_path = child.path();
        let destination_path = destination.join(child.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|_| recovery_invalid("recovery payload entry is unavailable"))?;
        if metadata.is_dir() {
            copy_tree_new(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            copy_private_file(&source_path, &destination_path, u64::MAX)?;
        } else {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery payload contains an unsupported file type",
            ));
        }
    }
    sync_dir(destination)
}

fn copy_private_file(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
) -> JanusResult<(u64, String)> {
    let bytes = read_private_bytes(source, max_bytes)?;
    let parent = destination
        .parent()
        .ok_or_else(|| recovery_invalid("recovery output has no parent"))?;
    ensure_private_dir(parent, false)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(destination)
        .map_err(|_| recovery_denied("recovery_output_exists", "recovery output is create-new"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| recovery_invalid("recovery output could not be persisted"))?;
    Ok((bytes.len() as u64, fingerprint_bytes(&bytes)))
}

fn read_reviewed_text(path: &Path, max_bytes: u64) -> JanusResult<String> {
    String::from_utf8(read_reviewed_bytes(path, max_bytes)?)
        .map_err(|_| recovery_invalid("reviewed recovery input is not UTF-8"))
}

fn read_reviewed_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| recovery_invalid("reviewed recovery input is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(recovery_denied(
            "recovery_input_invalid",
            "reviewed recovery input is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(recovery_denied(
                "recovery_input_invalid",
                "reviewed recovery input is mutable by group or world",
            ));
        }
    }
    fs::read(path).map_err(|_| recovery_invalid("reviewed recovery input could not be read"))
}

fn read_private_text(path: &Path, max_bytes: u64) -> JanusResult<String> {
    String::from_utf8(read_private_bytes(path, max_bytes)?)
        .map_err(|_| recovery_invalid("private recovery file is not UTF-8"))
}

fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path, max_bytes: u64) -> JanusResult<T> {
    let bytes = read_private_bytes(path, max_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| recovery_invalid("private recovery JSON is malformed"))
}

fn read_private_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    check_private_file(path, max_bytes)?;
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| recovery_invalid("private recovery file could not be read"))?;
    Ok(bytes)
}

fn check_private_file(path: &Path, max_bytes: u64) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| recovery_invalid("private recovery file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(recovery_denied(
            "recovery_insecure_path",
            "recovery file is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery file must be private",
            ));
        }
    }
    Ok(())
}

fn check_private_dir(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| recovery_invalid("private recovery directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(recovery_denied(
            "recovery_insecure_path",
            "recovery path is not a private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(recovery_denied(
                "recovery_insecure_path",
                "recovery directory must be private",
            ));
        }
    }
    Ok(())
}

fn ensure_private_dir(path: &Path, create: bool) -> JanusResult<()> {
    if create && !path.exists() {
        fs::create_dir_all(path)
            .map_err(|_| recovery_invalid("private recovery directory could not be created"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                recovery_invalid("private recovery directory permissions could not be set")
            })?;
        }
    }
    check_private_dir(path)
}

fn create_private_dir(path: &Path) -> JanusResult<()> {
    fs::create_dir(path).map_err(|_| {
        recovery_denied(
            "recovery_output_exists",
            "private recovery output is create-new",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| recovery_invalid("recovery output permissions could not be set"))?;
    }
    Ok(())
}

fn ensure_empty_dir(path: &Path) -> JanusResult<()> {
    if fs::read_dir(path)
        .map_err(|_| recovery_invalid("recovery target could not be inspected"))?
        .next()
        .is_some()
    {
        return Err(recovery_denied(
            "recovery_target_not_empty",
            "recovery drill requires an empty target",
        ));
    }
    Ok(())
}

fn write_private_json_new<T: Serialize>(path: &Path, value: &T) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| recovery_invalid("private recovery JSON could not be encoded"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| recovery_invalid("private recovery JSON could not be created"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| recovery_invalid("private recovery JSON could not be persisted"))
}

fn write_private_json_atomic<T: Serialize>(path: &Path, value: &T) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| recovery_invalid("private recovery JSON could not be encoded"))?;
    let parent = path
        .parent()
        .ok_or_else(|| recovery_invalid("private recovery JSON has no parent"))?;
    ensure_private_dir(parent, true)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| recovery_invalid("private recovery JSON name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| recovery_invalid("recovery clock is invalid"))?
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| recovery_invalid("private recovery JSON temp file could not be created"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| recovery_invalid("private recovery JSON could not be persisted"))?;
    fs::rename(&temp, path)
        .map_err(|_| recovery_invalid("private recovery JSON could not be installed"))?;
    sync_dir(parent)
}

fn set_file_private(file: &File) -> JanusResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| recovery_invalid("recovery lock permissions could not be set"))?;
    }
    Ok(())
}

fn cleanup_path(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(recovery_denied(
            "recovery_insecure_path",
            "recovery work path is a symlink",
        )),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)
            .map_err(|_| recovery_invalid("recovery work path could not be cleaned")),
        Ok(_) => fs::remove_file(path)
            .map_err(|_| recovery_invalid("recovery work path could not be cleaned")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(recovery_invalid(
            "recovery work path could not be inspected",
        )),
    }
}

fn reject_existing_path(path: &Path) -> JanusResult<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(recovery_denied(
            "recovery_orphan_work_state",
            "recovery work state already exists",
        ));
    }
    Ok(())
}

fn sync_dir(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| recovery_invalid("recovery directory could not be synchronized"))
}

fn sync_parent(path: &Path) -> JanusResult<()> {
    sync_dir(path.parent().unwrap_or_else(|| Path::new("/")))
}

fn work_component_name(kind: RecoveryComponentKind) -> &'static str {
    kind.as_str()
}

fn target_component_path(root: &Path, kind: RecoveryComponentKind) -> PathBuf {
    root.join(work_component_name(kind))
}

fn relative_path_text(path: &Path) -> JanusResult<String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(recovery_invalid("recovery relative path is invalid"));
    }
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            unreachable!()
        };
        let value = value
            .to_str()
            .ok_or_else(|| recovery_invalid("recovery relative path is not UTF-8"))?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(value);
    }
    Ok(output)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    let canonical = path.components().collect::<PathBuf>();
    !value.is_empty()
        && value.len() <= 4096
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && canonical.as_os_str() == path.as_os_str()
}

fn resolve_existing_prefix(path: &Path) -> JanusResult<PathBuf> {
    let mut existing = path;
    let mut suffix = Vec::<OsString>::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    recovery_denied(
                        "recovery_path_invalid",
                        "recovery path has no existing filesystem prefix",
                    )
                })?;
                suffix.push(name.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    recovery_denied(
                        "recovery_path_invalid",
                        "recovery path has no existing filesystem prefix",
                    )
                })?;
            }
            Err(_) => {
                return Err(recovery_denied(
                    "recovery_path_invalid",
                    "recovery path could not be resolved",
                ));
            }
        }
    }
    let mut resolved = fs::canonicalize(existing).map_err(|_| {
        recovery_denied(
            "recovery_path_invalid",
            "recovery path could not be resolved",
        )
    })?;
    for component in suffix.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(unix)]
fn owner_id(path: &Path) -> JanusResult<Option<u32>> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path)
        .map(|metadata| Some(metadata.uid()))
        .map_err(|_| recovery_invalid("recovery path ownership is unavailable"))
}

#[cfg(not(unix))]
fn owner_id(_path: &Path) -> JanusResult<Option<u32>> {
    Ok(None)
}

fn owner_id_of_existing_prefix(path: &Path) -> JanusResult<Option<u32>> {
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => return owner_id(current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = current
                    .parent()
                    .ok_or_else(|| recovery_invalid("recovery path ownership is unavailable"))?;
            }
            Err(_) => return Err(recovery_invalid("recovery path ownership is unavailable")),
        }
    }
}

fn forbidden_transient_name(name: &str) -> bool {
    name.starts_with('.')
        || name.ends_with(".tmp")
        || name.ends_with(".claim")
        || name.contains("rollback")
        || matches!(name, "stage" | "previous" | "failed")
}

fn fingerprint_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn fingerprint_domain(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn release_artifact(release: &ReleaseAdmission) -> String {
    release
        .artifact_id()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("not_required:{}", release.mode().as_str()))
}

fn unix_seconds(time: SystemTime) -> JanusResult<u64> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| recovery_invalid("recovery clock is invalid"))?
        .as_secs())
}

fn recovery_invalid(detail: &'static str) -> JanusError {
    JanusError::InvalidManifest {
        detail: detail.to_string(),
    }
}

fn recovery_denied(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LifecycleEvidenceRegistry, TombstoneRegistry};
    use janus_core::{
        ApprovalGrant, AuditWrite, DelegationPolicy, DelegationStatus, Destination, EgressMode,
        ExecutorRef, OwnerRef, Principal, PrincipalId, PrincipalKind, ProductMode, ProfileId,
        ProfilePolicy, Purpose, ScopePathV1, SecretClass, SecretDescriptor, SecretLifecycle,
        SecretName, SecretRef, SecretTombstoneRequest, TombstonePolicy, TrustLevel, UseProfile,
        UseRequest,
    };
    use std::time::Duration;
    use tempfile::tempdir;

    struct Fixture {
        _temp: tempfile::TempDir,
        manifest: PathBuf,
        sources: BTreeMap<RecoveryComponentKind, PathBuf>,
        target: PathBuf,
        evidence: PathBuf,
        config: PathBuf,
        scope: janus_core::ScopeRef,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempdir().unwrap();
            let root = temp.path();
            private_dir(root);
            let source_root = root.join("source");
            private_dir(&source_root);
            let mut sources = BTreeMap::new();
            for kind in RecoveryComponentKind::ALL {
                let path = source_root.join(kind.as_str());
                if kind.is_file() {
                    private_file(&path, b"");
                } else {
                    private_dir(&path);
                }
                sources.insert(kind, path);
            }
            let audit_path = sources[&RecoveryComponentKind::AuditLog].clone();
            let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
                .unwrap()
                .scope_ref();
            let principal = PrincipalChain::new(
                Principal::new(
                    PrincipalKind::Executor,
                    PrincipalId::new("recovery-fixture").unwrap(),
                ),
                scope.clone(),
            );
            let mut audit = JsonlAuditSink::open(&audit_path).unwrap();
            audit
                .record(AuditEvent::new(
                    AuditAction::BackendHealth,
                    AuditOutcome::Allowed,
                    "fixture_ok",
                    Severity::Info,
                    None,
                    &principal,
                ))
                .unwrap();
            drop(audit);

            let config = root.join("secretspec.toml");
            reviewed_file(&config, b"[project]\nname = \"janus\"\n");
            let permits = root.join("permits");
            private_dir(&permits);
            private_file(&permits.join("permit.json"), b"{}\n");
            let bundle = root.join("bundle");
            let target = root.join("target");
            let state = root.join("state");
            let operation_dir = root.join("operation-audit");
            private_dir(&operation_dir);
            let operation_audit = operation_dir.join("audit.jsonl");
            let evidence_dir = root.join("evidence");
            private_dir(&evidence_dir);
            let evidence = evidence_dir.join("evidence.json");
            let manifest = root.join("manifest.json");
            let components = RecoveryComponentKind::ALL
                .iter()
                .map(|kind| {
                    serde_json::json!({
                        "kind": kind.as_str(),
                        "source_path": sources[kind],
                    })
                })
                .collect::<Vec<_>>();
            let value = serde_json::json!({
                "schema_version": 1,
                "operation_id": "clean-state-fixture",
                "scope_ref": scope.as_str(),
                "release_artifact": "not_required:self_hosted",
                "expected_bundle_fingerprint": format!("sha256:{}", "0".repeat(64)),
                "components": components,
                "config_bindings": [{
                    "name": "secretspec",
                    "path": config,
                    "expected_fingerprint": fingerprint_bytes(b"[project]\nname = \"janus\"\n"),
                }],
                "permit_source_path": permits,
                "bundle_root": bundle,
                "target_root": target,
                "state_root": state,
                "operation_audit_path": operation_audit,
                "evidence_path": evidence,
                "minimum_free_bytes": 0,
                "maximum_bundle_bytes": 16 * 1024 * 1024,
                "maximum_bundle_files": 4096,
                "preflight_max_age_seconds": 900,
                "evidence_max_age_seconds": 86400,
            });
            reviewed_file(
                &manifest,
                serde_json::to_string_pretty(&value).unwrap().as_bytes(),
            );
            Self {
                _temp: temp,
                manifest,
                sources,
                target,
                evidence,
                config,
                scope,
            }
        }

        fn runner(&self) -> RecoveryDrillRunner {
            RecoveryDrillRunner::load(
                &self.manifest,
                ReleaseAdmission::not_required(ProductMode::SelfHosted),
                PrincipalChain::new(
                    Principal::new(
                        PrincipalKind::Executor,
                        PrincipalId::new("recovery-fixture").unwrap(),
                    ),
                    self.scope.clone(),
                ),
            )
            .unwrap()
        }

        fn bind_bundle(&self, fingerprint: &str) {
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&self.manifest).unwrap()).unwrap();
            value["expected_bundle_fingerprint"] =
                serde_json::Value::String(fingerprint.to_string());
            reviewed_file(
                &self.manifest,
                serde_json::to_string_pretty(&value).unwrap().as_bytes(),
            );
        }
    }

    #[test]
    fn clean_state_round_trip_excludes_permits_continues_audit_and_rolls_back() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let snapshot = fixture.runner().snapshot(now).unwrap();
        assert_eq!(snapshot.excluded_permit_count, 1);
        fixture.bind_bundle(&snapshot.bundle_fingerprint);
        let runner = fixture.runner();
        runner.preflight(now + Duration::from_secs(1)).unwrap();
        runner.restore(now + Duration::from_secs(2)).unwrap();
        let provider = runner.prepare_postflight().unwrap();
        assert_eq!(provider.expected_ciphertext_files(), 0);
        let completed = runner.postflight(now + Duration::from_secs(3), 0).unwrap();
        assert_eq!(completed.phase, "completed");
        assert!(completed.audit_sequence >= 2);
        assert!(fixture.evidence.is_file());
        assert!(!fixture.target.join("permits").exists());
        let rolled_back = runner.rollback().unwrap();
        assert_eq!(rolled_back.phase, "rolled_back");
        assert!(fs::read_dir(&fixture.target).unwrap().next().is_none());
    }

    #[test]
    fn mixed_authority_lifecycle_and_tombstone_state_survives_production_parsers() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let secret_ref = SecretRef::new("sec_recovery_fixture").unwrap();
        let profile_id = ProfileId::new("profile.recovery").unwrap();
        let executor = ExecutorRef::new("janus-run@fixture").unwrap();
        let destination = Destination::new("recovery-service").unwrap();
        let descriptor = SecretDescriptor {
            name: SecretName::new("RECOVERY_FIXTURE").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Recovery fixture").unwrap(),
            scope: fixture.scope.clone(),
            owner: Some(OwnerRef::new("security").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L2,
            allowed_uses: vec![profile_id.clone()],
            present: true,
        };
        let profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            scope: fixture.scope.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let policy = ProfilePolicy::new(vec![profile.clone()]);
        let mut grantor = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new(executor.as_str()).unwrap(),
            ),
            fixture.scope.clone(),
        );
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("recovery-grantor").unwrap(),
        ));
        let mut delegate = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new(executor.as_str()).unwrap(),
            ),
            fixture.scope.clone(),
        );
        delegate.agent = Some(Principal::new(
            PrincipalKind::AgentSession,
            PrincipalId::new("session:recovery-delegate").unwrap(),
        ));
        let delegations =
            FileDelegationRegistry::new(&fixture.sources[&RecoveryComponentKind::Delegations]);
        let mut delegation_ids = Vec::new();
        for (label, expires_at) in [
            ("active delegation", now + Duration::from_secs(900)),
            ("revoked delegation", now + Duration::from_secs(900)),
            ("expired delegation", now + Duration::from_secs(20)),
        ] {
            let request = UseRequest {
                secret_ref: secret_ref.clone(),
                scope: fixture.scope.clone(),
                profile_id: profile_id.clone(),
                destination: destination.clone(),
                purpose: Purpose::new(label).unwrap(),
            };
            let grant = DelegationPolicy::issue_use(
                &policy,
                &descriptor,
                &request,
                &grantor,
                &delegate,
                None,
                now,
                expires_at,
                SafeLabel::new(label).unwrap(),
                &mut AuditWrite::accepting(),
            )
            .unwrap();
            delegation_ids.push(grant.id().as_str().to_string());
            delegations.store(&grant).unwrap();
            if label == "revoked delegation" {
                let revocation = DelegationPolicy::authorize_revocation(
                    &grant,
                    &grantor,
                    now + Duration::from_secs(10),
                    SafeLabel::new("reviewed revocation").unwrap(),
                    &mut AuditWrite::accepting(),
                )
                .unwrap();
                delegations.revoke(&revocation).unwrap();
            }
        }

        let request = UseRequest {
            secret_ref: secret_ref.clone(),
            scope: fixture.scope.clone(),
            profile_id: profile_id.clone(),
            destination,
            purpose: Purpose::new("approved recovery use").unwrap(),
        };
        let approval = ApprovalGrant::for_request(
            &request,
            &profile,
            SecretClass::HighValue,
            now + Duration::from_secs(900),
            SafeLabel::new("reviewed recovery approval").unwrap(),
        );
        FileApprovalRegistry::new(&fixture.sources[&RecoveryComponentKind::Approvals])
            .store(&approval)
            .unwrap();

        let lifecycle = FileLifecycleEvidenceRegistry::new(
            &fixture.sources[&RecoveryComponentKind::LifecycleEvidence],
        );
        lifecycle.record_declared(&secret_ref, now).unwrap();
        lifecycle
            .record_used(&secret_ref, now + Duration::from_secs(1))
            .unwrap();
        lifecycle
            .record_rotated(&secret_ref, now + Duration::from_secs(2))
            .unwrap();

        let tombstone_ref = SecretRef::new("sec_recovery_destroyed").unwrap();
        let tombstone_descriptor = SecretDescriptor {
            name: SecretName::new("RECOVERY_DESTROYED").unwrap(),
            secret_ref: tombstone_ref.clone(),
            label: SafeLabel::new("Destroyed fixture").unwrap(),
            scope: fixture.scope.clone(),
            owner: Some(OwnerRef::new("security").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::PendingDelete,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id],
            present: false,
        };
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("recovery-admin").unwrap(),
            ),
            fixture.scope.clone(),
        );
        let tombstone = TombstonePolicy::record(
            &tombstone_descriptor,
            SecretTombstoneRequest::new(
                tombstone_ref.clone(),
                SafeLabel::new("reviewed destruction").unwrap(),
                now,
                now + Duration::from_secs(3600),
            ),
            &principal,
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        FileTombstoneRegistry::new(&fixture.sources[&RecoveryComponentKind::Tombstones])
            .record(&tombstone, &principal)
            .unwrap();

        let metadata = br#"
[[secrets]]
name = "RECOVERY_FIXTURE"
lifecycle = "disabled"

[[secrets]]
name = "RECOVERY_DESTROYED"
lifecycle = "destroyed"
"#;
        private_file(
            &fixture.sources[&RecoveryComponentKind::MetadataOverlay],
            metadata,
        );

        let snapshot = fixture.runner().snapshot(now).unwrap();
        fixture.bind_bundle(&snapshot.bundle_fingerprint);
        let runner = fixture.runner();
        runner.preflight(now + Duration::from_secs(3)).unwrap();
        runner.restore(now + Duration::from_secs(4)).unwrap();
        runner.postflight(now + Duration::from_secs(5), 0).unwrap();

        let restored_approvals = FileApprovalRegistry::new(fixture.target.join("approvals"));
        assert_eq!(restored_approvals.list().unwrap().len(), 1);
        let restored_delegations = FileDelegationRegistry::new(fixture.target.join("delegations"));
        assert_eq!(
            restored_delegations
                .get(&delegation_ids[0])
                .unwrap()
                .status_at(now + Duration::from_secs(30))
                .unwrap(),
            DelegationStatus::Active
        );
        assert_eq!(
            restored_delegations
                .get(&delegation_ids[1])
                .unwrap()
                .status_at(now + Duration::from_secs(30))
                .unwrap(),
            DelegationStatus::Revoked
        );
        assert_eq!(
            restored_delegations
                .get(&delegation_ids[2])
                .unwrap()
                .status_at(now + Duration::from_secs(30))
                .unwrap(),
            DelegationStatus::Expired
        );
        assert_eq!(
            FileLifecycleEvidenceRegistry::new(fixture.target.join("lifecycle_evidence"))
                .list()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            FileTombstoneRegistry::new(fixture.target.join("tombstones"))
                .list()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            fs::read(fixture.target.join("metadata_overlay/content")).unwrap(),
            metadata
        );
    }

    #[test]
    fn bundle_tamper_and_non_terminal_admin_state_fail_closed_without_echo() {
        let fixture = Fixture::new();
        private_file(
            &fixture.sources[&RecoveryComponentKind::AdminState].join("journal.json"),
            br#"{"phase":"applying"}"#,
        );
        assert!(matches!(
            fixture
                .runner()
                .snapshot(UNIX_EPOCH + Duration::from_secs(1)),
            Err(JanusError::PolicyDenied {
                reason_code: "recovery_source_incomplete",
                ..
            })
        ));

        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(20_000);
        let snapshot = fixture.runner().snapshot(now).unwrap();
        fixture.bind_bundle(&snapshot.bundle_fingerprint);
        let runner = fixture.runner();
        private_file(
            &runner
                .manifest()
                .bundle_root()
                .join("payload/metadata_overlay/content"),
            b"SENSITIVE_RECOVERY_CANARY_MUST_NOT_ESCAPE",
        );
        let error = runner.preflight(now + Duration::from_secs(1)).unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "recovery_bundle_tampered",
                ..
            }
        ));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("SENSITIVE_RECOVERY_CANARY_MUST_NOT_ESCAPE"));
    }

    #[test]
    fn incomplete_source_audit_is_rejected_without_mutating_the_live_log() {
        let fixture = Fixture::new();
        let audit_path = &fixture.sources[&RecoveryComponentKind::AuditLog];
        let mut file = OpenOptions::new().append(true).open(audit_path).unwrap();
        file.write_all(b"SENSITIVE_INCOMPLETE_AUDIT_CANARY")
            .unwrap();
        file.sync_all().unwrap();
        let before = fs::read(audit_path).unwrap();
        let error = fixture
            .runner()
            .snapshot(UNIX_EPOCH + Duration::from_secs(30_000))
            .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "recovery_source_not_offline",
                ..
            }
        ));
        assert_eq!(fs::read(audit_path).unwrap(), before);
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_INCOMPLETE_AUDIT_CANARY"));
    }

    #[test]
    fn orphan_snapshot_work_is_retry_safe_and_interrupted_restore_rolls_back() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(40_000);
        let runner = fixture.runner();
        private_dir(runner.manifest().state_root());
        private_dir(&runner.snapshot_stage_path());
        private_file(
            &runner.snapshot_stage_path().join("partial"),
            b"synthetic partial state",
        );
        let snapshot = runner.snapshot(now).unwrap();
        fs::remove_file(runner.journal_path()).unwrap();
        let recovered = runner.snapshot(now + Duration::from_secs(1)).unwrap();
        assert_eq!(recovered.reason_code, "recovery_snapshot_recovered");
        assert_eq!(recovered.bundle_fingerprint, snapshot.bundle_fingerprint);
        fixture.bind_bundle(&recovered.bundle_fingerprint);
        let runner = fixture.runner();
        runner.preflight(now + Duration::from_secs(2)).unwrap();
        let mut journal = runner.read_required_journal().unwrap();
        journal.phase = RecoveryPhase::Restoring;
        runner.write_journal(&journal).unwrap();
        let work = runner.work_paths().unwrap();
        fs::rename(&fixture.target, &work.previous).unwrap();
        private_dir(&work.stage);
        private_file(&work.stage.join("partial"), b"synthetic staged state");

        let status = runner.rollback().unwrap();
        assert_eq!(status.phase, "rolled_back");
        assert!(fixture.target.is_dir());
        assert!(fs::read_dir(&fixture.target).unwrap().next().is_none());
        assert!(!work.stage.exists());
        assert!(!work.previous.exists());
    }

    #[test]
    fn completed_evidence_enforces_current_config_scope_release_and_freshness() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(50_000);
        let snapshot = fixture.runner().snapshot(now).unwrap();
        fixture.bind_bundle(&snapshot.bundle_fingerprint);
        let runner = fixture.runner();
        runner.preflight(now + Duration::from_secs(1)).unwrap();
        runner.restore(now + Duration::from_secs(2)).unwrap();
        runner.postflight(now + Duration::from_secs(3), 0).unwrap();
        runner.validate_bound_config_path(&fixture.config).unwrap();
        let unbound = fixture._temp.path().join("unbound-profile.toml");
        reviewed_file(&unbound, b"[profiles]\n");
        assert!(matches!(
            runner.validate_bound_config_path(&unbound),
            Err(JanusError::PolicyDenied {
                reason_code: "recovery_config_unbound",
                ..
            })
        ));
        let release = ReleaseAdmission::not_required(ProductMode::SelfHosted);
        enforce_recovery_drill_freshness(
            &fixture.manifest,
            &fixture.evidence,
            &release,
            &fixture.scope,
            now + Duration::from_secs(4),
        )
        .unwrap();
        assert!(matches!(
            enforce_recovery_drill_freshness(
                &fixture.manifest,
                &fixture.evidence,
                &release,
                &fixture.scope,
                now + Duration::from_secs(86_404),
            ),
            Err(JanusError::PolicyDenied {
                reason_code: "recovery_evidence_stale",
                ..
            })
        ));
        reviewed_file(&fixture.config, b"SENSITIVE_CONFIG_DRIFT_CANARY");
        let error = enforce_recovery_drill_freshness(
            &fixture.manifest,
            &fixture.evidence,
            &release,
            &fixture.scope,
            now + Duration::from_secs(4),
        )
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_CONFIG_DRIFT_CANARY"));
    }

    #[cfg(unix)]
    fn private_dir(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    fn private_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn reviewed_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

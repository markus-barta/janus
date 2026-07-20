use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::{
    ApprovalId, AuditAction, AuditEvent, AuditOutcome, AuditSink, Destination, EgressMode,
    ExecutorRef, JanusError, JanusResult, MigrationCompatibility, MigrationManifest,
    MigrationPhase, PrincipalChain, ProfileId, Purpose, ReleaseAdmission, ReleaseAdmissionDecision,
    SafeLabel, ScopeRef, SecretClass, SecretRef, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{check_secure_approval_file, ApprovalGrantFileRecord, JsonlAuditSink};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const JOURNAL_VERSION: u8 = 1;
const APPROVAL_SCHEMA_MARKER: &str = ".janus-schema";
const JOURNAL_FILE: &str = "journal.json";
const SNAPSHOT_DIR: &str = "snapshot";

/// Value-free migration command/status output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationStatus {
    /// Stable migration id.
    pub migration_id: String,
    /// Stable schema family id.
    pub schema_id: String,
    /// Durable phase, or `not_started` before preflight.
    pub phase: String,
    /// Schema version currently visible at the target.
    pub current_version: u32,
    /// Reviewed target version.
    pub target_version: u32,
    /// Number of value-free approval records.
    pub record_count: u64,
    /// Safe content fingerprint, never record bodies.
    pub target_fingerprint: String,
    /// Stable value-free reason code.
    pub reason_code: &'static str,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Offline approval-registry migration runner.
pub struct ApprovalMigrationRunner {
    manifest: MigrationManifest,
    manifest_fingerprint: String,
    release: ReleaseAdmission,
    principal: PrincipalChain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationJournal {
    version: u8,
    migration_id: String,
    schema_id: String,
    manifest_fingerprint: String,
    from_version: u32,
    to_version: u32,
    phase: MigrationPhase,
    preflighted_at_unix_secs: u64,
    record_count: u64,
    source_fingerprint: String,
    authority_fingerprint: String,
    target_fingerprint: String,
    release_mode: String,
    release_policy_id: Option<String>,
    release_policy_version: Option<u64>,
    release_artifact_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalSchemaMarker {
    schema_version: u8,
    schema_id: String,
    migration_id: String,
}

#[derive(Clone)]
struct ApprovalInventory {
    schema_version: u32,
    records: Vec<(String, ApprovalGrantFileRecord, Vec<u8>)>,
    record_count: u64,
    total_bytes: u64,
    target_fingerprint: String,
    authority_fingerprint: String,
}

struct WorkPaths {
    stage: PathBuf,
    previous: PathBuf,
    failed: PathBuf,
}

impl ApprovalMigrationRunner {
    /// Load a reviewed manifest and bind this runner to the current release posture.
    pub fn load(
        manifest_path: &Path,
        release: ReleaseAdmission,
        principal: PrincipalChain,
    ) -> JanusResult<Self> {
        let contents = read_reviewed_file(manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest = MigrationManifest::parse_json(&contents)?;
        validate_supported_manifest(&manifest)?;
        if manifest.state_root().starts_with(manifest.target_root())
            || manifest.target_root().starts_with(manifest.state_root())
        {
            return Err(migration_denied(
                "migration_manifest_invalid",
                "migration state and target roots must be separate",
            ));
        }
        let encoded = serde_json::to_vec(&manifest).map_err(|_| {
            migration_denied(
                "migration_manifest_invalid",
                "migration manifest could not be canonicalized",
            )
        })?;
        Ok(Self {
            manifest,
            manifest_fingerprint: digest(&encoded),
            release,
            principal,
        })
    }

    /// Inspect, snapshot, and bind a target-read-only migration preflight.
    pub fn preflight(&self, now: SystemTime) -> JanusResult<MigrationStatus> {
        match self.preflight_inner(now) {
            Ok(status) => {
                self.audit(
                    AuditAction::UpgradePreflight,
                    AuditOutcome::Allowed,
                    "migration_preflight_ok",
                    Severity::Notice,
                    &status.phase,
                )?;
                Ok(status)
            }
            Err(error) => self.audit_denial(AuditAction::UpgradePreflight, error),
        }
    }

    /// Apply the exact preflighted migration using staged output and atomic swap.
    pub fn apply(&self, now: SystemTime) -> JanusResult<MigrationStatus> {
        match self.apply_inner(now) {
            Ok(status) => {
                self.audit(
                    AuditAction::MigrationApply,
                    AuditOutcome::Allowed,
                    "migration_apply_ok",
                    Severity::High,
                    &status.phase,
                )?;
                Ok(status)
            }
            Err(error) => self.audit_denial(AuditAction::MigrationApply, error),
        }
    }

    /// Verify migrated authority, audit, and release invariants before unblocking runtime.
    pub fn postflight(&self) -> JanusResult<MigrationStatus> {
        match self.postflight_inner() {
            Ok((mut journal, inventory)) => {
                self.audit(
                    AuditAction::UpgradePostflight,
                    AuditOutcome::Allowed,
                    "migration_postflight_ok",
                    Severity::Notice,
                    MigrationPhase::Completed.as_str(),
                )?;
                journal.phase = MigrationPhase::Completed;
                journal.target_fingerprint = inventory.target_fingerprint.clone();
                self.write_journal(&journal)?;
                Ok(self.status_from(&journal, &inventory, "migration_postflight_ok"))
            }
            Err(error) => {
                self.mark_failed_if_applied();
                self.audit_denial(AuditAction::UpgradePostflight, error)
            }
        }
    }

    /// Restore and verify the preflight snapshot.
    pub fn rollback(&self) -> JanusResult<MigrationStatus> {
        match self.rollback_inner() {
            Ok((mut journal, inventory)) => {
                self.audit(
                    AuditAction::UpgradeRollback,
                    AuditOutcome::Allowed,
                    "migration_rollback_ok",
                    Severity::Critical,
                    MigrationPhase::RolledBack.as_str(),
                )?;
                journal.phase = MigrationPhase::RolledBack;
                journal.target_fingerprint = inventory.target_fingerprint.clone();
                self.write_journal(&journal)?;
                Ok(self.status_from(&journal, &inventory, "migration_rollback_ok"))
            }
            Err(error) => self.audit_denial(AuditAction::UpgradeRollback, error),
        }
    }

    /// Return value-free current migration state.
    pub fn status(&self) -> JanusResult<MigrationStatus> {
        let inventory = inspect_approval_root(self.manifest.target_root())?;
        match self.read_journal()? {
            Some(journal) => {
                self.validate_journal(&journal)?;
                Ok(self.status_from(&journal, &inventory, "migration_status_ok"))
            }
            None => Ok(MigrationStatus {
                migration_id: self.manifest.migration_id().to_string(),
                schema_id: self.manifest.schema_id().to_string(),
                phase: "not_started".to_string(),
                current_version: inventory.schema_version,
                target_version: self.manifest.to_version(),
                record_count: inventory.record_count,
                target_fingerprint: inventory.target_fingerprint,
                reason_code: "migration_not_started",
                value_returned: false,
            }),
        }
    }

    fn preflight_inner(&self, now: SystemTime) -> JanusResult<MigrationStatus> {
        ensure_private_dir(self.manifest.target_root(), false)?;
        ensure_private_dir(self.manifest.state_root(), true)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        if let Some(journal) = self.read_journal()? {
            self.validate_journal(&journal)?;
            let inventory = inspect_approval_root(self.manifest.target_root())?;
            return match journal.phase {
                MigrationPhase::Completed => {
                    self.validate_terminal_inventory(
                        &journal,
                        &inventory,
                        self.manifest.to_version(),
                    )?;
                    Ok(self.status_from(&journal, &inventory, "migration_already_terminal"))
                }
                MigrationPhase::RolledBack => {
                    self.validate_terminal_inventory(
                        &journal,
                        &inventory,
                        self.manifest.from_version(),
                    )?;
                    Ok(self.status_from(&journal, &inventory, "migration_already_terminal"))
                }
                _ => Err(migration_denied(
                    "migration_incomplete",
                    "an existing migration must be completed or rolled back",
                )),
            };
        }
        self.reject_orphan_work_state()?;
        let inventory = inspect_approval_root(self.manifest.target_root())?;
        if inventory.schema_version != self.manifest.from_version() {
            return Err(migration_denied(
                "migration_source_version_mismatch",
                "migration target is not at the reviewed source version",
            ));
        }
        let required = inventory
            .total_bytes
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(self.manifest.minimum_free_bytes()))
            .ok_or_else(|| {
                migration_denied(
                    "migration_space_insufficient",
                    "migration disk requirement overflowed",
                )
            })?;
        let available = fs2::available_space(self.manifest.target_root()).map_err(|_| {
            migration_denied(
                "migration_space_unavailable",
                "migration free space could not be checked",
            )
        })?;
        if available < required {
            return Err(migration_denied(
                "migration_space_insufficient",
                "migration requires more private staging space",
            ));
        }

        let snapshot = self.snapshot_path();
        if snapshot.exists() {
            let snapshot_inventory = inspect_approval_root(&snapshot)?;
            if snapshot_inventory.schema_version != self.manifest.from_version()
                || snapshot_inventory.target_fingerprint != inventory.target_fingerprint
            {
                return Err(migration_denied(
                    "migration_snapshot_mismatch",
                    "existing rollback snapshot does not match the target",
                ));
            }
        } else {
            create_snapshot(self.manifest.target_root(), &snapshot, &inventory)?;
        }
        let now_secs = unix_seconds(now)?;
        let journal = MigrationJournal {
            version: JOURNAL_VERSION,
            migration_id: self.manifest.migration_id().to_string(),
            schema_id: self.manifest.schema_id().to_string(),
            manifest_fingerprint: self.manifest_fingerprint.clone(),
            from_version: self.manifest.from_version(),
            to_version: self.manifest.to_version(),
            phase: MigrationPhase::Preflighted,
            preflighted_at_unix_secs: now_secs,
            record_count: inventory.record_count,
            source_fingerprint: inventory.target_fingerprint.clone(),
            authority_fingerprint: inventory.authority_fingerprint.clone(),
            target_fingerprint: inventory.target_fingerprint.clone(),
            release_mode: self.release.mode().as_str().to_string(),
            release_policy_id: self.release.policy_id().map(ToOwned::to_owned),
            release_policy_version: self.release.policy_version(),
            release_artifact_id: self.release.artifact_id().map(ToOwned::to_owned),
        };
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, &inventory, "migration_preflight_ok"))
    }

    fn apply_inner(&self, now: SystemTime) -> JanusResult<MigrationStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == MigrationPhase::Completed {
            let inventory = inspect_approval_root(self.manifest.target_root())?;
            return Ok(self.status_from(&journal, &inventory, "migration_already_completed"));
        }
        if journal.phase != MigrationPhase::Preflighted {
            return Err(migration_denied(
                "migration_incomplete",
                "migration apply requires a clean preflighted journal",
            ));
        }
        let now_secs = unix_seconds(now)?;
        let age = now_secs
            .checked_sub(journal.preflighted_at_unix_secs)
            .ok_or_else(|| {
                migration_denied(
                    "migration_preflight_stale",
                    "migration clock moved behind preflight evidence",
                )
            })?;
        if age > self.manifest.backup_max_age_seconds() {
            return Err(migration_denied(
                "migration_preflight_stale",
                "migration preflight and snapshot evidence is stale",
            ));
        }
        self.validate_release_binding(&journal)?;
        let source = inspect_approval_root(self.manifest.target_root())?;
        if source.schema_version != journal.from_version
            || source.target_fingerprint != journal.source_fingerprint
            || source.authority_fingerprint != journal.authority_fingerprint
            || source.record_count != journal.record_count
        {
            return Err(migration_denied(
                "migration_input_changed",
                "migration target changed after preflight",
            ));
        }
        let snapshot = inspect_approval_root(&self.snapshot_path())?;
        if snapshot.target_fingerprint != journal.source_fingerprint
            || snapshot.authority_fingerprint != journal.authority_fingerprint
        {
            return Err(migration_denied(
                "migration_snapshot_mismatch",
                "rollback snapshot changed after preflight",
            ));
        }
        let work = self.work_paths()?;
        reject_existing_work_paths(&work)?;

        journal.phase = MigrationPhase::Applying;
        self.write_journal(&journal)?;
        create_migrated_stage(&work.stage, &source, &self.manifest)?;
        journal.phase = MigrationPhase::Staged;
        self.write_journal(&journal)?;
        let staged = inspect_approval_root(&work.stage)?;
        if staged.schema_version != journal.to_version
            || staged.authority_fingerprint != journal.authority_fingerprint
            || staged.record_count != journal.record_count
        {
            return Err(migration_denied(
                "migration_authority_changed",
                "staged migration changed authority-bearing fields",
            ));
        }

        journal.phase = MigrationPhase::Swapping;
        self.write_journal(&journal)?;
        fs::rename(self.manifest.target_root(), &work.previous).map_err(|_| {
            migration_denied(
                "migration_swap_failed",
                "migration could not preserve the previous target",
            )
        })?;
        if fs::rename(&work.stage, self.manifest.target_root()).is_err() {
            let _ = fs::rename(&work.previous, self.manifest.target_root());
            return Err(migration_denied(
                "migration_swap_failed",
                "migration could not install staged output",
            ));
        }
        sync_dir(
            self.manifest
                .target_root()
                .parent()
                .unwrap_or_else(|| Path::new("/")),
        )?;
        journal.phase = MigrationPhase::Applied;
        journal.target_fingerprint = staged.target_fingerprint.clone();
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, &staged, "migration_apply_ok"))
    }

    fn postflight_inner(&self) -> JanusResult<(MigrationJournal, ApprovalInventory)> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        let journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == MigrationPhase::Completed {
            let inventory = inspect_approval_root(self.manifest.target_root())?;
            self.validate_terminal_inventory(&journal, &inventory, self.manifest.to_version())?;
            return Ok((journal, inventory));
        }
        if journal.phase != MigrationPhase::Applied {
            return Err(migration_denied(
                "migration_incomplete",
                "migration postflight requires an applied journal",
            ));
        }
        self.validate_release_binding(&journal)?;
        let inventory = inspect_approval_root(self.manifest.target_root())?;
        if inventory.schema_version != journal.to_version
            || inventory.record_count != journal.record_count
            || inventory.authority_fingerprint != journal.authority_fingerprint
            || inventory.target_fingerprint != journal.target_fingerprint
        {
            return Err(migration_denied(
                "upgrade_postflight_failed",
                "migration postflight invariants did not match preflight",
            ));
        }
        let previous = inspect_approval_root(&self.work_paths()?.previous)?;
        if previous.target_fingerprint != journal.source_fingerprint
            || previous.authority_fingerprint != journal.authority_fingerprint
        {
            return Err(migration_denied(
                "upgrade_postflight_failed",
                "preserved pre-migration target does not match preflight",
            ));
        }
        Ok((journal, inventory))
    }

    fn rollback_inner(&self) -> JanusResult<(MigrationJournal, ApprovalInventory)> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if !self.manifest.reversible() {
            return Err(migration_denied(
                "migration_not_reversible",
                "migration manifest does not declare a rollback",
            ));
        }
        if journal.phase == MigrationPhase::RolledBack {
            let inventory = inspect_approval_root(self.manifest.target_root())?;
            self.validate_terminal_inventory(&journal, &inventory, self.manifest.from_version())?;
            return Ok((journal, inventory));
        }
        let snapshot_path = self.snapshot_path();
        let snapshot = inspect_approval_root(&snapshot_path)?;
        if snapshot.schema_version != journal.from_version
            || snapshot.target_fingerprint != journal.source_fingerprint
            || snapshot.authority_fingerprint != journal.authority_fingerprint
            || snapshot.record_count != journal.record_count
        {
            return Err(migration_denied(
                "migration_snapshot_mismatch",
                "rollback snapshot failed integrity checks",
            ));
        }

        journal.phase = MigrationPhase::RollingBack;
        self.write_journal(&journal)?;
        let work = self.work_paths()?;
        cleanup_path(&work.stage)?;
        cleanup_path(&work.failed)?;
        create_snapshot(&snapshot_path, &work.stage, &snapshot)?;
        if self.manifest.target_root().exists() {
            fs::rename(self.manifest.target_root(), &work.failed).map_err(|_| {
                migration_denied(
                    "migration_rollback_failed",
                    "rollback could not quarantine the current target",
                )
            })?;
        }
        if fs::rename(&work.stage, self.manifest.target_root()).is_err() {
            if work.failed.exists() {
                let _ = fs::rename(&work.failed, self.manifest.target_root());
            }
            return Err(migration_denied(
                "migration_rollback_failed",
                "rollback could not restore the snapshot",
            ));
        }
        let restored = inspect_approval_root(self.manifest.target_root())?;
        if restored.target_fingerprint != journal.source_fingerprint
            || restored.authority_fingerprint != journal.authority_fingerprint
        {
            return Err(migration_denied(
                "migration_rollback_failed",
                "restored target did not match the snapshot",
            ));
        }
        cleanup_path(&work.failed)?;
        cleanup_path(&work.previous)?;
        sync_dir(
            self.manifest
                .target_root()
                .parent()
                .unwrap_or_else(|| Path::new("/")),
        )?;
        Ok((journal, restored))
    }

    fn validate_release(&self) -> JanusResult<()> {
        if !self.release.allows_secret_use()
            || (self.release.mode().requires_trusted_release()
                && self.release.decision() != ReleaseAdmissionDecision::Trusted)
        {
            return Err(migration_denied(
                "migration_release_untrusted",
                "migration requires an admitted runtime release",
            ));
        }
        Ok(())
    }

    fn validate_release_binding(&self, journal: &MigrationJournal) -> JanusResult<()> {
        if journal.release_mode != self.release.mode().as_str()
            || journal.release_policy_id.as_deref() != self.release.policy_id()
            || journal.release_policy_version != self.release.policy_version()
            || journal.release_artifact_id.as_deref() != self.release.artifact_id()
        {
            return Err(migration_denied(
                "migration_release_changed",
                "release posture changed after migration preflight",
            ));
        }
        Ok(())
    }

    fn validate_terminal_inventory(
        &self,
        journal: &MigrationJournal,
        inventory: &ApprovalInventory,
        expected_version: u32,
    ) -> JanusResult<()> {
        if inventory.schema_version != expected_version
            || inventory.target_fingerprint != journal.target_fingerprint
            || inventory.authority_fingerprint != journal.authority_fingerprint
            || inventory.record_count != journal.record_count
        {
            return Err(migration_denied(
                "migration_terminal_state_mismatch",
                "terminal migration target does not match its journal",
            ));
        }
        Ok(())
    }

    fn acquire_lock(&self) -> JanusResult<File> {
        let path = self.manifest.state_root().join("migration.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| {
            migration_denied(
                "migration_lock_unavailable",
                "migration lock is unavailable",
            )
        })?;
        file.try_lock_exclusive().map_err(|_| {
            migration_denied(
                "migration_concurrent",
                "another migration process holds the maintenance lock",
            )
        })?;
        Ok(file)
    }

    fn read_journal(&self) -> JanusResult<Option<MigrationJournal>> {
        let path = self.journal_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => read_private_json(&path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(migration_denied(
                "migration_journal_unavailable",
                "migration journal is unavailable",
            )),
        }
    }

    fn read_required_journal(&self) -> JanusResult<MigrationJournal> {
        self.read_journal()?.ok_or_else(|| {
            migration_denied(
                "migration_preflight_missing",
                "migration requires a durable preflight journal",
            )
        })
    }

    fn validate_journal(&self, journal: &MigrationJournal) -> JanusResult<()> {
        if journal.version != JOURNAL_VERSION
            || journal.migration_id != self.manifest.migration_id()
            || journal.schema_id != self.manifest.schema_id()
            || journal.manifest_fingerprint != self.manifest_fingerprint
            || journal.from_version != self.manifest.from_version()
            || journal.to_version != self.manifest.to_version()
            || !valid_sha256(&journal.source_fingerprint)
            || !valid_sha256(&journal.authority_fingerprint)
            || !valid_sha256(&journal.target_fingerprint)
        {
            return Err(migration_denied(
                "migration_journal_invalid",
                "migration journal does not match the reviewed manifest",
            ));
        }
        Ok(())
    }

    fn write_journal(&self, journal: &MigrationJournal) -> JanusResult<()> {
        write_private_json_atomic(&self.journal_path(), journal)
    }

    fn journal_path(&self) -> PathBuf {
        self.manifest.state_root().join(JOURNAL_FILE)
    }

    fn snapshot_path(&self) -> PathBuf {
        self.manifest.state_root().join(SNAPSHOT_DIR)
    }

    fn work_paths(&self) -> JanusResult<WorkPaths> {
        let target = self.manifest.target_root();
        let parent = target.parent().ok_or_else(|| {
            migration_denied(
                "migration_manifest_invalid",
                "migration target has no parent directory",
            )
        })?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                migration_denied(
                    "migration_manifest_invalid",
                    "migration target name is invalid",
                )
            })?;
        let prefix = format!(".{name}.{}", self.manifest.migration_id());
        Ok(WorkPaths {
            stage: parent.join(format!("{prefix}.stage")),
            previous: parent.join(format!("{prefix}.previous")),
            failed: parent.join(format!("{prefix}.failed")),
        })
    }

    fn reject_orphan_work_state(&self) -> JanusResult<()> {
        let work = self.work_paths()?;
        reject_existing_work_paths(&work)
    }

    fn status_from(
        &self,
        journal: &MigrationJournal,
        inventory: &ApprovalInventory,
        reason_code: &'static str,
    ) -> MigrationStatus {
        MigrationStatus {
            migration_id: journal.migration_id.clone(),
            schema_id: journal.schema_id.clone(),
            phase: journal.phase.as_str().to_string(),
            current_version: inventory.schema_version,
            target_version: journal.to_version,
            record_count: inventory.record_count,
            target_fingerprint: inventory.target_fingerprint.clone(),
            reason_code,
            value_returned: false,
        }
    }

    fn mark_failed_if_applied(&self) {
        if let Ok(Some(mut journal)) = self.read_journal() {
            if journal.phase == MigrationPhase::Applied {
                journal.phase = MigrationPhase::Failed;
                let _ = self.write_journal(&journal);
            }
        }
    }

    fn audit_denial<T>(&self, action: AuditAction, error: JanusError) -> JanusResult<T> {
        let reason = migration_reason(&error);
        let phase = self
            .read_journal()
            .ok()
            .flatten()
            .map(|journal| journal.phase.as_str())
            .unwrap_or("not_started");
        self.audit(
            action,
            AuditOutcome::Denied,
            reason,
            Severity::Critical,
            phase,
        )?;
        Err(error)
    }

    fn audit(
        &self,
        action: AuditAction,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
        phase: &str,
    ) -> JanusResult<()> {
        let evidence = SafeLabel::new(format!(
            "{}:{}:{}-{}:{}",
            self.manifest.migration_id(),
            self.manifest.schema_id(),
            self.manifest.from_version(),
            self.manifest.to_version(),
            phase
        ))?;
        let event = AuditEvent::new(
            action,
            outcome,
            reason_code,
            severity,
            None,
            &self.principal,
        )
        .with_evidence(evidence);
        let mut audit = JsonlAuditSink::open(self.manifest.audit_path())?;
        audit.record(event)
    }
}

/// Fail normal runtime startup while a reviewed migration is incomplete,
/// failed, orphaned, or inconsistent with its terminal journal.
pub fn enforce_migration_ready_from_env() -> JanusResult<()> {
    let Some(path) = env::var_os("JANUS_MIGRATION_MANIFEST").filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let contents = read_reviewed_file(Path::new(&path), MAX_MANIFEST_BYTES)?;
    let manifest = MigrationManifest::parse_json(&contents)?;
    validate_supported_manifest(&manifest)?;
    let manifest_fingerprint = digest(&serde_json::to_vec(&manifest).map_err(|_| {
        migration_denied(
            "migration_manifest_invalid",
            "migration manifest could not be canonicalized",
        )
    })?);
    if !manifest.state_root().exists() {
        return Ok(());
    }
    ensure_private_dir(manifest.state_root(), false)?;
    let journal_path = manifest.state_root().join(JOURNAL_FILE);
    let journal: MigrationJournal = match fs::symlink_metadata(&journal_path) {
        Ok(_) => read_private_json(&journal_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if manifest.state_root().join(SNAPSHOT_DIR).exists() {
                return Err(migration_denied(
                    "migration_orphaned_state",
                    "migration snapshot exists without a journal",
                ));
            }
            return Ok(());
        }
        Err(_) => {
            return Err(migration_denied(
                "migration_journal_unavailable",
                "migration journal is unavailable",
            ))
        }
    };
    if journal.version != JOURNAL_VERSION
        || journal.migration_id != manifest.migration_id()
        || journal.schema_id != manifest.schema_id()
        || journal.manifest_fingerprint != manifest_fingerprint
        || journal.from_version != manifest.from_version()
        || journal.to_version != manifest.to_version()
        || journal.phase.blocks_runtime()
    {
        return Err(migration_denied(
            "migration_incomplete",
            "runtime is blocked by incomplete or invalid migration state",
        ));
    }
    let inventory = inspect_approval_root(manifest.target_root())?;
    let expected_version = if journal.phase == MigrationPhase::Completed {
        journal.to_version
    } else {
        journal.from_version
    };
    if inventory.schema_version != expected_version
        || inventory.target_fingerprint != journal.target_fingerprint
        || inventory.authority_fingerprint != journal.authority_fingerprint
    {
        return Err(migration_denied(
            "migration_terminal_state_mismatch",
            "runtime target does not match terminal migration evidence",
        ));
    }
    Ok(())
}

pub(crate) fn approval_schema_version(dir: &Path) -> JanusResult<u8> {
    let marker = dir.join(APPROVAL_SCHEMA_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            let marker: ApprovalSchemaMarker = read_private_json(&marker)?;
            if marker.schema_version != 1
                || marker.schema_id != "approval_registry"
                || marker.migration_id != "approval-registry-v0-v1"
            {
                return Err(migration_denied(
                    "migration_schema_marker_invalid",
                    "approval schema marker is invalid",
                ));
            }
            Ok(1)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(migration_denied(
            "migration_schema_marker_unavailable",
            "approval schema marker is unavailable",
        )),
    }
}

fn validate_supported_manifest(manifest: &MigrationManifest) -> JanusResult<()> {
    if manifest.migration_id() != "approval-registry-v0-v1"
        || manifest.schema_id() != "approval_registry"
        || manifest.from_version() != 0
        || manifest.to_version() != 1
        || manifest.compatibility() != MigrationCompatibility::Offline
        || !manifest.reversible()
    {
        return Err(migration_denied(
            "migration_unsupported",
            "migration is not in the reviewed local catalog",
        ));
    }
    if !manifest.risk_flags().is_empty() {
        return Err(migration_denied(
            "migration_requires_approval",
            "risk-bearing migrations fail closed in this migration catalog",
        ));
    }
    Ok(())
}

fn inspect_approval_root(path: &Path) -> JanusResult<ApprovalInventory> {
    ensure_private_dir(path, false)?;
    let schema_version = u32::from(approval_schema_version(path)?);
    let mut records = Vec::new();
    let mut marker_bytes = None;
    for entry in fs::read_dir(path).map_err(|_| {
        migration_denied(
            "migration_target_unavailable",
            "approval registry could not be listed",
        )
    })? {
        let entry = entry.map_err(|_| {
            migration_denied(
                "migration_target_unavailable",
                "approval registry entry could not be inspected",
            )
        })?;
        let file_name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                migration_denied(
                    "migration_record_invalid",
                    "approval registry entry name is invalid",
                )
            })?;
        let entry_path = entry.path();
        if file_name == APPROVAL_SCHEMA_MARKER {
            marker_bytes = Some(read_private_bytes(&entry_path, MAX_RECORD_BYTES)?);
            continue;
        }
        let Some(approval_id) = file_name.strip_suffix(".json") else {
            return Err(migration_denied(
                "migration_record_invalid",
                "approval registry contains an unsupported entry",
            ));
        };
        super::validate_approval_file_token(approval_id)?;
        check_secure_approval_file(&entry_path)?;
        let bytes = read_private_bytes(&entry_path, MAX_RECORD_BYTES)?;
        let record: ApprovalGrantFileRecord = serde_json::from_slice(&bytes).map_err(|_| {
            migration_denied(
                "migration_record_invalid",
                "approval registry record is malformed",
            )
        })?;
        if record.approval_id != approval_id {
            return Err(migration_denied(
                "migration_record_mismatch",
                "approval registry record id does not match its file",
            ));
        }
        let version_matches = match schema_version {
            0 => record.version.is_none(),
            1 => record.version == Some(1),
            _ => false,
        };
        if !version_matches {
            return Err(migration_denied(
                "migration_partial_state",
                "approval registry contains mixed schema versions",
            ));
        }
        validate_migration_approval_record(&record).map_err(|_| {
            migration_denied(
                "migration_record_invalid",
                "approval registry record failed semantic validation",
            )
        })?;
        records.push((file_name, record, bytes));
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));

    let mut target_hasher = Sha256::new();
    let mut authority_hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    if let Some(bytes) = marker_bytes {
        target_hasher.update(APPROVAL_SCHEMA_MARKER.as_bytes());
        target_hasher.update([0]);
        target_hasher.update(&bytes);
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
    }
    for (name, record, bytes) in &records {
        target_hasher.update(name.as_bytes());
        target_hasher.update([0]);
        target_hasher.update(bytes);
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);

        let mut authority = record.clone();
        authority.version = None;
        let canonical = serde_json::to_vec(&authority).map_err(|_| {
            migration_denied(
                "migration_record_invalid",
                "approval authority could not be canonicalized",
            )
        })?;
        authority_hasher.update(name.as_bytes());
        authority_hasher.update([0]);
        authority_hasher.update(canonical);
    }
    Ok(ApprovalInventory {
        schema_version,
        record_count: records.len() as u64,
        records,
        total_bytes,
        target_fingerprint: format!("sha256:{}", hex::encode(target_hasher.finalize())),
        authority_fingerprint: format!("sha256:{}", hex::encode(authority_hasher.finalize())),
    })
}

fn validate_migration_approval_record(record: &ApprovalGrantFileRecord) -> JanusResult<()> {
    ApprovalId::from_opaque(record.approval_id.clone())?;
    if let Some(scope_ref) = &record.scope_ref {
        ScopeRef::from_opaque(scope_ref.clone())?;
    }
    SecretRef::new(record.secret_ref.clone())?;
    ProfileId::new(record.profile_id.clone())?;
    ExecutorRef::new(record.executor.clone())?;
    Destination::new(record.destination.clone())?;
    SecretClass::parse(&record.class)?;
    EgressMode::parse(&record.egress)?;
    Purpose::new(record.purpose.clone())?;
    SafeLabel::new(record.reason.clone())?;
    if record.expires_at_subsec_nanos >= 1_000_000_000
        || UNIX_EPOCH
            .checked_add(std::time::Duration::new(
                record.expires_at_unix_secs,
                record.expires_at_subsec_nanos,
            ))
            .is_none()
    {
        return Err(migration_denied(
            "migration_record_invalid",
            "approval expiry is invalid",
        ));
    }
    Ok(())
}

fn create_snapshot(
    source_root: &Path,
    destination: &Path,
    inventory: &ApprovalInventory,
) -> JanusResult<()> {
    if destination.exists() {
        return Err(migration_denied(
            "migration_work_path_exists",
            "migration output path already exists",
        ));
    }
    create_private_dir(destination)?;
    for (name, _, bytes) in &inventory.records {
        write_private_bytes(&destination.join(name), bytes)?;
    }
    let source_marker = source_root.join(APPROVAL_SCHEMA_MARKER);
    if source_marker.exists() {
        let bytes = read_private_bytes(&source_marker, MAX_RECORD_BYTES)?;
        write_private_bytes(&destination.join(APPROVAL_SCHEMA_MARKER), &bytes)?;
    }
    sync_dir(destination)
}

fn create_migrated_stage(
    destination: &Path,
    source: &ApprovalInventory,
    manifest: &MigrationManifest,
) -> JanusResult<()> {
    create_private_dir(destination)?;
    for (name, record, _) in &source.records {
        let mut migrated = record.clone();
        migrated.version = Some(1);
        let mut bytes = serde_json::to_vec(&migrated).map_err(|_| {
            migration_denied(
                "migration_record_invalid",
                "migrated approval record could not be encoded",
            )
        })?;
        bytes.push(b'\n');
        write_private_bytes(&destination.join(name), &bytes)?;
    }
    let marker = ApprovalSchemaMarker {
        schema_version: 1,
        schema_id: manifest.schema_id().to_string(),
        migration_id: manifest.migration_id().to_string(),
    };
    write_private_json_atomic(&destination.join(APPROVAL_SCHEMA_MARKER), &marker)?;
    sync_dir(destination)
}

fn read_reviewed_file(path: &Path, max_bytes: u64) -> JanusResult<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        migration_denied(
            "migration_manifest_unavailable",
            "migration manifest is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(migration_denied(
            "migration_manifest_unavailable",
            "migration manifest is not a reviewed regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(migration_denied(
                "migration_manifest_unavailable",
                "migration manifest must not be group or world writable",
            ));
        }
    }
    fs::read_to_string(path).map_err(|_| {
        migration_denied(
            "migration_manifest_unavailable",
            "migration manifest could not be read",
        )
    })
}

fn ensure_private_dir(path: &Path, create: bool) -> JanusResult<()> {
    if create {
        fs::create_dir_all(path).map_err(|_| {
            migration_denied(
                "migration_state_unavailable",
                "private migration directory could not be created",
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                migration_denied(
                    "migration_state_unavailable",
                    "private migration directory permissions could not be set",
                )
            })?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        migration_denied(
            "migration_state_unavailable",
            "private migration directory is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(migration_denied(
            "migration_insecure_path",
            "migration path is not a private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(migration_denied(
                "migration_insecure_path",
                "migration directory must be private",
            ));
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> JanusResult<()> {
    fs::create_dir(path).map_err(|_| {
        migration_denied(
            "migration_work_path_exists",
            "private migration output could not be created",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            migration_denied(
                "migration_insecure_path",
                "migration output permissions could not be set",
            )
        })?;
    }
    Ok(())
}

fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> JanusResult<T> {
    let bytes = read_private_bytes(path, MAX_RECORD_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| {
        migration_denied(
            "migration_state_invalid",
            "private migration state is malformed",
        )
    })
}

fn read_private_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        migration_denied(
            "migration_state_unavailable",
            "private migration file is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(migration_denied(
            "migration_insecure_path",
            "migration file is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(migration_denied(
                "migration_insecure_path",
                "migration file must be private",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| {
            migration_denied(
                "migration_state_unavailable",
                "private migration file could not be read",
            )
        })?;
    Ok(bytes)
}

fn write_private_json_atomic<T: Serialize>(path: &Path, value: &T) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        migration_denied(
            "migration_state_invalid",
            "private migration state could not be encoded",
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        migration_denied(
            "migration_state_unavailable",
            "private migration state has no parent",
        )
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            migration_denied(
                "migration_state_unavailable",
                "private migration state name is invalid",
            )
        })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        write_private_bytes(&temp, &bytes)?;
        fs::rename(&temp, path).map_err(|_| {
            migration_denied(
                "migration_state_unavailable",
                "private migration state could not be replaced",
            )
        })?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_private_bytes(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| {
        migration_denied(
            "migration_state_unavailable",
            "private migration file could not be created",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            migration_denied(
                "migration_state_unavailable",
                "private migration file could not be persisted",
            )
        })?;
    Ok(())
}

fn sync_dir(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            migration_denied(
                "migration_state_unavailable",
                "migration directory could not be persisted",
            )
        })
}

fn reject_existing_work_paths(paths: &WorkPaths) -> JanusResult<()> {
    if paths.stage.exists() || paths.previous.exists() || paths.failed.exists() {
        return Err(migration_denied(
            "migration_orphaned_state",
            "migration work path exists without a matching phase",
        ));
    }
    Ok(())
}

fn cleanup_path(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(migration_denied(
            "migration_insecure_path",
            "migration cleanup refused a symlink",
        )),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).map_err(|_| {
            migration_denied(
                "migration_cleanup_failed",
                "migration work directory could not be removed",
            )
        }),
        Ok(_) => fs::remove_file(path).map_err(|_| {
            migration_denied(
                "migration_cleanup_failed",
                "migration work file could not be removed",
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(migration_denied(
            "migration_cleanup_failed",
            "migration work path could not be inspected",
        )),
    }
}

fn unix_seconds(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| migration_denied("migration_clock_invalid", "migration clock is invalid"))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn migration_denied(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn migration_reason(error: &JanusError) -> &'static str {
    match error {
        JanusError::PolicyDenied { reason_code, .. }
        | JanusError::PermitInvalid { reason_code, .. }
        | JanusError::ApprovalInvalid { reason_code, .. } => reason_code,
        JanusError::AuditUnavailable { .. } => "audit_sink_unavailable",
        JanusError::InvalidManifest { .. } => "migration_manifest_invalid",
        JanusError::InvalidIdentifier { .. } => "migration_identifier_invalid",
        JanusError::StoreUnavailable { .. }
        | JanusError::NotInManifest { .. }
        | JanusError::NotFound { .. }
        | JanusError::Unsupported { .. } => "migration_state_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use janus_core::{
        Principal, PrincipalId, PrincipalKind, ProductMode, ReleaseAdmissionDecision, ScopePathV1,
    };
    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("janusd-migrate").unwrap(),
            ),
            ScopePathV1::for_repository("fixture-org", "janus", "janus", "migration")
                .unwrap()
                .scope_ref(),
        )
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("approvals");
        let state = dir.path().join("migration-state");
        let audit = dir.path().join("audit/events.jsonl");
        fs::create_dir(&target).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let approval = serde_json::json!({
            "approval_id": "appr_fixture",
            "secret_ref": "sec_fixture",
            "profile_id": "profile.fixture",
            "executor": "janusd",
            "destination": "fixture-service",
            "class": "normal",
            "egress": "connector",
            "purpose": "migration fixture",
            "expires_at_unix_secs": 4102444800_u64,
            "expires_at_subsec_nanos": 0,
            "reason": "reviewed fixture"
        });
        let approval_path = target.join("appr_fixture.json");
        fs::write(&approval_path, serde_json::to_vec(&approval).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&approval_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let manifest_path = dir.path().join("migration.json");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "migration_id": "approval-registry-v0-v1",
            "schema_id": "approval_registry",
            "from_version": 0,
            "to_version": 1,
            "compatibility": "offline",
            "reversible": true,
            "risk_flags": [],
            "target_root": target,
            "state_root": state,
            "audit_path": audit,
            "minimum_free_bytes": 0,
            "backup_max_age_seconds": 900
        });
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        (dir, manifest_path, approval_path)
    }

    fn build_runner(path: &Path) -> ApprovalMigrationRunner {
        let release = ReleaseAdmission::not_required(ProductMode::SelfHosted);
        assert_eq!(release.decision(), ReleaseAdmissionDecision::NotRequired);
        ApprovalMigrationRunner::load(path, release, principal()).unwrap()
    }

    #[test]
    fn forward_postflight_and_rollback_preserve_authority_exactly() {
        let (_dir, manifest_path, approval_path) = fixture();
        let runner = build_runner(&manifest_path);
        let original: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();

        let preflight = runner.preflight(SystemTime::now()).unwrap();
        assert_eq!(preflight.phase, "preflighted");
        assert_eq!(preflight.current_version, 0);
        assert!(!preflight.value_returned);
        assert!(runner.apply(SystemTime::now()).unwrap().phase == "applied");
        let migrated: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
        assert_eq!(migrated["version"], 1);
        for (key, value) in original.as_object().unwrap() {
            assert_eq!(&migrated[key], value);
        }
        let complete = runner.postflight().unwrap();
        assert_eq!(complete.phase, "completed");
        assert_eq!(complete.current_version, 1);
        assert_eq!(runner.apply(SystemTime::now()).unwrap().phase, "completed");
        assert_eq!(runner.postflight().unwrap().phase, "completed");
        let rolled_back = runner.rollback().unwrap();
        assert_eq!(rolled_back.phase, "rolled_back");
        assert_eq!(rolled_back.current_version, 0);
        assert_eq!(runner.rollback().unwrap().phase, "rolled_back");
        assert_eq!(
            runner.preflight(SystemTime::now()).unwrap().phase,
            "rolled_back"
        );
        let restored: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn changed_input_stale_preflight_and_tampered_snapshot_fail_closed() {
        let (_dir, manifest_path, approval_path) = fixture();
        let runner = build_runner(&manifest_path);
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        runner.preflight(now).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&approval_path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(matches!(
            runner.apply(now),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_input_changed",
                ..
            })
        ));

        let (_dir, manifest_path, _) = fixture();
        let runner = build_runner(&manifest_path);
        runner.preflight(now).unwrap();
        assert!(matches!(
            runner.apply(now + Duration::from_secs(901)),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_preflight_stale",
                ..
            })
        ));

        let (_dir, manifest_path, _) = fixture();
        let runner = build_runner(&manifest_path);
        runner.preflight(now).unwrap();
        let snapshot = runner.snapshot_path().join("appr_fixture.json");
        fs::OpenOptions::new()
            .append(true)
            .open(snapshot)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(matches!(
            runner.apply(now),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_snapshot_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn incomplete_journal_blocks_runtime_and_terminal_state_allows_it() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_dir, manifest_path, approval_path) = fixture();
        let old = env::var_os("JANUS_MIGRATION_MANIFEST");
        env::set_var("JANUS_MIGRATION_MANIFEST", &manifest_path);
        assert!(enforce_migration_ready_from_env().is_ok());
        let runner = build_runner(&manifest_path);
        runner.preflight(SystemTime::now()).unwrap();
        assert!(matches!(
            enforce_migration_ready_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_incomplete",
                ..
            })
        ));
        runner.apply(SystemTime::now()).unwrap();
        runner.postflight().unwrap();
        assert!(enforce_migration_ready_from_env().is_ok());

        let reviewed_manifest = fs::read(&manifest_path).unwrap();
        let mut changed_manifest: Value = serde_json::from_slice(&reviewed_manifest).unwrap();
        changed_manifest["minimum_free_bytes"] = Value::from(1);
        fs::write(
            &manifest_path,
            serde_json::to_vec(&changed_manifest).unwrap(),
        )
        .unwrap();
        assert!(enforce_migration_ready_from_env().is_err());
        fs::write(&manifest_path, reviewed_manifest).unwrap();

        fs::OpenOptions::new()
            .append(true)
            .open(approval_path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(matches!(
            enforce_migration_ready_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_terminal_state_mismatch",
                ..
            })
        ));
        match old {
            Some(value) => env::set_var("JANUS_MIGRATION_MANIFEST", value),
            None => env::remove_var("JANUS_MIGRATION_MANIFEST"),
        }
    }

    #[test]
    fn malformed_mixed_risky_low_space_and_failed_postflight_are_denied() {
        let (_dir, manifest_path, approval_path) = fixture();
        let mut malformed: Value =
            serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
        malformed["version"] = Value::from(1);
        fs::write(&approval_path, serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert!(build_runner(&manifest_path)
            .preflight(SystemTime::now())
            .is_err());

        let (_dir, manifest_path, _) = fixture();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["risk_flags"] = serde_json::json!(["authority_widening"]);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(matches!(
            ApprovalMigrationRunner::load(
                &manifest_path,
                ReleaseAdmission::not_required(ProductMode::SelfHosted),
                principal()
            ),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_requires_approval",
                ..
            })
        ));

        let (_dir, manifest_path, _) = fixture();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["minimum_free_bytes"] = Value::from(u64::MAX);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(matches!(
            build_runner(&manifest_path).preflight(SystemTime::now()),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_space_insufficient",
                ..
            })
        ));

        let (_dir, manifest_path, approval_path) = fixture();
        let runner = build_runner(&manifest_path);
        runner.preflight(SystemTime::now()).unwrap();
        runner.apply(SystemTime::now()).unwrap();
        let mut migrated: Value =
            serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
        migrated["destination"] = Value::from("broader-destination");
        fs::write(&approval_path, serde_json::to_vec(&migrated).unwrap()).unwrap();
        assert!(matches!(
            runner.postflight(),
            Err(JanusError::PolicyDenied {
                reason_code: "upgrade_postflight_failed",
                ..
            })
        ));
        assert_eq!(
            runner.read_required_journal().unwrap().phase,
            MigrationPhase::Failed
        );
    }

    #[test]
    fn concurrent_and_untrusted_runs_fail_closed() {
        let (_dir, manifest_path, _) = fixture();
        let runner = build_runner(&manifest_path);
        ensure_private_dir(runner.manifest.state_root(), true).unwrap();
        let _held_lock = runner.acquire_lock().unwrap();
        assert!(matches!(
            runner.preflight(SystemTime::now()),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_concurrent",
                ..
            })
        ));

        let (_dir, manifest_path, _) = fixture();
        let denied = ApprovalMigrationRunner::load(
            &manifest_path,
            ReleaseAdmission::denied(ProductMode::Enterprise, "release_fixture_denied"),
            principal(),
        )
        .unwrap();
        assert!(matches!(
            denied.preflight(SystemTime::now()),
            Err(JanusError::PolicyDenied {
                reason_code: "migration_release_untrusted",
                ..
            })
        ));
    }

    #[test]
    fn audit_corruption_leaves_a_blocking_recoverable_journal() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_dir, manifest_path, _) = fixture();
        let runner = build_runner(&manifest_path);
        let audit = runner.manifest.audit_path();
        ensure_private_dir(audit.parent().unwrap(), true).unwrap();
        write_private_bytes(audit, b"{}\n").unwrap();

        assert!(matches!(
            runner.preflight(SystemTime::now()),
            Err(JanusError::AuditUnavailable { .. })
        ));
        assert_eq!(
            runner.read_required_journal().unwrap().phase,
            MigrationPhase::Preflighted
        );

        let old = env::var_os("JANUS_MIGRATION_MANIFEST");
        env::set_var("JANUS_MIGRATION_MANIFEST", &manifest_path);
        assert!(enforce_migration_ready_from_env().is_err());
        match old {
            Some(value) => env::set_var("JANUS_MIGRATION_MANIFEST", value),
            None => env::remove_var("JANUS_MIGRATION_MANIFEST"),
        }
    }

    #[test]
    fn rollback_recovers_each_interrupted_mutating_phase() {
        for phase in [
            MigrationPhase::Applying,
            MigrationPhase::Staged,
            MigrationPhase::Swapping,
            MigrationPhase::Applied,
        ] {
            let (_dir, manifest_path, approval_path) = fixture();
            let runner = build_runner(&manifest_path);
            let original = fs::read(&approval_path).unwrap();
            runner.preflight(SystemTime::now()).unwrap();

            if phase == MigrationPhase::Applied {
                runner.apply(SystemTime::now()).unwrap();
            } else {
                let mut journal = runner.read_required_journal().unwrap();
                if matches!(phase, MigrationPhase::Staged | MigrationPhase::Swapping) {
                    let source = inspect_approval_root(runner.manifest.target_root()).unwrap();
                    create_migrated_stage(
                        &runner.work_paths().unwrap().stage,
                        &source,
                        &runner.manifest,
                    )
                    .unwrap();
                }
                if phase == MigrationPhase::Swapping {
                    fs::rename(
                        runner.manifest.target_root(),
                        runner.work_paths().unwrap().previous,
                    )
                    .unwrap();
                }
                journal.phase = phase;
                runner.write_journal(&journal).unwrap();
            }

            let restored = runner.rollback().unwrap();
            assert_eq!(restored.phase, "rolled_back");
            assert_eq!(restored.current_version, 0);
            assert_eq!(fs::read(&approval_path).unwrap(), original);
            let work = runner.work_paths().unwrap();
            assert!(!work.stage.exists());
            assert!(!work.previous.exists());
            assert!(!work.failed.exists());
        }
    }
}

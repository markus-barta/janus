use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::{
    ApprovalId, AuditAction, AuditEvent, AuditOutcome, AuditSink, ConsumerRef, Destination,
    EgressMode, Environment, ExecutorRef, JanusError, JanusResult, MigrationPhase, OwnerRef,
    PrincipalChain, ProfileId, Purpose, ReleaseAdmission, ReleaseAdmissionDecision, SafeLabel,
    ScopeRef, ScopeTransferManifest, ScopeTransferMode, SecretClass, SecretLifecycle, SecretName,
    SecretRef, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::JsonlAuditSink;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const JOURNAL_VERSION: u8 = 1;
const BUNDLE_VERSION: u8 = 1;
const STATE_FILE: &str = "scope-state.json";
const JOURNAL_FILE: &str = "journal.json";
const SNAPSHOT_DIR: &str = "snapshot";

/// Value-free scope recovery/transfer command status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeTransferStatus {
    /// Stable reviewed operation id.
    pub operation_id: String,
    /// Exact recovery or boundary-changing transfer.
    pub mode: String,
    /// Durable phase, or `not_started` before preflight.
    pub phase: String,
    /// Opaque source scope ref.
    pub source_scope_ref: String,
    /// Opaque destination scope ref.
    pub destination_scope_ref: String,
    /// Number of value-free secret metadata records in planned output.
    pub record_count: u64,
    /// Number of durable approvals retained in planned output.
    pub approval_count: u64,
    /// Source approvals deliberately excluded from planned output.
    pub excluded_approval_count: u64,
    /// Source permits deliberately excluded from planned output.
    pub excluded_permit_count: u64,
    /// Canonical private source inventory fingerprint.
    pub source_inventory_fingerprint: String,
    /// Fingerprint currently installed at the target.
    pub target_fingerprint: String,
    /// Fingerprint preflight expects to install.
    pub planned_target_fingerprint: String,
    /// Reviewed manifest fingerprint; raw paths and scope components stay private.
    pub manifest_fingerprint: String,
    /// One-to-one source/destination mapping fingerprint.
    pub mapping_fingerprint: String,
    /// Stable value-free reason code.
    pub reason_code: &'static str,
    /// Invariant marker: transfer inspection never reads or returns values.
    pub value_returned: bool,
}

/// Offline runner for one reviewed scope-state recovery or transfer.
pub struct ScopeTransferRunner {
    manifest: ScopeTransferManifest,
    manifest_fingerprint: String,
    mapping_fingerprint: String,
    release: ReleaseAdmission,
    principal: PrincipalChain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferJournal {
    version: u8,
    operation_id: String,
    manifest_fingerprint: String,
    mapping_fingerprint: String,
    mode: ScopeTransferMode,
    source_scope_ref: String,
    destination_scope_ref: String,
    phase: MigrationPhase,
    preflighted_at_unix_secs: u64,
    source_inventory_fingerprint: String,
    expected_target_fingerprint: String,
    planned_target_fingerprint: String,
    target_fingerprint: String,
    record_count: u64,
    approval_count: u64,
    excluded_approval_count: u64,
    excluded_permit_count: u64,
    release_mode: String,
    release_policy_id: Option<String>,
    release_policy_version: Option<u64>,
    release_artifact_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeStateBundle {
    schema_version: u8,
    scope_ref: String,
    records: Vec<ScopeStateRecord>,
    approvals: Vec<TransferApprovalRecord>,
    permit_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeStateRecord {
    secret_name: String,
    secret_ref: String,
    class: String,
    owner: String,
    lifecycle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declared_at_unix_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_at_unix_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_rotated_at_unix_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tombstone: Option<TransferTombstoneRecord>,
    #[serde(default)]
    consumers: Vec<TransferConsumerRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferTombstoneRecord {
    reason: String,
    destroyed_at_unix_secs: u64,
    retain_until_unix_secs: u64,
    principal_binding: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferConsumerRecord {
    consumer_ref: String,
    secret_ref: String,
    scope_ref: String,
    kind: String,
    owner: String,
    environment: String,
    declared: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferApprovalRecord {
    approval_id: String,
    scope_ref: String,
    secret_ref: String,
    profile_id: String,
    executor: String,
    destination: String,
    class: String,
    egress: String,
    purpose: String,
    expires_at_unix_secs: u64,
    expires_at_subsec_nanos: u32,
    reason: String,
}

#[derive(Clone)]
struct ScopeInventory {
    bundle: Option<ScopeStateBundle>,
    fingerprint: String,
    total_bytes: u64,
    record_count: u64,
    approval_count: u64,
    permit_count: u64,
}

struct WorkPaths {
    stage: PathBuf,
    previous: PathBuf,
    failed: PathBuf,
}

impl ScopeTransferRunner {
    /// Load a reviewed private manifest and bind it to release and destination scope.
    pub fn load(
        manifest_path: &Path,
        release: ReleaseAdmission,
        principal: PrincipalChain,
    ) -> JanusResult<Self> {
        let contents = read_reviewed_file(manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest = ScopeTransferManifest::parse_json(&contents)?;
        validate_separate_roots(&manifest)?;
        if principal.scope != manifest.destination_scope_ref() {
            return Err(transfer_denied(
                "scope_transfer_principal_scope_mismatch",
                "operator runtime scope does not match the reviewed destination",
            ));
        }
        let encoded = serde_json::to_vec(&manifest).map_err(|_| {
            transfer_denied(
                "scope_transfer_manifest_invalid",
                "scope transfer manifest could not be canonicalized",
            )
        })?;
        let source = manifest.source_scope_ref();
        let destination = manifest.destination_scope_ref();
        let mapping = format!(
            "janus-scope-transfer-v1\0{}\0{}\0{}",
            manifest.mode().as_str(),
            source.as_str(),
            destination.as_str()
        );
        Ok(Self {
            manifest,
            manifest_fingerprint: digest(&encoded),
            mapping_fingerprint: digest(mapping.as_bytes()),
            release,
            principal,
        })
    }

    /// Inspect and bind source, target, release, mapping, and rollback evidence.
    pub fn preflight(&self, now: SystemTime) -> JanusResult<ScopeTransferStatus> {
        match self.preflight_inner(now) {
            Ok(status) => {
                self.audit(
                    AuditAction::ScopeTransferPreflight,
                    AuditOutcome::Allowed,
                    "scope_transfer_preflight_ok",
                    Severity::Notice,
                    &status,
                )?;
                Ok(status)
            }
            Err(error) => self.audit_denial(AuditAction::ScopeTransferPreflight, error),
        }
    }

    /// Build private staged output and atomically install the preflighted result.
    pub fn apply(&self, now: SystemTime) -> JanusResult<ScopeTransferStatus> {
        match self.apply_inner(now) {
            Ok(status) => {
                self.audit(
                    AuditAction::ScopeTransferApply,
                    AuditOutcome::Allowed,
                    "scope_transfer_apply_ok",
                    Severity::High,
                    &status,
                )?;
                Ok(status)
            }
            Err(error) => self.audit_denial(AuditAction::ScopeTransferApply, error),
        }
    }

    /// Verify installed state before normal runtime can resume.
    pub fn postflight(&self) -> JanusResult<ScopeTransferStatus> {
        match self.postflight_inner() {
            Ok((mut journal, inventory)) => {
                journal.phase = MigrationPhase::Completed;
                journal.target_fingerprint = inventory.fingerprint.clone();
                let status = self.status_from(&journal, &inventory, "scope_transfer_postflight_ok");
                self.audit(
                    AuditAction::ScopeTransferPostflight,
                    AuditOutcome::Allowed,
                    "scope_transfer_postflight_ok",
                    Severity::Notice,
                    &status,
                )?;
                self.write_journal(&journal)?;
                Ok(status)
            }
            Err(error) => {
                self.mark_failed_if_applied();
                self.audit_denial(AuditAction::ScopeTransferPostflight, error)
            }
        }
    }

    /// Restore and verify the exact target snapshot captured by preflight.
    pub fn rollback(&self) -> JanusResult<ScopeTransferStatus> {
        match self.rollback_inner() {
            Ok((mut journal, inventory)) => {
                journal.phase = MigrationPhase::RolledBack;
                journal.target_fingerprint = inventory.fingerprint.clone();
                let status = self.status_from(&journal, &inventory, "scope_transfer_rollback_ok");
                self.audit(
                    AuditAction::ScopeTransferRollback,
                    AuditOutcome::Allowed,
                    "scope_transfer_rollback_ok",
                    Severity::Critical,
                    &status,
                )?;
                self.write_journal(&journal)?;
                Ok(status)
            }
            Err(error) => self.audit_denial(AuditAction::ScopeTransferRollback, error),
        }
    }

    /// Return value-free actual source and target fingerprints, including before preflight.
    pub fn status(&self) -> JanusResult<ScopeTransferStatus> {
        let source = inspect_state_root(
            self.manifest.source_root(),
            Some(&self.manifest.source_scope_ref()),
            true,
        )?;
        let target = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        match self.read_journal()? {
            Some(journal) => {
                self.validate_journal(&journal)?;
                if source.fingerprint != journal.source_inventory_fingerprint {
                    return Err(transfer_denied(
                        "scope_transfer_input_changed",
                        "scope transfer source no longer matches preflight",
                    ));
                }
                Ok(self.status_from(&journal, &target, "scope_transfer_status_ok"))
            }
            None => {
                let output = transform_bundle(
                    source.bundle.as_ref().expect("required source bundle"),
                    self.manifest.mode(),
                    &self.manifest.destination_scope_ref(),
                )?;
                let planned = inventory_from_bundle(output)?;
                let excluded_approvals = source.approval_count - planned.approval_count;
                Ok(ScopeTransferStatus {
                    operation_id: self.manifest.operation_id().to_string(),
                    mode: self.manifest.mode().as_str().to_string(),
                    phase: "not_started".to_string(),
                    source_scope_ref: self.manifest.source_scope_ref().as_str().to_string(),
                    destination_scope_ref: self
                        .manifest
                        .destination_scope_ref()
                        .as_str()
                        .to_string(),
                    record_count: planned.record_count,
                    approval_count: planned.approval_count,
                    excluded_approval_count: excluded_approvals,
                    excluded_permit_count: source.permit_count,
                    source_inventory_fingerprint: source.fingerprint,
                    target_fingerprint: target.fingerprint,
                    planned_target_fingerprint: planned.fingerprint,
                    manifest_fingerprint: self.manifest_fingerprint.clone(),
                    mapping_fingerprint: self.mapping_fingerprint.clone(),
                    reason_code: "scope_transfer_not_started",
                    value_returned: false,
                })
            }
        }
    }

    fn preflight_inner(&self, now: SystemTime) -> JanusResult<ScopeTransferStatus> {
        ensure_private_dir(self.manifest.source_root(), false)?;
        ensure_private_dir(self.manifest.target_root(), true)?;
        ensure_private_dir(self.manifest.state_root(), true)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        if let Some(journal) = self.read_journal()? {
            self.validate_journal(&journal)?;
            let target = inspect_state_root(
                self.manifest.target_root(),
                Some(&self.manifest.destination_scope_ref()),
                false,
            )?;
            let expected = if journal.phase == MigrationPhase::Completed {
                &journal.planned_target_fingerprint
            } else if journal.phase == MigrationPhase::RolledBack {
                &journal.expected_target_fingerprint
            } else {
                return Err(transfer_denied(
                    "scope_transfer_incomplete",
                    "an existing scope transfer must be completed or rolled back",
                ));
            };
            if &target.fingerprint != expected {
                return Err(transfer_denied(
                    "scope_transfer_terminal_state_mismatch",
                    "terminal target does not match scope transfer evidence",
                ));
            }
            return Ok(self.status_from(&journal, &target, "scope_transfer_already_terminal"));
        }
        self.reject_orphan_work_state()?;

        let source = inspect_state_root(
            self.manifest.source_root(),
            Some(&self.manifest.source_scope_ref()),
            true,
        )?;
        if source.fingerprint != self.manifest.source_inventory_fingerprint() {
            return Err(transfer_denied(
                "scope_transfer_source_fingerprint_mismatch",
                "source inventory does not match the reviewed manifest",
            ));
        }
        let target = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if target.fingerprint != self.manifest.expected_target_fingerprint() {
            return Err(transfer_denied(
                "scope_transfer_target_fingerprint_mismatch",
                "target state does not match the reviewed manifest",
            ));
        }

        let output = transform_bundle(
            source.bundle.as_ref().expect("required source bundle"),
            self.manifest.mode(),
            &self.manifest.destination_scope_ref(),
        )?;
        let planned = inventory_from_bundle(output)?;
        let required = source
            .total_bytes
            .checked_add(target.total_bytes)
            .and_then(|bytes| bytes.checked_add(planned.total_bytes))
            .and_then(|bytes| bytes.checked_add(self.manifest.minimum_free_bytes()))
            .ok_or_else(|| {
                transfer_denied(
                    "scope_transfer_space_insufficient",
                    "scope transfer disk requirement overflowed",
                )
            })?;
        let available = fs2::available_space(self.manifest.target_root()).map_err(|_| {
            transfer_denied(
                "scope_transfer_space_unavailable",
                "scope transfer free space could not be checked",
            )
        })?;
        if available < required {
            return Err(transfer_denied(
                "scope_transfer_space_insufficient",
                "scope transfer requires more private staging space",
            ));
        }

        let snapshot_path = self.snapshot_path();
        if snapshot_path.exists() {
            let snapshot = inspect_state_root(
                &snapshot_path,
                Some(&self.manifest.destination_scope_ref()),
                false,
            )?;
            if snapshot.fingerprint != target.fingerprint {
                return Err(transfer_denied(
                    "scope_transfer_snapshot_mismatch",
                    "existing rollback snapshot does not match the target",
                ));
            }
        } else {
            copy_inventory_to(&target, &snapshot_path)?;
        }

        let journal = TransferJournal {
            version: JOURNAL_VERSION,
            operation_id: self.manifest.operation_id().to_string(),
            manifest_fingerprint: self.manifest_fingerprint.clone(),
            mapping_fingerprint: self.mapping_fingerprint.clone(),
            mode: self.manifest.mode(),
            source_scope_ref: self.manifest.source_scope_ref().as_str().to_string(),
            destination_scope_ref: self.manifest.destination_scope_ref().as_str().to_string(),
            phase: MigrationPhase::Preflighted,
            preflighted_at_unix_secs: unix_seconds(now)?,
            source_inventory_fingerprint: source.fingerprint,
            expected_target_fingerprint: target.fingerprint.clone(),
            planned_target_fingerprint: planned.fingerprint,
            target_fingerprint: target.fingerprint.clone(),
            record_count: planned.record_count,
            approval_count: planned.approval_count,
            excluded_approval_count: source.approval_count - planned.approval_count,
            excluded_permit_count: source.permit_count,
            release_mode: self.release.mode().as_str().to_string(),
            release_policy_id: self.release.policy_id().map(ToOwned::to_owned),
            release_policy_version: self.release.policy_version(),
            release_artifact_id: self.release.artifact_id().map(ToOwned::to_owned),
        };
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, &target, "scope_transfer_preflight_ok"))
    }

    fn apply_inner(&self, now: SystemTime) -> JanusResult<ScopeTransferStatus> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == MigrationPhase::Completed {
            let target = inspect_state_root(
                self.manifest.target_root(),
                Some(&self.manifest.destination_scope_ref()),
                true,
            )?;
            return Ok(self.status_from(&journal, &target, "scope_transfer_already_completed"));
        }
        if journal.phase != MigrationPhase::Preflighted {
            return Err(transfer_denied(
                "scope_transfer_incomplete",
                "scope transfer apply requires a clean preflighted journal",
            ));
        }
        let now_secs = unix_seconds(now)?;
        let age = now_secs
            .checked_sub(journal.preflighted_at_unix_secs)
            .ok_or_else(|| {
                transfer_denied(
                    "scope_transfer_preflight_stale",
                    "scope transfer clock moved behind preflight evidence",
                )
            })?;
        if age > self.manifest.preflight_max_age_seconds() {
            return Err(transfer_denied(
                "scope_transfer_preflight_stale",
                "scope transfer preflight evidence is stale",
            ));
        }
        self.validate_release_binding(&journal)?;

        let source = inspect_state_root(
            self.manifest.source_root(),
            Some(&self.manifest.source_scope_ref()),
            true,
        )?;
        if source.fingerprint != journal.source_inventory_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_input_changed",
                "scope transfer source changed after preflight",
            ));
        }
        let target = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if target.fingerprint != journal.expected_target_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_input_changed",
                "scope transfer target changed after preflight",
            ));
        }
        let snapshot = inspect_state_root(
            &self.snapshot_path(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if snapshot.fingerprint != journal.expected_target_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_snapshot_mismatch",
                "scope transfer rollback snapshot changed after preflight",
            ));
        }
        let output = transform_bundle(
            source.bundle.as_ref().expect("required source bundle"),
            self.manifest.mode(),
            &self.manifest.destination_scope_ref(),
        )?;
        let work = self.work_paths()?;
        reject_existing_work_paths(&work)?;

        journal.phase = MigrationPhase::Applying;
        self.write_journal(&journal)?;
        write_bundle_root(&work.stage, &output)?;
        journal.phase = MigrationPhase::Staged;
        self.write_journal(&journal)?;
        let staged = inspect_state_root(
            &work.stage,
            Some(&self.manifest.destination_scope_ref()),
            true,
        )?;
        if staged.fingerprint != journal.planned_target_fingerprint
            || staged.record_count != journal.record_count
            || staged.approval_count != journal.approval_count
            || staged.permit_count != 0
        {
            return Err(transfer_denied(
                "scope_transfer_output_mismatch",
                "staged scope transfer output does not match preflight",
            ));
        }

        journal.phase = MigrationPhase::Swapping;
        self.write_journal(&journal)?;
        fs::rename(self.manifest.target_root(), &work.previous).map_err(|_| {
            transfer_denied(
                "scope_transfer_swap_failed",
                "scope transfer could not preserve the previous target",
            )
        })?;
        if fs::rename(&work.stage, self.manifest.target_root()).is_err() {
            let _ = fs::rename(&work.previous, self.manifest.target_root());
            return Err(transfer_denied(
                "scope_transfer_swap_failed",
                "scope transfer could not install staged output",
            ));
        }
        sync_dir(
            self.manifest
                .target_root()
                .parent()
                .unwrap_or_else(|| Path::new("/")),
        )?;
        journal.phase = MigrationPhase::Applied;
        journal.target_fingerprint = staged.fingerprint.clone();
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, &staged, "scope_transfer_apply_ok"))
    }

    fn postflight_inner(&self) -> JanusResult<(TransferJournal, ScopeInventory)> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_release()?;
        let journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == MigrationPhase::Completed {
            let target = inspect_state_root(
                self.manifest.target_root(),
                Some(&self.manifest.destination_scope_ref()),
                true,
            )?;
            self.validate_completed_target(&journal, &target)?;
            return Ok((journal, target));
        }
        if journal.phase != MigrationPhase::Applied {
            return Err(transfer_denied(
                "scope_transfer_incomplete",
                "scope transfer postflight requires applied state",
            ));
        }
        self.validate_release_binding(&journal)?;
        let target = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            true,
        )?;
        self.validate_completed_target(&journal, &target)?;
        let previous = inspect_state_root(
            &self.work_paths()?.previous,
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if previous.fingerprint != journal.expected_target_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_postflight_failed",
                "preserved pre-transfer target does not match preflight",
            ));
        }
        Ok((journal, target))
    }

    fn rollback_inner(&self) -> JanusResult<(TransferJournal, ScopeInventory)> {
        ensure_private_dir(self.manifest.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == MigrationPhase::RolledBack {
            let target = inspect_state_root(
                self.manifest.target_root(),
                Some(&self.manifest.destination_scope_ref()),
                false,
            )?;
            if target.fingerprint != journal.expected_target_fingerprint {
                return Err(transfer_denied(
                    "scope_transfer_terminal_state_mismatch",
                    "rolled-back target does not match preflight evidence",
                ));
            }
            return Ok((journal, target));
        }
        let snapshot = inspect_state_root(
            &self.snapshot_path(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if snapshot.fingerprint != journal.expected_target_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_snapshot_mismatch",
                "scope transfer rollback snapshot failed integrity checks",
            ));
        }

        journal.phase = MigrationPhase::RollingBack;
        self.write_journal(&journal)?;
        let work = self.work_paths()?;
        cleanup_path(&work.stage)?;
        cleanup_path(&work.failed)?;
        copy_inventory_to(&snapshot, &work.stage)?;
        if self.manifest.target_root().exists() {
            fs::rename(self.manifest.target_root(), &work.failed).map_err(|_| {
                transfer_denied(
                    "scope_transfer_rollback_failed",
                    "rollback could not quarantine the current target",
                )
            })?;
        }
        if fs::rename(&work.stage, self.manifest.target_root()).is_err() {
            if work.failed.exists() {
                let _ = fs::rename(&work.failed, self.manifest.target_root());
            }
            return Err(transfer_denied(
                "scope_transfer_rollback_failed",
                "rollback could not restore the target snapshot",
            ));
        }
        let restored = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )?;
        if restored.fingerprint != journal.expected_target_fingerprint {
            return Err(transfer_denied(
                "scope_transfer_rollback_failed",
                "restored target does not match the snapshot",
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
            return Err(transfer_denied(
                "scope_transfer_release_untrusted",
                "scope transfer requires an admitted runtime release",
            ));
        }
        Ok(())
    }

    fn validate_release_binding(&self, journal: &TransferJournal) -> JanusResult<()> {
        if journal.release_mode != self.release.mode().as_str()
            || journal.release_policy_id.as_deref() != self.release.policy_id()
            || journal.release_policy_version != self.release.policy_version()
            || journal.release_artifact_id.as_deref() != self.release.artifact_id()
        {
            return Err(transfer_denied(
                "scope_transfer_release_changed",
                "release posture changed after scope transfer preflight",
            ));
        }
        Ok(())
    }

    fn validate_completed_target(
        &self,
        journal: &TransferJournal,
        target: &ScopeInventory,
    ) -> JanusResult<()> {
        if target.fingerprint != journal.planned_target_fingerprint
            || target.record_count != journal.record_count
            || target.approval_count != journal.approval_count
            || target.permit_count != 0
        {
            return Err(transfer_denied(
                "scope_transfer_postflight_failed",
                "installed scope transfer output does not match preflight",
            ));
        }
        Ok(())
    }

    fn acquire_lock(&self) -> JanusResult<File> {
        let path = self.manifest.state_root().join("scope-transfer.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| {
            transfer_denied(
                "scope_transfer_lock_unavailable",
                "scope transfer lock is unavailable",
            )
        })?;
        file.try_lock_exclusive().map_err(|_| {
            transfer_denied(
                "scope_transfer_concurrent",
                "another scope transfer holds the maintenance lock",
            )
        })?;
        Ok(file)
    }

    fn read_journal(&self) -> JanusResult<Option<TransferJournal>> {
        let path = self.journal_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => read_private_json(&path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(transfer_denied(
                "scope_transfer_journal_unavailable",
                "scope transfer journal is unavailable",
            )),
        }
    }

    fn read_required_journal(&self) -> JanusResult<TransferJournal> {
        self.read_journal()?.ok_or_else(|| {
            transfer_denied(
                "scope_transfer_preflight_missing",
                "scope transfer requires a durable preflight journal",
            )
        })
    }

    fn validate_journal(&self, journal: &TransferJournal) -> JanusResult<()> {
        if journal.version != JOURNAL_VERSION
            || journal.operation_id != self.manifest.operation_id()
            || journal.manifest_fingerprint != self.manifest_fingerprint
            || journal.mapping_fingerprint != self.mapping_fingerprint
            || journal.mode != self.manifest.mode()
            || journal.source_scope_ref != self.manifest.source_scope_ref().as_str()
            || journal.destination_scope_ref != self.manifest.destination_scope_ref().as_str()
            || !valid_sha256(&journal.source_inventory_fingerprint)
            || !valid_sha256(&journal.expected_target_fingerprint)
            || !valid_sha256(&journal.planned_target_fingerprint)
            || !valid_sha256(&journal.target_fingerprint)
        {
            return Err(transfer_denied(
                "scope_transfer_journal_invalid",
                "scope transfer journal does not match the reviewed manifest",
            ));
        }
        Ok(())
    }

    fn write_journal(&self, journal: &TransferJournal) -> JanusResult<()> {
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
            transfer_denied(
                "scope_transfer_manifest_invalid",
                "scope transfer target has no parent directory",
            )
        })?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                transfer_denied(
                    "scope_transfer_manifest_invalid",
                    "scope transfer target name is invalid",
                )
            })?;
        let prefix = format!(".{name}.{}", self.manifest.operation_id());
        Ok(WorkPaths {
            stage: parent.join(format!("{prefix}.stage")),
            previous: parent.join(format!("{prefix}.previous")),
            failed: parent.join(format!("{prefix}.failed")),
        })
    }

    fn reject_orphan_work_state(&self) -> JanusResult<()> {
        reject_existing_work_paths(&self.work_paths()?)
    }

    fn status_from(
        &self,
        journal: &TransferJournal,
        target: &ScopeInventory,
        reason_code: &'static str,
    ) -> ScopeTransferStatus {
        ScopeTransferStatus {
            operation_id: journal.operation_id.clone(),
            mode: journal.mode.as_str().to_string(),
            phase: journal.phase.as_str().to_string(),
            source_scope_ref: journal.source_scope_ref.clone(),
            destination_scope_ref: journal.destination_scope_ref.clone(),
            record_count: journal.record_count,
            approval_count: journal.approval_count,
            excluded_approval_count: journal.excluded_approval_count,
            excluded_permit_count: journal.excluded_permit_count,
            source_inventory_fingerprint: journal.source_inventory_fingerprint.clone(),
            target_fingerprint: target.fingerprint.clone(),
            planned_target_fingerprint: journal.planned_target_fingerprint.clone(),
            manifest_fingerprint: journal.manifest_fingerprint.clone(),
            mapping_fingerprint: journal.mapping_fingerprint.clone(),
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
        let reason_code = transfer_reason(&error);
        let target = inspect_state_root(
            self.manifest.target_root(),
            Some(&self.manifest.destination_scope_ref()),
            false,
        )
        .unwrap_or_else(|_| empty_inventory());
        let status = self
            .read_journal()
            .ok()
            .flatten()
            .map(|journal| self.status_from(&journal, &target, reason_code))
            .unwrap_or_else(|| ScopeTransferStatus {
                operation_id: self.manifest.operation_id().to_string(),
                mode: self.manifest.mode().as_str().to_string(),
                phase: "not_started".to_string(),
                source_scope_ref: self.manifest.source_scope_ref().as_str().to_string(),
                destination_scope_ref: self.manifest.destination_scope_ref().as_str().to_string(),
                record_count: 0,
                approval_count: 0,
                excluded_approval_count: 0,
                excluded_permit_count: 0,
                source_inventory_fingerprint: digest(b"unavailable"),
                target_fingerprint: target.fingerprint,
                planned_target_fingerprint: digest(b"unavailable"),
                manifest_fingerprint: self.manifest_fingerprint.clone(),
                mapping_fingerprint: self.mapping_fingerprint.clone(),
                reason_code,
                value_returned: false,
            });
        self.audit(
            action,
            AuditOutcome::Denied,
            reason_code,
            Severity::Critical,
            &status,
        )?;
        Err(error)
    }

    fn audit(
        &self,
        action: AuditAction,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
        status: &ScopeTransferStatus,
    ) -> JanusResult<()> {
        let evidence = SafeLabel::new(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            status.operation_id,
            status.mode,
            status.source_scope_ref,
            status.destination_scope_ref,
            status.mapping_fingerprint,
            status.phase,
            status.record_count,
            status.approval_count,
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

/// Fail normal runtime startup while a reviewed scope transfer is incomplete,
/// failed, orphaned, or inconsistent with terminal journal evidence.
pub fn enforce_scope_transfer_ready_from_env() -> JanusResult<()> {
    let Some(path) = env::var_os("JANUS_SCOPE_TRANSFER_MANIFEST").filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let contents = read_reviewed_file(Path::new(&path), MAX_MANIFEST_BYTES)?;
    let manifest = ScopeTransferManifest::parse_json(&contents)?;
    validate_separate_roots(&manifest)?;
    let manifest_fingerprint = digest(&serde_json::to_vec(&manifest).map_err(|_| {
        transfer_denied(
            "scope_transfer_manifest_invalid",
            "scope transfer manifest could not be canonicalized",
        )
    })?);
    if !manifest.state_root().exists() {
        return Ok(());
    }
    ensure_private_dir(manifest.state_root(), false)?;
    let journal_path = manifest.state_root().join(JOURNAL_FILE);
    let journal: TransferJournal = match fs::symlink_metadata(&journal_path) {
        Ok(_) => read_private_json(&journal_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if manifest.state_root().join(SNAPSHOT_DIR).exists() {
                return Err(transfer_denied(
                    "scope_transfer_orphaned_state",
                    "scope transfer snapshot exists without a journal",
                ));
            }
            return Ok(());
        }
        Err(_) => {
            return Err(transfer_denied(
                "scope_transfer_journal_unavailable",
                "scope transfer journal is unavailable",
            ))
        }
    };
    let terminal = matches!(
        journal.phase,
        MigrationPhase::Completed | MigrationPhase::RolledBack
    );
    if journal.version != JOURNAL_VERSION
        || journal.operation_id != manifest.operation_id()
        || journal.manifest_fingerprint != manifest_fingerprint
        || journal.mode != manifest.mode()
        || journal.source_scope_ref != manifest.source_scope_ref().as_str()
        || journal.destination_scope_ref != manifest.destination_scope_ref().as_str()
        || !terminal
    {
        return Err(transfer_denied(
            "scope_transfer_incomplete",
            "runtime is blocked by incomplete or invalid scope transfer state",
        ));
    }
    let target = inspect_state_root(
        manifest.target_root(),
        Some(&manifest.destination_scope_ref()),
        journal.phase == MigrationPhase::Completed,
    )?;
    let expected = if journal.phase == MigrationPhase::Completed {
        &journal.planned_target_fingerprint
    } else {
        &journal.expected_target_fingerprint
    };
    if &target.fingerprint != expected {
        return Err(transfer_denied(
            "scope_transfer_terminal_state_mismatch",
            "runtime target does not match terminal scope transfer evidence",
        ));
    }
    Ok(())
}

fn validate_separate_roots(manifest: &ScopeTransferManifest) -> JanusResult<()> {
    let roots = [
        manifest.source_root(),
        manifest.target_root(),
        manifest.state_root(),
    ];
    for (index, root) in roots.iter().enumerate() {
        for other in roots.iter().skip(index + 1) {
            if root.starts_with(other) || other.starts_with(root) {
                return Err(transfer_denied(
                    "scope_transfer_manifest_invalid",
                    "scope transfer source, target, and state roots must be separate",
                ));
            }
        }
    }
    Ok(())
}

fn inspect_state_root(
    path: &Path,
    expected_scope: Option<&ScopeRef>,
    require_bundle: bool,
) -> JanusResult<ScopeInventory> {
    ensure_private_dir(path, false)?;
    let mut state_bytes = None;
    for entry in fs::read_dir(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_state_unavailable",
            "scope state root could not be listed",
        )
    })? {
        let entry = entry.map_err(|_| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "scope state entry could not be inspected",
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(transfer_denied(
                "scope_transfer_record_invalid",
                "scope state entry name is invalid",
            ));
        };
        if name != STATE_FILE || state_bytes.is_some() {
            return Err(transfer_denied(
                "scope_transfer_record_invalid",
                "scope state root contains an unsupported entry",
            ));
        }
        state_bytes = Some(read_private_bytes(&entry.path(), MAX_STATE_BYTES)?);
    }
    let Some(bytes) = state_bytes else {
        if require_bundle {
            return Err(transfer_denied(
                "scope_transfer_source_missing",
                "scope transfer source bundle is missing",
            ));
        }
        return Ok(empty_inventory());
    };
    let mut bundle: ScopeStateBundle = serde_json::from_slice(&bytes).map_err(|_| {
        transfer_denied(
            "scope_transfer_record_invalid",
            "scope state bundle is malformed",
        )
    })?;
    canonicalize_bundle(&mut bundle);
    validate_bundle(&bundle, expected_scope)?;
    let canonical = serde_json::to_vec(&bundle).map_err(|_| {
        transfer_denied(
            "scope_transfer_record_invalid",
            "scope state bundle could not be canonicalized",
        )
    })?;
    Ok(ScopeInventory {
        record_count: bundle.records.len() as u64,
        approval_count: bundle.approvals.len() as u64,
        permit_count: bundle.permit_count,
        bundle: Some(bundle),
        fingerprint: digest(&canonical),
        total_bytes: bytes.len() as u64,
    })
}

fn inventory_from_bundle(mut bundle: ScopeStateBundle) -> JanusResult<ScopeInventory> {
    canonicalize_bundle(&mut bundle);
    validate_bundle(&bundle, None)?;
    let canonical = serde_json::to_vec(&bundle).map_err(|_| {
        transfer_denied(
            "scope_transfer_record_invalid",
            "scope state bundle could not be canonicalized",
        )
    })?;
    Ok(ScopeInventory {
        record_count: bundle.records.len() as u64,
        approval_count: bundle.approvals.len() as u64,
        permit_count: bundle.permit_count,
        bundle: Some(bundle),
        fingerprint: digest(&canonical),
        total_bytes: canonical.len() as u64,
    })
}

fn empty_inventory() -> ScopeInventory {
    ScopeInventory {
        bundle: None,
        fingerprint: digest(b"janus-empty-scope-state-v1"),
        total_bytes: 0,
        record_count: 0,
        approval_count: 0,
        permit_count: 0,
    }
}

fn canonicalize_bundle(bundle: &mut ScopeStateBundle) {
    for record in &mut bundle.records {
        record
            .consumers
            .sort_by(|left, right| left.consumer_ref.cmp(&right.consumer_ref));
    }
    bundle
        .records
        .sort_by(|left, right| left.secret_name.cmp(&right.secret_name));
    bundle
        .approvals
        .sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
}

fn validate_bundle(
    bundle: &ScopeStateBundle,
    expected_scope: Option<&ScopeRef>,
) -> JanusResult<()> {
    if bundle.schema_version != BUNDLE_VERSION {
        return Err(transfer_denied(
            "scope_transfer_record_invalid",
            "scope state bundle version is unsupported",
        ));
    }
    let scope = ScopeRef::from_opaque(bundle.scope_ref.clone()).map_err(|_| {
        transfer_denied(
            "scope_transfer_scope_invalid",
            "scope state bundle scope is malformed",
        )
    })?;
    if expected_scope.is_some_and(|expected| expected != &scope) {
        return Err(transfer_denied(
            "scope_transfer_scope_mismatch",
            "scope state bundle does not match the expected exact scope",
        ));
    }

    let mut names = BTreeSet::new();
    let mut refs = BTreeMap::new();
    let mut consumers = BTreeSet::new();
    for record in &bundle.records {
        let name = SecretName::new(record.secret_name.clone()).map_err(|_| {
            transfer_denied(
                "scope_transfer_record_invalid",
                "scope state secret name is invalid",
            )
        })?;
        let expected_ref = SecretRef::for_manifest_entry(&scope, &name);
        if record.secret_ref != expected_ref.as_str()
            || !names.insert(record.secret_name.clone())
            || refs
                .insert(record.secret_ref.clone(), record.secret_name.clone())
                .is_some()
        {
            return Err(transfer_denied(
                "scope_transfer_collision",
                "scope state contains a mismatched or colliding secret identity",
            ));
        }
        SecretClass::parse(&record.class).map_err(|_| invalid_record())?;
        OwnerRef::new(record.owner.clone()).map_err(|_| invalid_record())?;
        let lifecycle = SecretLifecycle::parse(&record.lifecycle).map_err(|_| invalid_record())?;
        if let Some(tombstone) = &record.tombstone {
            SafeLabel::new(tombstone.reason.clone()).map_err(|_| invalid_record())?;
            if tombstone.retain_until_unix_secs < tombstone.destroyed_at_unix_secs
                || tombstone.principal_binding.trim().is_empty()
                || !matches!(
                    lifecycle,
                    SecretLifecycle::PendingDelete | SecretLifecycle::Destroyed
                )
            {
                return Err(invalid_record());
            }
        }
        for consumer in &record.consumers {
            ConsumerRef::new(consumer.consumer_ref.clone()).map_err(|_| invalid_record())?;
            OwnerRef::new(consumer.owner.clone()).map_err(|_| invalid_record())?;
            Environment::new(consumer.environment.clone()).map_err(|_| invalid_record())?;
            if !matches!(
                consumer.kind.as_str(),
                "service"
                    | "ci_job"
                    | "dev_shell"
                    | "managed_command"
                    | "connector"
                    | "human_workflow"
            ) || consumer.secret_ref != record.secret_ref
                || consumer.scope_ref != bundle.scope_ref
                || !consumers.insert(consumer.consumer_ref.clone())
            {
                return Err(transfer_denied(
                    "scope_transfer_dangling_reference",
                    "scope state consumer relationship is inconsistent",
                ));
            }
        }
    }

    let mut approvals = BTreeSet::new();
    for approval in &bundle.approvals {
        ApprovalId::from_opaque(approval.approval_id.clone()).map_err(|_| invalid_record())?;
        ProfileId::new(approval.profile_id.clone()).map_err(|_| invalid_record())?;
        ExecutorRef::new(approval.executor.clone()).map_err(|_| invalid_record())?;
        Destination::new(approval.destination.clone()).map_err(|_| invalid_record())?;
        SecretClass::parse(&approval.class).map_err(|_| invalid_record())?;
        EgressMode::parse(&approval.egress).map_err(|_| invalid_record())?;
        Purpose::new(approval.purpose.clone()).map_err(|_| invalid_record())?;
        SafeLabel::new(approval.reason.clone()).map_err(|_| invalid_record())?;
        if approval.scope_ref != bundle.scope_ref
            || !refs.contains_key(&approval.secret_ref)
            || approval.expires_at_subsec_nanos >= 1_000_000_000
            || !approvals.insert(approval.approval_id.clone())
        {
            return Err(transfer_denied(
                "scope_transfer_dangling_reference",
                "scope state approval relationship is inconsistent",
            ));
        }
    }
    Ok(())
}

fn invalid_record() -> JanusError {
    transfer_denied(
        "scope_transfer_record_invalid",
        "scope state record failed semantic validation",
    )
}

fn transform_bundle(
    source: &ScopeStateBundle,
    mode: ScopeTransferMode,
    destination_scope: &ScopeRef,
) -> JanusResult<ScopeStateBundle> {
    let source_scope =
        ScopeRef::from_opaque(source.scope_ref.clone()).map_err(|_| invalid_record())?;
    let mode_matches = match mode {
        ScopeTransferMode::ExactScopeRecovery => source_scope == *destination_scope,
        ScopeTransferMode::BoundaryChangingTransfer => source_scope != *destination_scope,
    };
    if !mode_matches {
        return Err(transfer_denied(
            "scope_transfer_mode_mismatch",
            "scope transfer mode does not match source and destination scopes",
        ));
    }

    let mut output = source.clone();
    output.scope_ref = destination_scope.as_str().to_string();
    for record in &mut output.records {
        let name = SecretName::new(record.secret_name.clone()).map_err(|_| invalid_record())?;
        let destination_ref = SecretRef::for_manifest_entry(destination_scope, &name);
        record.secret_ref = destination_ref.as_str().to_string();
        for consumer in &mut record.consumers {
            consumer.secret_ref = destination_ref.as_str().to_string();
            consumer.scope_ref = destination_scope.as_str().to_string();
        }
    }
    if mode == ScopeTransferMode::BoundaryChangingTransfer {
        output.approvals.clear();
    }
    output.permit_count = 0;
    canonicalize_bundle(&mut output);
    validate_bundle(&output, Some(destination_scope))?;
    Ok(output)
}

fn copy_inventory_to(inventory: &ScopeInventory, destination: &Path) -> JanusResult<()> {
    create_private_dir(destination)?;
    if let Some(bundle) = &inventory.bundle {
        write_bundle_file(&destination.join(STATE_FILE), bundle)?;
    }
    sync_dir(destination)
}

fn write_bundle_root(destination: &Path, bundle: &ScopeStateBundle) -> JanusResult<()> {
    create_private_dir(destination)?;
    write_bundle_file(&destination.join(STATE_FILE), bundle)?;
    sync_dir(destination)
}

fn write_bundle_file(path: &Path, bundle: &ScopeStateBundle) -> JanusResult<()> {
    let mut bytes = serde_json::to_vec(bundle).map_err(|_| {
        transfer_denied(
            "scope_transfer_record_invalid",
            "scope state output could not be encoded",
        )
    })?;
    bytes.push(b'\n');
    write_private_bytes(path, &bytes)
}

fn read_reviewed_file(path: &Path, max_bytes: u64) -> JanusResult<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_manifest_unavailable",
            "scope transfer manifest is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(transfer_denied(
            "scope_transfer_manifest_unavailable",
            "scope transfer manifest is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(transfer_denied(
                "scope_transfer_manifest_unavailable",
                "scope transfer manifest must not be group or world writable",
            ));
        }
    }
    fs::read_to_string(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_manifest_unavailable",
            "scope transfer manifest could not be read",
        )
    })
}

fn ensure_private_dir(path: &Path, create: bool) -> JanusResult<()> {
    if create {
        fs::create_dir_all(path).map_err(|_| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "private scope transfer directory could not be created",
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                transfer_denied(
                    "scope_transfer_state_unavailable",
                    "private scope transfer directory permissions could not be set",
                )
            })?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_state_unavailable",
            "private scope transfer directory is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(transfer_denied(
            "scope_transfer_insecure_path",
            "scope transfer path is not a private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(transfer_denied(
                "scope_transfer_insecure_path",
                "scope transfer directory must be private",
            ));
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> JanusResult<()> {
    fs::create_dir(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_work_path_exists",
            "private scope transfer output could not be created",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            transfer_denied(
                "scope_transfer_insecure_path",
                "scope transfer output permissions could not be set",
            )
        })?;
    }
    Ok(())
}

fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> JanusResult<T> {
    let bytes = read_private_bytes(path, MAX_STATE_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| {
        transfer_denied(
            "scope_transfer_state_invalid",
            "private scope transfer state is malformed",
        )
    })
}

fn read_private_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        transfer_denied(
            "scope_transfer_state_unavailable",
            "private scope transfer file is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(transfer_denied(
            "scope_transfer_insecure_path",
            "scope transfer file is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(transfer_denied(
                "scope_transfer_insecure_path",
                "scope transfer file must be private",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "private scope transfer file could not be read",
            )
        })?;
    Ok(bytes)
}

fn write_private_json_atomic<T: Serialize>(path: &Path, value: &T) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        transfer_denied(
            "scope_transfer_state_invalid",
            "private scope transfer state could not be encoded",
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        transfer_denied(
            "scope_transfer_state_unavailable",
            "private scope transfer state has no parent",
        )
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "private scope transfer state name is invalid",
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
            transfer_denied(
                "scope_transfer_state_unavailable",
                "private scope transfer state could not be replaced",
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
        transfer_denied(
            "scope_transfer_state_unavailable",
            "private scope transfer file could not be created",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "private scope transfer file could not be persisted",
            )
        })?;
    Ok(())
}

fn sync_dir(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            transfer_denied(
                "scope_transfer_state_unavailable",
                "scope transfer directory could not be persisted",
            )
        })
}

fn reject_existing_work_paths(paths: &WorkPaths) -> JanusResult<()> {
    if paths.stage.exists() || paths.previous.exists() || paths.failed.exists() {
        return Err(transfer_denied(
            "scope_transfer_orphaned_state",
            "scope transfer work path exists without a matching phase",
        ));
    }
    Ok(())
}

fn cleanup_path(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(transfer_denied(
            "scope_transfer_insecure_path",
            "scope transfer cleanup refused a symlink",
        )),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).map_err(|_| {
            transfer_denied(
                "scope_transfer_cleanup_failed",
                "scope transfer work directory could not be removed",
            )
        }),
        Ok(_) => fs::remove_file(path).map_err(|_| {
            transfer_denied(
                "scope_transfer_cleanup_failed",
                "scope transfer work file could not be removed",
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(transfer_denied(
            "scope_transfer_cleanup_failed",
            "scope transfer work path could not be inspected",
        )),
    }
}

fn unix_seconds(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            transfer_denied(
                "scope_transfer_clock_invalid",
                "scope transfer clock is invalid",
            )
        })
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

fn transfer_denied(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn transfer_reason(error: &JanusError) -> &'static str {
    match error {
        JanusError::PolicyDenied { reason_code, .. }
        | JanusError::PermitInvalid { reason_code, .. }
        | JanusError::ApprovalInvalid { reason_code, .. } => reason_code,
        JanusError::AuditUnavailable { .. } => "audit_sink_unavailable",
        JanusError::InvalidManifest { .. } => "scope_transfer_manifest_invalid",
        JanusError::InvalidIdentifier { .. } => "scope_transfer_identifier_invalid",
        JanusError::StoreUnavailable { .. }
        | JanusError::NotInManifest { .. }
        | JanusError::NotFound { .. }
        | JanusError::Unsupported { .. } => "scope_transfer_state_unavailable",
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

    struct Fixture {
        _dir: tempfile::TempDir,
        manifest_path: PathBuf,
        source: PathBuf,
        target: PathBuf,
        state: PathBuf,
        source_scope: ScopeRef,
        destination_scope: ScopeRef,
    }

    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn bundle(scope: &ScopeRef) -> ScopeStateBundle {
        let active_name = SecretName::new("database-password").unwrap();
        let active_ref = SecretRef::for_manifest_entry(scope, &active_name);
        let destroyed_name = SecretName::new("retired-token").unwrap();
        let destroyed_ref = SecretRef::for_manifest_entry(scope, &destroyed_name);
        ScopeStateBundle {
            schema_version: BUNDLE_VERSION,
            scope_ref: scope.as_str().to_string(),
            records: vec![
                ScopeStateRecord {
                    secret_name: active_name.as_str().to_string(),
                    secret_ref: active_ref.as_str().to_string(),
                    class: "high_value".to_string(),
                    owner: "team-platform".to_string(),
                    lifecycle: "active".to_string(),
                    declared_at_unix_secs: Some(100),
                    last_used_at_unix_secs: Some(200),
                    last_rotated_at_unix_secs: Some(150),
                    tombstone: None,
                    consumers: vec![TransferConsumerRecord {
                        consumer_ref: "con_database".to_string(),
                        secret_ref: active_ref.as_str().to_string(),
                        scope_ref: scope.as_str().to_string(),
                        kind: "service".to_string(),
                        owner: "team-platform".to_string(),
                        environment: "dev".to_string(),
                        declared: true,
                    }],
                },
                ScopeStateRecord {
                    secret_name: destroyed_name.as_str().to_string(),
                    secret_ref: destroyed_ref.as_str().to_string(),
                    class: "break_glass".to_string(),
                    owner: "team-security".to_string(),
                    lifecycle: "destroyed".to_string(),
                    declared_at_unix_secs: Some(50),
                    last_used_at_unix_secs: None,
                    last_rotated_at_unix_secs: None,
                    tombstone: Some(TransferTombstoneRecord {
                        reason: "reviewed retirement".to_string(),
                        destroyed_at_unix_secs: 300,
                        retain_until_unix_secs: 600,
                        principal_binding: "source evidence binding".to_string(),
                    }),
                    consumers: vec![],
                },
            ],
            approvals: vec![TransferApprovalRecord {
                approval_id: "appr_fixture".to_string(),
                scope_ref: scope.as_str().to_string(),
                secret_ref: active_ref.as_str().to_string(),
                profile_id: "profile.database".to_string(),
                executor: "janusd".to_string(),
                destination: "database-service".to_string(),
                class: "high_value".to_string(),
                egress: "connector".to_string(),
                purpose: "reviewed restore fixture".to_string(),
                expires_at_unix_secs: 4_102_444_800,
                expires_at_subsec_nanos: 0,
                reason: "reviewed fixture".to_string(),
            }],
            permit_count: 2,
        }
    }

    fn make_fixture(mode: ScopeTransferMode) -> Fixture {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        let state = dir.path().join("transfer-state");
        let audit = dir.path().join("audit/events.jsonl");
        private_dir(&source);
        private_dir(&target);
        let source_path =
            ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev").unwrap();
        let destination_path = match mode {
            ScopeTransferMode::ExactScopeRecovery => source_path.clone(),
            ScopeTransferMode::BoundaryChangingTransfer => {
                ScopePathV1::for_repository("fixture-org", "janus", "janus", "prod").unwrap()
            }
        };
        let source_scope = source_path.scope_ref();
        let destination_scope = destination_path.scope_ref();
        let source_bundle = bundle(&source_scope);
        private_file(
            &source.join(STATE_FILE),
            &serde_json::to_vec(&source_bundle).unwrap(),
        );
        let source_fingerprint = inventory_from_bundle(source_bundle).unwrap().fingerprint;
        let target_fingerprint = empty_inventory().fingerprint;
        let manifest_path = dir.path().join("scope-transfer.json");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "operation_id": match mode {
                ScopeTransferMode::ExactScopeRecovery => "fixture-recovery",
                ScopeTransferMode::BoundaryChangingTransfer => "fixture-transfer",
            },
            "mode": mode.as_str(),
            "source_scope_ref": source_scope.as_str(),
            "destination_scope": destination_path,
            "expected_destination_scope_ref": destination_scope.as_str(),
            "source_inventory_fingerprint": source_fingerprint,
            "expected_target_fingerprint": target_fingerprint,
            "source_root": source,
            "target_root": target,
            "state_root": state,
            "audit_path": audit,
            "minimum_free_bytes": 0,
            "preflight_max_age_seconds": 900
        });
        private_file(&manifest_path, &serde_json::to_vec(&manifest).unwrap());
        Fixture {
            _dir: dir,
            manifest_path,
            source,
            target,
            state,
            source_scope,
            destination_scope,
        }
    }

    fn principal(scope: ScopeRef) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("janusd-scope-transfer").unwrap(),
            ),
            scope,
        )
    }

    fn build_runner(fixture: &Fixture) -> ScopeTransferRunner {
        let release = ReleaseAdmission::not_required(ProductMode::SelfHosted);
        assert_eq!(release.decision(), ReleaseAdmissionDecision::NotRequired);
        ScopeTransferRunner::load(
            &fixture.manifest_path,
            release,
            principal(fixture.destination_scope.clone()),
        )
        .unwrap()
    }

    #[test]
    fn exact_scope_recovery_preserves_refs_and_approvals_but_excludes_permits() {
        let fixture = make_fixture(ScopeTransferMode::ExactScopeRecovery);
        let runner = build_runner(&fixture);
        let discovered = runner.status().unwrap();
        assert_eq!(discovered.phase, "not_started");
        assert_eq!(discovered.approval_count, 1);
        assert_eq!(discovered.excluded_permit_count, 2);
        assert!(!discovered.value_returned);

        assert_eq!(
            runner.preflight(SystemTime::now()).unwrap().phase,
            "preflighted"
        );
        assert_eq!(runner.apply(SystemTime::now()).unwrap().phase, "applied");
        assert_eq!(runner.postflight().unwrap().phase, "completed");

        let installed = inspect_state_root(&fixture.target, Some(&fixture.destination_scope), true)
            .unwrap()
            .bundle
            .unwrap();
        let source = inspect_state_root(&fixture.source, Some(&fixture.source_scope), true)
            .unwrap()
            .bundle
            .unwrap();
        assert_eq!(
            installed.records[0].secret_ref,
            source.records[0].secret_ref
        );
        assert_eq!(installed.approvals.len(), 1);
        assert_eq!(installed.approvals[0].approval_id, "appr_fixture");
        assert_eq!(installed.permit_count, 0);
    }

    #[test]
    fn boundary_transfer_rewrites_every_supported_ref_and_drops_authority() {
        let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
        let runner = build_runner(&fixture);
        let source = inspect_state_root(&fixture.source, Some(&fixture.source_scope), true)
            .unwrap()
            .bundle
            .unwrap();
        runner.preflight(SystemTime::now()).unwrap();
        runner.apply(SystemTime::now()).unwrap();
        runner.postflight().unwrap();
        let installed = inspect_state_root(&fixture.target, Some(&fixture.destination_scope), true)
            .unwrap()
            .bundle
            .unwrap();

        assert_eq!(installed.scope_ref, fixture.destination_scope.as_str());
        assert!(installed.approvals.is_empty());
        assert_eq!(installed.permit_count, 0);
        for (before, after) in source.records.iter().zip(&installed.records) {
            assert_ne!(before.secret_ref, after.secret_ref);
            assert_eq!(before.class, after.class);
            assert_eq!(before.owner, after.owner);
            assert_eq!(before.lifecycle, after.lifecycle);
            assert_eq!(before.tombstone.is_some(), after.tombstone.is_some());
            for consumer in &after.consumers {
                assert_eq!(consumer.secret_ref, after.secret_ref);
                assert_eq!(consumer.scope_ref, fixture.destination_scope.as_str());
            }
        }
    }

    #[test]
    fn stale_preflight_changed_input_collision_and_wrong_principal_fail_closed() {
        let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
        let runner = build_runner(&fixture);
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        runner.preflight(now).unwrap();
        assert!(matches!(
            runner.apply(now + Duration::from_secs(901)),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_preflight_stale",
                ..
            })
        ));

        let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
        let runner = build_runner(&fixture);
        runner.preflight(now).unwrap();
        let mut source: Value =
            serde_json::from_slice(&fs::read(fixture.source.join(STATE_FILE)).unwrap()).unwrap();
        source["permit_count"] = Value::from(3);
        private_file(
            &fixture.source.join(STATE_FILE),
            &serde_json::to_vec(&source).unwrap(),
        );
        assert!(matches!(
            runner.apply(now),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_input_changed",
                ..
            })
        ));

        let fixture = make_fixture(ScopeTransferMode::ExactScopeRecovery);
        let mut source: Value =
            serde_json::from_slice(&fs::read(fixture.source.join(STATE_FILE)).unwrap()).unwrap();
        let duplicate = source["records"][0].clone();
        source["records"].as_array_mut().unwrap().push(duplicate);
        private_file(
            &fixture.source.join(STATE_FILE),
            &serde_json::to_vec(&source).unwrap(),
        );
        assert!(matches!(
            build_runner(&fixture).preflight(SystemTime::now()),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_collision",
                ..
            })
        ));

        let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
        assert!(matches!(
            ScopeTransferRunner::load(
                &fixture.manifest_path,
                ReleaseAdmission::not_required(ProductMode::SelfHosted),
                principal(fixture.source_scope.clone()),
            ),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_principal_scope_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn rollback_restores_the_exact_preflight_target() {
        let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
        let runner = build_runner(&fixture);
        let before = inspect_state_root(&fixture.target, None, false)
            .unwrap()
            .fingerprint;
        runner.preflight(SystemTime::now()).unwrap();
        runner.apply(SystemTime::now()).unwrap();
        let rolled_back = runner.rollback().unwrap();
        assert_eq!(rolled_back.phase, "rolled_back");
        assert_eq!(rolled_back.target_fingerprint, before);
        assert!(inspect_state_root(&fixture.target, None, false)
            .unwrap()
            .bundle
            .is_none());
        assert!(!runner.work_paths().unwrap().previous.exists());
    }

    #[test]
    fn rollback_recovers_each_interrupted_mutating_phase() {
        for phase in [
            MigrationPhase::Applying,
            MigrationPhase::Staged,
            MigrationPhase::Swapping,
            MigrationPhase::Applied,
        ] {
            let fixture = make_fixture(ScopeTransferMode::BoundaryChangingTransfer);
            let runner = build_runner(&fixture);
            let before = inspect_state_root(&fixture.target, None, false)
                .unwrap()
                .fingerprint;
            runner.preflight(SystemTime::now()).unwrap();

            if phase == MigrationPhase::Applied {
                runner.apply(SystemTime::now()).unwrap();
            } else {
                let mut journal = runner.read_required_journal().unwrap();
                if matches!(phase, MigrationPhase::Staged | MigrationPhase::Swapping) {
                    let source =
                        inspect_state_root(&fixture.source, Some(&fixture.source_scope), true)
                            .unwrap()
                            .bundle
                            .unwrap();
                    let output = transform_bundle(
                        &source,
                        runner.manifest.mode(),
                        &fixture.destination_scope,
                    )
                    .unwrap();
                    write_bundle_root(&runner.work_paths().unwrap().stage, &output).unwrap();
                }
                if phase == MigrationPhase::Swapping {
                    fs::rename(&fixture.target, runner.work_paths().unwrap().previous).unwrap();
                }
                journal.phase = phase;
                runner.write_journal(&journal).unwrap();
            }

            let restored = runner.rollback().unwrap();
            assert_eq!(restored.phase, "rolled_back");
            assert_eq!(restored.target_fingerprint, before);
            assert!(inspect_state_root(&fixture.target, None, false)
                .unwrap()
                .bundle
                .is_none());
            let work = runner.work_paths().unwrap();
            assert!(!work.stage.exists());
            assert!(!work.previous.exists());
            assert!(!work.failed.exists());
        }
    }

    #[test]
    fn incomplete_and_tampered_terminal_state_blocks_runtime() {
        let _lock = ENV_LOCK.lock().unwrap();
        let fixture = make_fixture(ScopeTransferMode::ExactScopeRecovery);
        let old = env::var_os("JANUS_SCOPE_TRANSFER_MANIFEST");
        env::set_var("JANUS_SCOPE_TRANSFER_MANIFEST", &fixture.manifest_path);
        assert!(enforce_scope_transfer_ready_from_env().is_ok());
        let runner = build_runner(&fixture);
        runner.preflight(SystemTime::now()).unwrap();
        assert!(matches!(
            enforce_scope_transfer_ready_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_incomplete",
                ..
            })
        ));
        runner.apply(SystemTime::now()).unwrap();
        runner.postflight().unwrap();
        assert!(enforce_scope_transfer_ready_from_env().is_ok());
        let target_path = fixture.target.join(STATE_FILE);
        let mut target: Value = serde_json::from_slice(&fs::read(&target_path).unwrap()).unwrap();
        target["permit_count"] = Value::from(1);
        private_file(&target_path, &serde_json::to_vec(&target).unwrap());
        assert!(matches!(
            enforce_scope_transfer_ready_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_terminal_state_mismatch",
                ..
            })
        ));
        match old {
            Some(value) => env::set_var("JANUS_SCOPE_TRANSFER_MANIFEST", value),
            None => env::remove_var("JANUS_SCOPE_TRANSFER_MANIFEST"),
        }
    }

    #[test]
    fn untrusted_release_and_orphan_snapshot_fail_closed() {
        let fixture = make_fixture(ScopeTransferMode::ExactScopeRecovery);
        let denied = ScopeTransferRunner::load(
            &fixture.manifest_path,
            ReleaseAdmission::denied(ProductMode::Enterprise, "release_fixture_denied"),
            principal(fixture.destination_scope.clone()),
        )
        .unwrap();
        assert!(matches!(
            denied.preflight(SystemTime::now()),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_release_untrusted",
                ..
            })
        ));

        private_dir(&fixture.state);
        private_dir(&fixture.state.join(SNAPSHOT_DIR));
        let _lock = ENV_LOCK.lock().unwrap();
        let old = env::var_os("JANUS_SCOPE_TRANSFER_MANIFEST");
        env::set_var("JANUS_SCOPE_TRANSFER_MANIFEST", &fixture.manifest_path);
        assert!(matches!(
            enforce_scope_transfer_ready_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "scope_transfer_orphaned_state",
                ..
            })
        ));
        match old {
            Some(value) => env::set_var("JANUS_SCOPE_TRANSFER_MANIFEST", value),
            None => env::remove_var("JANUS_SCOPE_TRANSFER_MANIFEST"),
        }
    }
}

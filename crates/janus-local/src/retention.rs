//! Offline, value-free retention planning, quarantine, rollback, and purge.

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
    ReleaseAdmission, ReleaseAdmissionDecision, RetentionEvidenceClass, RetentionEvidenceInput,
    RetentionEvidenceV1, RetentionHoldRegistryV1, RetentionPolicyV1, SafeLabel, SecretDescriptor,
    SecretLifecycle, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    audit::lock_verified_audit_for_snapshot, ApprovalRegistry, DelegationRegistry,
    FileApprovalRegistry, FileDelegationRegistry, FileLifecycleEvidenceRegistry,
    FileTombstoneRegistry, JsonlAuditSink, LifecycleEvidenceRegistry, TombstoneRegistry,
};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const JOURNAL_VERSION: u8 = 1;
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "retention.lock";

/// Value-free retention status for operator output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionStatus {
    /// Reviewed operation id.
    pub operation_id: String,
    /// Durable workflow phase.
    pub phase: String,
    /// Exact opaque scope.
    pub scope_ref: String,
    /// Reviewed policy fingerprint.
    pub policy_fingerprint: String,
    /// Current config aggregate fingerprint.
    pub config_fingerprint: String,
    /// Current hold registry fingerprint.
    pub hold_fingerprint: String,
    /// Full source inventory fingerprint.
    pub source_fingerprint: String,
    /// Closed quarantine inventory fingerprint.
    pub quarantine_fingerprint: String,
    /// Eligible closed record sets.
    pub eligible_count: u64,
    /// Active held record sets.
    pub held_count: u64,
    /// Protected class count.
    pub protected_count: u64,
    /// Earliest known next due time, or zero.
    pub next_due_at_unix_secs: u64,
    /// Stable value-free reason code.
    pub reason_code: &'static str,
    /// Retention never returns secret values.
    pub value_returned: bool,
}

/// Offline runner for one reviewed retention cycle.
pub struct RetentionRunner {
    policy: RetentionPolicyV1,
    policy_fingerprint: String,
    config_fingerprint: String,
    release: ReleaseAdmission,
    principal: PrincipalChain,
    reviewed_owner: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RetentionPhase {
    Preflighted,
    Quarantining,
    Quarantined,
    Purging,
    Completed,
    RollingBack,
    RolledBack,
}

impl RetentionPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preflighted => "preflighted",
            Self::Quarantining => "quarantining",
            Self::Quarantined => "quarantined",
            Self::Purging => "purging",
            Self::Completed => "completed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionJournal {
    version: u8,
    operation_id: String,
    policy_fingerprint: String,
    config_fingerprint: String,
    hold_fingerprint: String,
    source_fingerprint: String,
    quarantine_fingerprint: String,
    phase: RetentionPhase,
    evaluated_at_unix_secs: u64,
    quarantined_at_unix_secs: Option<u64>,
    completed_at_unix_secs: Option<u64>,
    next_due_at_unix_secs: Option<u64>,
    held_count: u64,
    protected_count: u64,
    total_bytes: u64,
    entries: Vec<RetentionPlanEntry>,
    release_mode: String,
    release_policy_id: Option<String>,
    release_policy_version: Option<u64>,
    release_artifact_id: Option<String>,
    integrity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionPlanEntry {
    class: RetentionEvidenceClass,
    target_fingerprint: String,
    terminal_at_unix_secs: u64,
    files: Vec<RetentionPlanFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionPlanFile {
    name: String,
    bytes: u64,
    fingerprint: String,
}

struct RetentionPlan {
    source_fingerprint: String,
    quarantine_fingerprint: String,
    hold_fingerprint: String,
    entries: Vec<RetentionPlanEntry>,
    held_count: u64,
    protected_count: u64,
    total_bytes: u64,
    next_due_at_unix_secs: Option<u64>,
}

struct RetentionLock(File);

impl Drop for RetentionLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

impl RetentionRunner {
    /// Load and bind a strict reviewed policy to current release/config/scope.
    pub fn load(
        policy_path: &Path,
        release: ReleaseAdmission,
        principal: PrincipalChain,
    ) -> JanusResult<Self> {
        let contents = read_reviewed_text(policy_path, MAX_POLICY_BYTES)?;
        let policy = RetentionPolicyV1::parse_json(&contents)?;
        let policy_fingerprint =
            fingerprint_domain("janus-retention-policy-v1", contents.as_bytes());
        let config_fingerprint = validate_config_bindings(&policy)?;
        let runner = Self {
            policy,
            policy_fingerprint,
            config_fingerprint,
            release,
            principal,
            reviewed_owner: owner_id(policy_path)?,
        };
        runner.validate_release()?;
        if runner.principal.scope != runner.policy.scope_ref() {
            return Err(retention_denied(
                "retention_scope_mismatch",
                "retention principal does not match the reviewed scope",
            ));
        }
        runner.validate_static_paths()?;
        Ok(runner)
    }

    /// Exact reviewed policy.
    pub fn policy(&self) -> &RetentionPolicyV1 {
        &self.policy
    }

    /// Require one runtime descriptor input to be an exact reviewed binding.
    pub fn validate_bound_config_path(&self, path: &Path) -> JanusResult<()> {
        self.validate_current_bindings()?;
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            retention_denied(
                "retention_config_unbound",
                "retention runtime configuration is not an available reviewed file",
            )
        })?;
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !self
                .policy
                .config_bindings()
                .iter()
                .any(|binding| binding.path() == path)
        {
            return Err(retention_denied(
                "retention_config_unbound",
                "retention runtime configuration is not an exact reviewed binding",
            ));
        }
        Ok(())
    }

    /// Read-only, exclusive eligibility preflight and durable plan.
    pub fn preflight(
        &self,
        now: SystemTime,
        descriptors: &[SecretDescriptor],
    ) -> JanusResult<RetentionStatus> {
        ensure_private_dir(self.policy.state_root(), true)?;
        let _lock = self.acquire_lock()?;
        self.validate_current_bindings()?;
        if self.read_journal()?.is_some() {
            return Err(retention_denied(
                "retention_operation_exists",
                "retention operation journal already exists",
            ));
        }
        reject_existing(self.policy.quarantine_root())?;
        reject_existing(&self.stage_path()?)?;
        let _source_audit = lock_verified_audit_for_snapshot(self.policy.audit_path())?;
        let plan = self.build_plan(now, descriptors)?;
        let available = fs2::available_space(
            self.policy
                .quarantine_root()
                .parent()
                .ok_or_else(|| retention_invalid("retention quarantine has no parent"))?,
        )
        .map_err(|_| retention_invalid("retention capacity is unavailable"))?;
        let required = plan
            .total_bytes
            .checked_add(self.policy.minimum_free_bytes())
            .ok_or_else(|| retention_invalid("retention capacity requirement overflowed"))?;
        if available < required {
            return Err(retention_denied(
                "retention_capacity_insufficient",
                "retention quarantine capacity is insufficient",
            ));
        }

        self.record_audit(
            AuditAction::RetentionApply,
            AuditOutcome::Allowed,
            "retention_preflight_ok",
            Severity::Notice,
        )?;
        let mut journal = RetentionJournal {
            version: JOURNAL_VERSION,
            operation_id: self.policy.operation_id().to_string(),
            policy_fingerprint: self.policy_fingerprint.clone(),
            config_fingerprint: self.config_fingerprint.clone(),
            hold_fingerprint: plan.hold_fingerprint,
            source_fingerprint: plan.source_fingerprint,
            quarantine_fingerprint: plan.quarantine_fingerprint,
            phase: RetentionPhase::Preflighted,
            evaluated_at_unix_secs: unix_seconds(now)?,
            quarantined_at_unix_secs: None,
            completed_at_unix_secs: None,
            next_due_at_unix_secs: plan.next_due_at_unix_secs,
            held_count: plan.held_count,
            protected_count: plan.protected_count,
            total_bytes: plan.total_bytes,
            entries: plan.entries,
            release_mode: self.release.mode().as_str().to_string(),
            release_policy_id: self.release.policy_id().map(ToOwned::to_owned),
            release_policy_version: self.release.policy_version(),
            release_artifact_id: self.release.artifact_id().map(ToOwned::to_owned),
            integrity: String::new(),
        };
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, "retention_preflight_ok"))
    }

    /// Atomically move the exact fresh plan into private reversible quarantine.
    pub fn quarantine(
        &self,
        now: SystemTime,
        descriptors: &[SecretDescriptor],
    ) -> JanusResult<RetentionStatus> {
        ensure_private_dir(self.policy.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_current_bindings()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == RetentionPhase::Quarantined {
            self.verify_quarantine(&journal, false)?;
            return Ok(self.status_from(&journal, "retention_quarantine_ok"));
        }
        if journal.phase == RetentionPhase::Quarantining {
            if self.policy.quarantine_root().exists() && !self.stage_path()?.exists() {
                self.verify_quarantine(&journal, false)?;
                journal.phase = RetentionPhase::Quarantined;
                journal.quarantined_at_unix_secs = Some(unix_seconds(now)?);
                seal_journal(&mut journal)?;
                self.write_journal(&journal)?;
                return Ok(self.status_from(&journal, "retention_quarantine_recovered"));
            }
            return Err(retention_denied(
                "retention_interrupted",
                "interrupted retention quarantine requires rollback",
            ));
        }
        if journal.phase != RetentionPhase::Preflighted {
            return Err(retention_denied(
                "retention_phase_invalid",
                "retention quarantine requires preflighted state",
            ));
        }
        self.validate_preflight_age(&journal, now)?;
        let current = self.build_plan(now, descriptors)?;
        if current.source_fingerprint != journal.source_fingerprint
            || current.hold_fingerprint != journal.hold_fingerprint
            || current.entries != journal.entries
            || current.quarantine_fingerprint != journal.quarantine_fingerprint
        {
            return Err(retention_denied(
                "retention_source_changed",
                "retention source or holds changed after preflight",
            ));
        }
        reject_existing(self.policy.quarantine_root())?;
        let stage = self.stage_path()?;
        reject_existing(&stage)?;
        self.record_audit(
            AuditAction::RetentionApply,
            AuditOutcome::Allowed,
            "retention_quarantine_started",
            Severity::High,
        )?;
        journal.phase = RetentionPhase::Quarantining;
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;

        create_private_dir(&stage)?;
        for entry in &journal.entries {
            let class_dir = stage.join(entry.class.as_str());
            if !class_dir.exists() {
                create_private_dir(&class_dir)?;
            }
            for file in &entry.files {
                let source = self.source_file(entry.class, &file.name)?;
                fs::rename(&source, class_dir.join(&file.name)).map_err(|_| {
                    retention_denied(
                        "retention_quarantine_failed",
                        "retention record could not be moved to quarantine",
                    )
                })?;
                sync_parent(&source)?;
            }
        }
        sync_tree(&stage)?;
        fs::rename(&stage, self.policy.quarantine_root()).map_err(|_| {
            retention_denied(
                "retention_quarantine_failed",
                "retention quarantine could not be installed",
            )
        })?;
        sync_parent(self.policy.quarantine_root())?;
        self.verify_quarantine(&journal, false)?;
        journal.phase = RetentionPhase::Quarantined;
        journal.quarantined_at_unix_secs = Some(unix_seconds(now)?);
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;
        self.record_audit(
            AuditAction::RetentionApply,
            AuditOutcome::Allowed,
            "retention_quarantine_ok",
            Severity::High,
        )?;
        Ok(self.status_from(&journal, "retention_quarantine_ok"))
    }

    /// Irreversibly purge only the exact verified quarantined closed sets.
    pub fn purge(&self, now: SystemTime) -> JanusResult<RetentionStatus> {
        ensure_private_dir(self.policy.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_current_bindings()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == RetentionPhase::Completed {
            self.verify_completed_evidence(&journal, now)?;
            return Ok(self.status_from(&journal, "retention_purge_ok"));
        }
        if !matches!(
            journal.phase,
            RetentionPhase::Quarantined | RetentionPhase::Purging
        ) {
            return Err(retention_denied(
                "retention_phase_invalid",
                "retention purge requires quarantined state",
            ));
        }
        let quarantined_at = journal.quarantined_at_unix_secs.ok_or_else(|| {
            retention_denied(
                "retention_journal_invalid",
                "retention quarantine timestamp is missing",
            )
        })?;
        let now_secs = unix_seconds(now)?;
        let grace_elapsed = match now_secs.checked_sub(quarantined_at) {
            Some(age) => age >= self.policy.quarantine_grace_seconds(),
            None => false,
        };
        if !grace_elapsed {
            return Err(retention_denied(
                "retention_grace_active",
                "retention quarantine grace has not elapsed",
            ));
        }
        let current_hold = load_holds(&self.policy)?.1;
        if current_hold != journal.hold_fingerprint {
            return Err(retention_denied(
                "retention_holds_changed",
                "retention holds changed after preflight",
            ));
        }
        if journal.phase == RetentionPhase::Quarantined {
            self.verify_quarantine(&journal, false)?;
            self.record_audit(
                AuditAction::RetentionExpire,
                AuditOutcome::Allowed,
                "retention_purge_started",
                Severity::Critical,
            )?;
            journal.phase = RetentionPhase::Purging;
            seal_journal(&mut journal)?;
            self.write_journal(&journal)?;
        } else if self.policy.quarantine_root().exists() {
            self.verify_quarantine(&journal, true)?;
        }

        self.purge_remaining(&journal)?;
        let (audit_sequence, audit_hash) = self.record_completion_audit()?;
        let completed_at = unix_seconds(now)?;
        let evidence = RetentionEvidenceV1::new(RetentionEvidenceInput {
            operation_id: journal.operation_id.clone(),
            scope_ref: self.policy.scope_ref().as_str().to_string(),
            release_artifact: self.policy.release_artifact().to_string(),
            policy_fingerprint: journal.policy_fingerprint.clone(),
            config_fingerprint: journal.config_fingerprint.clone(),
            hold_fingerprint: journal.hold_fingerprint.clone(),
            source_fingerprint: source_inventory_fingerprint(&self.policy)?,
            quarantine_fingerprint: journal.quarantine_fingerprint.clone(),
            evaluated_at_unix_secs: journal.evaluated_at_unix_secs,
            completed_at_unix_secs: completed_at,
            next_due_at_unix_secs: journal.next_due_at_unix_secs,
            eligible_count: journal.entries.len() as u64,
            purged_count: journal.entries.len() as u64,
            held_count: journal.held_count,
            protected_count: journal.protected_count,
            outcome: "completed".to_string(),
            reason_code: "retention_purge_ok".to_string(),
            audit_sequence,
            audit_hash,
        })?;
        write_private_json_atomic(self.policy.evidence_path(), &evidence)?;
        journal.phase = RetentionPhase::Completed;
        journal.completed_at_unix_secs = Some(completed_at);
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;
        Ok(self.status_from(&journal, "retention_purge_ok"))
    }

    /// Restore exact quarantined bytes before irreversible purge.
    pub fn rollback(&self) -> JanusResult<RetentionStatus> {
        ensure_private_dir(self.policy.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_current_bindings()?;
        let mut journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        if journal.phase == RetentionPhase::RolledBack {
            return Ok(self.status_from(&journal, "retention_rollback_ok"));
        }
        if matches!(
            journal.phase,
            RetentionPhase::Purging | RetentionPhase::Completed
        ) {
            return Err(retention_denied(
                "retention_rollback_unavailable",
                "retention purge cannot be rolled back",
            ));
        }
        self.record_audit(
            AuditAction::RetentionApply,
            AuditOutcome::Allowed,
            "retention_rollback_started",
            Severity::Critical,
        )?;
        journal.phase = RetentionPhase::RollingBack;
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;

        let quarantine = if self.policy.quarantine_root().exists() {
            Some(self.policy.quarantine_root().to_path_buf())
        } else if self.stage_path()?.exists() {
            Some(self.stage_path()?)
        } else {
            None
        };
        if let Some(root) = quarantine {
            self.restore_from(&journal, &root)?;
            remove_empty_tree(&root)?;
        }
        journal.phase = RetentionPhase::RolledBack;
        seal_journal(&mut journal)?;
        self.write_journal(&journal)?;
        self.record_audit(
            AuditAction::RetentionApply,
            AuditOutcome::Allowed,
            "retention_rollback_ok",
            Severity::Critical,
        )?;
        Ok(self.status_from(&journal, "retention_rollback_ok"))
    }

    /// Inspect current durable operation state.
    pub fn status(&self) -> JanusResult<RetentionStatus> {
        ensure_private_dir(self.policy.state_root(), false)?;
        let _lock = self.acquire_lock()?;
        self.validate_current_bindings()?;
        let journal = self.read_required_journal()?;
        self.validate_journal(&journal)?;
        Ok(self.status_from(&journal, "retention_status_ok"))
    }

    fn build_plan(
        &self,
        now: SystemTime,
        descriptors: &[SecretDescriptor],
    ) -> JanusResult<RetentionPlan> {
        let (holds, hold_fingerprint) = load_holds(&self.policy)?;
        let active_holds = holds
            .holds()
            .iter()
            .filter(|hold| hold.is_active_at(now))
            .map(|hold| (hold.class(), hold.target_fingerprint().to_string()))
            .collect::<BTreeSet<_>>();
        let now_secs = unix_seconds(now)?;
        let mut entries = Vec::new();
        let mut held_count = 0_u64;
        let mut next_due_at_unix_secs = None;

        let approvals = FileApprovalRegistry::new(self.policy.approval_root()).list()?;
        for approval in approvals {
            let terminal = unix_seconds(approval.expires_at)?;
            let due = terminal
                .checked_add(
                    self.policy
                        .rule(RetentionEvidenceClass::Approvals)
                        .minimum_age_seconds(),
                )
                .ok_or_else(|| retention_invalid("approval retention deadline overflowed"))?;
            if now_secs < due {
                update_next_due(&mut next_due_at_unix_secs, due);
                continue;
            }
            let target = target_fingerprint(
                RetentionEvidenceClass::Approvals,
                approval.approval_id.as_str(),
            );
            if active_holds.contains(&(RetentionEvidenceClass::Approvals, target.clone())) {
                held_count += 1;
                continue;
            }
            let name = format!("{}.json", approval.approval_id.as_str());
            entries.push(self.plan_entry(
                RetentionEvidenceClass::Approvals,
                target,
                terminal,
                &[name],
            )?);
        }

        let delegations = FileDelegationRegistry::new(self.policy.delegation_root()).list()?;
        for delegation in delegations {
            let terminal_time = delegation.revoked_at.unwrap_or(delegation.expires_at);
            let terminal = unix_seconds(terminal_time)?;
            let due = terminal
                .checked_add(
                    self.policy
                        .rule(RetentionEvidenceClass::Delegations)
                        .minimum_age_seconds(),
                )
                .ok_or_else(|| retention_invalid("delegation retention deadline overflowed"))?;
            if now_secs < due {
                update_next_due(&mut next_due_at_unix_secs, due);
                continue;
            }
            let target = target_fingerprint(
                RetentionEvidenceClass::Delegations,
                delegation.delegation_id.as_str(),
            );
            if active_holds.contains(&(RetentionEvidenceClass::Delegations, target.clone())) {
                held_count += 1;
                continue;
            }
            let mut files = vec![format!("{}.json", delegation.delegation_id.as_str())];
            if delegation.revoked_at.is_some() {
                files.push(format!(
                    "{}.revoked.json",
                    delegation.delegation_id.as_str()
                ));
            }
            entries.push(self.plan_entry(
                RetentionEvidenceClass::Delegations,
                target,
                terminal,
                &files,
            )?);
        }

        let descriptor_by_ref = descriptors
            .iter()
            .map(|descriptor| (descriptor.secret_ref.clone(), descriptor))
            .collect::<BTreeMap<_, _>>();
        if descriptors
            .iter()
            .any(|descriptor| descriptor.scope != self.policy.scope_ref())
        {
            return Err(retention_denied(
                "retention_descriptor_scope_mismatch",
                "retention descriptors cross the reviewed scope",
            ));
        }
        let tombstones = FileTombstoneRegistry::new(self.policy.tombstone_root()).list()?;
        let tombstone_by_ref = tombstones
            .iter()
            .map(|record| (record.secret_ref.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let lifecycle =
            FileLifecycleEvidenceRegistry::new(self.policy.lifecycle_evidence_root()).list()?;
        for evidence in lifecycle {
            let Some(descriptor) = descriptor_by_ref.get(&evidence.secret_ref) else {
                continue;
            };
            let Some(tombstone) = tombstone_by_ref.get(&evidence.secret_ref) else {
                continue;
            };
            if descriptor.lifecycle != SecretLifecycle::Destroyed || now < tombstone.retain_until {
                continue;
            }
            let Some(terminal_time) = [
                evidence.declared_at,
                evidence.last_used_at,
                evidence.last_rotated_at,
            ]
            .into_iter()
            .flatten()
            .max() else {
                continue;
            };
            let terminal = unix_seconds(terminal_time)?;
            let due = terminal
                .checked_add(
                    self.policy
                        .rule(RetentionEvidenceClass::LifecycleEvidence)
                        .minimum_age_seconds(),
                )
                .ok_or_else(|| retention_invalid("lifecycle retention deadline overflowed"))?;
            if now_secs < due {
                update_next_due(&mut next_due_at_unix_secs, due);
                continue;
            }
            let target = target_fingerprint(
                RetentionEvidenceClass::LifecycleEvidence,
                evidence.secret_ref.as_str(),
            );
            if active_holds.contains(&(RetentionEvidenceClass::LifecycleEvidence, target.clone())) {
                held_count += 1;
                continue;
            }
            entries.push(self.plan_entry(
                RetentionEvidenceClass::LifecycleEvidence,
                target,
                terminal,
                &[format!("{}.json", evidence.secret_ref.as_str())],
            )?);
        }

        entries.sort();
        if entries.len() as u64 > self.policy.maximum_records() {
            return Err(retention_denied(
                "retention_limit_exceeded",
                "retention eligible record limit was exceeded",
            ));
        }
        let total_bytes = entries
            .iter()
            .flat_map(|entry| &entry.files)
            .try_fold(0_u64, |total, file| total.checked_add(file.bytes))
            .ok_or_else(|| retention_invalid("retention byte total overflowed"))?;
        if total_bytes > self.policy.maximum_bytes() {
            return Err(retention_denied(
                "retention_limit_exceeded",
                "retention eligible byte limit was exceeded",
            ));
        }
        let source_fingerprint = source_inventory_fingerprint(&self.policy)?;
        let quarantine_fingerprint = fingerprint_json("janus-retention-quarantine-v1", &entries)?;
        Ok(RetentionPlan {
            source_fingerprint,
            quarantine_fingerprint,
            hold_fingerprint,
            entries,
            held_count,
            protected_count: 5,
            total_bytes,
            next_due_at_unix_secs,
        })
    }

    fn plan_entry(
        &self,
        class: RetentionEvidenceClass,
        target_fingerprint: String,
        terminal_at_unix_secs: u64,
        names: &[String],
    ) -> JanusResult<RetentionPlanEntry> {
        let mut files = Vec::new();
        for name in names {
            if !safe_file_name(name) {
                return Err(retention_invalid("retention record name is invalid"));
            }
            let path = self.source_file(class, name)?;
            let bytes = read_private_bytes(&path, MAX_RECORD_BYTES)?;
            files.push(RetentionPlanFile {
                name: name.clone(),
                bytes: bytes.len() as u64,
                fingerprint: fingerprint_bytes(&bytes),
            });
        }
        files.sort();
        Ok(RetentionPlanEntry {
            class,
            target_fingerprint,
            terminal_at_unix_secs,
            files,
        })
    }

    fn source_file(&self, class: RetentionEvidenceClass, name: &str) -> JanusResult<PathBuf> {
        if !safe_file_name(name) {
            return Err(retention_invalid("retention record name is invalid"));
        }
        let root = match class {
            RetentionEvidenceClass::Approvals => self.policy.approval_root(),
            RetentionEvidenceClass::Delegations => self.policy.delegation_root(),
            RetentionEvidenceClass::LifecycleEvidence => self.policy.lifecycle_evidence_root(),
            _ => {
                return Err(retention_denied(
                    "retention_class_protected",
                    "protected retention class has no purge source",
                ))
            }
        };
        Ok(root.join(name))
    }

    fn verify_quarantine(
        &self,
        journal: &RetentionJournal,
        allow_missing: bool,
    ) -> JanusResult<()> {
        let root = self.policy.quarantine_root();
        if !root.exists() {
            return if allow_missing {
                Ok(())
            } else {
                Err(retention_denied(
                    "retention_quarantine_missing",
                    "retention quarantine is missing",
                ))
            };
        }
        check_private_dir(root)?;
        let expected = journal
            .entries
            .iter()
            .flat_map(|entry| {
                entry
                    .files
                    .iter()
                    .map(move |file| ((entry.class.as_str().to_string(), file.name.clone()), file))
            })
            .collect::<BTreeMap<_, _>>();
        let mut found = BTreeSet::new();
        for class_entry in fs::read_dir(root)
            .map_err(|_| retention_invalid("retention quarantine could not be listed"))?
        {
            let class_entry = class_entry
                .map_err(|_| retention_invalid("retention quarantine entry is unavailable"))?;
            let class_name = class_entry
                .file_name()
                .to_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| retention_invalid("retention quarantine class is invalid"))?;
            check_private_dir(&class_entry.path())?;
            for file_entry in fs::read_dir(class_entry.path())
                .map_err(|_| retention_invalid("retention quarantine class is unavailable"))?
            {
                let file_entry = file_entry
                    .map_err(|_| retention_invalid("retention quarantine file is unavailable"))?;
                let name = file_entry
                    .file_name()
                    .to_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| retention_invalid("retention quarantine file is invalid"))?;
                let key = (class_name.clone(), name.clone());
                let Some(expected_file) = expected.get(&key) else {
                    return Err(retention_denied(
                        "retention_quarantine_tampered",
                        "retention quarantine contains unsupported state",
                    ));
                };
                let bytes = read_private_bytes(&file_entry.path(), MAX_RECORD_BYTES)?;
                if bytes.len() as u64 != expected_file.bytes
                    || fingerprint_bytes(&bytes) != expected_file.fingerprint
                    || !found.insert(key)
                {
                    return Err(retention_denied(
                        "retention_quarantine_tampered",
                        "retention quarantine record failed integrity checks",
                    ));
                }
            }
        }
        if !allow_missing && found.len() != expected.len() {
            return Err(retention_denied(
                "retention_quarantine_tampered",
                "retention quarantine is incomplete",
            ));
        }
        Ok(())
    }

    fn restore_from(&self, journal: &RetentionJournal, root: &Path) -> JanusResult<()> {
        for entry in &journal.entries {
            for file in &entry.files {
                let quarantined = root.join(entry.class.as_str()).join(&file.name);
                if !quarantined.exists() {
                    continue;
                }
                let bytes = read_private_bytes(&quarantined, MAX_RECORD_BYTES)?;
                if bytes.len() as u64 != file.bytes || fingerprint_bytes(&bytes) != file.fingerprint
                {
                    return Err(retention_denied(
                        "retention_quarantine_tampered",
                        "retention rollback record failed integrity checks",
                    ));
                }
                let source = self.source_file(entry.class, &file.name)?;
                reject_existing(&source)?;
                fs::rename(&quarantined, &source).map_err(|_| {
                    retention_denied(
                        "retention_rollback_failed",
                        "retention rollback could not restore a record",
                    )
                })?;
                sync_parent(&source)?;
            }
        }
        Ok(())
    }

    fn purge_remaining(&self, journal: &RetentionJournal) -> JanusResult<()> {
        let root = self.policy.quarantine_root();
        if !root.exists() {
            return Ok(());
        }
        for entry in &journal.entries {
            for file in &entry.files {
                let source = self.source_file(entry.class, &file.name)?;
                if source.exists() {
                    return Err(retention_denied(
                        "retention_source_collision",
                        "retention source was recreated before purge",
                    ));
                }
                let quarantined = root.join(entry.class.as_str()).join(&file.name);
                match fs::remove_file(&quarantined) {
                    Ok(()) => sync_parent(&quarantined)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        return Err(retention_denied(
                            "retention_purge_failed",
                            "retention quarantine record could not be purged",
                        ))
                    }
                }
            }
        }
        remove_empty_tree(root)
    }

    fn validate_static_paths(&self) -> JanusResult<()> {
        let mut paths = vec![
            self.policy.approval_root().to_path_buf(),
            self.policy.delegation_root().to_path_buf(),
            self.policy.lifecycle_evidence_root().to_path_buf(),
            self.policy.metadata_overlay_path().to_path_buf(),
            self.policy.tombstone_root().to_path_buf(),
            self.policy.audit_path().to_path_buf(),
            self.policy.recovery_evidence_path().to_path_buf(),
            self.policy.admin_evidence_root().to_path_buf(),
            self.policy.hold_registry_path().to_path_buf(),
            self.policy.quarantine_root().to_path_buf(),
            self.policy.state_root().to_path_buf(),
            self.policy.operation_audit_path().to_path_buf(),
            self.policy.evidence_path().to_path_buf(),
        ];
        paths.extend(
            self.policy
                .config_bindings()
                .iter()
                .filter(|binding| binding.path() != self.policy.metadata_overlay_path())
                .map(|binding| binding.path().to_path_buf()),
        );
        let resolved = paths
            .iter()
            .map(|path| resolve_existing_prefix(path))
            .collect::<JanusResult<Vec<_>>>()?;
        for (index, left) in resolved.iter().enumerate() {
            for right in resolved.iter().skip(index + 1) {
                if left == right || left.starts_with(right) || right.starts_with(left) {
                    return Err(retention_denied(
                        "retention_path_overlap",
                        "retention paths must be non-overlapping",
                    ));
                }
            }
        }
        for path in &paths {
            if owner_id_of_existing_prefix(path)? != self.reviewed_owner {
                return Err(retention_denied(
                    "retention_path_owner_mismatch",
                    "retention paths do not match the reviewed owner",
                ));
            }
        }
        for root in [
            self.policy.approval_root(),
            self.policy.delegation_root(),
            self.policy.lifecycle_evidence_root(),
            self.policy.tombstone_root(),
            self.policy.admin_evidence_root(),
        ] {
            check_private_dir(root)?;
        }
        for file in [
            self.policy.metadata_overlay_path(),
            self.policy.audit_path(),
            self.policy.hold_registry_path(),
        ] {
            let _ = read_private_bytes(file, MAX_POLICY_BYTES)?;
        }
        for output in [
            self.policy.quarantine_root(),
            self.policy.state_root(),
            self.policy.operation_audit_path(),
            self.policy.evidence_path(),
            self.policy.recovery_evidence_path(),
        ] {
            let parent = output
                .parent()
                .ok_or_else(|| retention_invalid("retention output has no parent"))?;
            check_private_dir(parent)?;
        }
        validate_same_filesystem(&[
            self.policy.approval_root(),
            self.policy.delegation_root(),
            self.policy.lifecycle_evidence_root(),
            self.policy.quarantine_root(),
        ])?;
        Ok(())
    }

    fn validate_current_bindings(&self) -> JanusResult<()> {
        self.validate_release()?;
        if validate_config_bindings(&self.policy)? != self.config_fingerprint {
            return Err(retention_denied(
                "retention_config_changed",
                "retention configuration changed after policy load",
            ));
        }
        Ok(())
    }

    fn validate_release(&self) -> JanusResult<()> {
        if !self.release.allows_secret_use()
            || (self.release.mode().requires_trusted_release()
                && self.release.decision() != ReleaseAdmissionDecision::Trusted)
        {
            return Err(retention_denied(
                "retention_release_untrusted",
                "retention requires an admitted runtime release",
            ));
        }
        if release_artifact(&self.release) != self.policy.release_artifact() {
            return Err(retention_denied(
                "retention_release_mismatch",
                "retention policy does not match the admitted release",
            ));
        }
        Ok(())
    }

    fn validate_release_binding(&self, journal: &RetentionJournal) -> JanusResult<()> {
        if journal.release_mode != self.release.mode().as_str()
            || journal.release_policy_id.as_deref() != self.release.policy_id()
            || journal.release_policy_version != self.release.policy_version()
            || journal.release_artifact_id.as_deref() != self.release.artifact_id()
        {
            return Err(retention_denied(
                "retention_release_changed",
                "release posture changed during retention",
            ));
        }
        Ok(())
    }

    fn validate_preflight_age(
        &self,
        journal: &RetentionJournal,
        now: SystemTime,
    ) -> JanusResult<()> {
        let age = unix_seconds(now)?
            .checked_sub(journal.evaluated_at_unix_secs)
            .ok_or_else(|| {
                retention_denied(
                    "retention_preflight_stale",
                    "retention clock moved behind preflight",
                )
            })?;
        if age > self.policy.preflight_max_age_seconds() {
            return Err(retention_denied(
                "retention_preflight_stale",
                "retention preflight is stale",
            ));
        }
        Ok(())
    }

    fn acquire_lock(&self) -> JanusResult<RetentionLock> {
        let path = self.policy.state_root().join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| {
            retention_denied(
                "retention_lock_unavailable",
                "retention lock is unavailable",
            )
        })?;
        set_file_private(&file)?;
        file.try_lock_exclusive().map_err(|_| {
            retention_denied(
                "retention_concurrent",
                "another retention operation holds the lock",
            )
        })?;
        Ok(RetentionLock(file))
    }

    fn read_journal(&self) -> JanusResult<Option<RetentionJournal>> {
        let path = self.journal_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => read_private_json(&path, MAX_STATE_BYTES).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(retention_invalid("retention journal is unavailable")),
        }
    }

    fn read_required_journal(&self) -> JanusResult<RetentionJournal> {
        self.read_journal()?.ok_or_else(|| {
            retention_denied(
                "retention_preflight_missing",
                "retention operation has no preflight journal",
            )
        })
    }

    fn validate_journal(&self, journal: &RetentionJournal) -> JanusResult<()> {
        if journal.version != JOURNAL_VERSION
            || journal.operation_id != self.policy.operation_id()
            || journal.policy_fingerprint != self.policy_fingerprint
            || journal.config_fingerprint != self.config_fingerprint
            || !valid_sha256(&journal.hold_fingerprint)
            || !valid_sha256(&journal.source_fingerprint)
            || !valid_sha256(&journal.quarantine_fingerprint)
            || journal.entries.len() as u64 > self.policy.maximum_records()
            || journal.total_bytes > self.policy.maximum_bytes()
            || !valid_sha256(&journal.integrity)
            || expected_journal_integrity(journal)? != journal.integrity
        {
            return Err(retention_denied(
                "retention_journal_invalid",
                "retention journal failed integrity or policy binding",
            ));
        }
        self.validate_release_binding(journal)
    }

    fn write_journal(&self, journal: &RetentionJournal) -> JanusResult<()> {
        write_private_json_atomic(&self.journal_path(), journal)
    }

    fn journal_path(&self) -> PathBuf {
        self.policy.state_root().join(JOURNAL_FILE)
    }

    fn stage_path(&self) -> JanusResult<PathBuf> {
        Ok(self
            .policy
            .quarantine_root()
            .parent()
            .ok_or_else(|| retention_invalid("retention quarantine has no parent"))?
            .join(format!(
                ".janus-retention-{}-stage",
                self.policy.operation_id()
            )))
    }

    fn record_audit(
        &self,
        action: AuditAction,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
    ) -> JanusResult<()> {
        let mut audit = JsonlAuditSink::open(self.policy.operation_audit_path())?;
        audit.record(
            AuditEvent::new(
                action,
                outcome,
                reason_code,
                severity,
                None,
                &self.principal,
            )
            .with_evidence(SafeLabel::new(format!(
                "operation={};scope={}",
                self.policy.operation_id(),
                self.policy.scope_ref().as_str()
            ))?),
        )
    }

    fn record_completion_audit(&self) -> JanusResult<(u64, String)> {
        let mut audit = JsonlAuditSink::open(self.policy.operation_audit_path())?;
        audit.record(
            AuditEvent::new(
                AuditAction::RetentionExpire,
                AuditOutcome::Allowed,
                "retention_purge_ok",
                Severity::Critical,
                None,
                &self.principal,
            )
            .with_evidence(SafeLabel::new(format!(
                "operation={};scope={}",
                self.policy.operation_id(),
                self.policy.scope_ref().as_str()
            ))?),
        )?;
        Ok((audit.last_sequence(), audit.last_event_hash().to_string()))
    }

    fn verify_completed_evidence(
        &self,
        journal: &RetentionJournal,
        now: SystemTime,
    ) -> JanusResult<()> {
        let text = read_reviewed_text(self.policy.evidence_path(), MAX_STATE_BYTES)?;
        let evidence = RetentionEvidenceV1::parse_json(&text)?;
        if journal.completed_at_unix_secs.is_none() {
            return Err(retention_denied(
                "retention_journal_invalid",
                "completed retention journal has no completion timestamp",
            ));
        }
        let hold_fingerprint = load_holds(&self.policy)?.1;
        let source_fingerprint = source_inventory_fingerprint(&self.policy)?;
        evidence.verify_current(
            &self.policy,
            self.policy.release_artifact(),
            &self.config_fingerprint,
            &hold_fingerprint,
            &source_fingerprint,
            &self.policy_fingerprint,
            now,
        )?;
        Ok(())
    }

    fn status_from(
        &self,
        journal: &RetentionJournal,
        reason_code: &'static str,
    ) -> RetentionStatus {
        RetentionStatus {
            operation_id: journal.operation_id.clone(),
            phase: journal.phase.as_str().to_string(),
            scope_ref: self.policy.scope_ref().as_str().to_string(),
            policy_fingerprint: journal.policy_fingerprint.clone(),
            config_fingerprint: journal.config_fingerprint.clone(),
            hold_fingerprint: journal.hold_fingerprint.clone(),
            source_fingerprint: journal.source_fingerprint.clone(),
            quarantine_fingerprint: journal.quarantine_fingerprint.clone(),
            eligible_count: journal.entries.len() as u64,
            held_count: journal.held_count,
            protected_count: journal.protected_count,
            next_due_at_unix_secs: journal.next_due_at_unix_secs.unwrap_or(0),
            reason_code,
            value_returned: false,
        }
    }
}

/// Enforce optional retention evidence on normal runtime startup.
pub fn enforce_retention_ready_from_env(
    release: &ReleaseAdmission,
    scope: &janus_core::ScopeRef,
) -> JanusResult<()> {
    let policy_path = env::var_os("JANUS_RETENTION_POLICY").filter(|value| !value.is_empty());
    let evidence_path = env::var_os("JANUS_RETENTION_EVIDENCE").filter(|value| !value.is_empty());
    match (policy_path, evidence_path) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(retention_denied(
            "retention_evidence_missing",
            "retention readiness requires policy and evidence",
        )),
        (Some(policy), Some(evidence)) => enforce_retention_ready(
            Path::new(&policy),
            Path::new(&evidence),
            release,
            scope,
            SystemTime::now(),
        ),
    }
}

/// Verify exact current retention completion evidence.
pub fn enforce_retention_ready(
    policy_path: &Path,
    evidence_path: &Path,
    release: &ReleaseAdmission,
    scope: &janus_core::ScopeRef,
    now: SystemTime,
) -> JanusResult<()> {
    let policy_text = read_reviewed_text(policy_path, MAX_POLICY_BYTES)?;
    let policy = RetentionPolicyV1::parse_json(&policy_text)?;
    if &policy.scope_ref() != scope || policy.release_artifact() != release_artifact(release) {
        return Err(retention_denied(
            "retention_evidence_mismatch",
            "retention readiness does not match scope or release",
        ));
    }
    let config_fingerprint = validate_config_bindings(&policy)?;
    let hold_fingerprint = load_holds(&policy)?.1;
    let source_fingerprint = source_inventory_fingerprint(&policy)?;
    let policy_fingerprint =
        fingerprint_domain("janus-retention-policy-v1", policy_text.as_bytes());
    let evidence_text = read_reviewed_text(evidence_path, MAX_STATE_BYTES)?;
    let evidence = RetentionEvidenceV1::parse_json(&evidence_text)?;
    evidence.verify_current(
        &policy,
        policy.release_artifact(),
        &config_fingerprint,
        &hold_fingerprint,
        &source_fingerprint,
        &policy_fingerprint,
        now,
    )
}

fn load_holds(policy: &RetentionPolicyV1) -> JanusResult<(RetentionHoldRegistryV1, String)> {
    let bytes = read_reviewed_bytes(policy.hold_registry_path(), MAX_POLICY_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| retention_invalid("retention hold registry is not UTF-8"))?;
    let holds = RetentionHoldRegistryV1::parse_json(text, &policy.scope_ref())?;
    Ok((holds, fingerprint_bytes(&bytes)))
}

fn validate_config_bindings(policy: &RetentionPolicyV1) -> JanusResult<String> {
    let mut bindings = BTreeMap::new();
    for binding in policy.config_bindings() {
        let bytes = read_reviewed_bytes(binding.path(), MAX_POLICY_BYTES)?;
        let fingerprint = fingerprint_bytes(&bytes);
        if fingerprint != binding.expected_fingerprint() {
            return Err(retention_denied(
                "retention_config_mismatch",
                "retention config does not match reviewed fingerprint",
            ));
        }
        bindings.insert(binding.name().to_string(), fingerprint);
    }
    fingerprint_json("janus-retention-config-v1", &bindings)
}

fn source_inventory_fingerprint(policy: &RetentionPolicyV1) -> JanusResult<String> {
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    for (class, root) in [
        (RetentionEvidenceClass::Approvals, policy.approval_root()),
        (
            RetentionEvidenceClass::Delegations,
            policy.delegation_root(),
        ),
        (
            RetentionEvidenceClass::LifecycleEvidence,
            policy.lifecycle_evidence_root(),
        ),
    ] {
        check_private_dir(root)?;
        let mut children = fs::read_dir(root)
            .map_err(|_| retention_invalid("retention source could not be listed"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| retention_invalid("retention source entry is unavailable"))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let name = child
                .file_name()
                .to_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| retention_invalid("retention source name is invalid"))?;
            if !valid_source_name(class, &name) {
                return Err(retention_denied(
                    "retention_source_invalid",
                    "retention source contains an unsupported entry",
                ));
            }
            let bytes = read_private_bytes(&child.path(), MAX_RECORD_BYTES)?;
            total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| retention_invalid("retention source byte total overflowed"))?;
            if total_bytes > policy.maximum_bytes() {
                return Err(retention_denied(
                    "retention_limit_exceeded",
                    "retention source byte limit was exceeded",
                ));
            }
            entries.push((
                class.as_str().to_string(),
                name,
                bytes.len() as u64,
                fingerprint_bytes(&bytes),
            ));
            if entries.len() as u64 > policy.maximum_records() * 2 {
                return Err(retention_denied(
                    "retention_limit_exceeded",
                    "retention source record limit was exceeded",
                ));
            }
        }
    }
    fingerprint_json("janus-retention-source-v1", &entries)
}

fn valid_source_name(class: RetentionEvidenceClass, name: &str) -> bool {
    match class {
        RetentionEvidenceClass::Approvals => {
            name == ".janus-schema"
                || name
                    .strip_suffix(".json")
                    .is_some_and(|id| super::validate_approval_file_token(id).is_ok())
        }
        RetentionEvidenceClass::Delegations => {
            let id = name
                .strip_suffix(".revoked.json")
                .or_else(|| name.strip_suffix(".json"));
            id.is_some_and(|id| janus_core::DelegationId::from_opaque(id.to_string()).is_ok())
        }
        RetentionEvidenceClass::LifecycleEvidence => name
            .strip_suffix(".json")
            .is_some_and(|secret_ref| janus_core::SecretRef::new(secret_ref).is_ok()),
        _ => false,
    }
}

fn seal_journal(journal: &mut RetentionJournal) -> JanusResult<()> {
    journal.integrity.clear();
    journal.integrity = expected_journal_integrity(journal)?;
    Ok(())
}

fn expected_journal_integrity(journal: &RetentionJournal) -> JanusResult<String> {
    let mut value = serde_json::to_value(journal)
        .map_err(|_| retention_invalid("retention journal could not be encoded"))?;
    value["integrity"] = serde_json::Value::String(String::new());
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| retention_invalid("retention journal could not be encoded"))?;
    Ok(fingerprint_domain("janus-retention-journal-v1", &bytes))
}

fn target_fingerprint(class: RetentionEvidenceClass, target: &str) -> String {
    fingerprint_domain(
        "janus-retention-target-v1",
        format!("{}\0{target}", class.as_str()).as_bytes(),
    )
}

fn update_next_due(current: &mut Option<u64>, candidate: u64) {
    *current = Some(current.map_or(candidate, |existing| existing.min(candidate)));
}

fn fingerprint_json<T: Serialize>(domain: &str, value: &T) -> JanusResult<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| retention_invalid("retention state could not be canonicalized"))?;
    Ok(fingerprint_domain(domain, &bytes))
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
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| retention_invalid("retention clock is invalid"))
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !name.starts_with('.')
        && !name.contains("..")
}

fn read_reviewed_text(path: &Path, max_bytes: u64) -> JanusResult<String> {
    String::from_utf8(read_reviewed_bytes(path, max_bytes)?)
        .map_err(|_| retention_invalid("reviewed retention file is not UTF-8"))
}

fn read_reviewed_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    read_private_bytes(path, max_bytes)
}

fn read_private_bytes(path: &Path, max_bytes: u64) -> JanusResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| retention_invalid("private retention file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(retention_denied(
            "retention_insecure_path",
            "private retention file is insecure or oversized",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(retention_denied(
                "retention_insecure_path",
                "private retention file permissions are too broad",
            ));
        }
    }
    let file =
        File::open(path).map_err(|_| retention_invalid("private retention file is unavailable"))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| retention_invalid("private retention file could not be read"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(retention_denied(
            "retention_limit_exceeded",
            "private retention file exceeded the byte limit",
        ));
    }
    Ok(bytes)
}

fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path, max_bytes: u64) -> JanusResult<T> {
    let bytes = read_private_bytes(path, max_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| retention_invalid("private retention JSON is malformed"))
}

fn write_private_json_atomic<T: Serialize>(path: &Path, value: &T) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| retention_invalid("private retention JSON could not be encoded"))?;
    let parent = path
        .parent()
        .ok_or_else(|| retention_invalid("private retention JSON has no parent"))?;
    ensure_private_dir(parent, true)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| retention_invalid("private retention JSON name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| retention_invalid("retention clock is invalid"))?
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
        .map_err(|_| retention_invalid("private retention temp could not be created"))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| retention_invalid("private retention JSON could not be persisted"))?;
    fs::rename(&temp, path)
        .map_err(|_| retention_invalid("private retention JSON could not be installed"))?;
    sync_dir(parent)
}

fn ensure_private_dir(path: &Path, create: bool) -> JanusResult<()> {
    if create {
        fs::create_dir_all(path)
            .map_err(|_| retention_invalid("private retention directory is unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                retention_invalid("private retention directory permissions are unavailable")
            })?;
        }
    }
    check_private_dir(path)
}

fn create_private_dir(path: &Path) -> JanusResult<()> {
    if path.exists() {
        return Err(retention_denied(
            "retention_work_exists",
            "retention work path already exists",
        ));
    }
    ensure_private_dir(path, true)
}

fn check_private_dir(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| retention_invalid("private retention directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(retention_denied(
            "retention_insecure_path",
            "retention directory is not a private regular directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(retention_denied(
                "retention_insecure_path",
                "retention directory permissions are too broad",
            ));
        }
    }
    Ok(())
}

fn reject_existing(path: &Path) -> JanusResult<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(retention_denied(
            "retention_work_exists",
            "retention create-new path already exists",
        ));
    }
    Ok(())
}

fn remove_empty_tree(root: &Path) -> JanusResult<()> {
    if !root.exists() {
        return Ok(());
    }
    check_private_dir(root)?;
    let mut dirs = fs::read_dir(root)
        .map_err(|_| retention_invalid("retention tree could not be listed"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| retention_invalid("retention tree entry is unavailable"))?;
    dirs.sort_by_key(|entry| entry.file_name());
    for entry in dirs {
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| retention_invalid("retention tree entry is unavailable"))?;
        if metadata.is_dir() {
            remove_empty_tree(&entry.path())?;
        } else {
            return Err(retention_denied(
                "retention_work_not_empty",
                "retention work tree contains unexpected files",
            ));
        }
    }
    fs::remove_dir(root)
        .map_err(|_| retention_invalid("empty retention work directory could not be removed"))?;
    sync_parent(root)
}

fn sync_tree(path: &Path) -> JanusResult<()> {
    for entry in fs::read_dir(path)
        .map_err(|_| retention_invalid("retention tree could not be synchronized"))?
    {
        let path = entry
            .map_err(|_| retention_invalid("retention tree entry is unavailable"))?
            .path();
        if fs::symlink_metadata(&path)
            .map_err(|_| retention_invalid("retention tree entry is unavailable"))?
            .is_dir()
        {
            sync_tree(&path)?;
        }
    }
    sync_dir(path)
}

fn sync_dir(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| retention_invalid("retention directory could not be synchronized"))
}

fn sync_parent(path: &Path) -> JanusResult<()> {
    sync_dir(path.parent().unwrap_or_else(|| Path::new("/")))
}

fn set_file_private(file: &File) -> JanusResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| retention_invalid("retention lock permissions are unavailable"))?;
    }
    Ok(())
}

fn resolve_existing_prefix(path: &Path) -> JanusResult<PathBuf> {
    let mut existing = path;
    let mut suffix = Vec::<OsString>::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    existing
                        .file_name()
                        .ok_or_else(|| retention_invalid("retention path has no prefix"))?
                        .to_os_string(),
                );
                existing = existing
                    .parent()
                    .ok_or_else(|| retention_invalid("retention path has no prefix"))?;
            }
            Err(_) => return Err(retention_invalid("retention path could not be resolved")),
        }
    }
    let mut resolved = fs::canonicalize(existing)
        .map_err(|_| retention_invalid("retention path could not be resolved"))?;
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
        .map_err(|_| retention_invalid("retention path owner is unavailable"))
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
                    .ok_or_else(|| retention_invalid("retention path owner is unavailable"))?;
            }
            Err(_) => return Err(retention_invalid("retention path owner is unavailable")),
        }
    }
}

#[cfg(unix)]
fn validate_same_filesystem(paths: &[&Path]) -> JanusResult<()> {
    use std::os::unix::fs::MetadataExt;
    let expected = metadata_of_existing_prefix(paths[0])?.dev();
    if paths
        .iter()
        .skip(1)
        .map(|path| metadata_of_existing_prefix(path))
        .collect::<JanusResult<Vec<_>>>()?
        .iter()
        .any(|metadata| metadata.dev() != expected)
    {
        return Err(retention_denied(
            "retention_filesystem_mismatch",
            "retention roots must share one filesystem",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_filesystem(_paths: &[&Path]) -> JanusResult<()> {
    Ok(())
}

fn metadata_of_existing_prefix(path: &Path) -> JanusResult<fs::Metadata> {
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) => return Ok(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = current
                    .parent()
                    .ok_or_else(|| retention_invalid("retention path prefix is unavailable"))?;
            }
            Err(_) => return Err(retention_invalid("retention path prefix is unavailable")),
        }
    }
}

fn retention_invalid(detail: &'static str) -> JanusError {
    JanusError::InvalidManifest {
        detail: detail.to_string(),
    }
}

fn retention_denied(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        ApprovalGrant, AuditWrite, DelegationPolicy, Destination, EgressMode, ExecutorRef,
        OwnerRef, Principal, PrincipalId, PrincipalKind, ProductMode, ProfileId, ProfilePolicy,
        Purpose, SecretClass, SecretLifecycle, SecretName, SecretRef, SecretTombstoneRequest,
        TombstonePolicy, TrustLevel, UseProfile, UseRequest,
    };
    use std::time::Duration;
    use tempfile::tempdir;

    struct Fixture {
        _temp: tempfile::TempDir,
        policy_path: PathBuf,
        approval_root: PathBuf,
        delegation_root: PathBuf,
        lifecycle_root: PathBuf,
        tombstone_root: PathBuf,
        audit_path: PathBuf,
        config_path: PathBuf,
        holds_path: PathBuf,
        quarantine_root: PathBuf,
        evidence_path: PathBuf,
        descriptors: Vec<SecretDescriptor>,
        principal: PrincipalChain,
        expired_approval: String,
        active_approval: String,
        expired_delegation: String,
        held_delegation: String,
        destroyed_ref: SecretRef,
        scope: janus_core::ScopeRef,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempdir().unwrap();
            let root = temp.path();
            private_dir(root);
            let approval_root = root.join("approvals");
            let delegation_root = root.join("delegations");
            let lifecycle_root = root.join("lifecycle");
            let tombstone_root = root.join("tombstones");
            let admin_root = root.join("admin");
            let protected_root = root.join("protected");
            let operation_root = root.join("operation");
            for path in [
                &approval_root,
                &delegation_root,
                &lifecycle_root,
                &tombstone_root,
                &admin_root,
                &protected_root,
                &operation_root,
            ] {
                private_dir(path);
            }
            private_file(
                &admin_root.join("terminal.json"),
                br#"{"phase":"completed"}"#,
            );

            let scope = janus_core::ScopePathV1::for_repository(
                "fixture-org",
                "janus",
                "janus",
                "retention",
            )
            .unwrap()
            .scope_ref();
            let principal = PrincipalChain::new(
                Principal::new(
                    PrincipalKind::Executor,
                    PrincipalId::new("runner-retention").unwrap(),
                ),
                scope.clone(),
            );
            let mut delegate = principal.clone();
            delegate.human = Some(Principal::new(
                PrincipalKind::Human,
                PrincipalId::new("retention-delegate").unwrap(),
            ));
            let audit_path = root.join("audit.jsonl");
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

            let profile_id = ProfileId::new("profile.retention").unwrap();
            let executor = ExecutorRef::new("runner-retention").unwrap();
            let destination = Destination::new("retention-target").unwrap();
            let active_ref = SecretRef::new("sec_retention_active").unwrap();
            let destroyed_ref = SecretRef::new("sec_retention_destroyed").unwrap();
            let profile = UseProfile {
                id: profile_id.clone(),
                secret_ref: active_ref.clone(),
                scope: scope.clone(),
                executor: executor.clone(),
                destination: destination.clone(),
                egress: EgressMode::Connector,
                trust_level: TrustLevel::L2,
                ttl: Duration::from_secs(60),
                single_use: true,
                enabled: true,
            };
            let request = UseRequest {
                secret_ref: active_ref.clone(),
                scope: scope.clone(),
                profile_id: profile_id.clone(),
                destination: destination.clone(),
                purpose: Purpose::new("retention fixture").unwrap(),
            };
            let descriptor_active = SecretDescriptor {
                name: SecretName::new("ACTIVE").unwrap(),
                secret_ref: active_ref.clone(),
                label: SafeLabel::new("Active fixture").unwrap(),
                scope: scope.clone(),
                owner: Some(OwnerRef::new("security").unwrap()),
                classification: Some(SecretClass::Normal),
                lifecycle: SecretLifecycle::Active,
                required: true,
                trust_level: TrustLevel::L2,
                allowed_uses: vec![profile_id.clone()],
                present: true,
            };
            let descriptor_destroyed = SecretDescriptor {
                name: SecretName::new("DESTROYED").unwrap(),
                secret_ref: destroyed_ref.clone(),
                label: SafeLabel::new("Destroyed fixture").unwrap(),
                scope: scope.clone(),
                owner: Some(OwnerRef::new("security").unwrap()),
                classification: Some(SecretClass::Normal),
                lifecycle: SecretLifecycle::Destroyed,
                required: false,
                trust_level: TrustLevel::L2,
                allowed_uses: vec![],
                present: false,
            };

            let approvals = FileApprovalRegistry::new(&approval_root);
            let expired = ApprovalGrant::for_request(
                &request,
                &profile,
                SecretClass::Normal,
                UNIX_EPOCH + Duration::from_secs(100),
                SafeLabel::new("expired approval").unwrap(),
            );
            approvals.store(&expired).unwrap();
            let active = ApprovalGrant::for_request(
                &request,
                &profile,
                SecretClass::Normal,
                UNIX_EPOCH + Duration::from_secs(2_000),
                SafeLabel::new("active approval").unwrap(),
            );
            approvals.store(&active).unwrap();

            let delegation_registry = FileDelegationRegistry::new(&delegation_root);
            let expired_delegation = DelegationPolicy::issue_use(
                &ProfilePolicy::new(vec![profile.clone()]),
                &descriptor_active,
                &request,
                &principal,
                &delegate,
                None,
                UNIX_EPOCH + Duration::from_secs(10),
                UNIX_EPOCH + Duration::from_secs(100),
                SafeLabel::new("expired delegation").unwrap(),
                &mut AuditWrite::accepting(),
            )
            .unwrap();
            delegation_registry.store(&expired_delegation).unwrap();
            let held_delegation = DelegationPolicy::issue_use(
                &ProfilePolicy::new(vec![profile]),
                &descriptor_active,
                &UseRequest {
                    purpose: Purpose::new("held delegation").unwrap(),
                    ..request
                },
                &principal,
                &delegate,
                None,
                UNIX_EPOCH + Duration::from_secs(20),
                UNIX_EPOCH + Duration::from_secs(110),
                SafeLabel::new("held delegation").unwrap(),
                &mut AuditWrite::accepting(),
            )
            .unwrap();
            delegation_registry.store(&held_delegation).unwrap();

            let lifecycle = FileLifecycleEvidenceRegistry::new(&lifecycle_root);
            lifecycle
                .record_declared(&destroyed_ref, UNIX_EPOCH + Duration::from_secs(50))
                .unwrap();
            lifecycle
                .record_declared(&active_ref, UNIX_EPOCH + Duration::from_secs(50))
                .unwrap();
            let tombstones = FileTombstoneRegistry::new(&tombstone_root);
            let pending = SecretDescriptor {
                lifecycle: SecretLifecycle::PendingDelete,
                ..descriptor_destroyed.clone()
            };
            let tombstone = TombstonePolicy::record(
                &pending,
                SecretTombstoneRequest::new(
                    destroyed_ref.clone(),
                    SafeLabel::new("fixture destroyed").unwrap(),
                    UNIX_EPOCH + Duration::from_secs(60),
                    UNIX_EPOCH + Duration::from_secs(200),
                ),
                &principal,
                &mut AuditWrite::accepting(),
            )
            .unwrap();
            tombstones.record(&tombstone, &principal).unwrap();

            let config_path = root.join("metadata.toml");
            private_file(
                &config_path,
                b"[[secrets]]\nname = \"DESTROYED\"\nlifecycle = \"destroyed\"\n",
            );
            let holds_path = root.join("holds.json");
            let held_target = target_fingerprint(
                RetentionEvidenceClass::Delegations,
                held_delegation.id().as_str(),
            );
            let holds = serde_json::json!({
                "schema_version": 1,
                "scope_ref": scope.as_str(),
                "holds": [{
                    "schema_version": 1,
                    "hold_id": "fixture-hold",
                    "scope_ref": scope.as_str(),
                    "class": "delegations",
                    "target_fingerprint": held_target,
                    "reason": "investigation hold",
                    "created_at_unix_secs": 1,
                    "expires_at_unix_secs": 5_000,
                }],
            });
            private_file(&holds_path, holds.to_string().as_bytes());

            let quarantine_root = root.join("quarantine");
            let state_root = root.join("state");
            let evidence_path = protected_root.join("retention-evidence.json");
            let policy_path = root.join("retention-policy.json");
            let rules = RetentionEvidenceClass::ALL
                .iter()
                .map(|class| {
                    let disposition = match class {
                        RetentionEvidenceClass::Approvals
                        | RetentionEvidenceClass::Delegations
                        | RetentionEvidenceClass::LifecycleEvidence => "quarantine_then_purge",
                        RetentionEvidenceClass::RecoveryEvidence => "replace_only",
                        _ => "retain",
                    };
                    serde_json::json!({
                        "class": class.as_str(),
                        "disposition": disposition,
                        "minimum_age_seconds": 10,
                    })
                })
                .collect::<Vec<_>>();
            let config_bytes = fs::read(&config_path).unwrap();
            let policy = serde_json::json!({
                "schema_version": 1,
                "operation_id": "fixture-retention",
                "scope_ref": scope.as_str(),
                "release_artifact": "not_required:self_hosted",
                "rules": rules,
                "config_bindings": [{
                    "name": "metadata",
                    "path": config_path,
                    "expected_fingerprint": fingerprint_bytes(&config_bytes),
                }],
                "approval_root": approval_root,
                "delegation_root": delegation_root,
                "lifecycle_evidence_root": lifecycle_root,
                "metadata_overlay_path": config_path,
                "tombstone_root": tombstone_root,
                "audit_path": audit_path,
                "recovery_evidence_path": protected_root.join("recovery-evidence.json"),
                "admin_evidence_root": admin_root,
                "hold_registry_path": holds_path,
                "quarantine_root": quarantine_root,
                "state_root": state_root,
                "operation_audit_path": operation_root.join("audit.jsonl"),
                "evidence_path": evidence_path,
                "minimum_free_bytes": 1,
                "maximum_records": 1024,
                "maximum_bytes": 1048576,
                "preflight_max_age_seconds": 60,
                "quarantine_grace_seconds": 5,
                "evidence_max_age_seconds": 86400,
            });
            private_file(&policy_path, policy.to_string().as_bytes());

            Self {
                _temp: temp,
                policy_path,
                approval_root,
                delegation_root,
                lifecycle_root,
                tombstone_root,
                audit_path,
                config_path,
                holds_path,
                quarantine_root,
                evidence_path,
                descriptors: vec![descriptor_active, descriptor_destroyed],
                principal,
                expired_approval: expired.id().as_str().to_string(),
                active_approval: active.id().as_str().to_string(),
                expired_delegation: expired_delegation.id().as_str().to_string(),
                held_delegation: held_delegation.id().as_str().to_string(),
                destroyed_ref,
                scope,
            }
        }

        fn runner(&self) -> RetentionRunner {
            RetentionRunner::load(
                &self.policy_path,
                ReleaseAdmission::not_required(ProductMode::SelfHosted),
                self.principal.clone(),
            )
            .unwrap()
        }
    }

    #[test]
    fn mixed_plan_quarantines_only_inert_unheld_state_and_rolls_back_exactly() {
        let fixture = Fixture::new();
        let before = source_inventory_fingerprint(fixture.runner().policy()).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let runner = fixture.runner();
        let preflight = runner.preflight(now, &fixture.descriptors).unwrap();
        assert_eq!(preflight.eligible_count, 3);
        assert_eq!(preflight.held_count, 1);
        assert_eq!(preflight.protected_count, 5);
        let quarantined = runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .unwrap();
        assert_eq!(quarantined.phase, "quarantined");
        assert!(!fixture
            .approval_root
            .join(format!("{}.json", fixture.expired_approval))
            .exists());
        assert!(fixture
            .approval_root
            .join(format!("{}.json", fixture.active_approval))
            .exists());
        assert!(!fixture
            .delegation_root
            .join(format!("{}.json", fixture.expired_delegation))
            .exists());
        assert!(fixture
            .delegation_root
            .join(format!("{}.json", fixture.held_delegation))
            .exists());
        assert!(!fixture
            .lifecycle_root
            .join(format!("{}.json", fixture.destroyed_ref.as_str()))
            .exists());
        assert!(fixture.audit_path.exists());
        assert!(fixture
            .tombstone_root
            .join(format!("{}.json", fixture.destroyed_ref.as_str()))
            .exists());

        let rolled_back = runner.rollback().unwrap();
        assert_eq!(rolled_back.phase, "rolled_back");
        assert_eq!(
            source_inventory_fingerprint(runner.policy()).unwrap(),
            before
        );
        assert!(!fixture.quarantine_root.exists());
    }

    #[test]
    fn purge_waits_for_grace_is_idempotent_and_writes_current_value_free_evidence() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .unwrap();
        assert!(matches!(
            runner.purge(now + Duration::from_secs(5)),
            Err(JanusError::PolicyDenied {
                reason_code: "retention_grace_active",
                ..
            })
        ));
        let completed = runner.purge(now + Duration::from_secs(6)).unwrap();
        assert_eq!(completed.phase, "completed");
        assert_eq!(completed.reason_code, "retention_purge_ok");
        assert!(!completed.value_returned);
        assert!(!fixture.quarantine_root.exists());
        assert!(fixture.evidence_path.exists());
        runner.purge(now + Duration::from_secs(7)).unwrap();
        enforce_retention_ready(
            &fixture.policy_path,
            &fixture.evidence_path,
            &ReleaseAdmission::not_required(ProductMode::SelfHosted),
            &fixture.scope,
            now + Duration::from_secs(7),
        )
        .unwrap();
        let rendered = fs::read_to_string(&fixture.evidence_path).unwrap();
        assert!(rendered.contains("\"value_returned\":false"));
        assert!(!rendered.contains(&fixture.expired_approval));
        assert!(!rendered.contains(&fixture.expired_delegation));
    }

    #[test]
    fn source_hold_config_and_quarantine_drift_fail_closed_without_canary_echo() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        private_file(
            &fixture.delegation_root.join("SENSITIVE_CANARY.txt"),
            b"SENSITIVE_RETENTION_CANARY",
        );
        let error = runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_RETENTION_CANARY"));

        let fixture = Fixture::new();
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        private_file(&fixture.holds_path, br#"{"schema_version":9}"#);
        assert!(runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .is_err());

        let fixture = Fixture::new();
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        private_file(&fixture.config_path, b"SENSITIVE_CONFIG_DRIFT_CANARY");
        let error = runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_CONFIG_DRIFT_CANARY"));

        let fixture = Fixture::new();
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        runner
            .quarantine(now + Duration::from_secs(1), &fixture.descriptors)
            .unwrap();
        let quarantined = fixture
            .quarantine_root
            .join("approvals")
            .join(format!("{}.json", fixture.expired_approval));
        private_file(&quarantined, b"SENSITIVE_QUARANTINE_CANARY");
        let error = runner.purge(now + Duration::from_secs(6)).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_QUARANTINE_CANARY"));
    }

    #[test]
    fn interrupted_partial_quarantine_rolls_back_exact_files() {
        let fixture = Fixture::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let runner = fixture.runner();
        runner.preflight(now, &fixture.descriptors).unwrap();
        let mut journal = runner.read_required_journal().unwrap();
        journal.phase = RetentionPhase::Quarantining;
        seal_journal(&mut journal).unwrap();
        runner.write_journal(&journal).unwrap();
        let stage = runner.stage_path().unwrap();
        private_dir(&stage);
        let entry = &journal.entries[0];
        let class_dir = stage.join(entry.class.as_str());
        private_dir(&class_dir);
        let file = &entry.files[0];
        fs::rename(
            runner.source_file(entry.class, &file.name).unwrap(),
            class_dir.join(&file.name),
        )
        .unwrap();
        let status = runner.rollback().unwrap();
        assert_eq!(status.phase, "rolled_back");
        assert!(runner
            .source_file(entry.class, &file.name)
            .unwrap()
            .exists());
        assert!(!stage.exists());
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
        if let Some(parent) = path.parent() {
            private_dir(parent);
        }
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
    }

    #[cfg(not(unix))]
    fn private_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            private_dir(parent);
        }
        fs::write(path, bytes).unwrap();
    }
}

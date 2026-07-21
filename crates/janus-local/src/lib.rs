//! Local filesystem integrations for Janus runtimes.
//!
//! This crate intentionally stores only value-free audit, permit, approval,
//! lifecycle, and tombstone metadata. Audit evidence, permit ids, approval ids,
//! and principal bindings remain operationally sensitive, so files are created
//! under private directories and permit files are consumed with a
//! rename-before-read single-use claim.

#![forbid(unsafe_code)]

mod audit;
mod delegation;
mod migration;
mod recovery;
mod release;
mod retention;
mod transfer;

pub use audit::{AuditRecovery, JsonlAuditSink};
pub use delegation::{
    DelegationListEntry, DelegationRecord, DelegationRegistry, FileDelegationRegistry,
    NoopDelegationRegistry,
};
pub use migration::{enforce_migration_ready_from_env, ApprovalMigrationRunner, MigrationStatus};
pub use recovery::{
    enforce_recovery_drill_freshness, enforce_recovery_drill_freshness_from_env,
    RecoveryDrillRunner, RecoveryDrillStatus, RecoveryPostflightTarget,
};
pub use release::{
    audit_release_admission, enforce_release_admission_from_env, load_release_admission,
};
pub use retention::{
    enforce_retention_ready, enforce_retention_ready_from_env, RetentionRunner, RetentionStatus,
};
pub use transfer::{
    enforce_scope_transfer_ready_from_env, ScopeTransferRunner, ScopeTransferStatus,
};

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use janus_core::{
    ApprovalGrant, ApprovalGrantSnapshot, ApprovalId, DelegatedUseContextSnapshotV1, Destination,
    EgressMode, ExecutorRef, JanusError, JanusResult, PrincipalChain, ProfileId, Purpose,
    SafeLabel, ScopeRef, SecretAgeEvidence, SecretClass, SecretRef, SecretTombstone, UsePermit,
    UsePermitSnapshot,
};
use serde::{Deserialize, Serialize};

/// Sink for newly issued permits.
pub trait PermitStore {
    /// Persist a permit so a later executor can consume it by opaque id.
    fn store(&self, permit: &UsePermit) -> JanusResult<()>;
}

/// Local registry for permits that can be consumed by id.
pub trait PermitRegistry: PermitStore {
    /// Atomically claim and remove a permit from the registry.
    fn take(&self, permit_id: &str) -> JanusResult<UsePermit>;
}

/// Local registry for exact approval grants.
pub trait ApprovalRegistry {
    /// Persist an approval grant by opaque approval id.
    fn store(&self, approval: &ApprovalGrant) -> JanusResult<()>;

    /// Read one approval grant by opaque approval id.
    fn get(&self, approval_id: &str) -> JanusResult<ApprovalGrant>;

    /// List value-free summaries, including stale pre-scope records.
    fn list(&self) -> JanusResult<Vec<ApprovalListEntry>>;

    /// Revoke one locally stored approval grant.
    fn revoke(&self, approval_id: &str) -> JanusResult<()>;
}

/// Value-free inventory entry for a current or stale approval record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalListEntry {
    /// Opaque approval id.
    pub approval_id: ApprovalId,
    /// Opaque secret ref from the stored record.
    pub secret_ref: SecretRef,
    /// Reviewed use profile.
    pub profile_id: ProfileId,
    /// Stored secret class.
    pub class: SecretClass,
    /// Stored egress mode.
    pub egress: EgressMode,
    /// Stored expiry.
    pub expires_at: SystemTime,
    /// Exact scope when the record was issued after the cutover.
    pub scope_ref: Option<ScopeRef>,
}

impl ApprovalListEntry {
    /// Stable safe scope-binding state for operator output.
    pub fn scope_status(&self) -> &'static str {
        if self.scope_ref.is_some() {
            "exact"
        } else {
            "stale_unbound"
        }
    }
}

/// Local registry for value-free lifecycle age evidence.
pub trait LifecycleEvidenceRegistry {
    /// Record when a secret entered the local lifecycle reporting scope.
    fn record_declared(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()>;

    /// Record an approved-use timestamp for stale reporting.
    fn record_used(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()>;

    /// Record a rotation timestamp for stale reporting.
    fn record_rotated(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()>;

    /// List value-free lifecycle evidence for stale reporting.
    fn list(&self) -> JanusResult<Vec<SecretAgeEvidence>>;
}

/// Local registry for value-free destroy tombstones.
pub trait TombstoneRegistry {
    /// Persist one immutable tombstone record.
    fn record(&self, tombstone: &SecretTombstone, principal: &PrincipalChain) -> JanusResult<()>;

    /// Read one tombstone by opaque secret ref.
    fn get(&self, secret_ref: &SecretRef) -> JanusResult<SecretTombstoneRecord>;

    /// List all locally stored tombstones.
    fn list(&self) -> JanusResult<Vec<SecretTombstoneRecord>>;
}

/// Value-free locally persisted destroy tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretTombstoneRecord {
    /// Opaque secret ref.
    pub secret_ref: SecretRef,
    /// Value-free operator/admin reason label.
    pub reason: SafeLabel,
    /// Timestamp when Janus recorded the destroy tombstone.
    pub destroyed_at: SystemTime,
    /// Timestamp until which the tombstone must be retained.
    pub retain_until: SystemTime,
    /// Value-free principal binding that recorded the tombstone.
    pub principal_binding: String,
}

/// Permit sink used when no local handoff registry is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopPermitStore;

impl PermitStore for NoopPermitStore {
    fn store(&self, _permit: &UsePermit) -> JanusResult<()> {
        Ok(())
    }
}

/// File-backed local permit registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePermitRegistry {
    dir: PathBuf,
}

/// File-backed local approval registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileApprovalRegistry {
    dir: PathBuf,
}

/// File-backed local lifecycle evidence registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileLifecycleEvidenceRegistry {
    dir: PathBuf,
}

/// File-backed local destroy tombstone registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTombstoneRegistry {
    dir: PathBuf,
}

impl FilePermitRegistry {
    /// Build a registry rooted at a private directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Registry root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        fs::create_dir_all(&self.dir)
            .map_err(|_| store_unavailable("permit registry unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| store_unavailable("permit registry permissions unavailable"))?;
        }

        let metadata = fs::symlink_metadata(&self.dir)
            .map_err(|_| store_unavailable("permit registry unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(store_unavailable("permit registry path is not a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(store_unavailable(
                    "permit registry directory must be private",
                ));
            }
        }
        Ok(())
    }

    fn path_for(&self, permit_id: &str) -> JanusResult<PathBuf> {
        validate_permit_file_token(permit_id)?;
        Ok(self.dir.join(format!("{permit_id}.json")))
    }

    fn claim_path_for(&self, permit_id: &str) -> JanusResult<PathBuf> {
        validate_permit_file_token(permit_id)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Ok(self.dir.join(format!(
            ".{permit_id}.{}.{}.claim",
            std::process::id(),
            nonce
        )))
    }
}

impl FileApprovalRegistry {
    /// Build a registry rooted at a private directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Registry root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        fs::create_dir_all(&self.dir)
            .map_err(|_| store_unavailable("approval registry unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| store_unavailable("approval registry permissions unavailable"))?;
        }

        let metadata = fs::symlink_metadata(&self.dir)
            .map_err(|_| store_unavailable("approval registry unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(store_unavailable(
                "approval registry path is not a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(store_unavailable(
                    "approval registry directory must be private",
                ));
            }
        }
        Ok(())
    }

    fn path_for(&self, approval_id: &str) -> JanusResult<PathBuf> {
        validate_approval_file_token(approval_id)?;
        Ok(self.dir.join(format!("{approval_id}.json")))
    }
}

impl FileLifecycleEvidenceRegistry {
    /// Build a registry rooted at a private directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Registry root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// List existing evidence without creating or chmodding registry state.
    pub fn list_existing_bounded(
        &self,
        max_entries: usize,
        max_file_bytes: u64,
    ) -> JanusResult<Vec<SecretAgeEvidence>> {
        check_existing_private_dir(&self.dir, "lifecycle evidence registry unavailable")?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir)
            .map_err(|_| store_unavailable("failed to list lifecycle evidence registry"))?
        {
            let entry =
                entry.map_err(|_| store_unavailable("failed to list lifecycle evidence entry"))?;
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| store_unavailable("lifecycle evidence entry name is malformed"))?;
            let secret_ref_text = file_name.strip_suffix(".json").ok_or_else(|| {
                store_unavailable("lifecycle evidence registry contains an unsupported entry")
            })?;
            if records.len() >= max_entries {
                return Err(store_unavailable(
                    "lifecycle evidence registry entry limit exceeded",
                ));
            }
            check_bounded_private_file(
                &path,
                max_file_bytes,
                "lifecycle evidence registry entry is unavailable",
            )?;
            let secret_ref = SecretRef::new(secret_ref_text)?;
            records.push(read_lifecycle_evidence(&path, &secret_ref)?);
        }
        records.sort_by(|left, right| left.secret_ref.as_str().cmp(right.secret_ref.as_str()));
        Ok(records)
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        fs::create_dir_all(&self.dir)
            .map_err(|_| store_unavailable("lifecycle evidence registry unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).map_err(|_| {
                store_unavailable("lifecycle evidence registry permissions unavailable")
            })?;
        }

        let metadata = fs::symlink_metadata(&self.dir)
            .map_err(|_| store_unavailable("lifecycle evidence registry unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(store_unavailable(
                "lifecycle evidence registry path is not a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(store_unavailable(
                    "lifecycle evidence registry directory must be private",
                ));
            }
        }
        Ok(())
    }

    fn path_for(&self, secret_ref: &SecretRef) -> JanusResult<PathBuf> {
        validate_secret_ref_file_token(secret_ref.as_str())?;
        Ok(self.dir.join(format!("{}.json", secret_ref.as_str())))
    }

    fn update<F>(&self, secret_ref: &SecretRef, update: F) -> JanusResult<()>
    where
        F: FnOnce(&mut SecretAgeEvidence),
    {
        self.ensure_dir()?;
        let path = self.path_for(secret_ref)?;
        let mut evidence = read_optional_lifecycle_evidence(&path, secret_ref)?;
        update(&mut evidence);
        write_lifecycle_evidence_atomic(&path, &evidence)
    }
}

impl FileTombstoneRegistry {
    /// Build a registry rooted at a private directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Registry root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// List existing tombstones without creating or chmodding registry state.
    pub fn list_existing_bounded(
        &self,
        max_entries: usize,
        max_file_bytes: u64,
    ) -> JanusResult<Vec<SecretTombstoneRecord>> {
        check_existing_private_dir(&self.dir, "tombstone registry unavailable")?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir)
            .map_err(|_| store_unavailable("failed to list tombstone registry"))?
        {
            let entry =
                entry.map_err(|_| store_unavailable("failed to list tombstone registry entry"))?;
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| store_unavailable("tombstone entry name is malformed"))?;
            let secret_ref_text = file_name.strip_suffix(".json").ok_or_else(|| {
                store_unavailable("tombstone registry contains an unsupported entry")
            })?;
            if records.len() >= max_entries {
                return Err(store_unavailable("tombstone registry entry limit exceeded"));
            }
            check_bounded_private_file(
                &path,
                max_file_bytes,
                "tombstone registry entry is unavailable",
            )?;
            let secret_ref = SecretRef::new(secret_ref_text)?;
            records.push(read_tombstone(&path, &secret_ref)?);
        }
        records.sort_by(|left, right| left.secret_ref.as_str().cmp(right.secret_ref.as_str()));
        Ok(records)
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        fs::create_dir_all(&self.dir)
            .map_err(|_| store_unavailable("tombstone registry unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| store_unavailable("tombstone registry permissions unavailable"))?;
        }

        let metadata = fs::symlink_metadata(&self.dir)
            .map_err(|_| store_unavailable("tombstone registry unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(store_unavailable(
                "tombstone registry path is not a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(store_unavailable(
                    "tombstone registry directory must be private",
                ));
            }
        }
        Ok(())
    }

    fn path_for(&self, secret_ref: &SecretRef) -> JanusResult<PathBuf> {
        validate_secret_ref_file_token(secret_ref.as_str())?;
        Ok(self.dir.join(format!("{}.json", secret_ref.as_str())))
    }
}

impl PermitStore for FilePermitRegistry {
    fn store(&self, permit: &UsePermit) -> JanusResult<()> {
        self.ensure_dir()?;
        let snapshot = permit.snapshot();
        let path = self.path_for(&snapshot.permit_id)?;
        let record = PermitFileRecord::from(snapshot);
        let file = create_secure_new_file(&path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &record)
            .map_err(|_| store_unavailable("failed to encode permit registry entry"))?;
        writer
            .write_all(b"\n")
            .map_err(|_| store_unavailable("failed to write permit registry entry"))?;
        writer
            .flush()
            .map_err(|_| store_unavailable("failed to flush permit registry entry"))?;
        Ok(())
    }
}

impl ApprovalRegistry for FileApprovalRegistry {
    fn store(&self, approval: &ApprovalGrant) -> JanusResult<()> {
        self.ensure_dir()?;
        let snapshot = approval.snapshot();
        let path = self.path_for(&snapshot.approval_id)?;
        let mut record = ApprovalGrantFileRecord::from(snapshot);
        if migration::approval_schema_version(&self.dir)? == 0 {
            record.version = None;
        }
        let file = create_secure_new_approval_file(&path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &record)
            .map_err(|_| store_unavailable("failed to encode approval registry entry"))?;
        writer
            .write_all(b"\n")
            .map_err(|_| store_unavailable("failed to write approval registry entry"))?;
        writer
            .flush()
            .map_err(|_| store_unavailable("failed to flush approval registry entry"))?;
        Ok(())
    }

    fn get(&self, approval_id: &str) -> JanusResult<ApprovalGrant> {
        self.ensure_dir()?;
        let path = self.path_for(approval_id)?;
        read_approval(&path, approval_id)
    }

    fn list(&self) -> JanusResult<Vec<ApprovalListEntry>> {
        self.ensure_dir()?;
        let mut approvals = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|_| store_unavailable("failed to list approval registry"))?;
        for entry in entries {
            let entry =
                entry.map_err(|_| store_unavailable("failed to list approval registry entry"))?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(JanusError::approval_invalid(
                    "denied_malformed_approval",
                    "approval registry entry name is malformed",
                ));
            };
            let Some(approval_id) = file_name.strip_suffix(".json") else {
                continue;
            };
            validate_approval_file_token(approval_id)?;
            approvals.push(read_approval_list_entry(&path, approval_id)?);
        }
        approvals.sort_by(|left, right| left.approval_id.as_str().cmp(right.approval_id.as_str()));
        Ok(approvals)
    }

    fn revoke(&self, approval_id: &str) -> JanusResult<()> {
        self.ensure_dir()?;
        let path = self.path_for(approval_id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(JanusError::approval_invalid(
                "denied_unknown_approval",
                "approval registry entry was not found",
            )),
            Err(_) => Err(store_unavailable(
                "failed to revoke approval registry entry",
            )),
        }
    }
}

impl PermitRegistry for FilePermitRegistry {
    fn take(&self, permit_id: &str) -> JanusResult<UsePermit> {
        self.ensure_dir()?;
        let path = self.path_for(permit_id)?;
        let claimed = self.claim_path_for(permit_id)?;
        match fs::rename(&path, &claimed) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(JanusError::permit_invalid(
                    "denied_unknown_permit",
                    "permit registry entry was not found",
                ))
            }
            Err(_) => return Err(store_unavailable("failed to claim permit registry entry")),
        }

        let result = read_claimed_permit(&claimed, permit_id);
        let _ = fs::remove_file(&claimed);
        result
    }
}

impl LifecycleEvidenceRegistry for FileLifecycleEvidenceRegistry {
    fn record_declared(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()> {
        self.update(secret_ref, |evidence| {
            evidence.declared_at = Some(match evidence.declared_at {
                Some(existing) if existing <= at => existing,
                _ => at,
            });
        })
    }

    fn record_used(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()> {
        self.update(secret_ref, |evidence| {
            evidence.last_used_at = Some(max_time(evidence.last_used_at, at));
        })
    }

    fn record_rotated(&self, secret_ref: &SecretRef, at: SystemTime) -> JanusResult<()> {
        self.update(secret_ref, |evidence| {
            evidence.last_rotated_at = Some(max_time(evidence.last_rotated_at, at));
        })
    }

    fn list(&self) -> JanusResult<Vec<SecretAgeEvidence>> {
        self.ensure_dir()?;
        let mut records = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|_| store_unavailable("failed to list lifecycle evidence registry"))?;
        for entry in entries {
            let entry =
                entry.map_err(|_| store_unavailable("failed to list lifecycle evidence entry"))?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(store_unavailable(
                    "lifecycle evidence entry name is malformed",
                ));
            };
            let Some(secret_ref_text) = file_name.strip_suffix(".json") else {
                continue;
            };
            validate_secret_ref_file_token(secret_ref_text)?;
            let secret_ref = SecretRef::new(secret_ref_text)?;
            records.push(read_lifecycle_evidence(&path, &secret_ref)?);
        }
        records.sort_by(|left, right| left.secret_ref.as_str().cmp(right.secret_ref.as_str()));
        Ok(records)
    }
}

impl TombstoneRegistry for FileTombstoneRegistry {
    fn record(&self, tombstone: &SecretTombstone, principal: &PrincipalChain) -> JanusResult<()> {
        self.ensure_dir()?;
        let path = self.path_for(tombstone.secret_ref())?;
        let record = SecretTombstoneFileRecord::from_tombstone(tombstone, principal);
        let file = create_secure_new_tombstone_file(&path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &record)
            .map_err(|_| store_unavailable("failed to encode tombstone registry entry"))?;
        writer
            .write_all(b"\n")
            .map_err(|_| store_unavailable("failed to write tombstone registry entry"))?;
        writer
            .flush()
            .map_err(|_| store_unavailable("failed to flush tombstone registry entry"))?;
        Ok(())
    }

    fn get(&self, secret_ref: &SecretRef) -> JanusResult<SecretTombstoneRecord> {
        self.ensure_dir()?;
        let path = self.path_for(secret_ref)?;
        read_tombstone(&path, secret_ref)
    }

    fn list(&self) -> JanusResult<Vec<SecretTombstoneRecord>> {
        self.ensure_dir()?;
        let mut records = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|_| store_unavailable("failed to list tombstone registry"))?;
        for entry in entries {
            let entry =
                entry.map_err(|_| store_unavailable("failed to list tombstone registry entry"))?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(store_unavailable("tombstone entry name is malformed"));
            };
            let Some(secret_ref_text) = file_name.strip_suffix(".json") else {
                continue;
            };
            validate_secret_ref_file_token(secret_ref_text)?;
            let secret_ref = SecretRef::new(secret_ref_text)?;
            records.push(read_tombstone(&path, &secret_ref)?);
        }
        records.sort_by(|left, right| left.secret_ref.as_str().cmp(right.secret_ref.as_str()));
        Ok(records)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PermitFileRecord {
    version: u8,
    permit_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_ref: Option<String>,
    secret_ref: String,
    profile_id: String,
    destination: String,
    executor: String,
    egress: Option<String>,
    purpose: Option<String>,
    approval: Option<ApprovalGrantFileRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegation: Option<DelegatedUseContextSnapshotV1>,
    principal_binding: String,
    expires_at_unix_secs: u64,
    expires_at_subsec_nanos: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding_version: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalGrantFileRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_ref: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleEvidenceFileRecord {
    version: u8,
    secret_ref: String,
    declared_at_unix_secs: Option<u64>,
    last_used_at_unix_secs: Option<u64>,
    last_rotated_at_unix_secs: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretTombstoneFileRecord {
    version: u8,
    secret_ref: String,
    reason: String,
    destroyed_at_unix_secs: u64,
    retain_until_unix_secs: u64,
    principal_binding: String,
}

impl From<UsePermitSnapshot> for PermitFileRecord {
    fn from(snapshot: UsePermitSnapshot) -> Self {
        Self {
            version: 5,
            permit_id: snapshot.permit_id,
            scope_ref: Some(snapshot.scope_ref),
            secret_ref: snapshot.secret_ref,
            profile_id: snapshot.profile_id,
            destination: snapshot.destination,
            executor: snapshot.executor,
            egress: Some(snapshot.egress),
            purpose: Some(snapshot.purpose),
            approval: snapshot.approval.map(ApprovalGrantFileRecord::from),
            delegation: snapshot.delegation,
            principal_binding: snapshot.principal_binding,
            expires_at_unix_secs: snapshot.expires_at_unix_secs,
            expires_at_subsec_nanos: snapshot.expires_at_subsec_nanos,
            binding_version: snapshot.binding_version,
        }
    }
}

impl PermitFileRecord {
    fn into_snapshot(self) -> JanusResult<UsePermitSnapshot> {
        if !matches!(self.version, 1..=5)
            || (self.version < 5 && (self.delegation.is_some() || self.binding_version.is_some()))
            || (self.version == 5 && self.binding_version != Some(1))
        {
            return Err(JanusError::permit_invalid(
                "denied_unsupported_permit_record",
                "permit registry entry version is unsupported",
            ));
        }
        Ok(UsePermitSnapshot {
            permit_id: self.permit_id,
            scope_ref: self.scope_ref.ok_or_else(|| {
                JanusError::permit_invalid(
                    "denied_stale_scope_binding",
                    "permit predates exact scope binding",
                )
            })?,
            secret_ref: self.secret_ref,
            profile_id: self.profile_id,
            destination: self.destination,
            executor: self.executor,
            egress: self.egress.unwrap_or_else(|| "declared_only".to_string()),
            purpose: self.purpose.unwrap_or_else(|| "legacy permit".to_string()),
            approval: self
                .approval
                .map(ApprovalGrantFileRecord::into_snapshot)
                .transpose()?,
            delegation: self.delegation,
            principal_binding: self.principal_binding,
            expires_at_unix_secs: self.expires_at_unix_secs,
            expires_at_subsec_nanos: self.expires_at_subsec_nanos,
            binding_version: self.binding_version,
        })
    }
}

impl From<ApprovalGrantSnapshot> for ApprovalGrantFileRecord {
    fn from(snapshot: ApprovalGrantSnapshot) -> Self {
        Self {
            version: Some(1),
            approval_id: snapshot.approval_id,
            scope_ref: Some(snapshot.scope_ref),
            secret_ref: snapshot.secret_ref,
            profile_id: snapshot.profile_id,
            executor: snapshot.executor,
            destination: snapshot.destination,
            class: snapshot.class,
            egress: snapshot.egress,
            purpose: snapshot.purpose,
            expires_at_unix_secs: snapshot.expires_at_unix_secs,
            expires_at_subsec_nanos: snapshot.expires_at_subsec_nanos,
            reason: snapshot.reason,
        }
    }
}

impl ApprovalGrantFileRecord {
    fn into_snapshot(self) -> JanusResult<ApprovalGrantSnapshot> {
        if !matches!(self.version, None | Some(1)) {
            return Err(JanusError::approval_invalid(
                "denied_unsupported_approval_record",
                "approval registry entry version is unsupported",
            ));
        }
        Ok(ApprovalGrantSnapshot {
            approval_id: self.approval_id,
            scope_ref: self.scope_ref.ok_or_else(|| {
                JanusError::approval_invalid(
                    "denied_stale_scope_binding",
                    "approval predates exact scope binding",
                )
            })?,
            secret_ref: self.secret_ref,
            profile_id: self.profile_id,
            executor: self.executor,
            destination: self.destination,
            class: self.class,
            egress: self.egress,
            purpose: self.purpose,
            expires_at_unix_secs: self.expires_at_unix_secs,
            expires_at_subsec_nanos: self.expires_at_subsec_nanos,
            reason: self.reason,
        })
    }

    fn to_list_entry(&self) -> JanusResult<ApprovalListEntry> {
        if !matches!(self.version, None | Some(1)) {
            return Err(JanusError::approval_invalid(
                "denied_unsupported_approval_record",
                "approval registry entry version is unsupported",
            ));
        }
        let approval_id = ApprovalId::from_opaque(self.approval_id.clone())?;
        let secret_ref = SecretRef::new(self.secret_ref.clone())?;
        let profile_id = ProfileId::new(self.profile_id.clone())?;
        ExecutorRef::new(self.executor.clone())?;
        Destination::new(self.destination.clone())?;
        let class = SecretClass::parse(&self.class)?;
        let egress = EgressMode::parse(&self.egress)?;
        Purpose::new(self.purpose.clone())?;
        SafeLabel::new(self.reason.clone())?;
        let scope_ref = self
            .scope_ref
            .as_ref()
            .map(|scope| ScopeRef::from_opaque(scope.clone()))
            .transpose()?;
        if self.expires_at_subsec_nanos >= 1_000_000_000 {
            return Err(JanusError::approval_invalid(
                "denied_malformed_approval",
                "approval expiry is malformed",
            ));
        }
        let expires_at = UNIX_EPOCH
            .checked_add(std::time::Duration::new(
                self.expires_at_unix_secs,
                self.expires_at_subsec_nanos,
            ))
            .ok_or_else(|| {
                JanusError::approval_invalid(
                    "denied_malformed_approval",
                    "approval expiry is malformed",
                )
            })?;
        Ok(ApprovalListEntry {
            approval_id,
            secret_ref,
            profile_id,
            class,
            egress,
            expires_at,
            scope_ref,
        })
    }
}

impl From<&SecretAgeEvidence> for LifecycleEvidenceFileRecord {
    fn from(evidence: &SecretAgeEvidence) -> Self {
        Self {
            version: 1,
            secret_ref: evidence.secret_ref.as_str().to_string(),
            declared_at_unix_secs: evidence.declared_at.map(unix_seconds),
            last_used_at_unix_secs: evidence.last_used_at.map(unix_seconds),
            last_rotated_at_unix_secs: evidence.last_rotated_at.map(unix_seconds),
        }
    }
}

impl LifecycleEvidenceFileRecord {
    fn into_evidence(self) -> JanusResult<SecretAgeEvidence> {
        if self.version != 1 {
            return Err(store_unavailable(
                "lifecycle evidence registry entry version is unsupported",
            ));
        }
        let secret_ref = SecretRef::new(self.secret_ref)?;
        Ok(SecretAgeEvidence {
            secret_ref,
            declared_at: self.declared_at_unix_secs.map(unix_time),
            last_used_at: self.last_used_at_unix_secs.map(unix_time),
            last_rotated_at: self.last_rotated_at_unix_secs.map(unix_time),
        })
    }
}

impl SecretTombstoneFileRecord {
    fn from_tombstone(tombstone: &SecretTombstone, principal: &PrincipalChain) -> Self {
        Self {
            version: 1,
            secret_ref: tombstone.secret_ref().as_str().to_string(),
            reason: tombstone.reason().as_str().to_string(),
            destroyed_at_unix_secs: unix_seconds(tombstone.destroyed_at()),
            retain_until_unix_secs: unix_seconds(tombstone.retain_until()),
            principal_binding: principal.binding_key(),
        }
    }

    fn into_record(self) -> JanusResult<SecretTombstoneRecord> {
        if self.version != 1 {
            return Err(store_unavailable(
                "tombstone registry entry version is unsupported",
            ));
        }
        Ok(SecretTombstoneRecord {
            secret_ref: SecretRef::new(self.secret_ref)?,
            reason: SafeLabel::new(self.reason)?,
            destroyed_at: unix_time(self.destroyed_at_unix_secs),
            retain_until: unix_time(self.retain_until_unix_secs),
            principal_binding: self.principal_binding,
        })
    }
}

fn read_claimed_permit(path: &Path, requested_permit_id: &str) -> JanusResult<UsePermit> {
    check_secure_file(path)?;
    let file =
        File::open(path).map_err(|_| store_unavailable("failed to open permit registry entry"))?;
    let record: PermitFileRecord = serde_json::from_reader(BufReader::new(file)).map_err(|_| {
        JanusError::permit_invalid(
            "denied_malformed_permit",
            "permit registry entry is malformed",
        )
    })?;
    if record.permit_id != requested_permit_id {
        return Err(JanusError::permit_invalid(
            "denied_permit_mismatch",
            "permit registry entry does not match the requested permit",
        ));
    }
    UsePermit::from_snapshot(record.into_snapshot()?)
}

fn read_approval(path: &Path, requested_approval_id: &str) -> JanusResult<ApprovalGrant> {
    let record = read_approval_record(path, requested_approval_id)?;
    ApprovalGrant::from_snapshot(record.into_snapshot()?).map_err(|_| {
        JanusError::approval_invalid(
            "denied_malformed_approval",
            "approval registry entry is malformed",
        )
    })
}

fn read_approval_list_entry(
    path: &Path,
    requested_approval_id: &str,
) -> JanusResult<ApprovalListEntry> {
    read_approval_record(path, requested_approval_id)?.to_list_entry()
}

fn read_approval_record(
    path: &Path,
    requested_approval_id: &str,
) -> JanusResult<ApprovalGrantFileRecord> {
    check_secure_approval_file(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(JanusError::approval_invalid(
                "denied_unknown_approval",
                "approval registry entry was not found",
            ))
        }
        Err(_) => return Err(store_unavailable("failed to open approval registry entry")),
    };
    let record: ApprovalGrantFileRecord =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| {
            JanusError::approval_invalid(
                "denied_malformed_approval",
                "approval registry entry is malformed",
            )
        })?;
    if record.approval_id != requested_approval_id {
        return Err(JanusError::approval_invalid(
            "denied_approval_mismatch",
            "approval registry entry does not match the requested approval",
        ));
    }
    Ok(record)
}

fn read_optional_lifecycle_evidence(
    path: &Path,
    secret_ref: &SecretRef,
) -> JanusResult<SecretAgeEvidence> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_lifecycle_evidence(path, secret_ref),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Ok(SecretAgeEvidence::new(secret_ref.clone()))
        }
        Err(_) => Err(store_unavailable(
            "lifecycle evidence registry entry unavailable",
        )),
    }
}

fn read_lifecycle_evidence(
    path: &Path,
    requested_secret_ref: &SecretRef,
) -> JanusResult<SecretAgeEvidence> {
    check_secure_lifecycle_evidence_file(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(store_unavailable(
                "lifecycle evidence registry entry was not found",
            ))
        }
        Err(_) => {
            return Err(store_unavailable(
                "failed to open lifecycle evidence registry entry",
            ))
        }
    };
    let record: LifecycleEvidenceFileRecord = serde_json::from_reader(BufReader::new(file))
        .map_err(|_| store_unavailable("lifecycle evidence registry entry is malformed"))?;
    let evidence = record.into_evidence()?;
    if &evidence.secret_ref != requested_secret_ref {
        return Err(store_unavailable(
            "lifecycle evidence registry entry does not match the requested secret ref",
        ));
    }
    Ok(evidence)
}

fn read_tombstone(
    path: &Path,
    requested_secret_ref: &SecretRef,
) -> JanusResult<SecretTombstoneRecord> {
    check_secure_tombstone_file(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(store_unavailable("tombstone registry entry was not found"))
        }
        Err(_) => return Err(store_unavailable("failed to open tombstone registry entry")),
    };
    let record: SecretTombstoneFileRecord = serde_json::from_reader(BufReader::new(file))
        .map_err(|_| store_unavailable("tombstone registry entry is malformed"))?;
    let record = record.into_record()?;
    if &record.secret_ref != requested_secret_ref {
        return Err(store_unavailable(
            "tombstone registry entry does not match the requested secret ref",
        ));
    }
    Ok(record)
}

fn validate_permit_file_token(permit_id: &str) -> JanusResult<()> {
    if permit_id.trim().is_empty()
        || permit_id.trim().len() != permit_id.len()
        || !permit_id.starts_with("use_")
        || permit_id.len() <= "use_".len()
        || !permit_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(JanusError::permit_invalid(
            "denied_invalid_permit_id",
            "permit id is malformed",
        ));
    }
    Ok(())
}

fn validate_approval_file_token(approval_id: &str) -> JanusResult<()> {
    if approval_id.trim().is_empty()
        || approval_id.trim().len() != approval_id.len()
        || !approval_id.starts_with("appr_")
        || approval_id.len() <= "appr_".len()
        || !approval_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(JanusError::approval_invalid(
            "denied_invalid_approval_id",
            "approval id is malformed",
        ));
    }
    Ok(())
}

fn validate_secret_ref_file_token(secret_ref: &str) -> JanusResult<()> {
    if secret_ref.trim().is_empty()
        || secret_ref.trim().len() != secret_ref.len()
        || !secret_ref
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(JanusError::InvalidIdentifier { kind: "secret_ref" });
    }
    Ok(())
}

fn create_secure_new_file(path: &Path) -> JanusResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(JanusError::permit_invalid(
                "denied_duplicate_permit",
                "permit registry entry already exists",
            ))
        }
        Err(_) => return Err(store_unavailable("failed to create permit registry entry")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| store_unavailable("permit registry file permissions unavailable"))?;
    }
    Ok(file)
}

fn create_secure_new_approval_file(path: &Path) -> JanusResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(JanusError::approval_invalid(
                "denied_duplicate_approval",
                "approval registry entry already exists",
            ))
        }
        Err(_) => {
            return Err(store_unavailable(
                "failed to create approval registry entry",
            ))
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| store_unavailable("approval registry file permissions unavailable"))?;
    }
    Ok(file)
}

fn create_secure_new_tombstone_file(path: &Path) -> JanusResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(store_unavailable("tombstone registry entry already exists"))
        }
        Err(_) => {
            return Err(store_unavailable(
                "failed to create tombstone registry entry",
            ))
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| store_unavailable("tombstone registry file permissions unavailable"))?;
    }
    Ok(file)
}

fn write_lifecycle_evidence_atomic(path: &Path, evidence: &SecretAgeEvidence) -> JanusResult<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| store_unavailable("lifecycle evidence path is malformed"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| -> JanusResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&temp_path)
            .map_err(|_| store_unavailable("failed to create lifecycle evidence entry"))?;
        let mut writer = BufWriter::new(file);
        let record = LifecycleEvidenceFileRecord::from(evidence);
        serde_json::to_writer(&mut writer, &record)
            .map_err(|_| store_unavailable("failed to encode lifecycle evidence entry"))?;
        writer
            .write_all(b"\n")
            .map_err(|_| store_unavailable("failed to write lifecycle evidence entry"))?;
        writer
            .flush()
            .map_err(|_| store_unavailable("failed to flush lifecycle evidence entry"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|_| store_unavailable("failed to sync lifecycle evidence entry"))?;
        fs::rename(&temp_path, path)
            .map_err(|_| store_unavailable("failed to replace lifecycle evidence entry"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| {
                store_unavailable("lifecycle evidence file permissions unavailable")
            })?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn check_secure_file(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| store_unavailable("permit registry entry unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JanusError::permit_invalid(
            "denied_malformed_permit",
            "permit registry entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JanusError::permit_invalid(
                "denied_insecure_permit_file",
                "permit registry entry is not private",
            ));
        }
    }
    Ok(())
}

fn check_secure_approval_file(path: &Path) -> JanusResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(JanusError::approval_invalid(
                "denied_unknown_approval",
                "approval registry entry was not found",
            ))
        }
        Err(_) => return Err(store_unavailable("approval registry entry unavailable")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JanusError::approval_invalid(
            "denied_malformed_approval",
            "approval registry entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JanusError::approval_invalid(
                "denied_insecure_approval_file",
                "approval registry entry is not private",
            ));
        }
    }
    Ok(())
}

fn check_existing_private_dir(path: &Path, unavailable: &'static str) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| store_unavailable(unavailable))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(store_unavailable(unavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable(unavailable));
        }
    }
    Ok(())
}

fn check_bounded_private_file(
    path: &Path,
    max_file_bytes: u64,
    unavailable: &'static str,
) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| store_unavailable(unavailable))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_file_bytes {
        return Err(store_unavailable(unavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable(unavailable));
        }
    }
    Ok(())
}

fn check_secure_lifecycle_evidence_file(path: &Path) -> JanusResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(store_unavailable(
                "lifecycle evidence registry entry was not found",
            ))
        }
        Err(_) => {
            return Err(store_unavailable(
                "lifecycle evidence registry entry unavailable",
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(store_unavailable(
            "lifecycle evidence registry entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable(
                "lifecycle evidence registry entry is not private",
            ));
        }
    }
    Ok(())
}

fn check_secure_tombstone_file(path: &Path) -> JanusResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(store_unavailable("tombstone registry entry was not found"))
        }
        Err(_) => return Err(store_unavailable("tombstone registry entry unavailable")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(store_unavailable(
            "tombstone registry entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable("tombstone registry entry is not private"));
        }
    }
    Ok(())
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(seconds)
}

fn max_time(existing: Option<SystemTime>, candidate: SystemTime) -> SystemTime {
    match existing {
        Some(existing) if existing >= candidate => existing,
        _ => candidate,
    }
}

fn store_unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use janus_core::{
        ApprovalGrant, AuditWrite, DelegatedUseContext, DelegationPolicy, Destination, EgressMode,
        ExecutorRef, OwnerRef, PermitIssuer, Principal, PrincipalChain, PrincipalId, PrincipalKind,
        ProfileId, ProfilePolicy, Purpose, SafeLabel, ScopePathV1, ScopeRef, SecretClass,
        SecretDescriptor, SecretLifecycle, SecretName, SecretRef, TombstonePolicy, TrustLevel,
        UseProfile, UseRequest,
    };

    use super::*;

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    fn fixture_permit(now: SystemTime) -> UsePermit {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.fixture").unwrap();
        let executor = ExecutorRef::new("janus-run@fixture").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new(executor.as_str()).unwrap(),
            ),
            scope(),
        );
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: scope(),
            secret_ref: secret_ref.clone(),
            executor,
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            scope: scope(),
            secret_ref,
            profile_id,
            destination,
            purpose: Purpose::new("fixture").unwrap(),
        };
        let mut issuer =
            PermitIssuer::new(ProfilePolicy::new(vec![profile]), AuditWrite::accepting());
        issuer.issue(&request, &principal, now).unwrap()
    }

    fn fixture_approval(expires_at: SystemTime) -> ApprovalGrant {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.fixture").unwrap();
        let executor = ExecutorRef::new("janus-run@fixture").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: scope(),
            secret_ref: secret_ref.clone(),
            executor,
            destination: destination.clone(),
            egress: EgressMode::DeclaredOnly,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            scope: scope(),
            secret_ref,
            profile_id,
            destination,
            purpose: Purpose::new("fixture break glass").unwrap(),
        };
        ApprovalGrant::for_request(
            &request,
            &profile,
            SecretClass::HighValue,
            expires_at,
            SafeLabel::new("approved fixture").unwrap(),
        )
    }

    fn fixture_delegated_permit(now: SystemTime) -> UsePermit {
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.fixture").unwrap();
        let executor = ExecutorRef::new("janus-run@fixture").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let descriptor = SecretDescriptor {
            name: SecretName::new("FIXTURE").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Fixture").unwrap(),
            scope: scope(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L2,
            allowed_uses: vec![profile_id.clone()],
            present: true,
        };
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: scope(),
            secret_ref: secret_ref.clone(),
            executor,
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            scope: scope(),
            secret_ref,
            profile_id,
            destination,
            purpose: Purpose::new("fixture delegation").unwrap(),
        };
        let mut grantor = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("janus-run@fixture").unwrap(),
            ),
            scope(),
        );
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("grantor").unwrap(),
        ));
        let mut delegate = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("janus-run@fixture").unwrap(),
            ),
            scope(),
        );
        delegate.agent = Some(Principal::new(
            PrincipalKind::AgentSession,
            PrincipalId::new("session:delegate").unwrap(),
        ));
        let policy = ProfilePolicy::new(vec![profile]);
        let mut audit = AuditWrite::accepting();
        let grant = DelegationPolicy::issue_use(
            &policy,
            &descriptor,
            &request,
            &grantor,
            &delegate,
            None,
            now,
            now + Duration::from_secs(30),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap();
        let context = DelegatedUseContext::from_grant(&grant);
        let mut issuer = PermitIssuer::new(&policy, &mut audit);
        issuer
            .issue_for_delegation(&request, &delegate, now, SecretClass::Normal, &context)
            .unwrap()
    }

    fn fixture_tombstone(
        secret_ref: &SecretRef,
        destroyed_at: SystemTime,
        retain_until: SystemTime,
    ) -> SecretTombstone {
        let descriptor = SecretDescriptor {
            name: SecretName::new("CANARY").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: scope(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::PendingDelete,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            present: false,
        };
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-cli").unwrap(),
            ),
            scope(),
        );
        let request = janus_core::SecretTombstoneRequest::new(
            secret_ref.clone(),
            SafeLabel::new("reviewed destroy record").unwrap(),
            destroyed_at,
            retain_until,
        );
        let mut audit = AuditWrite::accepting();
        TombstonePolicy::record(&descriptor, request, &principal, &mut audit).unwrap()
    }

    #[test]
    fn file_registry_round_trips_and_consumes_permit() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FilePermitRegistry::new(dir.path());
        let permit = fixture_permit(SystemTime::UNIX_EPOCH);
        let permit_id = permit.id().as_str().to_string();

        registry.store(&permit).unwrap();
        let rehydrated = registry.take(&permit_id).unwrap();

        assert_eq!(rehydrated, permit);
        assert!(matches!(
            registry.take(&permit_id),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_unknown_permit",
                ..
            })
        ));
    }

    #[test]
    fn file_registry_round_trips_delegated_permit_context() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FilePermitRegistry::new(dir.path());
        let permit = fixture_delegated_permit(SystemTime::UNIX_EPOCH);
        let permit_id = permit.id().as_str().to_string();

        registry.store(&permit).unwrap();
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join(format!("{permit_id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(record["version"], 5);
        assert_eq!(record["binding_version"], 1);
        assert!(record["delegation"].is_object());

        let rehydrated = registry.take(&permit_id).unwrap();
        assert_eq!(rehydrated, permit);
        assert_eq!(
            rehydrated.delegation().unwrap().delegation_id().as_str(),
            permit.delegation().unwrap().delegation_id().as_str()
        );
    }

    #[test]
    fn file_registry_rejects_path_like_permit_ids() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FilePermitRegistry::new(dir.path());

        let err = registry.take("use_../escape").unwrap_err();

        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_invalid_permit_id",
                ..
            }
        ));
    }

    #[test]
    fn pre_scope_permits_and_approvals_fail_closed_but_remain_revocable() {
        fn write_private(path: &Path, value: serde_json::Value) {
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        let permit_dir = tempfile::tempdir().unwrap();
        let permits = FilePermitRegistry::new(permit_dir.path());
        write_private(
            &permit_dir.path().join("use_legacy.json"),
            serde_json::json!({
                "version": 3,
                "permit_id": "use_legacy",
                "secret_ref": "sec_fixture",
                "profile_id": "profile.fixture",
                "destination": "deploy-api",
                "executor": "janus-run@fixture",
                "egress": "connector",
                "purpose": "legacy fixture",
                "approval": null,
                "principal_binding": "executor:janus-run@fixture|scope:legacy",
                "expires_at_unix_secs": 4102444800_u64,
                "expires_at_subsec_nanos": 0
            }),
        );
        assert!(matches!(
            permits.take("use_legacy"),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_stale_scope_binding",
                ..
            })
        ));

        let approval_dir = tempfile::tempdir().unwrap();
        let approvals = FileApprovalRegistry::new(approval_dir.path());
        write_private(
            &approval_dir.path().join("appr_legacy.json"),
            serde_json::json!({
                "version": 1,
                "approval_id": "appr_legacy",
                "secret_ref": "sec_fixture",
                "profile_id": "profile.fixture",
                "executor": "janus-run@fixture",
                "destination": "deploy-api",
                "class": "high_value",
                "egress": "connector",
                "purpose": "legacy fixture",
                "expires_at_unix_secs": 4102444800_u64,
                "expires_at_subsec_nanos": 0,
                "reason": "reviewed legacy fixture"
            }),
        );
        assert!(matches!(
            approvals.get("appr_legacy"),
            Err(JanusError::ApprovalInvalid {
                reason_code: "denied_stale_scope_binding",
                ..
            })
        ));
        let listed = approvals.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].approval_id.as_str(), "appr_legacy");
        assert_eq!(listed[0].scope_status(), "stale_unbound");
        approvals.revoke("appr_legacy").unwrap();
    }

    #[test]
    fn approval_registry_round_trips_lists_and_revokes_grants() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileApprovalRegistry::new(dir.path());
        let approval = fixture_approval(SystemTime::UNIX_EPOCH + Duration::from_secs(60));
        let approval_id = approval.id().as_str().to_string();

        registry.store(&approval).unwrap();
        let rehydrated = registry.get(&approval_id).unwrap();
        let listed = registry.list().unwrap();

        assert_eq!(rehydrated, approval);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].approval_id.as_str(), approval_id);
        assert_eq!(listed[0].scope_ref.as_ref(), Some(&approval.scope().scope));
        assert_eq!(listed[0].scope_status(), "exact");

        registry.revoke(&approval_id).unwrap();
        assert!(matches!(
            registry.get(&approval_id),
            Err(JanusError::ApprovalInvalid {
                reason_code: "denied_unknown_approval",
                ..
            })
        ));
    }

    #[test]
    fn approval_registry_rejects_path_like_approval_ids() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileApprovalRegistry::new(dir.path());

        let err = registry.get("appr_../escape").unwrap_err();

        assert!(matches!(
            err,
            JanusError::ApprovalInvalid {
                reason_code: "denied_invalid_approval_id",
                ..
            }
        ));
    }

    #[test]
    fn lifecycle_evidence_registry_merges_and_lists_records() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(dir.path());
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let other_ref = SecretRef::new("sec_other").unwrap();

        registry
            .record_declared(&secret_ref, UNIX_EPOCH + Duration::from_secs(50))
            .unwrap();
        registry
            .record_declared(&secret_ref, UNIX_EPOCH + Duration::from_secs(40))
            .unwrap();
        registry
            .record_used(&secret_ref, UNIX_EPOCH + Duration::from_secs(20))
            .unwrap();
        registry
            .record_used(&secret_ref, UNIX_EPOCH + Duration::from_secs(10))
            .unwrap();
        registry
            .record_rotated(&secret_ref, UNIX_EPOCH + Duration::from_secs(30))
            .unwrap();
        registry
            .record_used(&other_ref, UNIX_EPOCH + Duration::from_secs(5))
            .unwrap();

        let listed = registry.list().unwrap();

        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].secret_ref, secret_ref);
        assert_eq!(
            listed[0].declared_at,
            Some(UNIX_EPOCH + Duration::from_secs(40))
        );
        assert_eq!(
            listed[0].last_used_at,
            Some(UNIX_EPOCH + Duration::from_secs(20))
        );
        assert_eq!(
            listed[0].last_rotated_at,
            Some(UNIX_EPOCH + Duration::from_secs(30))
        );
        assert_eq!(listed[1].secret_ref, other_ref);
        assert_eq!(
            listed[1].last_used_at,
            Some(UNIX_EPOCH + Duration::from_secs(5))
        );
    }

    #[test]
    fn lifecycle_evidence_registry_rejects_path_like_refs() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileLifecycleEvidenceRegistry::new(dir.path());
        let secret_ref = SecretRef::new("sec_../escape").unwrap();

        let err = registry.record_used(&secret_ref, UNIX_EPOCH).unwrap_err();

        assert!(matches!(
            err,
            JanusError::InvalidIdentifier { kind: "secret_ref" }
        ));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn tombstone_registry_round_trips_lists_and_rejects_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path());
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-cli").unwrap(),
            ),
            scope(),
        );
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let other_ref = SecretRef::new("sec_other").unwrap();
        let destroyed_at = UNIX_EPOCH + Duration::from_secs(10);
        let retain_until = UNIX_EPOCH + Duration::from_secs(20);
        let tombstone = fixture_tombstone(&secret_ref, destroyed_at, retain_until);
        let other = fixture_tombstone(
            &other_ref,
            UNIX_EPOCH + Duration::from_secs(30),
            UNIX_EPOCH + Duration::from_secs(40),
        );

        TombstoneRegistry::record(&registry, &other, &principal).unwrap();
        TombstoneRegistry::record(&registry, &tombstone, &principal).unwrap();

        let rehydrated = TombstoneRegistry::get(&registry, &secret_ref).unwrap();
        assert_eq!(rehydrated.secret_ref, secret_ref);
        assert_eq!(rehydrated.reason.as_str(), "reviewed destroy record");
        assert_eq!(rehydrated.destroyed_at, destroyed_at);
        assert_eq!(rehydrated.retain_until, retain_until);
        assert_eq!(
            rehydrated.principal_binding,
            format!("executor:admin-cli|scope:{}", scope().as_str())
        );
        assert!(!format!("{rehydrated:?}").contains("expected-canary"));

        let listed = TombstoneRegistry::list(&registry).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].secret_ref.as_str(), "sec_fixture");
        assert_eq!(listed[1].secret_ref.as_str(), "sec_other");

        let err = TombstoneRegistry::record(&registry, &tombstone, &principal).unwrap_err();
        assert!(matches!(
            err,
            JanusError::StoreUnavailable { detail } if detail.contains("already exists")
        ));
    }

    #[test]
    fn tombstone_registry_rejects_path_like_refs() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileTombstoneRegistry::new(dir.path());
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-cli").unwrap(),
            ),
            scope(),
        );
        let secret_ref = SecretRef::new("sec_../escape").unwrap();
        let tombstone = fixture_tombstone(
            &secret_ref,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
        );

        let err = TombstoneRegistry::record(&registry, &tombstone, &principal).unwrap_err();

        assert!(matches!(
            err,
            JanusError::InvalidIdentifier { kind: "secret_ref" }
        ));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

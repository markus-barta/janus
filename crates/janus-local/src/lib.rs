//! Local filesystem integrations for Janus runtimes.
//!
//! This crate intentionally stores only value-free permit and approval
//! metadata. Permit ids, approval ids, and principal bindings remain
//! operationally sensitive, so files are created under private directories and
//! permit files are consumed with a rename-before-read single-use claim.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use janus_core::{
    ApprovalGrant, ApprovalGrantSnapshot, JanusError, JanusResult, UsePermit, UsePermitSnapshot,
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

    /// List all locally stored approval grants.
    fn list(&self) -> JanusResult<Vec<ApprovalGrant>>;

    /// Revoke one locally stored approval grant.
    fn revoke(&self, approval_id: &str) -> JanusResult<()>;
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
        let record = ApprovalGrantFileRecord::from(snapshot);
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

    fn list(&self) -> JanusResult<Vec<ApprovalGrant>> {
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
            approvals.push(read_approval(&path, approval_id)?);
        }
        approvals.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PermitFileRecord {
    version: u8,
    permit_id: String,
    secret_ref: String,
    profile_id: String,
    destination: String,
    executor: String,
    egress: Option<String>,
    purpose: Option<String>,
    approval: Option<ApprovalGrantFileRecord>,
    principal_binding: String,
    expires_at_unix_secs: u64,
    expires_at_subsec_nanos: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalGrantFileRecord {
    approval_id: String,
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

impl From<UsePermitSnapshot> for PermitFileRecord {
    fn from(snapshot: UsePermitSnapshot) -> Self {
        Self {
            version: 3,
            permit_id: snapshot.permit_id,
            secret_ref: snapshot.secret_ref,
            profile_id: snapshot.profile_id,
            destination: snapshot.destination,
            executor: snapshot.executor,
            egress: Some(snapshot.egress),
            purpose: Some(snapshot.purpose),
            approval: snapshot.approval.map(ApprovalGrantFileRecord::from),
            principal_binding: snapshot.principal_binding,
            expires_at_unix_secs: snapshot.expires_at_unix_secs,
            expires_at_subsec_nanos: snapshot.expires_at_subsec_nanos,
        }
    }
}

impl PermitFileRecord {
    fn into_snapshot(self) -> JanusResult<UsePermitSnapshot> {
        if !matches!(self.version, 1..=3) {
            return Err(JanusError::permit_invalid(
                "denied_unsupported_permit_record",
                "permit registry entry version is unsupported",
            ));
        }
        Ok(UsePermitSnapshot {
            permit_id: self.permit_id,
            secret_ref: self.secret_ref,
            profile_id: self.profile_id,
            destination: self.destination,
            executor: self.executor,
            egress: self.egress.unwrap_or_else(|| "declared_only".to_string()),
            purpose: self.purpose.unwrap_or_else(|| "legacy permit".to_string()),
            approval: self.approval.map(ApprovalGrantFileRecord::into_snapshot),
            principal_binding: self.principal_binding,
            expires_at_unix_secs: self.expires_at_unix_secs,
            expires_at_subsec_nanos: self.expires_at_subsec_nanos,
        })
    }
}

impl From<ApprovalGrantSnapshot> for ApprovalGrantFileRecord {
    fn from(snapshot: ApprovalGrantSnapshot) -> Self {
        Self {
            approval_id: snapshot.approval_id,
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
    fn into_snapshot(self) -> ApprovalGrantSnapshot {
        ApprovalGrantSnapshot {
            approval_id: self.approval_id,
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
        }
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
    ApprovalGrant::from_snapshot(record.into_snapshot()).map_err(|_| {
        JanusError::approval_invalid(
            "denied_malformed_approval",
            "approval registry entry is malformed",
        )
    })
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

fn store_unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use janus_core::{
        ApprovalGrant, AuditWrite, Destination, EgressMode, ExecutorRef, PermitIssuer, Principal,
        PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy, Purpose, SafeLabel,
        ScopeRef, SecretClass, SecretRef, TrustLevel, UseProfile, UseRequest,
    };

    use super::*;

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
            ScopeRef::new("janus/dev").unwrap(),
        );
        let profile = UseProfile {
            id: profile_id.clone(),
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
    fn approval_registry_round_trips_lists_and_revokes_grants() {
        let dir = tempfile::tempdir().unwrap();
        let registry = FileApprovalRegistry::new(dir.path());
        let approval = fixture_approval(SystemTime::UNIX_EPOCH + Duration::from_secs(60));
        let approval_id = approval.id().as_str().to_string();

        registry.store(&approval).unwrap();
        let rehydrated = registry.get(&approval_id).unwrap();
        let listed = registry.list().unwrap();

        assert_eq!(rehydrated, approval);
        assert_eq!(listed, vec![approval]);

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
}

//! Private local persistence for value-free delegation grants and revocations.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use janus_core::{
    DelegationAction, DelegationGrant, DelegationGrantSnapshotV1, DelegationId,
    DelegationRevocation, DelegationRevocationSnapshotV1, DelegationStatus, JanusError,
    JanusResult, ScopeRef, SecretClass, SecretLifecycle, SecretRef,
};

const MAX_DELEGATION_RECORDS: usize = 4_096;
const MAX_DELEGATION_FILE_BYTES: u64 = 32 * 1024;

/// Durable registry for exact delegation grants and immutable revocations.
pub trait DelegationRegistry {
    /// Store one new immutable grant.
    fn store(&self, grant: &DelegationGrant) -> JanusResult<()>;

    /// Load one grant and any immutable revocation evidence.
    fn get(&self, delegation_id: &str) -> JanusResult<DelegationRecord>;

    /// List bounded, value-free summaries in canonical id order.
    fn list(&self) -> JanusResult<Vec<DelegationListEntry>>;

    /// Persist immutable revocation evidence without deleting the grant.
    fn revoke(&self, revocation: &DelegationRevocation) -> JanusResult<()>;
}

/// Fail-closed delegation registry used when delegation is not configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopDelegationRegistry;

impl DelegationRegistry for NoopDelegationRegistry {
    fn store(&self, _grant: &DelegationGrant) -> JanusResult<()> {
        Err(unavailable("delegation registry is not configured"))
    }

    fn get(&self, _delegation_id: &str) -> JanusResult<DelegationRecord> {
        Err(unavailable("delegation registry is not configured"))
    }

    fn list(&self) -> JanusResult<Vec<DelegationListEntry>> {
        Ok(Vec::new())
    }

    fn revoke(&self, _revocation: &DelegationRevocation) -> JanusResult<()> {
        Err(unavailable("delegation registry is not configured"))
    }
}

/// One persisted grant plus optional immutable revocation evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationRecord {
    /// Exact delegation grant.
    pub grant: DelegationGrant,
    /// Revocation evidence when present.
    pub revocation: Option<DelegationRevocation>,
}

impl DelegationRecord {
    /// Current status at a supplied instant.
    pub fn status_at(&self, now: SystemTime) -> JanusResult<DelegationStatus> {
        self.grant.status_at(self.revocation.as_ref(), now)
    }
}

/// Redacted, value-free inventory row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationListEntry {
    /// Opaque delegation id.
    pub delegation_id: DelegationId,
    /// Opaque secret target.
    pub secret_ref: SecretRef,
    /// Opaque exact scope.
    pub scope_ref: ScopeRef,
    /// Closed delegated action.
    pub action: DelegationAction,
    /// Bound secret class.
    pub class: SecretClass,
    /// Bound lifecycle state.
    pub lifecycle: SecretLifecycle,
    /// Grant issue time.
    pub issued_at: SystemTime,
    /// Grant expiry time.
    pub expires_at: SystemTime,
    /// Revocation time when present.
    pub revoked_at: Option<SystemTime>,
}

impl DelegationListEntry {
    /// Current safe status text.
    pub fn status_at(&self, now: SystemTime) -> DelegationStatus {
        if self.revoked_at.is_some() {
            DelegationStatus::Revoked
        } else if now >= self.expires_at {
            DelegationStatus::Expired
        } else {
            DelegationStatus::Active
        }
    }
}

/// File-backed private delegation registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDelegationRegistry {
    dir: PathBuf,
}

impl FileDelegationRegistry {
    /// Build a registry rooted at one private directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Registry root.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        match fs::symlink_metadata(&self.dir) {
            Ok(metadata) => check_private_dir_metadata(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.dir)
                    .map_err(|_| unavailable("delegation registry unavailable"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                        .map_err(|_| unavailable("delegation registry permissions unavailable"))?;
                }
                let metadata = fs::symlink_metadata(&self.dir)
                    .map_err(|_| unavailable("delegation registry unavailable"))?;
                check_private_dir_metadata(&metadata)
            }
            Err(_) => Err(unavailable("delegation registry unavailable")),
        }
    }

    fn grant_path(&self, delegation_id: &str) -> JanusResult<PathBuf> {
        let id = DelegationId::from_opaque(delegation_id.to_string())?;
        Ok(self.dir.join(format!("{}.json", id.as_str())))
    }

    fn revocation_path(&self, delegation_id: &str) -> JanusResult<PathBuf> {
        let id = DelegationId::from_opaque(delegation_id.to_string())?;
        Ok(self.dir.join(format!("{}.revoked.json", id.as_str())))
    }

    fn read_grant(&self, delegation_id: &str) -> JanusResult<DelegationGrant> {
        let path = self.grant_path(delegation_id)?;
        check_private_file(&path, "delegation grant")?;
        let file = File::open(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                delegation_error("delegation_unknown", "delegation grant was not found")
            } else {
                unavailable("delegation grant is unavailable")
            }
        })?;
        let snapshot: DelegationGrantSnapshotV1 = serde_json::from_reader(BufReader::new(file))
            .map_err(|_| {
                delegation_error(
                    "delegation_record_malformed",
                    "delegation grant record is malformed",
                )
            })?;
        if snapshot.delegation_id != delegation_id {
            return Err(delegation_error(
                "delegation_record_mismatch",
                "delegation grant record does not match its path",
            ));
        }
        DelegationGrant::from_snapshot(snapshot).map_err(|_| {
            delegation_error(
                "delegation_record_malformed",
                "delegation grant record is malformed",
            )
        })
    }

    fn read_optional_revocation(
        &self,
        grant: &DelegationGrant,
    ) -> JanusResult<Option<DelegationRevocation>> {
        let path = self.revocation_path(grant.id().as_str())?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unavailable("delegation revocation is unavailable")),
        }
        check_private_file(&path, "delegation revocation")?;
        let file =
            File::open(&path).map_err(|_| unavailable("delegation revocation is unavailable"))?;
        let snapshot: DelegationRevocationSnapshotV1 =
            serde_json::from_reader(BufReader::new(file)).map_err(|_| {
                delegation_error(
                    "delegation_revocation_malformed",
                    "delegation revocation record is malformed",
                )
            })?;
        if snapshot.delegation_id != grant.id().as_str() {
            return Err(delegation_error(
                "delegation_revocation_mismatch",
                "delegation revocation does not match its grant",
            ));
        }
        let revocation = DelegationRevocation::from_snapshot(snapshot).map_err(|_| {
            delegation_error(
                "delegation_revocation_malformed",
                "delegation revocation record is malformed",
            )
        })?;
        grant
            .status_at(Some(&revocation), revocation.revoked_at())
            .map_err(|_| {
                delegation_error(
                    "delegation_revocation_malformed",
                    "delegation revocation record is malformed",
                )
            })?;
        Ok(Some(revocation))
    }
}

impl DelegationRegistry for FileDelegationRegistry {
    fn store(&self, grant: &DelegationGrant) -> JanusResult<()> {
        self.ensure_dir()?;
        let path = self.grant_path(grant.id().as_str())?;
        write_new_private_json(
            &path,
            &grant.snapshot(),
            "delegation_duplicate",
            "delegation grant already exists",
        )
    }

    fn get(&self, delegation_id: &str) -> JanusResult<DelegationRecord> {
        self.ensure_dir()?;
        let grant = self.read_grant(delegation_id)?;
        let revocation = self.read_optional_revocation(&grant)?;
        Ok(DelegationRecord { grant, revocation })
    }

    fn list(&self) -> JanusResult<Vec<DelegationListEntry>> {
        self.ensure_dir()?;
        let mut grants = BTreeSet::new();
        let mut revocations = BTreeSet::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|_| unavailable("failed to list delegation registry"))?;
        let mut file_count = 0usize;
        for entry in entries {
            let entry = entry.map_err(|_| unavailable("failed to list delegation entry"))?;
            file_count = file_count
                .checked_add(1)
                .ok_or_else(|| unavailable("delegation registry entry limit exceeded"))?;
            if file_count > MAX_DELEGATION_RECORDS * 2 {
                return Err(unavailable("delegation registry entry limit exceeded"));
            }
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| unavailable("delegation entry name is malformed"))?;
            if let Some(id) = name.strip_suffix(".revoked.json") {
                DelegationId::from_opaque(id.to_string())?;
                if !revocations.insert(id.to_string()) {
                    return Err(unavailable("delegation registry contains duplicates"));
                }
            } else if let Some(id) = name.strip_suffix(".json") {
                DelegationId::from_opaque(id.to_string())?;
                if !grants.insert(id.to_string()) {
                    return Err(unavailable("delegation registry contains duplicates"));
                }
            } else {
                return Err(unavailable(
                    "delegation registry contains an unsupported entry",
                ));
            }
        }
        if grants.len() > MAX_DELEGATION_RECORDS {
            return Err(unavailable("delegation registry entry limit exceeded"));
        }
        if revocations.iter().any(|id| !grants.contains(id)) {
            return Err(delegation_error(
                "delegation_orphan_revocation",
                "delegation revocation has no matching grant",
            ));
        }

        let mut rows = Vec::with_capacity(grants.len());
        for delegation_id in grants {
            let record = self.get(&delegation_id)?;
            rows.push(DelegationListEntry {
                delegation_id: record.grant.id().clone(),
                secret_ref: record.grant.scope().secret_ref.clone(),
                scope_ref: record.grant.scope().scope_ref.clone(),
                action: record.grant.scope().action,
                class: record.grant.scope().class,
                lifecycle: record.grant.scope().lifecycle,
                issued_at: record.grant.issued_at(),
                expires_at: record.grant.expires_at(),
                revoked_at: record
                    .revocation
                    .as_ref()
                    .map(DelegationRevocation::revoked_at),
            });
        }
        Ok(rows)
    }

    fn revoke(&self, revocation: &DelegationRevocation) -> JanusResult<()> {
        self.ensure_dir()?;
        let grant = self.read_grant(revocation.delegation_id().as_str())?;
        grant
            .status_at(Some(revocation), revocation.revoked_at())
            .map_err(|_| {
                delegation_error(
                    "delegation_revocation_mismatch",
                    "delegation revocation does not match its grant",
                )
            })?;
        let path = self.revocation_path(revocation.delegation_id().as_str())?;
        write_new_private_json(
            &path,
            &revocation.snapshot(),
            "delegation_already_revoked",
            "delegation revocation already exists",
        )
    }
}

fn check_private_dir_metadata(metadata: &fs::Metadata) -> JanusResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unavailable(
            "delegation registry path is not a private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(unavailable("delegation registry directory must be private"));
        }
    }
    Ok(())
}

fn check_private_file(path: &Path, kind: &'static str) -> JanusResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(delegation_error(
                "delegation_unknown",
                "delegation record was not found",
            ))
        }
        Err(_) => return Err(unavailable("delegation record is unavailable")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(delegation_error(
            "delegation_record_insecure",
            "delegation record is not a regular private file",
        ));
    }
    if metadata.len() > MAX_DELEGATION_FILE_BYTES {
        return Err(delegation_error(
            "delegation_record_oversized",
            "delegation record exceeds the reviewed byte limit",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(delegation_error(
                "delegation_record_insecure",
                "delegation record is not private",
            ));
        }
    }
    let _ = kind;
    Ok(())
}

fn write_new_private_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
    duplicate_reason: &'static str,
    duplicate_detail: &'static str,
) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(delegation_error(duplicate_reason, duplicate_detail))
        }
        Err(_) => return Err(unavailable("failed to create delegation record")),
    };
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| unavailable("failed to encode delegation record"))?;
    writer
        .write_all(b"\n")
        .map_err(|_| unavailable("failed to write delegation record"))?;
    writer
        .flush()
        .map_err(|_| unavailable("failed to flush delegation record"))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| unavailable("failed to sync delegation record"))?;
    #[cfg(unix)]
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable("failed to sync delegation registry"))?;
    Ok(())
}

fn delegation_error(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn unavailable(detail: &'static str) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use janus_core::{
        AuditWrite, DelegationPolicy, Destination, EgressMode, ExecutorRef, OwnerRef, Principal,
        PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy, Purpose, SafeLabel,
        SecretDescriptor, SecretName, TrustLevel, UseProfile, UseRequest,
    };

    use super::*;

    struct Fixture {
        descriptor: SecretDescriptor,
        profile: UseProfile,
        request: UseRequest,
        grantor: PrincipalChain,
        delegate: PrincipalChain,
    }

    fn fixture() -> Fixture {
        let scope = janus_core::ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.fixture").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let executor = ExecutorRef::new("runner-a").unwrap();
        let descriptor = SecretDescriptor {
            name: SecretName::new("FIXTURE").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Fixture").unwrap(),
            scope: scope.clone(),
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
            secret_ref,
            scope: scope.clone(),
            profile_id,
            destination,
            purpose: Purpose::new("deploy release").unwrap(),
        };
        let mut grantor = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope.clone(),
        );
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("grantor").unwrap(),
        ));
        let mut delegate = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope,
        );
        delegate.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("delegate").unwrap(),
        ));
        Fixture {
            descriptor,
            profile,
            request,
            grantor,
            delegate,
        }
    }

    fn grant(fixture: &Fixture, offset: u64) -> DelegationGrant {
        let mut request = fixture.request.clone();
        request.purpose = Purpose::new(format!("deploy release {offset}")).unwrap();
        DelegationPolicy::issue_use(
            &ProfilePolicy::new(vec![fixture.profile.clone()]),
            &fixture.descriptor,
            &request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10 + offset),
            UNIX_EPOCH + Duration::from_secs(610 + offset),
            SafeLabel::new("vacation coverage").unwrap(),
            &mut AuditWrite::accepting(),
        )
        .unwrap()
    }

    fn revocation(fixture: &Fixture, grant: &DelegationGrant) -> DelegationRevocation {
        DelegationPolicy::authorize_revocation(
            grant,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage ended").unwrap(),
            &mut AuditWrite::accepting(),
        )
        .unwrap()
    }

    #[test]
    fn registry_round_trips_restart_lists_and_preserves_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture();
        let first = grant(&fixture, 0);
        let second = grant(&fixture, 1);
        let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
        registry.store(&second).unwrap();
        registry.store(&first).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(registry.dir()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(registry.dir().join(format!("{}.json", first.id().as_str())))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let restarted = FileDelegationRegistry::new(registry.dir());
        let before = restarted.get(first.id().as_str()).unwrap();
        assert_eq!(before.grant, first);
        assert!(before.revocation.is_none());
        let listed = restarted.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].delegation_id < listed[1].delegation_id);

        let revocation = revocation(&fixture, &first);
        restarted.revoke(&revocation).unwrap();
        let after = restarted.get(first.id().as_str()).unwrap();
        assert_eq!(after.revocation, Some(revocation));
        assert_eq!(
            after
                .status_at(UNIX_EPOCH + Duration::from_secs(21))
                .unwrap(),
            DelegationStatus::Revoked
        );
        assert!(registry
            .dir()
            .join(format!("{}.json", first.id().as_str()))
            .exists());
        assert!(registry
            .dir()
            .join(format!("{}.revoked.json", first.id().as_str()))
            .exists());
    }

    #[test]
    fn registry_rejects_duplicate_grants_revocations_and_path_ids() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture();
        let grant = grant(&fixture, 0);
        let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
        registry.store(&grant).unwrap();
        assert!(matches!(
            registry.store(&grant),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_duplicate",
                ..
            })
        ));
        let revocation = revocation(&fixture, &grant);
        registry.revoke(&revocation).unwrap();
        assert!(matches!(
            registry.revoke(&revocation),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_already_revoked",
                ..
            })
        ));
        let error = registry.get("dlg_../../escape").unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("../../escape"));
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_symlink_insecure_corrupt_and_oversized_state() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture();
        let grant = grant(&fixture, 0);
        let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
        registry.store(&grant).unwrap();
        let path = registry.dir().join(format!("{}.json", grant.id().as_str()));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            registry.get(grant.id().as_str()),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_record_insecure",
                ..
            })
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"{malformed").unwrap();
        assert!(matches!(
            registry.get(grant.id().as_str()),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_record_malformed",
                ..
            })
        ));

        fs::write(&path, vec![b'x'; MAX_DELEGATION_FILE_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            registry.get(grant.id().as_str()),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_record_oversized",
                ..
            })
        ));

        fs::remove_file(&path).unwrap();
        symlink(temp.path().join("missing"), &path).unwrap();
        assert!(matches!(
            registry.get(grant.id().as_str()),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_record_insecure",
                ..
            })
        ));

        let symlink_root = temp.path().join("symlink-root");
        symlink(registry.dir(), &symlink_root).unwrap();
        let symlinked = FileDelegationRegistry::new(symlink_root);
        assert!(matches!(
            symlinked.list(),
            Err(JanusError::StoreUnavailable { .. })
        ));
    }

    #[test]
    fn malformed_record_errors_do_not_echo_file_canaries() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture();
        let grant = grant(&fixture, 0);
        let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
        registry.store(&grant).unwrap();
        let path = registry.dir().join(format!("{}.json", grant.id().as_str()));
        let canary = "delegation-record-secret-canary";
        fs::write(&path, format!("{{\"canary\":\"{canary}\"}}")).unwrap();
        let error = registry.get(grant.id().as_str()).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(canary));
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_orphan_revocation_evidence() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture();
        let stored = grant(&fixture, 0);
        let orphan = grant(&fixture, 1);
        let orphan_revocation = revocation(&fixture, &orphan);
        let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
        registry.store(&stored).unwrap();
        let path = registry
            .dir()
            .join(format!("{}.revoked.json", orphan.id().as_str()));
        fs::write(
            &path,
            serde_json::to_vec(&orphan_revocation.snapshot()).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            registry.list(),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_orphan_revocation",
                ..
            })
        ));
    }
}

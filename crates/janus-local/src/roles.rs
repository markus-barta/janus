//! Strict private persistence for role bindings and immutable revocations.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use janus_core::{
    authorize_role_action, DutyEvidence, JanusError, JanusResult, Permission, PrincipalChain,
    ProductMode, Role, RoleBinding, RoleBindingId, RoleBindingSnapshotV1, RoleBindingSourceKind,
    RoleDecisionInput, RolePolicyV1, RuntimeAction, SafeLabel, ScopeRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_ROLE_RECORDS: usize = 4_096;
const MAX_ROLE_FILE_BYTES: u64 = 32 * 1024;
const ROLE_REVOCATION_SNAPSHOT_VERSION: u8 = 1;

/// Checked authorization material loaded from the explicit runtime posture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedRoleAuthorization {
    /// Shared role policy restricted by the reviewed snapshot.
    pub policy: RolePolicyV1,
    /// Trusted durable bindings; revoked records have already been excluded.
    pub bindings: Vec<RoleBinding>,
}

/// Load the explicit runtime role posture.
///
/// `enforced` loads private durable bindings and a checked policy. The only
/// compatibility mode is the conspicuous `unsafe_disabled_dev`, and it is
/// rejected for production and enterprise product modes. Missing posture never
/// silently disables authorization.
pub fn load_role_authorization_from_env() -> JanusResult<Option<LoadedRoleAuthorization>> {
    let mode = env::var("JANUS_ROLE_AUTHORIZATION_MODE").map_err(|_| {
        role_error(
            "role_authorization_mode_missing",
            "set JANUS_ROLE_AUTHORIZATION_MODE to enforced or unsafe_disabled_dev",
        )
    })?;
    match mode.as_str() {
        "enforced" => {
            let root = required_env_path("JANUS_ROLE_BINDINGS_ROOT")?;
            let policy = match env::var_os("JANUS_ROLE_POLICY_FILE") {
                Some(path) if !path.is_empty() => {
                    let path = PathBuf::from(path);
                    let text = read_reviewed_policy(&path)?;
                    RolePolicyV1::parse_json(&text)?
                }
                _ => RolePolicyV1::embedded()?,
            };
            let bindings = FileRoleBindingRegistry::new(root).bindings()?;
            Ok(Some(LoadedRoleAuthorization { policy, bindings }))
        }
        "unsafe_disabled_dev" => {
            let product_mode = env::var("JANUS_PRODUCT_MODE")
                .ok()
                .map(|value| ProductMode::parse(&value))
                .transpose()?
                .unwrap_or(ProductMode::SelfHosted);
            if product_mode.requires_trusted_release() {
                return Err(role_error(
                    "unsafe_role_mode_forbidden",
                    "production and enterprise cannot disable role authorization",
                ));
            }
            Ok(None)
        }
        _ => Err(role_error(
            "role_authorization_mode_invalid",
            "role authorization mode is unsupported",
        )),
    }
}

/// Enforce one Rust runtime action from trusted durable bindings and write the
/// required value-free decision evidence. Returns loaded material so the same
/// checked context can be attached to broker permit issue/consume paths.
pub fn enforce_runtime_role_from_env(
    action: RuntimeAction,
    principal: &PrincipalChain,
    target_binding: Option<&str>,
    duties: &[DutyEvidence],
    now: SystemTime,
) -> JanusResult<Option<LoadedRoleAuthorization>> {
    let Some(authorization) = load_role_authorization_from_env()? else {
        return Ok(None);
    };
    let audit_path = required_env_path("JANUS_ROLE_AUDIT_FILE")?;
    let mut audit = crate::JsonlAuditSink::open(audit_path)?;
    let input = RoleDecisionInput {
        principal,
        permission: Permission::for_runtime_action(action),
        scope: &principal.scope,
        target_binding,
        resource_owner_fingerprint: None,
        resource_class: None,
        resource_lifecycle: None,
        approval_fingerprint: None,
        delegation_fingerprint: None,
        audit_available: true,
        duties,
        bindings: &authorization.bindings,
        now,
    };
    let decision = authorize_role_action(&authorization.policy, &input, &mut audit)?;
    if !decision.allowed {
        return Err(role_error(
            decision.reason_code,
            "role authorization denied runtime action",
        ));
    }
    Ok(Some(authorization))
}

fn required_env_path(key: &'static str) -> JanusResult<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            role_error(
                "role_authorization_config_missing",
                format!("{key} is required"),
            )
        })
}

fn read_reviewed_policy(path: &Path) -> JanusResult<String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable("role policy file is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err(unavailable("role policy file is invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(unavailable(
                "role policy file must not be mutable by group/world",
            ));
        }
    }
    fs::read_to_string(path).map_err(|_| unavailable("role policy file is unavailable"))
}

/// Current durable status of one binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleBindingStatus {
    /// Binding start is still in the future.
    NotYetValid,
    /// Binding is valid now.
    Active,
    /// Binding reached its immutable expiry.
    Expired,
    /// An immutable revocation exists.
    Revoked,
}

impl RoleBindingStatus {
    /// Stable operator output text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotYetValid => "not_yet_valid",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// Strict immutable durable revocation record.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBindingRevocationSnapshotV1 {
    /// Exact snapshot version.
    pub schema_version: u8,
    /// Revoked opaque binding id.
    pub binding_id: String,
    /// Revocation time as seconds since Unix epoch.
    pub revoked_at_unix_secs: u64,
    /// Opaque fingerprint of the revoking principal binding.
    pub revoker_fingerprint: String,
    /// Curated value-free reason.
    pub reason: String,
    /// Integrity id over every preceding field.
    pub integrity_id: String,
}

/// One durable binding plus optional immutable revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleBindingRecord {
    /// Exact role binding.
    pub binding: RoleBinding,
    /// Immutable revocation evidence when present.
    pub revocation: Option<RoleBindingRevocationSnapshotV1>,
}

impl RoleBindingRecord {
    /// Evaluate status at one instant.
    pub fn status_at(&self, now: SystemTime) -> RoleBindingStatus {
        if self.revocation.is_some() {
            RoleBindingStatus::Revoked
        } else if now < self.binding.valid_from() {
            RoleBindingStatus::NotYetValid
        } else if now >= self.binding.expires_at() {
            RoleBindingStatus::Expired
        } else {
            RoleBindingStatus::Active
        }
    }
}

/// Value-free bounded inventory row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleBindingListEntry {
    /// Opaque binding id.
    pub binding_id: RoleBindingId,
    /// Closed role.
    pub role: Role,
    /// Opaque exact scope.
    pub scope: ScopeRef,
    /// Whether an exact service/workload target is present.
    pub targeted: bool,
    /// Binding start.
    pub valid_from: SystemTime,
    /// Binding expiry.
    pub expires_at: SystemTime,
    /// Checked binding provenance kind.
    pub source_kind: RoleBindingSourceKind,
    /// Current durable status.
    pub status: RoleBindingStatus,
}

/// Durable registry for exact role bindings and immutable revocations.
pub trait RoleBindingRegistry {
    /// Store one new immutable role binding.
    fn store(&self, binding: &RoleBinding) -> JanusResult<()>;
    /// Read one exact binding and any revocation.
    fn get(&self, binding_id: &str) -> JanusResult<RoleBindingRecord>;
    /// Load every binding in stable id order for trusted policy evaluation.
    fn bindings(&self) -> JanusResult<Vec<RoleBinding>>;
    /// List bounded value-free summaries.
    fn list(&self, now: SystemTime) -> JanusResult<Vec<RoleBindingListEntry>>;
    /// Add immutable revocation evidence without deleting the binding.
    fn revoke(
        &self,
        binding_id: &str,
        revoker_binding: &str,
        reason: &SafeLabel,
        revoked_at: SystemTime,
    ) -> JanusResult<()>;
}

/// Fail-closed registry used when durable authorization is not configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRoleBindingRegistry;

impl RoleBindingRegistry for NoopRoleBindingRegistry {
    fn store(&self, _binding: &RoleBinding) -> JanusResult<()> {
        Err(unavailable("role binding registry is not configured"))
    }

    fn get(&self, _binding_id: &str) -> JanusResult<RoleBindingRecord> {
        Err(unavailable("role binding registry is not configured"))
    }

    fn bindings(&self) -> JanusResult<Vec<RoleBinding>> {
        Err(unavailable("role binding registry is not configured"))
    }

    fn list(&self, _now: SystemTime) -> JanusResult<Vec<RoleBindingListEntry>> {
        Err(unavailable("role binding registry is not configured"))
    }

    fn revoke(
        &self,
        _binding_id: &str,
        _revoker_binding: &str,
        _reason: &SafeLabel,
        _revoked_at: SystemTime,
    ) -> JanusResult<()> {
        Err(unavailable("role binding registry is not configured"))
    }
}

/// File-backed strict private role binding registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRoleBindingRegistry {
    dir: PathBuf,
}

impl FileRoleBindingRegistry {
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
            Ok(metadata) => check_private_dir(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.dir)
                    .map_err(|_| unavailable("role binding registry unavailable"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).map_err(
                        |_| unavailable("role binding registry permissions unavailable"),
                    )?;
                }
                let metadata = fs::symlink_metadata(&self.dir)
                    .map_err(|_| unavailable("role binding registry unavailable"))?;
                check_private_dir(&metadata)
            }
            Err(_) => Err(unavailable("role binding registry unavailable")),
        }
    }

    fn binding_path(&self, binding_id: &str) -> JanusResult<PathBuf> {
        let id = RoleBindingId::from_opaque(binding_id.to_string())?;
        Ok(self.dir.join(format!("{}.json", id.as_str())))
    }

    fn revocation_path(&self, binding_id: &str) -> JanusResult<PathBuf> {
        let id = RoleBindingId::from_opaque(binding_id.to_string())?;
        Ok(self.dir.join(format!("{}.revoked.json", id.as_str())))
    }

    fn read_binding(&self, binding_id: &str) -> JanusResult<RoleBinding> {
        let path = self.binding_path(binding_id)?;
        let snapshot: RoleBindingSnapshotV1 = read_private_json(&path, "role binding")?;
        if snapshot.binding_id != binding_id {
            return Err(role_error(
                "role_binding_record_mismatch",
                "role binding record does not match its path",
            ));
        }
        RoleBinding::from_snapshot(snapshot).map_err(|_| {
            role_error(
                "role_binding_record_malformed",
                "role binding record is malformed",
            )
        })
    }

    fn read_optional_revocation(
        &self,
        binding: &RoleBinding,
    ) -> JanusResult<Option<RoleBindingRevocationSnapshotV1>> {
        let path = self.revocation_path(binding.id().as_str())?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unavailable("role binding revocation is unavailable")),
        }
        let revocation: RoleBindingRevocationSnapshotV1 =
            read_private_json(&path, "role binding revocation")?;
        validate_revocation(&revocation, binding.id())?;
        Ok(Some(revocation))
    }

    fn inventory(&self) -> JanusResult<BTreeSet<String>> {
        self.ensure_dir()?;
        let mut bindings = BTreeSet::new();
        let mut revocations = BTreeSet::new();
        let mut count = 0usize;
        for entry in fs::read_dir(&self.dir)
            .map_err(|_| unavailable("failed to list role binding registry"))?
        {
            let entry = entry.map_err(|_| unavailable("failed to list role binding entry"))?;
            count = count
                .checked_add(1)
                .ok_or_else(|| unavailable("role binding entry limit exceeded"))?;
            if count > MAX_ROLE_RECORDS * 2 {
                return Err(unavailable("role binding entry limit exceeded"));
            }
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| unavailable("role binding entry name is malformed"))?
                .to_string();
            if let Some(id) = name.strip_suffix(".revoked.json") {
                RoleBindingId::from_opaque(id.to_string())?;
                if !revocations.insert(id.to_string()) {
                    return Err(unavailable("role binding registry contains duplicates"));
                }
            } else if let Some(id) = name.strip_suffix(".json") {
                RoleBindingId::from_opaque(id.to_string())?;
                if !bindings.insert(id.to_string()) {
                    return Err(unavailable("role binding registry contains duplicates"));
                }
            } else {
                return Err(unavailable(
                    "role binding registry contains an unsupported entry",
                ));
            }
        }
        if bindings.len() > MAX_ROLE_RECORDS {
            return Err(unavailable("role binding entry limit exceeded"));
        }
        if revocations.iter().any(|id| !bindings.contains(id)) {
            return Err(role_error(
                "role_binding_orphan_revocation",
                "role binding registry contains an orphan revocation",
            ));
        }
        Ok(bindings)
    }
}

impl RoleBindingRegistry for FileRoleBindingRegistry {
    fn store(&self, binding: &RoleBinding) -> JanusResult<()> {
        self.ensure_dir()?;
        for id in self.inventory()? {
            let record = self.get(&id)?;
            if record.revocation.is_some() {
                continue;
            }
            let existing = record.binding;
            let validity_overlaps = binding.valid_from() < existing.expires_at()
                && existing.valid_from() < binding.expires_at();
            let same_actor_scope = binding.principal_binding() == existing.principal_binding()
                && binding.scope() == existing.scope();
            let target_distinguishes = binding.target_binding().is_some()
                && existing.target_binding().is_some()
                && binding.target_binding() != existing.target_binding();
            if validity_overlaps && same_actor_scope && !target_distinguishes {
                return Err(role_error(
                    "role_binding_overlap_conflict",
                    "overlapping effective role bindings are ambiguous",
                ));
            }
        }
        let path = self.binding_path(binding.id().as_str())?;
        let snapshot = binding.snapshot()?;
        write_new_private_json(
            &path,
            &snapshot,
            "role_binding_duplicate",
            "role binding already exists",
        )
    }

    fn get(&self, binding_id: &str) -> JanusResult<RoleBindingRecord> {
        self.ensure_dir()?;
        let binding = self.read_binding(binding_id)?;
        let revocation = self.read_optional_revocation(&binding)?;
        Ok(RoleBindingRecord {
            binding,
            revocation,
        })
    }

    fn bindings(&self) -> JanusResult<Vec<RoleBinding>> {
        self.inventory()?
            .into_iter()
            .map(|id| {
                let record = self.get(&id)?;
                if record.revocation.is_some() {
                    return Ok(None);
                }
                Ok(Some(record.binding))
            })
            .filter_map(|result| match result {
                Ok(Some(binding)) => Some(Ok(binding)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn list(&self, now: SystemTime) -> JanusResult<Vec<RoleBindingListEntry>> {
        self.inventory()?
            .into_iter()
            .map(|id| {
                let record = self.get(&id)?;
                Ok(RoleBindingListEntry {
                    binding_id: record.binding.id().clone(),
                    role: record.binding.role(),
                    scope: record.binding.scope().clone(),
                    targeted: record.binding.target_binding().is_some(),
                    valid_from: record.binding.valid_from(),
                    expires_at: record.binding.expires_at(),
                    source_kind: record.binding.source().kind,
                    status: record.status_at(now),
                })
            })
            .collect()
    }

    fn revoke(
        &self,
        binding_id: &str,
        revoker_binding: &str,
        reason: &SafeLabel,
        revoked_at: SystemTime,
    ) -> JanusResult<()> {
        self.ensure_dir()?;
        let binding = self.read_binding(binding_id)?;
        if revoker_binding.is_empty() || revoker_binding.len() > 4 * 1024 {
            return Err(JanusError::InvalidIdentifier {
                kind: "revoker_binding",
            });
        }
        let revoked_at_unix_secs = revoked_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| role_error("role_revocation_time_invalid", "revocation time is invalid"))?
            .as_secs();
        let revoker_fingerprint = fingerprint("janus-role-revoker-v1", revoker_binding);
        let integrity_id = revocation_integrity_id(
            binding.id().as_str(),
            revoked_at_unix_secs,
            &revoker_fingerprint,
            reason.as_str(),
        );
        let snapshot = RoleBindingRevocationSnapshotV1 {
            schema_version: ROLE_REVOCATION_SNAPSHOT_VERSION,
            binding_id: binding.id().as_str().to_string(),
            revoked_at_unix_secs,
            revoker_fingerprint,
            reason: reason.as_str().to_string(),
            integrity_id,
        };
        write_new_private_json(
            &self.revocation_path(binding.id().as_str())?,
            &snapshot,
            "role_binding_already_revoked",
            "role binding already has revocation evidence",
        )
    }
}

fn validate_revocation(
    snapshot: &RoleBindingRevocationSnapshotV1,
    binding_id: &RoleBindingId,
) -> JanusResult<()> {
    if snapshot.schema_version != ROLE_REVOCATION_SNAPSHOT_VERSION
        || snapshot.binding_id != binding_id.as_str()
        || SafeLabel::new(snapshot.reason.clone()).is_err()
        || !valid_fingerprint(&snapshot.revoker_fingerprint)
        || snapshot.integrity_id
            != revocation_integrity_id(
                &snapshot.binding_id,
                snapshot.revoked_at_unix_secs,
                &snapshot.revoker_fingerprint,
                &snapshot.reason,
            )
    {
        return Err(role_error(
            "role_binding_revocation_malformed",
            "role binding revocation record is malformed",
        ));
    }
    Ok(())
}

fn read_private_json<T>(path: &Path, label: &'static str) -> JanusResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    check_private_file(path, label)?;
    let file = File::open(path).map_err(|_| unavailable("role binding record is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable("role binding record metadata is unavailable"))?;
    if metadata.len() == 0 || metadata.len() > MAX_ROLE_FILE_BYTES {
        return Err(role_error(
            "role_binding_record_malformed",
            "role binding record size is invalid",
        ));
    }
    serde_json::from_reader(BufReader::new(file)).map_err(|_| {
        role_error(
            "role_binding_record_malformed",
            "role binding record is malformed",
        )
    })
}

fn write_new_private_json<T: Serialize>(
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
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            role_error(duplicate_reason, duplicate_detail)
        } else {
            unavailable("role binding record cannot be created")
        }
    })?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| unavailable("role binding record cannot be encoded"))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|_| unavailable("role binding record cannot be written"))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| unavailable("role binding record cannot be synchronized"))
}

fn check_private_dir(metadata: &fs::Metadata) -> JanusResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unavailable("role binding registry path is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(unavailable("role binding registry must be private"));
        }
    }
    Ok(())
}

fn check_private_file(path: &Path, label: &'static str) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            role_error("role_binding_unknown", format!("{label} was not found"))
        } else {
            unavailable("role binding record is unavailable")
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unavailable("role binding record must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(unavailable("role binding record must be private"));
        }
    }
    Ok(())
}

fn revocation_integrity_id(
    binding_id: &str,
    revoked_at_unix_secs: u64,
    revoker_fingerprint: &str,
    reason: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-role-revocation-v1");
    hash_field(&mut hasher, binding_id);
    hasher.update(revoked_at_unix_secs.to_be_bytes());
    hash_field(&mut hasher, revoker_fingerprint);
    hash_field(&mut hasher, reason);
    format!("rrv_{}", hex::encode(&hasher.finalize()[..12]))
}

fn fingerprint(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain);
    hash_field(&mut hasher, value);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn role_error(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        EnvironmentId, OrganizationId, Principal, PrincipalChain, PrincipalId, PrincipalKind,
        ProjectId, RepositoryId, RoleBindingSource, ScopePathV1,
    };
    use std::sync::Mutex;
    use std::time::Duration;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const ROLE_ENV: &[&str] = &[
        "JANUS_ROLE_AUTHORIZATION_MODE",
        "JANUS_ROLE_BINDINGS_ROOT",
        "JANUS_ROLE_POLICY_FILE",
        "JANUS_ROLE_AUDIT_FILE",
        "JANUS_PRODUCT_MODE",
    ];

    struct EnvGuard(Vec<(String, Option<String>)>);

    impl EnvGuard {
        fn clear() -> Self {
            let saved = ROLE_ENV
                .iter()
                .map(|key| ((*key).to_string(), env::var(key).ok()))
                .collect();
            for key in ROLE_ENV {
                env::remove_var(key);
            }
            Self(saved)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn fixture_binding(role: Role) -> RoleBinding {
        let scope = ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("test").unwrap(),
        )
        .scope_ref();
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("role-fixture").unwrap(),
            ),
            scope.clone(),
        );
        RoleBinding::issue(
            principal.binding_key(),
            scope,
            role,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(100),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "review-1").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn restart_round_trip_expiry_and_immutable_revocation_are_fail_closed() {
        let root = TempDir::new().unwrap();
        let binding = fixture_binding(Role::Operator);
        let registry_root = root.path().join("roles");
        FileRoleBindingRegistry::new(&registry_root)
            .store(&binding)
            .unwrap();

        let restarted = FileRoleBindingRegistry::new(&registry_root);
        assert_eq!(
            restarted
                .get(binding.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(20)),
            RoleBindingStatus::Active
        );
        assert_eq!(
            restarted
                .get(binding.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(100)),
            RoleBindingStatus::Expired
        );
        restarted
            .revoke(
                binding.id().as_str(),
                "security-admin",
                &SafeLabel::new("access ended").unwrap(),
                UNIX_EPOCH + Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(
            restarted
                .get(binding.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(31)),
            RoleBindingStatus::Revoked
        );
        assert!(restarted
            .revoke(
                binding.id().as_str(),
                "security-admin",
                &SafeLabel::new("duplicate").unwrap(),
                UNIX_EPOCH + Duration::from_secs(32),
            )
            .is_err());
        assert!(restarted.bindings().unwrap().is_empty());
    }

    #[test]
    fn corruption_unknown_schema_and_integrity_tamper_are_denied() {
        let root = TempDir::new().unwrap();
        let registry = FileRoleBindingRegistry::new(root.path().join("roles"));
        let binding = fixture_binding(Role::Viewer);
        registry.store(&binding).unwrap();
        let path = registry.binding_path(binding.id().as_str()).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(registry.get(binding.id().as_str()).is_err());

        value["schema_version"] = serde_json::json!(1);
        value["role"] = serde_json::json!("operator");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(registry.get(binding.id().as_str()).is_err());

        value["unknown"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(registry.get(binding.id().as_str()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_public_permissions_are_denied() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let parent = TempDir::new().unwrap();
        let real = parent.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = parent.path().join("linked");
        symlink(&real, &linked).unwrap();
        assert!(FileRoleBindingRegistry::new(&linked).bindings().is_err());

        let registry = FileRoleBindingRegistry::new(&real);
        let binding = fixture_binding(Role::Viewer);
        registry.store(&binding).unwrap();
        let path = registry.binding_path(binding.id().as_str()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry.get(binding.id().as_str()).is_err());
    }

    #[test]
    fn orphan_revocation_and_unsupported_entries_block_inventory() {
        let root = TempDir::new().unwrap();
        let registry = FileRoleBindingRegistry::new(root.path().join("roles"));
        let binding = fixture_binding(Role::Viewer);
        registry.store(&binding).unwrap();
        fs::write(registry.dir().join("unexpected"), b"x").unwrap();
        assert!(registry.list(SystemTime::now()).is_err());
    }

    #[test]
    fn overlapping_effective_bindings_are_rejected_but_exact_targets_can_differ() {
        let root = TempDir::new().unwrap();
        let registry = FileRoleBindingRegistry::new(root.path().join("roles"));
        let viewer = fixture_binding(Role::Viewer);
        registry.store(&viewer).unwrap();

        let conflicting = RoleBinding::issue(
            viewer.principal_binding().to_string(),
            viewer.scope().clone(),
            Role::Operator,
            None,
            viewer.valid_from(),
            viewer.expires_at(),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "review-2").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            registry.store(&conflicting),
            Err(JanusError::PolicyDenied {
                reason_code: "role_binding_overlap_conflict",
                ..
            })
        ));

        let target_root = TempDir::new().unwrap();
        let targeted = FileRoleBindingRegistry::new(target_root.path().join("roles"));
        for (target, source) in [("service:a", "review-a"), ("service:b", "review-b")] {
            let binding = RoleBinding::issue(
                viewer.principal_binding().to_string(),
                viewer.scope().clone(),
                Role::ServiceAdmin,
                Some(target.to_string()),
                viewer.valid_from(),
                viewer.expires_at(),
                RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, source).unwrap(),
            )
            .unwrap();
            targeted.store(&binding).unwrap();
        }
        assert_eq!(targeted.bindings().unwrap().len(), 2);
    }

    #[test]
    fn runtime_posture_requires_explicit_mode_and_forbids_unsafe_trusted_modes() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::clear();
        assert!(matches!(
            load_role_authorization_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "role_authorization_mode_missing",
                ..
            })
        ));

        env::set_var("JANUS_ROLE_AUTHORIZATION_MODE", "unsafe_disabled_dev");
        env::set_var("JANUS_PRODUCT_MODE", "self_hosted");
        assert_eq!(load_role_authorization_from_env().unwrap(), None);
        env::set_var("JANUS_PRODUCT_MODE", "production");
        assert!(matches!(
            load_role_authorization_from_env(),
            Err(JanusError::PolicyDenied {
                reason_code: "unsafe_role_mode_forbidden",
                ..
            })
        ));
    }

    #[test]
    fn enforced_runtime_loads_only_registry_bindings_and_writes_decision_audit() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::clear();
        let root = TempDir::new().unwrap();
        let registry_root = root.path().join("roles");
        let audit_root = root.path().join("audit");
        fs::create_dir(&audit_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&audit_root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let audit_path = audit_root.join("role-audit.jsonl");
        let binding = fixture_binding(Role::Viewer);
        FileRoleBindingRegistry::new(&registry_root)
            .store(&binding)
            .unwrap();
        env::set_var("JANUS_ROLE_AUTHORIZATION_MODE", "enforced");
        env::set_var("JANUS_ROLE_BINDINGS_ROOT", &registry_root);
        env::set_var("JANUS_ROLE_AUDIT_FILE", &audit_path);

        let loaded = load_role_authorization_from_env().unwrap().unwrap();
        assert_eq!(loaded.bindings, vec![binding.clone()]);

        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("role-fixture").unwrap(),
            ),
            binding.scope().clone(),
        );
        let authorized = enforce_runtime_role_from_env(
            RuntimeAction::WardenDescribeSecret,
            &principal,
            None,
            &[],
            UNIX_EPOCH + Duration::from_secs(20),
        )
        .unwrap();
        assert!(authorized.is_some());
        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("role.check"));
    }
}

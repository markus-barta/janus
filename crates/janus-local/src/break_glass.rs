//! Strict private append-only persistence for emergency authority lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use janus_core::{
    BreakGlassActivation, BreakGlassActivationId, BreakGlassActivationSnapshotV1,
    BreakGlassAttempt, BreakGlassAttemptId, BreakGlassAttemptSnapshotV1, BreakGlassCompletion,
    BreakGlassCompletionId, BreakGlassCompletionSnapshotV1, BreakGlassRequest, BreakGlassRequestId,
    BreakGlassRequestSnapshotV1, BreakGlassReview, BreakGlassReviewId, BreakGlassReviewSnapshotV1,
    BreakGlassRevocation, JanusError, JanusResult, Permission, ScopeRef, SecretRef,
};
use serde::{de::DeserializeOwned, Serialize};

const MAX_RECORDS: usize = 16_384;
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Durable lifecycle state computed from immutable records and current time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakGlassStatus {
    PendingApproval,
    Active,
    Expired,
    Revoked,
    ReviewRequired,
    ReviewClosed,
}

impl BreakGlassStatus {
    /// Stable operator output text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingApproval => "pending_approval",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::ReviewRequired => "review_required",
            Self::ReviewClosed => "review_closed",
        }
    }
}

/// Complete durable facts for one approved activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakGlassRecord {
    pub request: BreakGlassRequest,
    pub activation: BreakGlassActivation,
    pub revocation: Option<BreakGlassRevocation>,
    pub attempts: Vec<BreakGlassAttempt>,
    pub completion: Option<BreakGlassCompletion>,
    pub review: Option<BreakGlassReview>,
}

impl BreakGlassRecord {
    /// Compute fail-closed current lifecycle state.
    pub fn status_at(&self, now: SystemTime) -> BreakGlassStatus {
        if self.review.is_some() {
            BreakGlassStatus::ReviewClosed
        } else if self.completion.is_some() || self.attempts.iter().any(BreakGlassAttempt::allowed)
        {
            BreakGlassStatus::ReviewRequired
        } else if self.revocation.is_some() {
            BreakGlassStatus::Revoked
        } else if self.activation.is_expired_at(now) {
            BreakGlassStatus::Expired
        } else {
            BreakGlassStatus::Active
        }
    }
}

/// Bounded value-free lifecycle inventory row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakGlassListEntry {
    pub request_id: BreakGlassRequestId,
    pub activation_id: Option<BreakGlassActivationId>,
    pub scope: ScopeRef,
    pub permission: Permission,
    pub target: SecretRef,
    pub expires_at: SystemTime,
    pub status: BreakGlassStatus,
    pub attempt_count: usize,
    pub review_required: bool,
}

/// Append-only durable break-glass registry.
pub trait BreakGlassRegistry {
    fn store_request(&self, request: &BreakGlassRequest) -> JanusResult<()>;
    fn get_request(&self, request_id: &str) -> JanusResult<BreakGlassRequest>;
    fn store_activation(&self, activation: &BreakGlassActivation) -> JanusResult<()>;
    fn get(&self, activation_id: &str) -> JanusResult<BreakGlassRecord>;
    fn record_attempt(&self, attempt: &BreakGlassAttempt) -> JanusResult<()>;
    fn record_completion(&self, completion: &BreakGlassCompletion) -> JanusResult<()>;
    fn record_revocation(&self, revocation: &BreakGlassRevocation) -> JanusResult<()>;
    fn record_review(&self, review: &BreakGlassReview) -> JanusResult<()>;
    fn list(&self, now: SystemTime) -> JanusResult<Vec<BreakGlassListEntry>>;
}

/// Strict file-backed registry. Every transition creates a new `0600` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileBreakGlassRegistry {
    dir: PathBuf,
}

#[derive(Default)]
struct Inventory {
    requests: BTreeSet<String>,
    activations: BTreeSet<String>,
    revocations: BTreeSet<String>,
    attempts: BTreeSet<String>,
    completions: BTreeSet<String>,
    reviews: BTreeSet<String>,
}

impl FileBreakGlassRegistry {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> JanusResult<()> {
        match fs::symlink_metadata(&self.dir) {
            Ok(metadata) => check_private_dir(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.dir)
                    .map_err(|_| unavailable("break-glass registry unavailable"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                        .map_err(|_| unavailable("break-glass registry permissions unavailable"))?;
                }
                check_private_dir(
                    &fs::symlink_metadata(&self.dir)
                        .map_err(|_| unavailable("break-glass registry unavailable"))?,
                )
            }
            Err(_) => Err(unavailable("break-glass registry unavailable")),
        }
    }

    fn path(&self, id: &str, kind: &'static str) -> JanusResult<PathBuf> {
        match kind {
            "request" => {
                BreakGlassRequestId::from_opaque(id.to_string())?;
            }
            "activation" | "revocation" => {
                BreakGlassActivationId::from_opaque(id.to_string())?;
            }
            "attempt" => {
                BreakGlassAttemptId::from_opaque(id.to_string())?;
            }
            "completion" => {
                BreakGlassCompletionId::from_opaque(id.to_string())?;
            }
            "review" => {
                BreakGlassReviewId::from_opaque(id.to_string())?;
            }
            _ => return Err(malformed("unsupported break-glass record kind")),
        }
        Ok(self.dir.join(format!("{id}.{kind}.json")))
    }

    fn inventory(&self) -> JanusResult<Inventory> {
        self.ensure_dir()?;
        let mut out = Inventory::default();
        let mut count = 0usize;
        for entry in fs::read_dir(&self.dir)
            .map_err(|_| unavailable("failed to list break-glass registry"))?
        {
            let entry = entry.map_err(|_| unavailable("failed to list break-glass entry"))?;
            count = count
                .checked_add(1)
                .ok_or_else(|| unavailable("break-glass entry limit exceeded"))?;
            if count > MAX_RECORDS {
                return Err(unavailable("break-glass entry limit exceeded"));
            }
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| unavailable("break-glass entry name is malformed"))?
                .to_string();
            let recognized = [
                (".request.json", "request", &mut out.requests),
                (".activation.json", "activation", &mut out.activations),
                (".revocation.json", "revocation", &mut out.revocations),
                (".attempt.json", "attempt", &mut out.attempts),
                (".completion.json", "completion", &mut out.completions),
                (".review.json", "review", &mut out.reviews),
            ]
            .into_iter()
            .find_map(|(suffix, kind, set)| {
                name.strip_suffix(suffix)
                    .map(|id| (id.to_string(), kind, set))
            });
            let Some((id, kind, set)) = recognized else {
                return Err(unavailable(
                    "break-glass registry contains an unsupported entry",
                ));
            };
            self.path(&id, kind)?;
            if !set.insert(id) {
                return Err(malformed("break-glass registry contains duplicates"));
            }
        }
        self.validate_inventory(&out)?;
        Ok(out)
    }

    fn validate_inventory(&self, inv: &Inventory) -> JanusResult<()> {
        let mut activation_requests = BTreeSet::new();
        for id in &inv.activations {
            let snapshot: BreakGlassActivationSnapshotV1 =
                read_private_json(&self.path(id, "activation")?)?;
            if snapshot.activation_id != *id || !inv.requests.contains(&snapshot.request_id) {
                return Err(malformed("break-glass activation is orphaned"));
            }
            if !activation_requests.insert(snapshot.request_id) {
                return Err(malformed("break-glass request has multiple approvals"));
            }
        }
        if inv
            .revocations
            .iter()
            .any(|id| !inv.activations.contains(id))
        {
            return Err(malformed("break-glass revocation is orphaned"));
        }

        let mut attempt_activation = BTreeMap::new();
        for id in &inv.attempts {
            let snapshot: BreakGlassAttemptSnapshotV1 =
                read_private_json(&self.path(id, "attempt")?)?;
            if snapshot.attempt_id != *id || !inv.activations.contains(&snapshot.activation_id) {
                return Err(malformed("break-glass attempt is orphaned"));
            }
            BreakGlassAttempt::from_snapshot(snapshot.clone())?;
            attempt_activation.insert(id.clone(), snapshot.activation_id);
        }

        let mut completion_by_activation = BTreeMap::new();
        for id in &inv.completions {
            let snapshot: BreakGlassCompletionSnapshotV1 =
                read_private_json(&self.path(id, "completion")?)?;
            if snapshot.completion_id != *id
                || attempt_activation.get(&snapshot.attempt_id) != Some(&snapshot.activation_id)
            {
                return Err(malformed("break-glass completion is orphaned"));
            }
            BreakGlassCompletion::from_snapshot(snapshot.clone())?;
            if completion_by_activation
                .insert(snapshot.activation_id, id.clone())
                .is_some()
            {
                return Err(malformed("break-glass activation has multiple completions"));
            }
        }

        let mut reviewed = BTreeSet::new();
        for id in &inv.reviews {
            let snapshot: BreakGlassReviewSnapshotV1 =
                read_private_json(&self.path(id, "review")?)?;
            if snapshot.review_id != *id
                || completion_by_activation.get(&snapshot.activation_id)
                    != Some(&snapshot.completion_id)
                || !reviewed.insert(snapshot.activation_id.clone())
            {
                return Err(malformed("break-glass review is orphaned or duplicated"));
            }
            BreakGlassReview::from_snapshot(snapshot)?;
        }
        Ok(())
    }

    fn activation_for_request(
        &self,
        inv: &Inventory,
        request_id: &str,
    ) -> JanusResult<Option<String>> {
        let mut found = None;
        for id in &inv.activations {
            let snapshot: BreakGlassActivationSnapshotV1 =
                read_private_json(&self.path(id, "activation")?)?;
            if snapshot.request_id == request_id && found.replace(id.clone()).is_some() {
                return Err(malformed("break-glass request has multiple approvals"));
            }
        }
        Ok(found)
    }
}

impl BreakGlassRegistry for FileBreakGlassRegistry {
    fn store_request(&self, request: &BreakGlassRequest) -> JanusResult<()> {
        self.ensure_dir()?;
        write_new_private_json(
            &self.path(request.id().as_str(), "request")?,
            &request.snapshot()?,
            "break_glass_request_duplicate",
        )
    }

    fn get_request(&self, request_id: &str) -> JanusResult<BreakGlassRequest> {
        self.ensure_dir()?;
        let snapshot: BreakGlassRequestSnapshotV1 =
            read_private_json(&self.path(request_id, "request")?)?;
        if snapshot.request_id != request_id {
            return Err(malformed("break-glass request path mismatch"));
        }
        BreakGlassRequest::from_snapshot(snapshot)
            .map_err(|_| malformed("break-glass request is malformed"))
    }

    fn store_activation(&self, activation: &BreakGlassActivation) -> JanusResult<()> {
        let inv = self.inventory()?;
        let request_id = activation.request().id().as_str();
        if self.get_request(request_id)? != *activation.request()
            || self.activation_for_request(&inv, request_id)?.is_some()
        {
            return Err(malformed(
                "break-glass request is mismatched or already approved",
            ));
        }
        write_new_private_json(
            &self.path(activation.id().as_str(), "activation")?,
            &activation.snapshot()?,
            "break_glass_activation_duplicate",
        )
    }

    fn get(&self, activation_id: &str) -> JanusResult<BreakGlassRecord> {
        let inv = self.inventory()?;
        if !inv.activations.contains(activation_id) {
            return Err(unknown("break-glass activation was not found"));
        }
        let activation_snapshot: BreakGlassActivationSnapshotV1 =
            read_private_json(&self.path(activation_id, "activation")?)?;
        let request = self.get_request(&activation_snapshot.request_id)?;
        let activation = BreakGlassActivation::from_snapshot(request.clone(), activation_snapshot)?;

        let revocation = if inv.revocations.contains(activation_id) {
            Some(BreakGlassRevocation::from_snapshot(read_private_json(
                &self.path(activation_id, "revocation")?,
            )?)?)
        } else {
            None
        };
        let mut attempts = Vec::new();
        for id in &inv.attempts {
            let snapshot: BreakGlassAttemptSnapshotV1 =
                read_private_json(&self.path(id, "attempt")?)?;
            if snapshot.activation_id == activation_id {
                attempts.push(BreakGlassAttempt::from_snapshot(snapshot)?);
            }
        }
        let mut completion = None;
        for id in &inv.completions {
            let snapshot: BreakGlassCompletionSnapshotV1 =
                read_private_json(&self.path(id, "completion")?)?;
            if snapshot.activation_id == activation_id
                && completion
                    .replace(BreakGlassCompletion::from_snapshot(snapshot)?)
                    .is_some()
            {
                return Err(malformed("break-glass activation has multiple completions"));
            }
        }
        let mut review = None;
        for id in &inv.reviews {
            let snapshot: BreakGlassReviewSnapshotV1 =
                read_private_json(&self.path(id, "review")?)?;
            if snapshot.activation_id == activation_id
                && review
                    .replace(BreakGlassReview::from_snapshot(snapshot)?)
                    .is_some()
            {
                return Err(malformed("break-glass activation has multiple reviews"));
            }
        }
        Ok(BreakGlassRecord {
            request,
            activation,
            revocation,
            attempts,
            completion,
            review,
        })
    }

    fn record_attempt(&self, attempt: &BreakGlassAttempt) -> JanusResult<()> {
        if self.get(attempt.activation_id().as_str())?.review.is_some() {
            return Err(malformed("reviewed break-glass activation is closed"));
        }
        write_new_private_json(
            &self.path(attempt.id().as_str(), "attempt")?,
            &attempt.snapshot()?,
            "break_glass_attempt_duplicate",
        )
    }

    fn record_completion(&self, completion: &BreakGlassCompletion) -> JanusResult<()> {
        let record = self.get(completion.activation_id().as_str())?;
        let snapshot = completion.snapshot()?;
        if record.completion.is_some()
            || !record
                .attempts
                .iter()
                .any(|attempt| attempt.id().as_str() == snapshot.attempt_id && attempt.allowed())
        {
            return Err(malformed(
                "break-glass completion is duplicate or lacks an admitted attempt",
            ));
        }
        write_new_private_json(
            &self.path(completion.id().as_str(), "completion")?,
            &snapshot,
            "break_glass_completion_duplicate",
        )
    }

    fn record_revocation(&self, revocation: &BreakGlassRevocation) -> JanusResult<()> {
        let record = self.get(revocation.activation_id().as_str())?;
        if record.revocation.is_some() || record.review.is_some() {
            return Err(malformed(
                "break-glass activation is already revoked or closed",
            ));
        }
        write_new_private_json(
            &self.path(revocation.activation_id().as_str(), "revocation")?,
            &revocation.snapshot()?,
            "break_glass_revocation_duplicate",
        )
    }

    fn record_review(&self, review: &BreakGlassReview) -> JanusResult<()> {
        let record = self.get(review.activation_id().as_str())?;
        let snapshot = review.snapshot()?;
        let completion_matches = match record.completion.as_ref() {
            Some(completion) => completion.id().as_str() == snapshot.completion_id,
            None => false,
        };
        if record.review.is_some() || !completion_matches {
            return Err(malformed(
                "break-glass review is duplicate or lacks exact completion",
            ));
        }
        write_new_private_json(
            &self.path(review.id().as_str(), "review")?,
            &snapshot,
            "break_glass_review_duplicate",
        )
    }

    fn list(&self, now: SystemTime) -> JanusResult<Vec<BreakGlassListEntry>> {
        let inv = self.inventory()?;
        let mut rows = Vec::with_capacity(inv.requests.len());
        for request_id in &inv.requests {
            let request = self.get_request(request_id)?;
            let activation_id = self.activation_for_request(&inv, request_id)?;
            let (status, attempts, review_required) = match activation_id.as_deref() {
                Some(id) => {
                    let record = self.get(id)?;
                    let status = record.status_at(now);
                    (
                        status,
                        record.attempts.len(),
                        status == BreakGlassStatus::ReviewRequired,
                    )
                }
                None if now >= request.expires_at() => (BreakGlassStatus::Expired, 0, false),
                None => (BreakGlassStatus::PendingApproval, 0, false),
            };
            rows.push(BreakGlassListEntry {
                request_id: request.id().clone(),
                activation_id: activation_id
                    .map(BreakGlassActivationId::from_opaque)
                    .transpose()?,
                scope: request.scope().clone(),
                permission: request.permission(),
                target: request.target().clone(),
                expires_at: request.expires_at(),
                status,
                attempt_count: attempts,
                review_required,
            });
        }
        Ok(rows)
    }
}

fn read_private_json<T: DeserializeOwned>(path: &Path) -> JanusResult<T> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            unknown("break-glass record was not found")
        } else {
            unavailable("break-glass record is unavailable")
        }
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err(unavailable(
            "break-glass record must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(unavailable("break-glass record must be private"));
        }
    }
    serde_json::from_reader(BufReader::new(
        File::open(path).map_err(|_| unavailable("break-glass record is unavailable"))?,
    ))
    .map_err(|_| malformed("break-glass record is malformed"))
}

fn write_new_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    duplicate_reason: &'static str,
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
            JanusError::policy_denied(duplicate_reason, "break-glass record already exists")
        } else {
            unavailable("break-glass record cannot be created")
        }
    })?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| unavailable("break-glass record cannot be encoded"))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|_| unavailable("break-glass record cannot be written"))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| unavailable("break-glass record cannot be synchronized"))
}

fn check_private_dir(metadata: &fs::Metadata) -> JanusResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unavailable("break-glass registry path is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(unavailable("break-glass registry must be private"));
        }
    }
    Ok(())
}

fn malformed(detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied("break_glass_record_malformed", detail)
}
fn unknown(detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied("break_glass_unknown", detail)
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
        AuditWrite, BreakGlassCompletionOutcome, BreakGlassReviewClosure, EnvironmentId,
        OrganizationId, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProjectId,
        RepositoryId, Role, RoleBinding, RoleBindingSource, RoleBindingSourceKind, SafeLabel,
        ScopePathV1,
    };
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::TempDir;

    fn scope() -> ScopeRef {
        ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("prod").unwrap(),
        )
        .scope_ref()
    }
    fn principal(id: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(id).unwrap()),
            scope(),
        )
    }
    fn activation() -> (BreakGlassActivation, PrincipalChain) {
        let beneficiary = principal("beneficiary");
        let eligibility = RoleBinding::issue(
            beneficiary.binding_key(),
            scope(),
            Role::BreakGlassAdmin,
            None,
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(1_000),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "eligibility").unwrap(),
        )
        .unwrap();
        let request = BreakGlassRequest::request(
            &eligibility,
            &principal("activator"),
            Permission::ManagedRun,
            SecretRef::new("sec_emergency").unwrap(),
            SafeLabel::new("incident response").unwrap(),
            UNIX_EPOCH + Duration::from_secs(10),
            Duration::from_secs(300),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        (
            BreakGlassActivation::approve(
                request,
                &principal("approver"),
                UNIX_EPOCH + Duration::from_secs(20),
                &mut AuditWrite::accepting(),
            )
            .unwrap(),
            beneficiary,
        )
    }

    #[test]
    fn append_only_lifecycle_survives_restart_and_requires_review() {
        let root = TempDir::new().unwrap();
        let registry = FileBreakGlassRegistry::new(root.path().join("break-glass"));
        let (activation, beneficiary) = activation();
        registry.store_request(activation.request()).unwrap();
        registry.store_activation(&activation).unwrap();
        let attempt = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::ManagedRun,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(30),
            None,
            false,
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        registry.record_attempt(&attempt).unwrap();
        let completion = BreakGlassCompletion::complete(
            &activation,
            &attempt,
            &beneficiary,
            BreakGlassCompletionOutcome::Succeeded,
            UNIX_EPOCH + Duration::from_secs(31),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        registry.record_completion(&completion).unwrap();

        let restarted = FileBreakGlassRegistry::new(registry.dir());
        assert_eq!(
            restarted
                .get(activation.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(32)),
            BreakGlassStatus::ReviewRequired
        );
        let review = BreakGlassReview::review(
            &activation,
            &completion,
            &principal("independent-reviewer"),
            SafeLabel::new("expected action only").unwrap(),
            SafeLabel::new("none required").unwrap(),
            BreakGlassReviewClosure::ClosedNoFindings,
            UNIX_EPOCH + Duration::from_secs(40),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        restarted.record_review(&review).unwrap();
        assert_eq!(
            restarted
                .get(activation.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(41)),
            BreakGlassStatus::ReviewClosed
        );
    }

    #[test]
    fn revocation_expiry_and_denied_attempt_survive_restart() {
        let root = TempDir::new().unwrap();
        let registry = FileBreakGlassRegistry::new(root.path().join("break-glass"));
        let (activation, beneficiary) = activation();
        registry.store_request(activation.request()).unwrap();
        registry.store_activation(&activation).unwrap();
        let revocation = BreakGlassRevocation::revoke(
            &activation,
            &principal("revoker"),
            SafeLabel::new("incident contained").unwrap(),
            UNIX_EPOCH + Duration::from_secs(25),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        registry.record_revocation(&revocation).unwrap();
        let denied = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::ManagedRun,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(30),
            Some(&revocation),
            false,
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        registry.record_attempt(&denied).unwrap();
        let record = FileBreakGlassRegistry::new(registry.dir())
            .get(activation.id().as_str())
            .unwrap();
        assert_eq!(
            record.status_at(UNIX_EPOCH + Duration::from_secs(30)),
            BreakGlassStatus::Revoked
        );
        assert_eq!(record.attempts.len(), 1);
        assert!(!record.attempts[0].allowed());

        let other_root = TempDir::new().unwrap();
        let other = FileBreakGlassRegistry::new(other_root.path().join("break-glass"));
        other.store_request(activation.request()).unwrap();
        other.store_activation(&activation).unwrap();
        assert_eq!(
            FileBreakGlassRegistry::new(other.dir())
                .get(activation.id().as_str())
                .unwrap()
                .status_at(UNIX_EPOCH + Duration::from_secs(400)),
            BreakGlassStatus::Expired
        );
    }

    #[cfg(unix)]
    #[test]
    fn corruption_unknown_entries_symlinks_and_public_files_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = TempDir::new().unwrap();
        let registry = FileBreakGlassRegistry::new(root.path().join("break-glass"));
        let (activation, _) = activation();
        registry.store_request(activation.request()).unwrap();
        registry.store_activation(&activation).unwrap();
        let path = registry
            .path(activation.request().id().as_str(), "request")
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry.get(activation.id().as_str()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(registry.dir().join("unknown"), b"x").unwrap();
        assert!(registry.list(SystemTime::now()).is_err());

        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.path().join("linked");
        symlink(&real, &linked).unwrap();
        assert!(FileBreakGlassRegistry::new(linked)
            .list(SystemTime::now())
            .is_err());
    }
}

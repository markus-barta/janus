use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use janus_core::{
    audit_integrity_hash, AuditAction, AuditEvent, AuditIntegrityInput, AuditOutcome, AuditSink,
    DelegatedUseContext, DelegatedUseContextSnapshotV1, JanusError, JanusResult, SafeLabel,
    SecretRef, Severity,
};
use serde::{Deserialize, Serialize};

const AUDIT_RECORD_VERSION: u8 = 1;
const GENESIS_HASH: &str = "genesis";

/// Recovery state observed while opening a durable audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecovery {
    /// Last fully persisted sequence, or zero for an empty log.
    pub last_sequence: u64,
    /// Last verified event hash, or `genesis` for an empty log.
    pub last_event_hash: String,
    /// Unterminated tail bytes discarded during deterministic recovery.
    pub truncated_tail_bytes: u64,
}

/// Private append-only JSONL audit sink with hash-chain recovery.
///
/// `open` validates every complete record before accepting new events. An
/// unterminated tail is never parsed as history: it is discarded after the
/// complete prefix validates and the truncation is persisted before append
/// resumes.
pub struct JsonlAuditSink {
    path: PathBuf,
    writer: Box<dyn DurableAuditWriter + Send>,
    _lock_file: Option<File>,
    last_sequence: u64,
    last_event_hash: String,
    recovery: AuditRecovery,
    poisoned: bool,
}

/// Exclusive read-only verification lock used while snapshotting an offline log.
pub(crate) struct VerifiedAuditLock {
    _file: File,
}

/// Lock and verify a complete private audit chain without recovering or mutating it.
pub(crate) fn lock_verified_audit_for_snapshot(path: &Path) -> JanusResult<VerifiedAuditLock> {
    reject_symlink(path)?;
    if !path.exists() {
        return Err(audit_unavailable("audit log is unavailable"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| audit_unavailable("audit log is unavailable"))?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| audit_unavailable("audit log is already in use"))?;
    ensure_private_regular_file(path, true)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| audit_unavailable("audit log verification read failed"))?;
    if bytes.last().is_some_and(|byte| *byte != b'\n') {
        return Err(audit_unavailable("audit log has an incomplete record"));
    }
    verify_complete_records(&bytes)?;
    Ok(VerifiedAuditLock { _file: file })
}

impl JsonlAuditSink {
    /// Open or create a private JSONL log and recover its verified chain head.
    pub fn open(path: impl Into<PathBuf>) -> JanusResult<Self> {
        let path = path.into();
        ensure_private_parent(&path)?;
        reject_symlink(&path)?;
        let path_existed = path.exists();

        let mut file = open_recovery_file(&path)?;
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| audit_unavailable("audit log is already in use"))?;
        ensure_private_regular_file(&path, path_existed)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| audit_unavailable("audit log recovery read failed"))?;

        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let (last_sequence, last_event_hash) = verify_complete_records(&bytes[..complete_len])?;
        let truncated_tail_bytes = (bytes.len() - complete_len) as u64;
        if truncated_tail_bytes > 0 {
            file.set_len(complete_len as u64)
                .map_err(|_| audit_unavailable("audit log tail recovery failed"))?;
            file.sync_all()
                .map_err(|_| audit_unavailable("audit log tail recovery persistence failed"))?;
        }
        let writer = FileAuditWriter(open_append_file(&path)?);
        let recovery = AuditRecovery {
            last_sequence,
            last_event_hash: last_event_hash.clone(),
            truncated_tail_bytes,
        };
        Ok(Self {
            path,
            writer: Box::new(writer),
            _lock_file: Some(file),
            last_sequence,
            last_event_hash,
            recovery,
            poisoned: false,
        })
    }

    /// Audit log path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verified recovery state captured when the sink opened.
    pub fn recovery(&self) -> &AuditRecovery {
        &self.recovery
    }

    /// Most recently persisted sequence in this process.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Most recently persisted event hash in this process.
    pub fn last_event_hash(&self) -> &str {
        &self.last_event_hash
    }

    #[cfg(test)]
    fn with_test_writer(writer: impl DurableAuditWriter + Send + 'static) -> Self {
        let recovery = AuditRecovery {
            last_sequence: 0,
            last_event_hash: GENESIS_HASH.to_string(),
            truncated_tail_bytes: 0,
        };
        Self {
            path: PathBuf::from("<test-audit-log>"),
            writer: Box::new(writer),
            _lock_file: None,
            last_sequence: 0,
            last_event_hash: GENESIS_HASH.to_string(),
            recovery,
            poisoned: false,
        }
    }

    fn poison(&mut self, detail: &'static str) -> JanusError {
        self.poisoned = true;
        audit_unavailable(detail)
    }
}

impl AuditSink for JsonlAuditSink {
    fn record(&mut self, mut event: AuditEvent) -> JanusResult<()> {
        if self.poisoned {
            return Err(audit_unavailable(
                "audit log unavailable after persistence failure",
            ));
        }
        if event.value_returned {
            return Err(self.poison("audit log rejected value-bearing event"));
        }

        let sequence = self
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| self.poison("audit log sequence exhausted"))?;
        event.seal_integrity(sequence, self.last_event_hash.clone());
        let event_hash = event
            .event_hash
            .clone()
            .ok_or_else(|| self.poison("audit log integrity sealing failed"))?;
        let record = JsonlAuditRecord::from_event(&event)?;
        record.verify(sequence, &self.last_event_hash)?;
        let mut encoded =
            serde_json::to_vec(&record).map_err(|_| self.poison("audit log encoding failed"))?;
        encoded.push(b'\n');

        if self.writer.write_all(&encoded).is_err() {
            return Err(self.poison("audit log write failed"));
        }
        if self.writer.flush().is_err() {
            return Err(self.poison("audit log flush failed"));
        }
        if self.writer.sync_data().is_err() {
            return Err(self.poison("audit log persistence failed"));
        }

        self.last_sequence = sequence;
        self.last_event_hash = event_hash;
        Ok(())
    }
}

trait DurableAuditWriter {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
    fn sync_data(&mut self) -> std::io::Result<()>;
}

struct FileAuditWriter(File);

impl DurableAuditWriter for FileAuditWriter {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_all(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }

    fn sync_data(&mut self) -> std::io::Result<()> {
        self.0.sync_data()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JsonlAuditRecord {
    version: u8,
    action: String,
    outcome: String,
    reason_code: String,
    severity: String,
    secret_ref: Option<String>,
    principal_binding: String,
    sequence: u64,
    prev_hash: String,
    event_hash: String,
    value_returned: bool,
    evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegation: Option<DelegatedUseContextSnapshotV1>,
}

impl JsonlAuditRecord {
    fn from_event(event: &AuditEvent) -> JanusResult<Self> {
        Ok(Self {
            version: AUDIT_RECORD_VERSION,
            action: event.action.as_str().to_string(),
            outcome: event.outcome.as_str().to_string(),
            reason_code: event.reason_code.to_string(),
            severity: event.severity.as_str().to_string(),
            secret_ref: event
                .secret_ref
                .as_ref()
                .map(|secret_ref| secret_ref.as_str().to_string()),
            principal_binding: event.principal_binding.clone(),
            sequence: event
                .sequence
                .ok_or_else(|| audit_unavailable("audit log event sequence missing"))?,
            prev_hash: event
                .prev_hash
                .clone()
                .ok_or_else(|| audit_unavailable("audit log previous hash missing"))?,
            event_hash: event
                .event_hash
                .clone()
                .ok_or_else(|| audit_unavailable("audit log event hash missing"))?,
            value_returned: event.value_returned,
            evidence: event
                .evidence
                .as_ref()
                .map(|evidence| evidence.as_str().to_string()),
            delegation: event.delegation.as_ref().map(DelegatedUseContext::snapshot),
        })
    }

    fn verify(&self, expected_sequence: u64, expected_prev_hash: &str) -> JanusResult<()> {
        if self.version != AUDIT_RECORD_VERSION
            || AuditAction::parse(&self.action).is_none()
            || AuditOutcome::parse(&self.outcome).is_none()
            || Severity::parse(&self.severity).is_none()
            || !valid_reason_code(&self.reason_code)
            || self.principal_binding.trim().is_empty()
            || self.principal_binding.trim().len() != self.principal_binding.len()
            || self.sequence != expected_sequence
            || self.prev_hash != expected_prev_hash
            || self.value_returned
        {
            return Err(audit_unavailable("audit log integrity validation failed"));
        }
        if let Some(secret_ref) = &self.secret_ref {
            SecretRef::new(secret_ref.clone())
                .map_err(|_| audit_unavailable("audit log integrity validation failed"))?;
        }
        if let Some(evidence) = &self.evidence {
            SafeLabel::new(evidence.clone())
                .map_err(|_| audit_unavailable("audit log integrity validation failed"))?;
        }
        let delegation = self
            .delegation
            .clone()
            .map(DelegatedUseContext::from_snapshot)
            .transpose()
            .map_err(|_| audit_unavailable("audit log integrity validation failed"))?;

        let expected_hash = audit_integrity_hash(AuditIntegrityInput {
            action: &self.action,
            outcome: &self.outcome,
            reason_code: &self.reason_code,
            severity: &self.severity,
            secret_ref: self.secret_ref.as_deref(),
            principal_binding: &self.principal_binding,
            sequence: self.sequence,
            prev_hash: &self.prev_hash,
            value_returned: self.value_returned,
            evidence: self.evidence.as_deref(),
            delegation: delegation.as_ref(),
        });
        if self.event_hash != expected_hash {
            return Err(audit_unavailable("audit log integrity validation failed"));
        }
        Ok(())
    }
}

fn verify_complete_records(bytes: &[u8]) -> JanusResult<(u64, String)> {
    if bytes.is_empty() {
        return Ok((0, GENESIS_HASH.to_string()));
    }
    let records = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut last_sequence = 0_u64;
    let mut last_event_hash = GENESIS_HASH.to_string();
    for line in records.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(audit_unavailable("audit log integrity validation failed"));
        }
        let record: JsonlAuditRecord = serde_json::from_slice(line)
            .map_err(|_| audit_unavailable("audit log integrity validation failed"))?;
        let expected_sequence = last_sequence
            .checked_add(1)
            .ok_or_else(|| audit_unavailable("audit log sequence exhausted"))?;
        record.verify(expected_sequence, &last_event_hash)?;
        last_sequence = record.sequence;
        last_event_hash = record.event_hash;
    }
    Ok((last_sequence, last_event_hash))
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
}

fn ensure_private_parent(path: &Path) -> JanusResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).map_err(|_| audit_unavailable("audit log directory unavailable"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| audit_unavailable("audit log directory unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(audit_unavailable("audit log directory is not private"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_existed {
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(audit_unavailable("audit log directory must be private"));
            }
        } else {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| audit_unavailable("audit log directory permissions unavailable"))?;
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(audit_unavailable("audit log path is not a regular file"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(audit_unavailable("audit log unavailable")),
    }
}

fn open_recovery_file(path: &Path) -> JanusResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| audit_unavailable("audit log unavailable"))
}

fn open_append_file(path: &Path) -> JanusResult<File> {
    OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| audit_unavailable("audit log unavailable"))
}

fn ensure_private_regular_file(path: &Path, path_existed: bool) -> JanusResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| audit_unavailable("audit log unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(audit_unavailable("audit log path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !path_existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| audit_unavailable("audit log permissions unavailable"))?;
        }
        let mode = fs::metadata(path)
            .map_err(|_| audit_unavailable("audit log unavailable"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(audit_unavailable("audit log file must be private"));
        }
    }
    Ok(())
}

fn audit_unavailable(detail: &'static str) -> JanusError {
    JanusError::AuditUnavailable {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;
    use std::io;
    use std::time::{Duration, SystemTime};

    use janus_core::{
        AuditWrite, DelegatedUseContext, DelegationPolicy, Destination, EgressMode, ExecutorRef,
        ManifestCatalog, OwnerRef, PermitIssuer, Principal, PrincipalChain, PrincipalId,
        PrincipalKind, ProfileId, ProfilePolicy, Purpose, SafeLabel, ScopePathV1, ScopeRef,
        SecretBroker, SecretClass, SecretDescriptor, SecretLifecycle, SecretMeta, SecretName,
        SecretRef, TrustLevel, UseProfile, UseRequest,
    };
    use janus_mock::MockStore;
    use proptest::prelude::*;
    use proptest::test_runner::FileFailurePersistence;
    use serde_json::Value;
    use tempfile::tempdir;

    #[derive(Clone)]
    struct RedactedAuditInput(Vec<u8>);

    impl fmt::Debug for RedactedAuditInput {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("<redacted-generated-audit-input>")
        }
    }

    fn property_env_usize(name: &str, fallback: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(fallback)
    }

    fn property_config(local_cases: u32) -> ProptestConfig {
        ProptestConfig {
            cases: property_env_usize("JANUS_PROPERTY_CASES", local_cases as usize)
                .try_into()
                .unwrap_or(u32::MAX),
            max_shrink_iters: property_env_usize("JANUS_PROPERTY_MAX_SHRINK_ITERATIONS", 4096)
                .try_into()
                .unwrap_or(u32::MAX),
            failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proptest-regressions/audit.txt"
            )))),
            ..ProptestConfig::default()
        }
    }

    fn arbitrary_audit_input() -> impl Strategy<Value = RedactedAuditInput> {
        let max_bytes = property_env_usize("JANUS_PROPERTY_MAX_INPUT_BYTES", 8192);
        proptest::collection::vec(any::<u8>(), 0..=max_bytes).prop_map(RedactedAuditInput)
    }

    proptest! {
        #![proptest_config(property_config(64))]

        #[test]
        fn security_property_audit_jsonl_rejects_arbitrary_complete_records_without_echo(
            input in arbitrary_audit_input(),
        ) {
            let canary = b"SENSITIVE_AUDIT_CANARY_MUST_NOT_ESCAPE";
            let mut line = canary.to_vec();
            line.extend_from_slice(&input.0);
            line.push(b'\n');
            let error = verify_complete_records(&line).unwrap_err();
            let rendered = format!("{error:?} {error}");
            prop_assert!(!rendered.contains("SENSITIVE_AUDIT_CANARY_MUST_NOT_ESCAPE"));
        }

        #[test]
        fn security_property_audit_jsonl_recovers_only_unterminated_tail(
            tail in proptest::collection::vec(1_u8..=255, 1..=256)
                .prop_filter("tail must not contain a record delimiter", |tail| !tail.contains(&b'\n')),
        ) {
            let dir = tempdir().unwrap();
            let path = dir.path().join("audit/events.jsonl");
            {
                let mut sink = JsonlAuditSink::open(&path).unwrap();
                sink.record(event("property-prefix")).unwrap();
            }
            OpenOptions::new().append(true).open(&path).unwrap().write_all(&tail).unwrap();
            let recovered = JsonlAuditSink::open(&path).unwrap();
            prop_assert_eq!(recovered.recovery().last_sequence, 1);
            prop_assert_eq!(recovered.recovery().truncated_tail_bytes, tail.len() as u64);
        }
    }

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "audit-test")
            .unwrap()
            .scope_ref()
    }

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope(),
        )
    }

    fn event(reason: &'static str) -> AuditEvent {
        AuditEvent::new(
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            reason,
            Severity::Notice,
            None,
            &principal(),
        )
    }

    fn delegated_context() -> DelegatedUseContext {
        let secret_ref = SecretRef::new("sec_audit_fixture").unwrap();
        let profile_id = ProfileId::new("profile.audit").unwrap();
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let descriptor = SecretDescriptor {
            name: SecretName::new("AUDIT_FIXTURE").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Audit fixture").unwrap(),
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
            secret_ref,
            scope: scope(),
            profile_id,
            destination,
            purpose: Purpose::new("audit fixture").unwrap(),
        };
        let mut grantor = principal();
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("grantor").unwrap(),
        ));
        let mut delegate = principal();
        delegate.agent = Some(Principal::new(
            PrincipalKind::AgentSession,
            PrincipalId::new("session:delegate").unwrap(),
        ));
        let mut audit = AuditWrite::accepting();
        let grant = DelegationPolicy::issue_use(
            &ProfilePolicy::new(vec![profile]),
            &descriptor,
            &request,
            &grantor,
            &delegate,
            None,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap();
        DelegatedUseContext::from_grant(&grant)
    }

    fn records(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn restart_preserves_monotonic_sequence_and_hash_continuity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit/events.jsonl");
        let first_hash = {
            let mut sink = JsonlAuditSink::open(&path).unwrap();
            sink.record(event("first")).unwrap();
            assert_eq!(sink.last_sequence(), 1);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(path.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            sink.last_event_hash().to_string()
        };

        let mut reopened = JsonlAuditSink::open(&path).unwrap();
        assert_eq!(reopened.recovery().last_sequence, 1);
        assert_eq!(reopened.recovery().last_event_hash, first_hash);
        reopened.record(event("second")).unwrap();

        let records = records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["sequence"], 2);
        assert_eq!(records[1]["prev_hash"], records[0]["event_hash"]);
    }

    #[test]
    fn mixed_plain_and_delegated_audit_records_recover_with_context_integrity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit/events.jsonl");
        let delegation_id = {
            let context = delegated_context();
            let id = context.delegation_id().as_str().to_string();
            let mut sink = JsonlAuditSink::open(&path).unwrap();
            sink.record(event("plain")).unwrap();
            sink.record(event("delegated").with_delegation(context))
                .unwrap();
            id
        };

        let reopened = JsonlAuditSink::open(&path).unwrap();
        assert_eq!(reopened.recovery().last_sequence, 2);
        let records = records(&path);
        assert!(records[0].get("delegation").is_none());
        assert_eq!(records[1]["delegation"]["delegation_id"], delegation_id);
        assert_eq!(records[1]["sequence"], 2);
        assert_eq!(records[1]["prev_hash"], records[0]["event_hash"]);
    }

    #[test]
    fn a_second_writer_fails_closed_until_the_chain_owner_closes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit/events.jsonl");
        let first = JsonlAuditSink::open(&path).unwrap();

        let error = match JsonlAuditSink::open(&path) {
            Ok(_) => panic!("a concurrent audit writer must not open"),
            Err(error) => error,
        };
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));

        drop(first);
        JsonlAuditSink::open(&path).unwrap();
    }

    #[test]
    fn unterminated_tail_is_discarded_before_append_resumes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit/events.jsonl");
        {
            let mut sink = JsonlAuditSink::open(&path).unwrap();
            sink.record(event("first")).unwrap();
        }
        let fabricated_tail = br#"{"version":1,"action":"secret.use","sequence":999"#;
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(fabricated_tail)
            .unwrap();

        let mut reopened = JsonlAuditSink::open(&path).unwrap();
        assert_eq!(
            reopened.recovery().truncated_tail_bytes,
            fabricated_tail.len() as u64
        );
        assert_eq!(reopened.recovery().last_sequence, 1);
        reopened.record(event("second")).unwrap();

        let rendered = fs::read_to_string(&path).unwrap();
        assert!(!rendered.contains("999"));
        let records = records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["sequence"], 2);
        assert_eq!(records[1]["prev_hash"], records[0]["event_hash"]);
    }

    #[test]
    fn tampered_complete_record_blocks_recovery_without_echoing_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit/events.jsonl");
        {
            let mut sink = JsonlAuditSink::open(&path).unwrap();
            sink.record(event("first")).unwrap();
        }
        let mut record = records(&path).remove(0);
        record["reason_code"] = Value::String("SENSITIVE_CANARY_DO_NOT_ECHO".to_string());
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&record).unwrap()),
        )
        .unwrap();

        let error = match JsonlAuditSink::open(&path) {
            Err(error) => error,
            Ok(_) => panic!("tampered audit record was accepted"),
        };
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("SENSITIVE_CANARY_DO_NOT_ECHO"));
    }

    #[derive(Clone, Copy)]
    enum FailureStage {
        Write,
        Flush,
        Sync,
    }

    struct FailingWriter {
        stage: FailureStage,
    }

    impl DurableAuditWriter for FailingWriter {
        fn write_all(&mut self, _bytes: &[u8]) -> io::Result<()> {
            if matches!(self.stage, FailureStage::Write) {
                Err(io::Error::other("injected write failure"))
            } else {
                Ok(())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if matches!(self.stage, FailureStage::Flush) {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }

        fn sync_data(&mut self) -> io::Result<()> {
            if matches!(self.stage, FailureStage::Sync) {
                Err(io::Error::other("injected sync failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn write_flush_and_sync_failures_poison_the_sink_with_value_free_errors() {
        for stage in [FailureStage::Write, FailureStage::Flush, FailureStage::Sync] {
            let mut sink = JsonlAuditSink::with_test_writer(FailingWriter { stage });
            let error = sink
                .record(
                    event("ok")
                        .with_evidence(SafeLabel::new("SENSITIVE_CANARY_DO_NOT_ECHO").unwrap()),
                )
                .unwrap_err();
            assert!(matches!(error, JanusError::AuditUnavailable { .. }));
            assert!(!format!("{error:?} {error}").contains("SENSITIVE_CANARY_DO_NOT_ECHO"));
            let retry = sink.record(event("retry")).unwrap_err();
            assert!(matches!(retry, JanusError::AuditUnavailable { .. }));
            assert_eq!(sink.last_sequence(), 0);
        }
    }

    #[test]
    fn durable_sink_failure_blocks_secret_use_before_value_return() {
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Audit canary").unwrap(),
            scope: scope(),
            owner: Some(OwnerRef::new("security").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }])
        .unwrap();
        let store = MockStore::new(catalog)
            .with_value(name, b"SENSITIVE_CANARY_DO_NOT_ECHO".to_vec())
            .unwrap();
        let profile = UseProfile {
            id: ProfileId::new("profile.canary").unwrap(),
            scope: scope(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("runner-a").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            scope: scope(),
            secret_ref,
            profile_id: ProfileId::new("profile.canary").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            purpose: Purpose::new("audit durability test").unwrap(),
        };
        let mut issuer = PermitIssuer::new(
            ProfilePolicy::new(vec![profile.clone()]),
            AuditWrite::accepting(),
        );
        let permit = issuer
            .issue(&request, &principal(), SystemTime::UNIX_EPOCH)
            .unwrap();
        let failing_sink = JsonlAuditSink::with_test_writer(FailingWriter {
            stage: FailureStage::Sync,
        });
        let mut broker = SecretBroker::new(store, ProfilePolicy::new(vec![profile]), failing_sink);

        let caller = principal();
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let error = match runtime.block_on(broker.use_permit(
            &permit,
            &caller,
            &executor,
            &destination,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )) {
            Err(error) => error,
            Ok(_) => panic!("secret use succeeded despite durable audit persistence failure"),
        };
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));
        assert!(!format!("{error:?} {error}").contains("SENSITIVE_CANARY_DO_NOT_ECHO"));
    }
}

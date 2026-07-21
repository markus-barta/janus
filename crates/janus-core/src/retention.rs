//! Strict value-free contracts for offline Rust-engine evidence retention.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{JanusError, JanusResult, SafeLabel, ScopeRef};

const POLICY_SCHEMA_VERSION: u8 = 1;
const HOLD_SCHEMA_VERSION: u8 = 1;
const HOLD_REGISTRY_SCHEMA_VERSION: u8 = 1;
const EVIDENCE_SCHEMA_VERSION: u8 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_CONFIG_BINDINGS: usize = 32;
const MAX_HOLDS: usize = 16_384;
const MAX_RETENTION_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;
const MAX_GRACE_SECONDS: u64 = 90 * 24 * 60 * 60;
const MAX_EVIDENCE_AGE_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_RECORDS: u64 = 1_000_000;
const MAX_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Closed set of current Rust-engine evidence classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionEvidenceClass {
    /// Locally persisted exact approval grants.
    Approvals,
    /// Delegation grants plus immutable revocation evidence.
    Delegations,
    /// Last-use/rotation/declaration lifecycle evidence.
    LifecycleEvidence,
    /// Active hash-chained audit log.
    Audit,
    /// Denial evidence embedded in the active audit log.
    Denials,
    /// Immutable destroy tombstones.
    Tombstones,
    /// Current successful recovery-drill evidence.
    RecoveryEvidence,
    /// Terminal administration journals/evidence.
    AdminEvidence,
}

impl RetentionEvidenceClass {
    /// Every supported v1 evidence class in canonical order.
    pub const ALL: [Self; 8] = [
        Self::Approvals,
        Self::Delegations,
        Self::LifecycleEvidence,
        Self::Audit,
        Self::Denials,
        Self::Tombstones,
        Self::RecoveryEvidence,
        Self::AdminEvidence,
    ];

    /// Stable policy and evidence text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approvals => "approvals",
            Self::Delegations => "delegations",
            Self::LifecycleEvidence => "lifecycle_evidence",
            Self::Audit => "audit",
            Self::Denials => "denials",
            Self::Tombstones => "tombstones",
            Self::RecoveryEvidence => "recovery_evidence",
            Self::AdminEvidence => "admin_evidence",
        }
    }

    /// Only these classes may be physically quarantined in v1.
    pub const fn is_quarantinable(self) -> bool {
        matches!(
            self,
            Self::Approvals | Self::Delegations | Self::LifecycleEvidence
        )
    }
}

/// Closed physical disposition for one evidence class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDisposition {
    /// Inert closed records may move to reversible quarantine and later purge.
    QuarantineThenPurge,
    /// Records remain protected from physical deletion.
    Retain,
    /// Only a purpose-built replacement protocol may remove the current record.
    ReplaceOnly,
}

impl RetentionDisposition {
    /// Stable policy text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuarantineThenPurge => "quarantine_then_purge",
            Self::Retain => "retain",
            Self::ReplaceOnly => "replace_only",
        }
    }
}

/// One exact class rule.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionClassRule {
    class: RetentionEvidenceClass,
    disposition: RetentionDisposition,
    minimum_age_seconds: u64,
}

impl RetentionClassRule {
    /// Evidence class.
    pub fn class(&self) -> RetentionEvidenceClass {
        self.class
    }

    /// Physical disposition.
    pub fn disposition(&self) -> RetentionDisposition {
        self.disposition
    }

    /// Minimum inert age before quarantine eligibility.
    pub fn minimum_age_seconds(&self) -> u64 {
        self.minimum_age_seconds
    }
}

/// One immutable current config binding.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfigBinding {
    name: String,
    path: String,
    expected_fingerprint: String,
}

impl RetentionConfigBinding {
    /// Stable reviewed name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Exact absolute current path.
    pub fn path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// Expected content digest.
    pub fn expected_fingerprint(&self) -> &str {
        &self.expected_fingerprint
    }
}

impl fmt::Debug for RetentionConfigBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionConfigBinding")
            .field("name", &self.name)
            .field("path", &"<redacted>")
            .field("expected_fingerprint", &"<redacted>")
            .finish()
    }
}

/// Reviewed policy for one offline retention cycle.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicyV1 {
    schema_version: u8,
    operation_id: String,
    scope_ref: String,
    release_artifact: String,
    rules: Vec<RetentionClassRule>,
    config_bindings: Vec<RetentionConfigBinding>,
    approval_root: String,
    delegation_root: String,
    lifecycle_evidence_root: String,
    metadata_overlay_path: String,
    tombstone_root: String,
    audit_path: String,
    recovery_evidence_path: String,
    admin_evidence_root: String,
    hold_registry_path: String,
    quarantine_root: String,
    state_root: String,
    operation_audit_path: String,
    evidence_path: String,
    minimum_free_bytes: u64,
    maximum_records: u64,
    maximum_bytes: u64,
    preflight_max_age_seconds: u64,
    quarantine_grace_seconds: u64,
    evidence_max_age_seconds: u64,
}

impl RetentionPolicyV1 {
    /// Parse and fully validate a strict policy.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let policy: Self = serde_json::from_str(contents).map_err(|_| invalid_policy())?;
        policy.validate()?;
        Ok(policy)
    }

    /// Stable operation id.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Exact opaque scope.
    pub fn scope_ref(&self) -> ScopeRef {
        ScopeRef::from_opaque(self.scope_ref.clone()).expect("validated retention scope")
    }

    /// Exact release artifact binding.
    pub fn release_artifact(&self) -> &str {
        &self.release_artifact
    }

    /// Canonical class rules.
    pub fn rules(&self) -> &[RetentionClassRule] {
        &self.rules
    }

    /// Rule for one closed class.
    pub fn rule(&self, class: RetentionEvidenceClass) -> &RetentionClassRule {
        self.rules
            .iter()
            .find(|rule| rule.class == class)
            .expect("validated retention rule completeness")
    }

    /// Current config bindings.
    pub fn config_bindings(&self) -> &[RetentionConfigBinding] {
        &self.config_bindings
    }

    /// Approval registry root.
    pub fn approval_root(&self) -> &Path {
        Path::new(&self.approval_root)
    }

    /// Delegation registry root.
    pub fn delegation_root(&self) -> &Path {
        Path::new(&self.delegation_root)
    }

    /// Lifecycle evidence root.
    pub fn lifecycle_evidence_root(&self) -> &Path {
        Path::new(&self.lifecycle_evidence_root)
    }

    /// Current lifecycle metadata overlay.
    pub fn metadata_overlay_path(&self) -> &Path {
        Path::new(&self.metadata_overlay_path)
    }

    /// Protected tombstone root.
    pub fn tombstone_root(&self) -> &Path {
        Path::new(&self.tombstone_root)
    }

    /// Protected active audit path.
    pub fn audit_path(&self) -> &Path {
        Path::new(&self.audit_path)
    }

    /// Protected current recovery evidence.
    pub fn recovery_evidence_path(&self) -> &Path {
        Path::new(&self.recovery_evidence_path)
    }

    /// Protected terminal administration evidence root.
    pub fn admin_evidence_root(&self) -> &Path {
        Path::new(&self.admin_evidence_root)
    }

    /// Reviewed hold registry file.
    pub fn hold_registry_path(&self) -> &Path {
        Path::new(&self.hold_registry_path)
    }

    /// Create-new quarantine root.
    pub fn quarantine_root(&self) -> &Path {
        Path::new(&self.quarantine_root)
    }

    /// Private operation state root.
    pub fn state_root(&self) -> &Path {
        Path::new(&self.state_root)
    }

    /// Durable operation audit.
    pub fn operation_audit_path(&self) -> &Path {
        Path::new(&self.operation_audit_path)
    }

    /// Durable value-free completion evidence.
    pub fn evidence_path(&self) -> &Path {
        Path::new(&self.evidence_path)
    }

    /// Required spare capacity.
    pub fn minimum_free_bytes(&self) -> u64 {
        self.minimum_free_bytes
    }

    /// Maximum scanned/quarantined records.
    pub fn maximum_records(&self) -> u64 {
        self.maximum_records
    }

    /// Maximum aggregate scanned/quarantined bytes.
    pub fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Maximum preflight age.
    pub fn preflight_max_age_seconds(&self) -> u64 {
        self.preflight_max_age_seconds
    }

    /// Required reversible quarantine grace.
    pub fn quarantine_grace_seconds(&self) -> u64 {
        self.quarantine_grace_seconds
    }

    /// Maximum accepted completion-evidence age.
    pub fn evidence_max_age_seconds(&self) -> u64 {
        self.evidence_max_age_seconds
    }

    fn validate(&self) -> JanusResult<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION
            || !safe_identifier(&self.operation_id)
            || ScopeRef::from_opaque(self.scope_ref.clone()).is_err()
            || self.release_artifact.is_empty()
            || self.release_artifact.len() > 512
            || self.release_artifact.trim() != self.release_artifact
        {
            return Err(invalid_policy());
        }

        let mut classes = BTreeSet::new();
        for rule in &self.rules {
            if !classes.insert(rule.class)
                || rule.minimum_age_seconds == 0
                || rule.minimum_age_seconds > MAX_RETENTION_SECONDS
            {
                return Err(invalid_policy());
            }
            let disposition_ok = match rule.class {
                RetentionEvidenceClass::Approvals
                | RetentionEvidenceClass::Delegations
                | RetentionEvidenceClass::LifecycleEvidence => {
                    rule.disposition == RetentionDisposition::QuarantineThenPurge
                }
                RetentionEvidenceClass::RecoveryEvidence => {
                    rule.disposition == RetentionDisposition::ReplaceOnly
                }
                RetentionEvidenceClass::Audit
                | RetentionEvidenceClass::Denials
                | RetentionEvidenceClass::Tombstones
                | RetentionEvidenceClass::AdminEvidence => {
                    rule.disposition == RetentionDisposition::Retain
                }
            };
            if !disposition_ok {
                return Err(invalid_policy());
            }
        }
        if classes != RetentionEvidenceClass::ALL.into_iter().collect() {
            return Err(invalid_policy());
        }

        if self.config_bindings.is_empty()
            || self.config_bindings.len() > MAX_CONFIG_BINDINGS
            || self.maximum_records == 0
            || self.maximum_records > MAX_RECORDS
            || self.maximum_bytes == 0
            || self.maximum_bytes > MAX_BYTES
            || self.preflight_max_age_seconds == 0
            || self.preflight_max_age_seconds > 24 * 60 * 60
            || self.quarantine_grace_seconds == 0
            || self.quarantine_grace_seconds > MAX_GRACE_SECONDS
            || self.evidence_max_age_seconds == 0
            || self.evidence_max_age_seconds > MAX_EVIDENCE_AGE_SECONDS
        {
            return Err(invalid_policy());
        }
        let mut binding_names = BTreeSet::new();
        let mut binding_paths = BTreeSet::new();
        for binding in &self.config_bindings {
            if !safe_identifier(&binding.name)
                || !safe_absolute_path(binding.path())
                || !valid_sha256(&binding.expected_fingerprint)
                || !binding_names.insert(binding.name.clone())
                || !binding_paths.insert(binding.path.clone())
            {
                return Err(invalid_policy());
            }
        }
        if !self
            .config_bindings
            .iter()
            .any(|binding| binding.path() == self.metadata_overlay_path())
        {
            return Err(invalid_policy());
        }

        let paths = [
            self.approval_root(),
            self.delegation_root(),
            self.lifecycle_evidence_root(),
            self.metadata_overlay_path(),
            self.tombstone_root(),
            self.audit_path(),
            self.recovery_evidence_path(),
            self.admin_evidence_root(),
            self.hold_registry_path(),
            self.quarantine_root(),
            self.state_root(),
            self.operation_audit_path(),
            self.evidence_path(),
        ];
        if paths.iter().any(|path| !safe_absolute_path(path)) {
            return Err(invalid_policy());
        }
        for (index, left) in paths.iter().enumerate() {
            for right in paths.iter().skip(index + 1) {
                if left == right || left.starts_with(right) || right.starts_with(left) {
                    return Err(invalid_policy());
                }
            }
        }
        for binding in &self.config_bindings {
            if binding.path() == self.metadata_overlay_path() {
                continue;
            }
            if paths.iter().any(|path| {
                binding.path() == *path
                    || binding.path().starts_with(path)
                    || path.starts_with(binding.path())
            }) {
                return Err(invalid_policy());
            }
        }
        for (index, left) in self.config_bindings.iter().enumerate() {
            for right in self.config_bindings.iter().skip(index + 1) {
                if left.path().starts_with(right.path()) || right.path().starts_with(left.path()) {
                    return Err(invalid_policy());
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for RetentionPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionPolicyV1")
            .field("schema_version", &self.schema_version)
            .field("operation_id", &self.operation_id)
            .field("scope_ref", &"<opaque>")
            .field("release_artifact", &"<opaque>")
            .field("rules", &self.rules)
            .field("config_bindings", &self.config_bindings)
            .field("paths", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// One exact opaque legal/security hold.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionHoldV1 {
    schema_version: u8,
    hold_id: String,
    scope_ref: String,
    class: RetentionEvidenceClass,
    target_fingerprint: String,
    reason: String,
    created_at_unix_secs: u64,
    expires_at_unix_secs: Option<u64>,
}

impl RetentionHoldV1 {
    /// Evidence class held.
    pub fn class(&self) -> RetentionEvidenceClass {
        self.class
    }

    /// Opaque target digest.
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }

    /// Whether the hold is active at one instant.
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        match self.expires_at_unix_secs {
            None => true,
            Some(expiry) => unix_seconds(now).is_ok_and(|now| now < expiry),
        }
    }

    fn validate(&self, expected_scope: &ScopeRef) -> JanusResult<()> {
        if self.schema_version != HOLD_SCHEMA_VERSION
            || !safe_identifier(&self.hold_id)
            || ScopeRef::from_opaque(self.scope_ref.clone()).as_ref() != Ok(expected_scope)
            || !self.class.is_quarantinable()
            || !valid_sha256(&self.target_fingerprint)
            || SafeLabel::new(self.reason.clone()).is_err()
            || self
                .expires_at_unix_secs
                .is_some_and(|expiry| expiry <= self.created_at_unix_secs)
        {
            return Err(invalid_hold());
        }
        Ok(())
    }
}

/// Strict private hold registry.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionHoldRegistryV1 {
    schema_version: u8,
    scope_ref: String,
    holds: Vec<RetentionHoldV1>,
}

impl RetentionHoldRegistryV1 {
    /// Parse and validate one exact hold registry.
    pub fn parse_json(contents: &str, expected_scope: &ScopeRef) -> JanusResult<Self> {
        let registry: Self = serde_json::from_str(contents).map_err(|_| invalid_hold())?;
        if registry.schema_version != HOLD_REGISTRY_SCHEMA_VERSION
            || ScopeRef::from_opaque(registry.scope_ref.clone()).as_ref() != Ok(expected_scope)
            || registry.holds.len() > MAX_HOLDS
        {
            return Err(invalid_hold());
        }
        let mut ids = BTreeSet::new();
        let mut targets = BTreeSet::new();
        for hold in &registry.holds {
            hold.validate(expected_scope)?;
            if !ids.insert(hold.hold_id.clone())
                || !targets.insert((hold.class, hold.target_fingerprint.clone()))
            {
                return Err(invalid_hold());
            }
        }
        Ok(registry)
    }

    /// Canonical holds.
    pub fn holds(&self) -> &[RetentionHoldV1] {
        &self.holds
    }
}

/// Inputs for durable value-free retention completion evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionEvidenceInput {
    /// Exact operation id.
    pub operation_id: String,
    /// Exact opaque scope.
    pub scope_ref: String,
    /// Exact release artifact.
    pub release_artifact: String,
    /// Policy fingerprint.
    pub policy_fingerprint: String,
    /// Current config aggregate fingerprint.
    pub config_fingerprint: String,
    /// Current hold registry fingerprint.
    pub hold_fingerprint: String,
    /// Preflight source inventory fingerprint.
    pub source_fingerprint: String,
    /// Quarantine inventory fingerprint.
    pub quarantine_fingerprint: String,
    /// Policy evaluation timestamp.
    pub evaluated_at_unix_secs: u64,
    /// Irreversible purge completion timestamp.
    pub completed_at_unix_secs: u64,
    /// Earliest next known retention deadline.
    pub next_due_at_unix_secs: Option<u64>,
    /// Eligible closed record sets.
    pub eligible_count: u64,
    /// Purged closed record sets.
    pub purged_count: u64,
    /// Active held record sets.
    pub held_count: u64,
    /// Protected/non-purgeable record count.
    pub protected_count: u64,
    /// Stable outcome.
    pub outcome: String,
    /// Stable reason code.
    pub reason_code: String,
    /// Required audit sequence.
    pub audit_sequence: u64,
    /// Required audit hash.
    pub audit_hash: String,
}

/// Durable value-free retention completion evidence.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionEvidenceV1 {
    schema_version: u8,
    operation_id: String,
    scope_ref: String,
    release_artifact: String,
    policy_fingerprint: String,
    config_fingerprint: String,
    hold_fingerprint: String,
    source_fingerprint: String,
    quarantine_fingerprint: String,
    evaluated_at_unix_secs: u64,
    completed_at_unix_secs: u64,
    next_due_at_unix_secs: Option<u64>,
    eligible_count: u64,
    purged_count: u64,
    held_count: u64,
    protected_count: u64,
    outcome: String,
    reason_code: String,
    audit_sequence: u64,
    audit_hash: String,
    value_returned: bool,
    integrity: String,
}

impl RetentionEvidenceV1 {
    /// Build integrity-bound completion evidence.
    pub fn new(input: RetentionEvidenceInput) -> JanusResult<Self> {
        let mut evidence = Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            operation_id: input.operation_id,
            scope_ref: input.scope_ref,
            release_artifact: input.release_artifact,
            policy_fingerprint: input.policy_fingerprint,
            config_fingerprint: input.config_fingerprint,
            hold_fingerprint: input.hold_fingerprint,
            source_fingerprint: input.source_fingerprint,
            quarantine_fingerprint: input.quarantine_fingerprint,
            evaluated_at_unix_secs: input.evaluated_at_unix_secs,
            completed_at_unix_secs: input.completed_at_unix_secs,
            next_due_at_unix_secs: input.next_due_at_unix_secs,
            eligible_count: input.eligible_count,
            purged_count: input.purged_count,
            held_count: input.held_count,
            protected_count: input.protected_count,
            outcome: input.outcome,
            reason_code: input.reason_code,
            audit_sequence: input.audit_sequence,
            audit_hash: input.audit_hash,
            value_returned: false,
            integrity: String::new(),
        };
        evidence.integrity = evidence.expected_integrity()?;
        evidence.validate()?;
        Ok(evidence)
    }

    /// Parse strict evidence.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let evidence: Self = serde_json::from_str(contents).map_err(|_| invalid_evidence())?;
        evidence.validate()?;
        Ok(evidence)
    }

    /// Verify current bindings and freshness.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_current(
        &self,
        policy: &RetentionPolicyV1,
        release_artifact: &str,
        config_fingerprint: &str,
        hold_fingerprint: &str,
        source_fingerprint: &str,
        policy_fingerprint: &str,
        now: SystemTime,
    ) -> JanusResult<()> {
        self.validate()?;
        if self.operation_id != policy.operation_id
            || self.scope_ref != policy.scope_ref
            || self.release_artifact != release_artifact
            || self.policy_fingerprint != policy_fingerprint
            || self.config_fingerprint != config_fingerprint
            || self.hold_fingerprint != hold_fingerprint
            || self.source_fingerprint != source_fingerprint
        {
            return Err(evidence_denied("retention_evidence_mismatch"));
        }
        let now = unix_seconds(now)?;
        let age = now
            .checked_sub(self.completed_at_unix_secs)
            .ok_or_else(|| evidence_denied("retention_evidence_stale"))?;
        if age > policy.evidence_max_age_seconds
            || self.next_due_at_unix_secs.is_some_and(|due| now >= due)
        {
            return Err(evidence_denied("retention_evidence_stale"));
        }
        Ok(())
    }

    /// Stable completion time.
    pub fn completed_at_unix_secs(&self) -> u64 {
        self.completed_at_unix_secs
    }

    fn validate(&self) -> JanusResult<()> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || !safe_identifier(&self.operation_id)
            || ScopeRef::from_opaque(self.scope_ref.clone()).is_err()
            || self.release_artifact.is_empty()
            || !valid_sha256(&self.policy_fingerprint)
            || !valid_sha256(&self.config_fingerprint)
            || !valid_sha256(&self.hold_fingerprint)
            || !valid_sha256(&self.source_fingerprint)
            || !valid_sha256(&self.quarantine_fingerprint)
            || self.completed_at_unix_secs < self.evaluated_at_unix_secs
            || self.purged_count != self.eligible_count
            || self.outcome != "completed"
            || self.reason_code != "retention_purge_ok"
            || self.audit_sequence == 0
            || !valid_hex_hash(&self.audit_hash)
            || self.value_returned
            || !valid_sha256(&self.integrity)
            || self.expected_integrity()? != self.integrity
        {
            return Err(invalid_evidence());
        }
        Ok(())
    }

    fn expected_integrity(&self) -> JanusResult<String> {
        let mut value = serde_json::to_value(self).map_err(|_| invalid_evidence())?;
        value["integrity"] = serde_json::Value::String(String::new());
        let bytes = serde_json::to_vec(&value).map_err(|_| invalid_evidence())?;
        Ok(fingerprint_domain("janus-retention-evidence-v1", &bytes))
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn safe_absolute_path(path: &Path) -> bool {
    let canonical = path.components().collect::<PathBuf>();
    path.is_absolute()
        && path.as_os_str().len() <= MAX_PATH_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && canonical.as_os_str() == path.as_os_str()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unix_seconds(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_evidence())
}

fn fingerprint_domain(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn invalid_policy() -> JanusError {
    JanusError::InvalidManifest {
        detail: "retention policy is invalid".to_string(),
    }
}

fn invalid_hold() -> JanusError {
    JanusError::InvalidManifest {
        detail: "retention hold registry is invalid".to_string(),
    }
}

fn invalid_evidence() -> JanusError {
    JanusError::InvalidManifest {
        detail: "retention evidence is invalid".to_string(),
    }
}

fn evidence_denied(reason_code: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, "retention evidence failed current policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_policy() -> String {
        let scope = crate::ScopePathV1::for_repository("fixture", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
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
                    "minimum_age_seconds": 60,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": 1,
            "operation_id": "fixture-retention",
            "scope_ref": scope.as_str(),
            "release_artifact": "not_required:self_hosted",
            "rules": rules,
            "config_bindings": [
                {
                    "name": "secretspec",
                    "path": "/private/secretspec.toml",
                    "expected_fingerprint": format!("sha256:{}", "a".repeat(64)),
                },
                {
                    "name": "metadata",
                    "path": "/private/metadata.toml",
                    "expected_fingerprint": format!("sha256:{}", "b".repeat(64)),
                }
            ],
            "approval_root": "/private/approvals",
            "delegation_root": "/private/delegations",
            "lifecycle_evidence_root": "/private/lifecycle",
            "metadata_overlay_path": "/private/metadata.toml",
            "tombstone_root": "/private/tombstones",
            "audit_path": "/private/audit.jsonl",
            "recovery_evidence_path": "/private/recovery.json",
            "admin_evidence_root": "/private/admin",
            "hold_registry_path": "/private/holds.json",
            "quarantine_root": "/private/quarantine",
            "state_root": "/private/state",
            "operation_audit_path": "/private/operation-audit.jsonl",
            "evidence_path": "/private/evidence.json",
            "minimum_free_bytes": 1,
            "maximum_records": 1024,
            "maximum_bytes": 1048576,
            "preflight_max_age_seconds": 600,
            "quarantine_grace_seconds": 60,
            "evidence_max_age_seconds": 86400,
        })
        .to_string()
    }

    #[test]
    fn policy_requires_closed_safe_class_dispositions_and_paths() {
        let policy = RetentionPolicyV1::parse_json(&valid_policy()).unwrap();
        assert_eq!(policy.rules().len(), RetentionEvidenceClass::ALL.len());
        assert_eq!(
            policy.rule(RetentionEvidenceClass::Audit).disposition(),
            RetentionDisposition::Retain
        );

        let mut value: serde_json::Value = serde_json::from_str(&valid_policy()).unwrap();
        value["rules"][3]["disposition"] = serde_json::json!("quarantine_then_purge");
        assert!(RetentionPolicyV1::parse_json(&value.to_string()).is_err());
        value = serde_json::from_str(&valid_policy()).unwrap();
        value["quarantine_root"] = serde_json::json!("/private/../escape");
        assert!(RetentionPolicyV1::parse_json(&value.to_string()).is_err());
        value = serde_json::from_str(&valid_policy()).unwrap();
        value["config_bindings"][0]["path"] =
            serde_json::json!("/private/approvals/appr_bound.json");
        assert!(RetentionPolicyV1::parse_json(&value.to_string()).is_err());
        value = serde_json::from_str(&valid_policy()).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(RetentionPolicyV1::parse_json(&value.to_string()).is_err());
    }

    #[test]
    fn hold_registry_and_evidence_are_strict_opaque_and_freshness_bound() {
        let policy = RetentionPolicyV1::parse_json(&valid_policy()).unwrap();
        let holds = serde_json::json!({
            "schema_version": 1,
            "scope_ref": policy.scope_ref().as_str(),
            "holds": [{
                "schema_version": 1,
                "hold_id": "legal-1",
                "scope_ref": policy.scope_ref().as_str(),
                "class": "delegations",
                "target_fingerprint": format!("sha256:{}", "b".repeat(64)),
                "reason": "investigation hold",
                "created_at_unix_secs": 10,
                "expires_at_unix_secs": 100,
            }],
        });
        let registry =
            RetentionHoldRegistryV1::parse_json(&holds.to_string(), &policy.scope_ref()).unwrap();
        assert!(registry.holds()[0].is_active_at(UNIX_EPOCH + Duration::from_secs(99)));

        let input = RetentionEvidenceInput {
            operation_id: policy.operation_id().to_string(),
            scope_ref: policy.scope_ref().as_str().to_string(),
            release_artifact: policy.release_artifact().to_string(),
            policy_fingerprint: format!("sha256:{}", "1".repeat(64)),
            config_fingerprint: format!("sha256:{}", "2".repeat(64)),
            hold_fingerprint: format!("sha256:{}", "3".repeat(64)),
            source_fingerprint: format!("sha256:{}", "4".repeat(64)),
            quarantine_fingerprint: format!("sha256:{}", "5".repeat(64)),
            evaluated_at_unix_secs: 20,
            completed_at_unix_secs: 30,
            next_due_at_unix_secs: Some(100),
            eligible_count: 2,
            purged_count: 2,
            held_count: 1,
            protected_count: 4,
            outcome: "completed".to_string(),
            reason_code: "retention_purge_ok".to_string(),
            audit_sequence: 7,
            audit_hash: "6".repeat(64),
        };
        let evidence = RetentionEvidenceV1::new(input).unwrap();
        evidence
            .verify_current(
                &policy,
                "not_required:self_hosted",
                &format!("sha256:{}", "2".repeat(64)),
                &format!("sha256:{}", "3".repeat(64)),
                &format!("sha256:{}", "4".repeat(64)),
                &format!("sha256:{}", "1".repeat(64)),
                UNIX_EPOCH + Duration::from_secs(99),
            )
            .unwrap();
        assert!(evidence
            .verify_current(
                &policy,
                "not_required:self_hosted",
                &format!("sha256:{}", "2".repeat(64)),
                &format!("sha256:{}", "3".repeat(64)),
                &format!("sha256:{}", "4".repeat(64)),
                &format!("sha256:{}", "1".repeat(64)),
                UNIX_EPOCH + Duration::from_secs(100),
            )
            .is_err());
    }
}

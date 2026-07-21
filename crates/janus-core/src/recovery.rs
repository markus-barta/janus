//! Strict value-free contracts for an offline clean-state recovery drill.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{JanusError, JanusResult, ScopeRef};

const MANIFEST_SCHEMA_VERSION: u8 = 1;
const EVIDENCE_SCHEMA_VERSION: u8 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_RELEASE_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 4096;
const MAX_CONFIG_BINDINGS: usize = 32;
const MAX_PREFLIGHT_AGE_SECONDS: u64 = 24 * 60 * 60;
const MAX_EVIDENCE_AGE_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_BUNDLE_FILES: u64 = 1_000_000;

/// Closed set of security-state components supported by recovery bundle v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryComponentKind {
    /// Encrypted Age payload hierarchy.
    AgeCiphertext,
    /// Current metadata overlay.
    MetadataOverlay,
    /// Durable hash-chained runtime audit log.
    AuditLog,
    /// Approval grants and immutable revocation markers.
    Approvals,
    /// Delegation grants and immutable revocation evidence.
    Delegations,
    /// Durable role bindings and immutable revocation evidence.
    RoleBindings,
    /// Emergency requests, activations, attempts, completions, revocations, and reviews.
    BreakGlassState,
    /// Lifecycle use and rotation evidence.
    LifecycleEvidence,
    /// Immutable destroy tombstones.
    Tombstones,
    /// Manifest-first lifecycle-entry journals.
    LifecycleEntry,
    /// Terminal migration, scope-transfer, and retirement state.
    AdminState,
}

impl RecoveryComponentKind {
    /// Every required v1 component in canonical order.
    pub const ALL: [Self; 11] = [
        Self::AgeCiphertext,
        Self::MetadataOverlay,
        Self::AuditLog,
        Self::Approvals,
        Self::Delegations,
        Self::RoleBindings,
        Self::BreakGlassState,
        Self::LifecycleEvidence,
        Self::Tombstones,
        Self::LifecycleEntry,
        Self::AdminState,
    ];

    /// Stable bundle directory/output label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgeCiphertext => "age_ciphertext",
            Self::MetadataOverlay => "metadata_overlay",
            Self::AuditLog => "audit_log",
            Self::Approvals => "approvals",
            Self::Delegations => "delegations",
            Self::RoleBindings => "role_bindings",
            Self::BreakGlassState => "break_glass_state",
            Self::LifecycleEvidence => "lifecycle_evidence",
            Self::Tombstones => "tombstones",
            Self::LifecycleEntry => "lifecycle_entry",
            Self::AdminState => "admin_state",
        }
    }

    /// Whether this component is one regular file rather than a directory.
    pub const fn is_file(self) -> bool {
        matches!(self, Self::MetadataOverlay | Self::AuditLog)
    }
}

/// One operator-private component source.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryComponentSource {
    kind: RecoveryComponentKind,
    source_path: String,
}

impl RecoveryComponentSource {
    /// Component kind.
    pub fn kind(&self) -> RecoveryComponentKind {
        self.kind
    }

    /// Private source path.
    pub fn source_path(&self) -> &Path {
        Path::new(&self.source_path)
    }
}

impl fmt::Debug for RecoveryComponentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryComponentSource")
            .field("kind", &self.kind)
            .field("source_path", &"<redacted>")
            .finish()
    }
}

/// One immutable release/configuration input binding.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfigBinding {
    name: String,
    path: String,
    expected_fingerprint: String,
}

impl RecoveryConfigBinding {
    /// Stable reviewed binding name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Operator-private current input path.
    pub fn path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// Reviewed content fingerprint.
    pub fn expected_fingerprint(&self) -> &str {
        &self.expected_fingerprint
    }
}

impl fmt::Debug for RecoveryConfigBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryConfigBinding")
            .field("name", &self.name)
            .field("path", &"<redacted>")
            .field("expected_fingerprint", &"<redacted>")
            .finish()
    }
}

/// Reviewed private plan for one offline clean-state recovery drill.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDrillManifest {
    schema_version: u8,
    operation_id: String,
    scope_ref: String,
    release_artifact: String,
    expected_bundle_fingerprint: String,
    components: Vec<RecoveryComponentSource>,
    config_bindings: Vec<RecoveryConfigBinding>,
    permit_source_path: String,
    bundle_root: String,
    target_root: String,
    state_root: String,
    operation_audit_path: String,
    evidence_path: String,
    minimum_free_bytes: u64,
    maximum_bundle_bytes: u64,
    maximum_bundle_files: u64,
    preflight_max_age_seconds: u64,
    evidence_max_age_seconds: u64,
}

impl RecoveryDrillManifest {
    /// Parse and validate a strict JSON manifest.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let manifest: Self = serde_json::from_str(contents).map_err(|_| invalid_manifest())?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Stable operation id.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Exact opaque scope ref.
    pub fn scope_ref(&self) -> ScopeRef {
        ScopeRef::from_opaque(self.scope_ref.clone()).expect("validated recovery scope")
    }

    /// Exact trusted release binding or explicit not-required marker.
    pub fn release_artifact(&self) -> &str {
        &self.release_artifact
    }

    /// Reviewed sealed inventory fingerprint.
    pub fn expected_bundle_fingerprint(&self) -> &str {
        &self.expected_bundle_fingerprint
    }

    /// Closed canonical component sources.
    pub fn components(&self) -> &[RecoveryComponentSource] {
        &self.components
    }

    /// Immutable current configuration inputs.
    pub fn config_bindings(&self) -> &[RecoveryConfigBinding] {
        &self.config_bindings
    }

    /// Permit registry inspected only for exclusion/counting.
    pub fn permit_source_path(&self) -> &Path {
        Path::new(&self.permit_source_path)
    }

    /// New sealed snapshot bundle root.
    pub fn bundle_root(&self) -> &Path {
        Path::new(&self.bundle_root)
    }

    /// Disposable empty recovery target.
    pub fn target_root(&self) -> &Path {
        Path::new(&self.target_root)
    }

    /// Private operation journal/work root.
    pub fn state_root(&self) -> &Path {
        Path::new(&self.state_root)
    }

    /// Durable audit for the drill workflow itself.
    pub fn operation_audit_path(&self) -> &Path {
        Path::new(&self.operation_audit_path)
    }

    /// Durable value-free postflight evidence path.
    pub fn evidence_path(&self) -> &Path {
        Path::new(&self.evidence_path)
    }

    /// Extra free-space floor.
    pub fn minimum_free_bytes(&self) -> u64 {
        self.minimum_free_bytes
    }

    /// Maximum admitted aggregate source/bundle bytes.
    pub fn maximum_bundle_bytes(&self) -> u64 {
        self.maximum_bundle_bytes
    }

    /// Maximum admitted regular files.
    pub fn maximum_bundle_files(&self) -> u64 {
        self.maximum_bundle_files
    }

    /// Maximum delay between preflight and restore.
    pub fn preflight_max_age_seconds(&self) -> u64 {
        self.preflight_max_age_seconds
    }

    /// Maximum accepted age of completed drill evidence.
    pub fn evidence_max_age_seconds(&self) -> u64 {
        self.evidence_max_age_seconds
    }

    fn validate(&self) -> JanusResult<()> {
        ScopeRef::from_opaque(self.scope_ref.clone())?;
        let component_kinds = self
            .components
            .iter()
            .map(|component| component.kind)
            .collect::<BTreeSet<_>>();
        let required = RecoveryComponentKind::ALL
            .into_iter()
            .collect::<BTreeSet<_>>();
        let component_paths = self
            .components
            .iter()
            .map(|component| component.source_path.as_str())
            .collect::<BTreeSet<_>>();
        let config_names = self
            .config_bindings
            .iter()
            .map(|binding| binding.name.as_str())
            .collect::<BTreeSet<_>>();
        let config_paths = self
            .config_bindings
            .iter()
            .map(|binding| binding.path.as_str())
            .collect::<BTreeSet<_>>();

        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || !safe_identifier(&self.operation_id)
            || !safe_release(&self.release_artifact)
            || !valid_sha256(&self.expected_bundle_fingerprint)
            || component_kinds != required
            || component_paths.len() != self.components.len()
            || self
                .components
                .iter()
                .any(|component| !safe_absolute_path(&component.source_path))
            || self.config_bindings.is_empty()
            || self.config_bindings.len() > MAX_CONFIG_BINDINGS
            || config_names.len() != self.config_bindings.len()
            || config_paths.len() != self.config_bindings.len()
            || self.config_bindings.iter().any(|binding| {
                !safe_identifier(&binding.name)
                    || !safe_absolute_path(&binding.path)
                    || !valid_sha256(&binding.expected_fingerprint)
            })
            || !safe_absolute_path(&self.permit_source_path)
            || !safe_absolute_path(&self.bundle_root)
            || !safe_absolute_path(&self.target_root)
            || !safe_absolute_path(&self.state_root)
            || !safe_absolute_path(&self.operation_audit_path)
            || !safe_absolute_path(&self.evidence_path)
            || !all_distinct(&[
                &self.permit_source_path,
                &self.bundle_root,
                &self.target_root,
                &self.state_root,
                &self.operation_audit_path,
                &self.evidence_path,
            ])
            || self.maximum_bundle_bytes == 0
            || self.maximum_bundle_bytes > MAX_BUNDLE_BYTES
            || self.maximum_bundle_files == 0
            || self.maximum_bundle_files > MAX_BUNDLE_FILES
            || self.preflight_max_age_seconds == 0
            || self.preflight_max_age_seconds > MAX_PREFLIGHT_AGE_SECONDS
            || self.evidence_max_age_seconds == 0
            || self.evidence_max_age_seconds > MAX_EVIDENCE_AGE_SECONDS
        {
            return Err(invalid_manifest());
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryDrillManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDrillManifest")
            .field("schema_version", &self.schema_version)
            .field("operation_id", &self.operation_id)
            .field("scope_ref", &self.scope_ref)
            .field("release_artifact", &self.release_artifact)
            .field("expected_bundle_fingerprint", &"<redacted>")
            .field("components", &self.components)
            .field("config_bindings", &self.config_bindings)
            .field("paths", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Strict durable value-free evidence from a successful drill postflight.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDrillEvidenceV1 {
    /// Exact schema version.
    pub schema_version: u8,
    /// Reviewed operation id.
    pub operation_id: String,
    /// Exact opaque scope ref.
    pub scope_ref: String,
    /// Exact trusted release binding.
    pub release_artifact: String,
    /// Sealed bundle inventory fingerprint.
    pub bundle_fingerprint: String,
    /// Current configuration-set fingerprint.
    pub config_fingerprint: String,
    /// Installed clean-target fingerprint.
    pub target_fingerprint: String,
    /// Closed component count.
    pub component_count: u64,
    /// Restored regular file count.
    pub file_count: u64,
    /// Restored aggregate byte count.
    pub total_bytes: u64,
    /// Permit records deliberately excluded.
    pub excluded_permit_count: u64,
    /// Continued durable audit sequence.
    pub audit_sequence: u64,
    /// Continued durable audit hash.
    pub audit_hash: String,
    /// Completion timestamp seconds since Unix epoch.
    pub completed_at_unix_secs: u64,
    /// Completion timestamp nanoseconds.
    pub completed_at_subsec_nanos: u32,
    /// Evidence expiry timestamp seconds since Unix epoch.
    pub expires_at_unix_secs: u64,
    /// Evidence expiry timestamp nanoseconds.
    pub expires_at_subsec_nanos: u32,
    /// Stable successful outcome.
    pub outcome: String,
    /// Stable successful reason code.
    pub reason_code: String,
    /// Recovery evidence never returns values.
    pub value_returned: bool,
    /// Canonical integrity fingerprint over every preceding field.
    pub evidence_fingerprint: String,
}

/// Value-free inputs for constructing successful drill evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDrillEvidenceInput {
    /// Sealed bundle fingerprint.
    pub bundle_fingerprint: String,
    /// Current configuration-set fingerprint.
    pub config_fingerprint: String,
    /// Installed clean-target fingerprint.
    pub target_fingerprint: String,
    /// Restored regular file count.
    pub file_count: u64,
    /// Restored aggregate bytes.
    pub total_bytes: u64,
    /// Excluded permit records.
    pub excluded_permit_count: u64,
    /// Continued audit sequence.
    pub audit_sequence: u64,
    /// Continued audit hash.
    pub audit_hash: String,
    /// Completion time.
    pub completed_at: SystemTime,
}

impl RecoveryDrillEvidenceV1 {
    /// Construct canonical successful evidence for one exact manifest.
    pub fn successful(
        manifest: &RecoveryDrillManifest,
        input: RecoveryDrillEvidenceInput,
    ) -> JanusResult<Self> {
        let completed = input
            .completed_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_evidence())?;
        let expires_at = input
            .completed_at
            .checked_add(Duration::from_secs(manifest.evidence_max_age_seconds))
            .ok_or_else(invalid_evidence)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_evidence())?;
        let mut evidence = Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            operation_id: manifest.operation_id.clone(),
            scope_ref: manifest.scope_ref.clone(),
            release_artifact: manifest.release_artifact.clone(),
            bundle_fingerprint: input.bundle_fingerprint,
            config_fingerprint: input.config_fingerprint,
            target_fingerprint: input.target_fingerprint,
            component_count: RecoveryComponentKind::ALL.len() as u64,
            file_count: input.file_count,
            total_bytes: input.total_bytes,
            excluded_permit_count: input.excluded_permit_count,
            audit_sequence: input.audit_sequence,
            audit_hash: input.audit_hash,
            completed_at_unix_secs: completed.as_secs(),
            completed_at_subsec_nanos: completed.subsec_nanos(),
            expires_at_unix_secs: expires_at.as_secs(),
            expires_at_subsec_nanos: expires_at.subsec_nanos(),
            outcome: "passed".to_string(),
            reason_code: "recovery_drill_ok".to_string(),
            value_returned: false,
            evidence_fingerprint: String::new(),
        };
        evidence.evidence_fingerprint = evidence.canonical_fingerprint();
        evidence.validate_shape()?;
        Ok(evidence)
    }

    /// Parse strict evidence and verify its canonical integrity.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let evidence: Self = serde_json::from_str(contents).map_err(|_| invalid_evidence())?;
        evidence.validate_shape()?;
        if evidence.evidence_fingerprint != evidence.canonical_fingerprint() {
            return Err(invalid_evidence());
        }
        Ok(evidence)
    }

    /// Verify exact current scope/release/plan binding and freshness.
    pub fn validate_current(
        &self,
        manifest: &RecoveryDrillManifest,
        now: SystemTime,
    ) -> JanusResult<()> {
        self.validate_shape()?;
        if self.evidence_fingerprint != self.canonical_fingerprint()
            || self.operation_id != manifest.operation_id
            || self.scope_ref != manifest.scope_ref
            || self.release_artifact != manifest.release_artifact
            || self.bundle_fingerprint != manifest.expected_bundle_fingerprint
        {
            return Err(recovery_denied(
                "recovery_evidence_mismatch",
                "recovery drill evidence does not match current policy",
            ));
        }
        let completed =
            time_from_parts(self.completed_at_unix_secs, self.completed_at_subsec_nanos)?;
        let expires = time_from_parts(self.expires_at_unix_secs, self.expires_at_subsec_nanos)?;
        let expected_expiry = completed
            .checked_add(Duration::from_secs(manifest.evidence_max_age_seconds))
            .ok_or_else(invalid_evidence)?;
        if expires != expected_expiry || now < completed {
            return Err(recovery_denied(
                "recovery_evidence_invalid_time",
                "recovery drill evidence time is invalid",
            ));
        }
        if now > expires {
            return Err(recovery_denied(
                "recovery_evidence_stale",
                "recovery drill evidence is stale",
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> JanusResult<()> {
        ScopeRef::from_opaque(self.scope_ref.clone()).map_err(|_| invalid_evidence())?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || !safe_identifier(&self.operation_id)
            || !safe_release(&self.release_artifact)
            || !valid_sha256(&self.bundle_fingerprint)
            || !valid_sha256(&self.config_fingerprint)
            || !valid_sha256(&self.target_fingerprint)
            || self.component_count != RecoveryComponentKind::ALL.len() as u64
            || !valid_hex_hash(&self.audit_hash)
            || self.outcome != "passed"
            || self.reason_code != "recovery_drill_ok"
            || self.value_returned
            || !valid_sha256(&self.evidence_fingerprint)
            || time_from_parts(self.completed_at_unix_secs, self.completed_at_subsec_nanos).is_err()
            || time_from_parts(self.expires_at_unix_secs, self.expires_at_subsec_nanos).is_err()
        {
            return Err(invalid_evidence());
        }
        Ok(())
    }

    fn canonical_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "janus-recovery-evidence-v1");
        hash_field(&mut hasher, &self.schema_version.to_string());
        hash_field(&mut hasher, &self.operation_id);
        hash_field(&mut hasher, &self.scope_ref);
        hash_field(&mut hasher, &self.release_artifact);
        hash_field(&mut hasher, &self.bundle_fingerprint);
        hash_field(&mut hasher, &self.config_fingerprint);
        hash_field(&mut hasher, &self.target_fingerprint);
        hash_field(&mut hasher, &self.component_count.to_string());
        hash_field(&mut hasher, &self.file_count.to_string());
        hash_field(&mut hasher, &self.total_bytes.to_string());
        hash_field(&mut hasher, &self.excluded_permit_count.to_string());
        hash_field(&mut hasher, &self.audit_sequence.to_string());
        hash_field(&mut hasher, &self.audit_hash);
        hash_field(&mut hasher, &self.completed_at_unix_secs.to_string());
        hash_field(&mut hasher, &self.completed_at_subsec_nanos.to_string());
        hash_field(&mut hasher, &self.expires_at_unix_secs.to_string());
        hash_field(&mut hasher, &self.expires_at_subsec_nanos.to_string());
        hash_field(&mut hasher, &self.outcome);
        hash_field(&mut hasher, &self.reason_code);
        hash_field(&mut hasher, &self.value_returned.to_string());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn safe_release(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RELEASE_BYTES
        && value.trim().len() == value.len()
        && !value.chars().any(char::is_control)
}

fn safe_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    let canonical = path.components().collect::<PathBuf>();
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && value.trim().len() == value.len()
        && !value.chars().any(char::is_control)
        && path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
        && canonical.as_os_str() == path.as_os_str()
}

fn all_distinct(values: &[&str]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && valid_hex_hash(&value[7..])
}

fn valid_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn time_from_parts(seconds: u64, nanos: u32) -> JanusResult<SystemTime> {
    if nanos >= 1_000_000_000 {
        return Err(invalid_evidence());
    }
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos))
        .ok_or_else(invalid_evidence)
}

fn invalid_manifest() -> JanusError {
    JanusError::InvalidManifest {
        detail: "recovery drill manifest is invalid".to_string(),
    }
}

fn invalid_evidence() -> JanusError {
    JanusError::InvalidManifest {
        detail: "recovery drill evidence is invalid".to_string(),
    }
}

fn recovery_denied(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScopePathV1;

    fn manifest_json() -> String {
        let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
        let components = RecoveryComponentKind::ALL
            .iter()
            .map(|kind| {
                format!(
                    r#"{{"kind":"{}","source_path":"/var/lib/janus/source/{}"}}"#,
                    kind.as_str(),
                    kind.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{
  "schema_version": 1,
  "operation_id": "clean-state-fixture",
  "scope_ref": "{}",
  "release_artifact": "not_required:self_hosted",
  "expected_bundle_fingerprint": "sha256:{}",
  "components": [{}],
  "config_bindings": [{{"name":"secretspec","path":"/etc/janus/secretspec.toml","expected_fingerprint":"sha256:{}"}}],
  "permit_source_path": "/var/lib/janus/permits",
  "bundle_root": "/var/lib/janus/recovery/bundle",
  "target_root": "/var/lib/janus/recovery/target",
  "state_root": "/var/lib/janus/recovery/state",
  "operation_audit_path": "/var/log/janus/recovery.jsonl",
  "evidence_path": "/var/lib/janus/recovery/evidence.json",
  "minimum_free_bytes": 1048576,
  "maximum_bundle_bytes": 16777216,
  "maximum_bundle_files": 4096,
  "preflight_max_age_seconds": 900,
  "evidence_max_age_seconds": 86400
}}"#,
            scope.as_str(),
            "0".repeat(64),
            components,
            "1".repeat(64),
        )
    }

    #[test]
    fn strict_manifest_requires_closed_components_and_private_paths() {
        let manifest = RecoveryDrillManifest::parse_json(&manifest_json()).unwrap();
        assert_eq!(
            manifest.components().len(),
            RecoveryComponentKind::ALL.len()
        );
        let debug = format!("{manifest:?}");
        assert!(!debug.contains("/var/lib/janus/source"));

        for invalid in [
            manifest_json().replace("\n}", ",\n\"unknown\":true\n}"),
            manifest_json().replace("/var/lib/janus/permits", "relative/permits"),
            manifest_json().replace("/var/lib/janus/permits", "/var/lib/janus/../janus/permits"),
            manifest_json().replace("\"age_ciphertext\",", "\"approvals\","),
            manifest_json().replace("sha256:0000", "sha256:AAAA"),
        ] {
            assert!(RecoveryDrillManifest::parse_json(&invalid).is_err());
        }
    }

    #[test]
    fn evidence_is_integrity_scope_release_and_freshness_bound() {
        let manifest = RecoveryDrillManifest::parse_json(&manifest_json()).unwrap();
        let completed = UNIX_EPOCH + Duration::from_secs(1_000);
        let evidence = RecoveryDrillEvidenceV1::successful(
            &manifest,
            RecoveryDrillEvidenceInput {
                bundle_fingerprint: manifest.expected_bundle_fingerprint().to_string(),
                config_fingerprint: format!("sha256:{}", "2".repeat(64)),
                target_fingerprint: format!("sha256:{}", "3".repeat(64)),
                file_count: 9,
                total_bytes: 1024,
                excluded_permit_count: 2,
                audit_sequence: 7,
                audit_hash: "4".repeat(64),
                completed_at: completed,
            },
        )
        .unwrap();
        let encoded = serde_json::to_string(&evidence).unwrap();
        let restored = RecoveryDrillEvidenceV1::parse_json(&encoded).unwrap();
        restored
            .validate_current(&manifest, completed + Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            restored.validate_current(&manifest, completed + Duration::from_secs(86_401)),
            Err(JanusError::PolicyDenied {
                reason_code: "recovery_evidence_stale",
                ..
            })
        ));

        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["excluded_permit_count"] = serde_json::json!(0);
        assert!(RecoveryDrillEvidenceV1::parse_json(&tampered.to_string()).is_err());
    }
}

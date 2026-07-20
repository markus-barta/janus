//! Strict contracts for offline scope-bound metadata recovery and transfer.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{JanusError, JanusResult, ScopePathV1, ScopeRef};

const MANIFEST_SCHEMA_VERSION: u8 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PREFLIGHT_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Explicit operation class for one source and one destination scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTransferMode {
    /// Source and destination are the same exact scope.
    ExactScopeRecovery,
    /// Source and destination differ and authority must not travel with state.
    BoundaryChangingTransfer,
}

impl ScopeTransferMode {
    /// Stable value-free operator/audit text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactScopeRecovery => "exact_scope_recovery",
            Self::BoundaryChangingTransfer => "boundary_changing_transfer",
        }
    }
}

/// Reviewed private manifest for one offline scope-state operation.
///
/// Raw destination path components and filesystem paths are operator-only input.
/// Model-facing and ordinary audit output use only opaque refs and fingerprints.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeTransferManifest {
    schema_version: u8,
    operation_id: String,
    mode: ScopeTransferMode,
    source_scope_ref: String,
    destination_scope: ScopePathV1,
    expected_destination_scope_ref: String,
    source_inventory_fingerprint: String,
    expected_target_fingerprint: String,
    source_root: String,
    target_root: String,
    state_root: String,
    audit_path: String,
    minimum_free_bytes: u64,
    preflight_max_age_seconds: u64,
}

impl ScopeTransferManifest {
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

    /// Explicit operation class.
    pub fn mode(&self) -> ScopeTransferMode {
        self.mode
    }

    /// Reviewed source opaque scope ref.
    pub fn source_scope_ref(&self) -> ScopeRef {
        ScopeRef::from_opaque(self.source_scope_ref.clone())
            .expect("validated scope-transfer source ref")
    }

    /// Reviewed destination typed scope path.
    pub fn destination_scope(&self) -> &ScopePathV1 {
        &self.destination_scope
    }

    /// Reviewed destination opaque scope ref.
    pub fn destination_scope_ref(&self) -> ScopeRef {
        self.destination_scope.scope_ref()
    }

    /// Reviewed canonical source inventory fingerprint.
    pub fn source_inventory_fingerprint(&self) -> &str {
        &self.source_inventory_fingerprint
    }

    /// Reviewed canonical target-before-operation fingerprint.
    pub fn expected_target_fingerprint(&self) -> &str {
        &self.expected_target_fingerprint
    }

    /// Private source bundle root.
    pub fn source_root(&self) -> &Path {
        Path::new(&self.source_root)
    }

    /// Private installed target root.
    pub fn target_root(&self) -> &Path {
        Path::new(&self.target_root)
    }

    /// Private operation journal/snapshot root.
    pub fn state_root(&self) -> &Path {
        Path::new(&self.state_root)
    }

    /// Durable audit log path.
    pub fn audit_path(&self) -> &Path {
        Path::new(&self.audit_path)
    }

    /// Required free-space floor beyond the source, snapshot, and stage.
    pub fn minimum_free_bytes(&self) -> u64 {
        self.minimum_free_bytes
    }

    /// Maximum age accepted between preflight and apply.
    pub fn preflight_max_age_seconds(&self) -> u64 {
        self.preflight_max_age_seconds
    }

    fn validate(&self) -> JanusResult<()> {
        let source = ScopeRef::from_opaque(self.source_scope_ref.clone())?;
        let expected_destination =
            ScopeRef::from_opaque(self.expected_destination_scope_ref.clone())?;
        let destination = self.destination_scope.scope_ref();
        let mode_matches = match self.mode {
            ScopeTransferMode::ExactScopeRecovery => source == destination,
            ScopeTransferMode::BoundaryChangingTransfer => source != destination,
        };
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || !safe_identifier(&self.operation_id)
            || expected_destination != destination
            || !mode_matches
            || !valid_sha256(&self.source_inventory_fingerprint)
            || !valid_sha256(&self.expected_target_fingerprint)
            || !safe_absolute_path(&self.source_root)
            || !safe_absolute_path(&self.target_root)
            || !safe_absolute_path(&self.state_root)
            || !safe_absolute_path(&self.audit_path)
            || self.source_root == self.target_root
            || self.source_root == self.state_root
            || self.target_root == self.state_root
            || self.preflight_max_age_seconds == 0
            || self.preflight_max_age_seconds > MAX_PREFLIGHT_AGE_SECONDS
        {
            return Err(invalid_manifest());
        }
        Ok(())
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn safe_absolute_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && value.trim().len() == value.len()
        && !value.chars().any(char::is_control)
        && Path::new(value).is_absolute()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn invalid_manifest() -> JanusError {
    JanusError::InvalidManifest {
        detail: "scope transfer manifest is invalid".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json(mode: &str, source: &str, destination: &str) -> String {
        format!(
            r#"{{
  "schema_version": 1,
  "operation_id": "restore-fixture",
  "mode": "{mode}",
  "source_scope_ref": "{source}",
  "destination_scope": {{
    "schema_version": 1,
    "organization": "fixture-org",
    "project": "janus",
    "repository": "janus",
    "environment": "{destination}"
  }},
  "expected_destination_scope_ref": "{}",
  "source_inventory_fingerprint": "sha256:{}",
  "expected_target_fingerprint": "sha256:{}",
  "source_root": "/var/lib/janus/import",
  "target_root": "/var/lib/janus/state",
  "state_root": "/var/lib/janus/transfers/restore-fixture",
  "audit_path": "/var/log/janus/audit.jsonl",
  "minimum_free_bytes": 1048576,
  "preflight_max_age_seconds": 900
}}"#,
            ScopePathV1::for_repository("fixture-org", "janus", "janus", destination)
                .unwrap()
                .scope_ref()
                .as_str(),
            "0".repeat(64),
            "1".repeat(64),
        )
    }

    #[test]
    fn exact_and_boundary_modes_are_classified_explicitly() {
        let dev = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
        let exact = ScopeTransferManifest::parse_json(&manifest_json(
            "exact_scope_recovery",
            dev.as_str(),
            "dev",
        ))
        .unwrap();
        assert_eq!(exact.mode(), ScopeTransferMode::ExactScopeRecovery);

        let transfer = ScopeTransferManifest::parse_json(&manifest_json(
            "boundary_changing_transfer",
            dev.as_str(),
            "prod",
        ))
        .unwrap();
        assert_eq!(transfer.mode(), ScopeTransferMode::BoundaryChangingTransfer);
    }

    #[test]
    fn mismatched_modes_refs_unknown_fields_and_ambiguous_paths_fail_closed() {
        let dev = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
        assert!(ScopeTransferManifest::parse_json(&manifest_json(
            "boundary_changing_transfer",
            dev.as_str(),
            "dev",
        ))
        .is_err());

        let base = manifest_json("exact_scope_recovery", dev.as_str(), "dev");
        for invalid in [
            base.replace("\n}", ",\n  \"unknown\": true\n}"),
            base.replace("\"repository\": \"janus\"", "\"repository\": \"*\""),
            base.replace(
                "\"expected_destination_scope_ref\": \"scp_",
                "\"expected_destination_scope_ref\": \"scp_0",
            ),
            base.replace(
                "\"target_root\": \"/var/lib/janus/state\"",
                "\"target_root\": \"relative/state\"",
            ),
        ] {
            assert!(ScopeTransferManifest::parse_json(&invalid).is_err());
        }
    }
}

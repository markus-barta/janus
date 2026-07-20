//! Versioned migration contracts for offline Janus upgrades.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{JanusError, JanusResult};

const MANIFEST_SCHEMA_VERSION: u8 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_BACKUP_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Compatibility posture required while a migration runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCompatibility {
    /// All Janus runtimes must be stopped; only migration commands may run.
    Offline,
}

/// Security-sensitive effects a migration declares before it can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRisk {
    /// The migration could broaden an authorization or policy decision.
    AuthorityWidening,
    /// The migration could weaken or remove audit evidence.
    AuditWeakening,
    /// The migration could change encrypted backend or key custody.
    CustodyChange,
    /// The migration could collapse a scope/environment boundary.
    BoundaryChange,
}

/// Reviewed migration manifest. Paths are operationally sensitive and never
/// copied into model-facing output or audit evidence.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationManifest {
    schema_version: u8,
    migration_id: String,
    schema_id: String,
    from_version: u32,
    to_version: u32,
    compatibility: MigrationCompatibility,
    reversible: bool,
    risk_flags: Vec<MigrationRisk>,
    target_root: String,
    state_root: String,
    audit_path: String,
    minimum_free_bytes: u64,
    backup_max_age_seconds: u64,
}

impl MigrationManifest {
    /// Parse and structurally validate a reviewed JSON migration manifest.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let manifest: Self = serde_json::from_str(contents).map_err(|_| invalid_manifest())?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Stable migration id.
    pub fn migration_id(&self) -> &str {
        &self.migration_id
    }

    /// Stable schema family id.
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Source schema version.
    pub fn from_version(&self) -> u32 {
        self.from_version
    }

    /// Target schema version.
    pub fn to_version(&self) -> u32 {
        self.to_version
    }

    /// Required compatibility posture.
    pub fn compatibility(&self) -> MigrationCompatibility {
        self.compatibility
    }

    /// Whether the reviewed migration declares a supported rollback.
    pub fn reversible(&self) -> bool {
        self.reversible
    }

    /// Declared security-sensitive effects.
    pub fn risk_flags(&self) -> &[MigrationRisk] {
        &self.risk_flags
    }

    /// Reviewed target root.
    pub fn target_root(&self) -> &Path {
        Path::new(&self.target_root)
    }

    /// Private migration state root.
    pub fn state_root(&self) -> &Path {
        Path::new(&self.state_root)
    }

    /// Durable audit log path.
    pub fn audit_path(&self) -> &Path {
        Path::new(&self.audit_path)
    }

    /// Extra free-space floor after accounting for snapshot and staging bytes.
    pub fn minimum_free_bytes(&self) -> u64 {
        self.minimum_free_bytes
    }

    /// Maximum age of preflight/snapshot evidence accepted by apply.
    pub fn backup_max_age_seconds(&self) -> u64 {
        self.backup_max_age_seconds
    }

    fn validate(&self) -> JanusResult<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || !safe_identifier(&self.migration_id)
            || !safe_identifier(&self.schema_id)
            || self.from_version.checked_add(1) != Some(self.to_version)
            || !self.reversible
            || self.backup_max_age_seconds == 0
            || self.backup_max_age_seconds > MAX_BACKUP_AGE_SECONDS
            || !safe_absolute_path(&self.target_root)
            || !safe_absolute_path(&self.state_root)
            || !safe_absolute_path(&self.audit_path)
            || self.target_root == self.state_root
        {
            return Err(invalid_manifest());
        }
        let mut risks = BTreeSet::new();
        if self.risk_flags.iter().any(|risk| !risks.insert(*risk)) {
            return Err(invalid_manifest());
        }
        Ok(())
    }
}

/// Durable migration journal phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Target and snapshot passed preflight; no target mutation occurred.
    Preflighted,
    /// Apply started and staging is being built.
    Applying,
    /// Complete target output was staged and synced.
    Staged,
    /// Atomic target replacement is in progress.
    Swapping,
    /// Target replacement completed and awaits postflight.
    Applied,
    /// Postflight passed and normal runtime may resume.
    Completed,
    /// Snapshot restoration is in progress.
    RollingBack,
    /// Snapshot was restored and verified.
    RolledBack,
    /// An invariant or persistence step failed.
    Failed,
}

impl MigrationPhase {
    /// Stable status text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preflighted => "preflighted",
            Self::Applying => "applying",
            Self::Staged => "staged",
            Self::Swapping => "swapping",
            Self::Applied => "applied",
            Self::Completed => "completed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }

    /// Whether secret-bearing runtime startup must fail closed.
    pub fn blocks_runtime(self) -> bool {
        !matches!(self, Self::Completed | Self::RolledBack)
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

fn invalid_manifest() -> JanusError {
    JanusError::InvalidManifest {
        detail: "migration manifest is invalid".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json() -> String {
        r#"{
  "schema_version": 1,
  "migration_id": "approval-registry-v0-v1",
  "schema_id": "approval_registry",
  "from_version": 0,
  "to_version": 1,
  "compatibility": "offline",
  "reversible": true,
  "risk_flags": [],
  "target_root": "/var/lib/janus/approvals",
  "state_root": "/var/lib/janus/migrations/approval-v1",
  "audit_path": "/var/log/janus/audit.jsonl",
  "minimum_free_bytes": 1048576,
  "backup_max_age_seconds": 900
}"#
        .to_string()
    }

    #[test]
    fn strict_manifest_accepts_the_ordered_offline_plan() {
        let manifest = MigrationManifest::parse_json(&manifest_json()).unwrap();
        assert_eq!(manifest.migration_id(), "approval-registry-v0-v1");
        assert_eq!(manifest.schema_id(), "approval_registry");
        assert_eq!(manifest.from_version(), 0);
        assert_eq!(manifest.to_version(), 1);
        assert!(manifest.reversible());
        assert!(manifest.risk_flags().is_empty());
    }

    #[test]
    fn malformed_gapped_duplicate_risky_and_relative_plans_are_rejected() {
        let cases = [
            ("\"to_version\": 1", "\"to_version\": 2"),
            (
                "\"risk_flags\": []",
                "\"risk_flags\": [\"authority_widening\", \"authority_widening\"]",
            ),
            (
                "\"target_root\": \"/var/lib/janus/approvals\"",
                "\"target_root\": \"relative/approvals\"",
            ),
            ("\"reversible\": true", "\"reversible\": false"),
        ];
        for (from, to) in cases {
            assert!(MigrationManifest::parse_json(&manifest_json().replace(from, to)).is_err());
        }
        assert!(MigrationManifest::parse_json(&manifest_json().replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"extra\": true,"
        ))
        .is_err());
    }

    #[test]
    fn incomplete_and_failed_phases_block_runtime() {
        assert!(MigrationPhase::Preflighted.blocks_runtime());
        assert!(MigrationPhase::Applied.blocks_runtime());
        assert!(MigrationPhase::Failed.blocks_runtime());
        assert!(!MigrationPhase::Completed.blocks_runtime());
        assert!(!MigrationPhase::RolledBack.blocks_runtime());
    }
}

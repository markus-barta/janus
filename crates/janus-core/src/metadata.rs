//! Owner/classification metadata overlay for manifest-declared secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    JanusError, JanusResult, OwnerRef, SecretClass, SecretLifecycle, SecretMeta, SecretName,
};

const MAX_METADATA_OVERLAY_BYTES: usize = 8 * 1024;

/// Optional owner/class metadata patch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretMetadataPatch {
    /// Owning team/service.
    pub owner: Option<OwnerRef>,
    /// Risk classification.
    pub classification: Option<SecretClass>,
    /// Lifecycle state.
    pub lifecycle: Option<SecretLifecycle>,
}

impl SecretMetadataPatch {
    fn apply_to(&self, meta: &mut SecretMeta) {
        if let Some(owner) = &self.owner {
            meta.owner = Some(owner.clone());
        }
        if let Some(classification) = self.classification {
            meta.classification = Some(classification);
        }
        if let Some(lifecycle) = self.lifecycle {
            meta.lifecycle = lifecycle;
        }
    }

    fn to_toml(&self) -> SecretMetadataPatchTomlOut {
        SecretMetadataPatchTomlOut {
            owner: self.owner.as_ref().map(|owner| owner.as_str().to_string()),
            classification: self
                .classification
                .map(|classification| classification.as_str().to_string()),
            lifecycle: self
                .lifecycle
                .map(|lifecycle| lifecycle.as_str().to_string()),
        }
    }
}

/// Value-free metadata overlay matched against manifest secret names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretMetadataOverlay {
    defaults: SecretMetadataPatch,
    secrets: BTreeMap<SecretName, SecretMetadataPatch>,
}

impl SecretMetadataOverlay {
    /// Empty overlay.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a TOML metadata overlay.
    pub fn parse_toml(contents: &str) -> JanusResult<Self> {
        if contents.len() > MAX_METADATA_OVERLAY_BYTES {
            return Err(JanusError::InvalidManifest {
                detail: "metadata overlay exceeds the reviewed size limit".to_string(),
            });
        }
        let parsed: SecretMetadataOverlayToml =
            toml::from_str(contents).map_err(|err| JanusError::InvalidManifest {
                detail: format!("metadata overlay parse failed: {err}"),
            })?;

        let defaults = SecretMetadataPatch::try_from(parsed.defaults)?;
        let mut secrets = BTreeMap::new();
        for entry in parsed.secrets {
            let name = SecretName::new(entry.name)?;
            let patch = SecretMetadataPatch::try_from(SecretMetadataPatchToml {
                owner: entry.owner,
                classification: entry.classification,
                lifecycle: entry.lifecycle,
            })?;
            if secrets.insert(name.clone(), patch).is_some() {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate metadata entry for {}", name.as_str()),
                });
            }
        }

        Ok(Self { defaults, secrets })
    }

    /// Load a TOML metadata overlay from disk.
    pub fn load_toml_file(path: impl AsRef<Path>) -> JanusResult<Self> {
        let contents =
            fs::read_to_string(path.as_ref()).map_err(|err| JanusError::StoreUnavailable {
                detail: format!("metadata overlay read failed: {err}"),
            })?;
        Self::parse_toml(&contents)
    }

    /// Set or replace the per-secret lifecycle patch while preserving other metadata.
    pub fn set_secret_lifecycle(&mut self, name: SecretName, lifecycle: SecretLifecycle) {
        self.secrets.entry(name).or_default().lifecycle = Some(lifecycle);
    }

    /// Serialize this overlay to canonical TOML.
    pub fn to_toml_string(&self) -> JanusResult<String> {
        let output = SecretMetadataOverlayTomlOut {
            defaults: self.defaults.to_toml(),
            secrets: self
                .secrets
                .iter()
                .map(|(name, patch)| SecretMetadataEntryTomlOut {
                    name: name.as_str().to_string(),
                    owner: patch.owner.as_ref().map(|owner| owner.as_str().to_string()),
                    classification: patch
                        .classification
                        .map(|classification| classification.as_str().to_string()),
                    lifecycle: patch
                        .lifecycle
                        .map(|lifecycle| lifecycle.as_str().to_string()),
                })
                .collect(),
        };
        toml::to_string_pretty(&output).map_err(|err| JanusError::InvalidManifest {
            detail: format!("metadata overlay serialize failed: {err}"),
        })
    }

    /// Apply this overlay to manifest entries, rejecting stale overlay names.
    pub fn apply_to_entries(&self, entries: &mut [SecretMeta]) -> JanusResult<()> {
        let names = entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        for name in self.secrets.keys() {
            if !names.contains(name) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("metadata entry has no manifest secret {}", name.as_str()),
                });
            }
        }

        for entry in entries {
            self.defaults.apply_to(entry);
            if let Some(patch) = self.secrets.get(&entry.name) {
                patch.apply_to(entry);
            }
        }
        Ok(())
    }
}

impl TryFrom<SecretMetadataPatchToml> for SecretMetadataPatch {
    type Error = JanusError;

    fn try_from(value: SecretMetadataPatchToml) -> Result<Self, Self::Error> {
        Ok(Self {
            owner: value.owner.map(OwnerRef::new).transpose()?,
            classification: value
                .classification
                .as_deref()
                .map(SecretClass::parse)
                .transpose()?,
            lifecycle: value
                .lifecycle
                .as_deref()
                .map(SecretLifecycle::parse)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataOverlayToml {
    #[serde(default)]
    defaults: SecretMetadataPatchToml,
    #[serde(default)]
    secrets: Vec<SecretMetadataEntryToml>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataPatchToml {
    owner: Option<String>,
    classification: Option<String>,
    lifecycle: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataEntryToml {
    name: String,
    owner: Option<String>,
    classification: Option<String>,
    lifecycle: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SecretMetadataOverlayTomlOut {
    #[serde(skip_serializing_if = "SecretMetadataPatchTomlOut::is_empty")]
    defaults: SecretMetadataPatchTomlOut,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<SecretMetadataEntryTomlOut>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SecretMetadataPatchTomlOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<String>,
}

impl SecretMetadataPatchTomlOut {
    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.classification.is_none() && self.lifecycle.is_none()
    }
}

#[derive(Clone, Debug, Serialize)]
struct SecretMetadataEntryTomlOut {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileId, SafeLabel, SecretRef, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let scope = crate::test_scope("dev");
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope,
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }
    }

    #[test]
    fn overlay_applies_defaults_and_per_secret_overrides() {
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "disabled"
            "#,
        )
        .unwrap();
        let mut entries = vec![meta("CANARY"), meta("OTHER")];

        overlay.apply_to_entries(&mut entries).unwrap();

        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Disabled);
        assert_eq!(entries[1].owner.as_ref().unwrap().as_str(), "infra");
        assert_eq!(entries[1].classification, Some(SecretClass::Normal));
        assert_eq!(entries[1].lifecycle, SecretLifecycle::Active);
    }

    #[test]
    fn overlay_rejects_duplicate_unknown_and_invalid_class_entries() {
        let duplicate = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            owner = "infra"

            [[secrets]]
            name = "CANARY"
            classification = "normal"
            "#,
        )
        .unwrap_err();
        assert!(matches!(duplicate, JanusError::InvalidManifest { .. }));

        let mut entries = vec![meta("CANARY")];
        let stale = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "STALE"
            owner = "infra"
            classification = "normal"
            "#,
        )
        .unwrap();
        let err = stale.apply_to_entries(&mut entries).unwrap_err();
        assert!(matches!(err, JanusError::InvalidManifest { .. }));

        let invalid = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            classification = "critical"
            "#,
        )
        .unwrap_err();
        assert!(matches!(invalid, JanusError::InvalidIdentifier { .. }));

        let invalid_lifecycle = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            lifecycle = "deleted"
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            invalid_lifecycle,
            JanusError::InvalidIdentifier { .. }
        ));
    }

    #[test]
    fn overlay_updates_lifecycle_and_serializes_without_losing_metadata() {
        let mut overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "active"
            "#,
        )
        .unwrap();

        overlay.set_secret_lifecycle(
            SecretName::new("CANARY").unwrap(),
            SecretLifecycle::Disabled,
        );
        overlay.set_secret_lifecycle(
            SecretName::new("OTHER").unwrap(),
            SecretLifecycle::PendingDelete,
        );
        let encoded = overlay.to_toml_string().unwrap();
        let round_tripped = SecretMetadataOverlay::parse_toml(&encoded).unwrap();
        let mut entries = vec![meta("CANARY"), meta("OTHER")];

        round_tripped.apply_to_entries(&mut entries).unwrap();

        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Disabled);
        assert_eq!(entries[1].owner.as_ref().unwrap().as_str(), "infra");
        assert_eq!(entries[1].classification, Some(SecretClass::Normal));
        assert_eq!(entries[1].lifecycle, SecretLifecycle::PendingDelete);
    }
}

//! Owner/classification metadata overlay for manifest-declared secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::{JanusError, JanusResult, OwnerRef, SecretClass, SecretMeta, SecretName};

/// Optional owner/class metadata patch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretMetadataPatch {
    /// Owning team/service.
    pub owner: Option<OwnerRef>,
    /// Risk classification.
    pub classification: Option<SecretClass>,
}

impl SecretMetadataPatch {
    fn apply_to(&self, meta: &mut SecretMeta) {
        if let Some(owner) = &self.owner {
            meta.owner = Some(owner.clone());
        }
        if let Some(classification) = self.classification {
            meta.classification = Some(classification);
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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataEntryToml {
    name: String,
    owner: Option<String>,
    classification: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileId, ProjectId, SafeLabel, ScopeRef, SecretRef, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&project, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: None,
            classification: None,
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

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            "#,
        )
        .unwrap();
        let mut entries = vec![meta("CANARY"), meta("OTHER")];

        overlay.apply_to_entries(&mut entries).unwrap();

        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[1].owner.as_ref().unwrap().as_str(), "infra");
        assert_eq!(entries[1].classification, Some(SecretClass::Normal));
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
    }
}

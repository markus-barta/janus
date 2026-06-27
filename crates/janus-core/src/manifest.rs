//! Manifest-derived allowlist catalog.

use std::collections::HashSet;

use crate::{JanusError, JanusResult, SecretDescriptor, SecretMeta, SecretName, SecretRef};

/// Manifest allowlist with stable name-to-ref mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCatalog {
    entries: Vec<SecretMeta>,
}

impl ManifestCatalog {
    /// Construct a catalog from manifest metadata.
    pub fn new(entries: Vec<SecretMeta>) -> JanusResult<Self> {
        let mut names = HashSet::new();
        let mut refs = HashSet::new();
        for entry in &entries {
            if !names.insert(entry.name.clone()) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate secret name {}", entry.name.as_str()),
                });
            }
            if !refs.insert(entry.secret_ref.clone()) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate secret ref {}", entry.secret_ref.as_str()),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Borrow the catalog entries.
    pub fn entries(&self) -> &[SecretMeta] {
        &self.entries
    }

    /// Find manifest metadata by name.
    pub fn meta_by_name(&self, name: &SecretName) -> JanusResult<&SecretMeta> {
        self.entries
            .iter()
            .find(|entry| &entry.name == name)
            .ok_or_else(|| JanusError::NotInManifest {
                name: name.as_str().to_string(),
            })
    }

    /// Find manifest metadata by opaque ref.
    pub fn meta_by_ref(&self, secret_ref: &SecretRef) -> JanusResult<&SecretMeta> {
        self.entries
            .iter()
            .find(|entry| &entry.secret_ref == secret_ref)
            .ok_or_else(|| JanusError::NotInManifest {
                name: secret_ref.as_str().to_string(),
            })
    }

    /// Build a descriptor with caller-supplied presence.
    pub fn descriptor_by_name(
        &self,
        name: &SecretName,
        present: bool,
    ) -> JanusResult<SecretDescriptor> {
        Ok(self.meta_by_name(name)?.descriptor(present))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnerRef, ProfileId, ProjectId, SafeLabel, ScopeRef, SecretClass, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&project, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }
    }

    #[test]
    fn catalog_denies_non_manifest_names() {
        let catalog = ManifestCatalog::new(vec![meta("CANARY")]).unwrap();
        let err = catalog
            .meta_by_name(&SecretName::new("OTHER").unwrap())
            .unwrap_err();
        assert!(matches!(err, JanusError::NotInManifest { .. }));
    }

    #[test]
    fn catalog_rejects_duplicate_names() {
        let err = ManifestCatalog::new(vec![meta("CANARY"), meta("CANARY")]).unwrap_err();
        assert!(matches!(err, JanusError::InvalidManifest { .. }));
    }
}

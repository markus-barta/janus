//! In-memory `SecretStore` for JANUS-14 conformance and tracer tests.

use std::collections::BTreeMap;

use async_trait::async_trait;
use janus_core::{
    HealthStatus, JanusError, JanusResult, ManifestCatalog, RotationOutcome, RotationSpec,
    RotationStrategy, SecretDescriptor, SecretName, SecretStore, SecretValue, StoreCapabilities,
};

/// In-memory manifest-backed store.
#[derive(Clone, Debug)]
pub struct MockStore {
    catalog: ManifestCatalog,
    values: BTreeMap<SecretName, Vec<u8>>,
    capabilities: StoreCapabilities,
}

impl MockStore {
    /// Construct an empty mock store.
    pub fn new(catalog: ManifestCatalog) -> Self {
        Self {
            catalog,
            values: BTreeMap::new(),
            capabilities: StoreCapabilities {
                write: true,
                delete: true,
                generated_rotate: true,
                rotate_native: false,
                versioning: false,
                leasing: false,
                native_audit: false,
                backend_key_custody: false,
            },
        }
    }

    /// Insert a manifest-declared secret value.
    pub fn with_value(mut self, name: SecretName, value: impl Into<Vec<u8>>) -> JanusResult<Self> {
        self.catalog.meta_by_name(&name)?;
        self.values.insert(name, value.into());
        Ok(self)
    }

    fn ensure_manifest(&self, name: &SecretName) -> JanusResult<()> {
        self.catalog.meta_by_name(name).map(|_| ())
    }
}

#[async_trait]
impl SecretStore for MockStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.capabilities.clone()
    }

    async fn health(&self) -> JanusResult<HealthStatus> {
        Ok(HealthStatus {
            backend: "mock",
            ok: true,
            detail: "in-memory fixture ready".to_string(),
        })
    }

    async fn list(&self) -> JanusResult<Vec<SecretDescriptor>> {
        Ok(self
            .catalog
            .entries()
            .iter()
            .map(|meta| meta.descriptor(self.values.contains_key(&meta.name)))
            .collect())
    }

    async fn get(&self, name: &SecretName) -> JanusResult<SecretValue> {
        self.ensure_manifest(name)?;
        self.values
            .get(name)
            .cloned()
            .map(SecretValue::new)
            .ok_or_else(|| JanusError::NotFound {
                name: name.as_str().to_string(),
            })
    }

    async fn set(&mut self, name: &SecretName, value: SecretValue) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        self.values
            .insert(name.clone(), value.expose_bytes().to_vec());
        Ok(())
    }

    async fn rotate(
        &mut self,
        name: &SecretName,
        spec: &RotationSpec,
    ) -> JanusResult<RotationOutcome> {
        self.ensure_manifest(name)?;
        if spec.strategy != RotationStrategy::Generated {
            return Err(JanusError::Unsupported {
                capability: "rotation_strategy",
            });
        }
        let value = spec
            .generated_value
            .as_ref()
            .ok_or(JanusError::Unsupported {
                capability: "generated_value",
            })?;
        self.values
            .insert(name.clone(), value.expose_bytes().to_vec());
        let descriptor = self.catalog.descriptor_by_name(name, true)?;
        Ok(RotationOutcome::rotated(descriptor.secret_ref))
    }

    async fn delete(&mut self, name: &SecretName) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        self.values.remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        OwnerRef, ProfileId, ProjectId, SafeLabel, ScopeRef, SecretClass, SecretLifecycle,
        SecretMeta, SecretRef, TrustLevel,
    };

    fn catalog() -> (ManifestCatalog, SecretName) {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&project, &name),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }])
        .unwrap();
        (catalog, name)
    }

    #[tokio::test]
    async fn mock_store_denies_non_manifest_reads() {
        let (catalog, _) = catalog();
        let store = MockStore::new(catalog);
        let err = match store.get(&SecretName::new("OTHER").unwrap()).await {
            Ok(_) => panic!("non-manifest get should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, JanusError::NotInManifest { .. }));
    }

    #[tokio::test]
    async fn mock_store_lists_metadata_without_values() {
        let (catalog, name) = catalog();
        let store = MockStore::new(catalog)
            .with_value(name, b"super-secret".to_vec())
            .unwrap();
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        let rendered = format!("{listed:?}");
        assert!(!rendered.contains("super-secret"));
    }
}

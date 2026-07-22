//! Manifest-derived allowlist catalog.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::{
    JanusError, JanusResult, ProfileId, ProjectId, SafeLabel, ScopeRef, SecretDescriptor,
    SecretLifecycle, SecretMeta, SecretMetadataOverlay, SecretName, SecretRef, TrustLevel,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecManifestToml {
    project: SecretspecProjectToml,
    profiles: BTreeMap<String, SecretspecProfileToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecProjectToml {
    name: String,
    revision: String,
}

#[derive(Debug, Default, Deserialize)]
struct SecretspecProfileToml {
    #[serde(default)]
    defaults: SecretspecDefaultsToml,
    #[serde(flatten)]
    secrets: BTreeMap<String, SecretspecSecretToml>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecDefaultsToml {
    required: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecSecretToml {
    description: Option<String>,
    required: Option<bool>,
}

/// Load the strict Secretspec manifest subset that Janus uses as its allowlist.
///
/// Janus intentionally parses only project identity, named profiles, descriptions,
/// and required flags. Provider construction and secret generation stay outside
/// this parser, so an unused RSA generator cannot enter the production graph.
pub fn load_secretspec_manifest_catalog(
    path: impl AsRef<Path>,
    profile: &str,
    scope: &ScopeRef,
    metadata: Option<&SecretMetadataOverlay>,
) -> JanusResult<(ProjectId, ManifestCatalog)> {
    let content = fs::read_to_string(path).map_err(|err| JanusError::StoreUnavailable {
        detail: format!("secretspec manifest could not be read: {}", err.kind()),
    })?;
    parse_secretspec_manifest_catalog(&content, profile, scope, metadata)
}

fn parse_secretspec_manifest_catalog(
    content: &str,
    profile: &str,
    scope: &ScopeRef,
    metadata: Option<&SecretMetadataOverlay>,
) -> JanusResult<(ProjectId, ManifestCatalog)> {
    if profile.is_empty() || profile.trim() != profile {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec profile is invalid".to_string(),
        });
    }
    let parsed: SecretspecManifestToml =
        toml::from_str(content).map_err(|_| JanusError::InvalidManifest {
            detail: "secretspec manifest schema is invalid".to_string(),
        })?;
    if parsed.project.name.is_empty()
        || parsed.project.name.trim() != parsed.project.name
        || parsed.project.revision.is_empty()
        || parsed.project.revision.trim() != parsed.project.revision
    {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec project identity is invalid".to_string(),
        });
    }
    let profile = parsed
        .profiles
        .get(profile)
        .ok_or_else(|| JanusError::InvalidManifest {
            detail: format!("missing secretspec profile {profile}"),
        })?;
    if profile.secrets.is_empty() {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec profile has no declared secrets".to_string(),
        });
    }

    let project = ProjectId::new(parsed.project.name)?;
    let mut entries = Vec::with_capacity(profile.secrets.len());
    for (name, secret) in &profile.secrets {
        let name = SecretName::new(name.clone())?;
        entries.push(SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(scope, &name),
            name: name.clone(),
            label: SafeLabel::new(
                secret
                    .description
                    .clone()
                    .unwrap_or_else(|| "Manifest-declared secret".to_string()),
            )?,
            scope: scope.clone(),
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: secret
                .required
                .or(profile.defaults.required)
                .unwrap_or(true),
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new(format!("profile.{}", name.as_str()))?],
        });
    }
    if let Some(metadata) = metadata {
        metadata.apply_to_entries(&mut entries)?;
    }
    Ok((project, ManifestCatalog::new(entries)?))
}

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
    use crate::{OwnerRef, ProfileId, SafeLabel, SecretClass, SecretLifecycle, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let scope = crate::test_scope("dev");
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope,
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
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

    #[test]
    fn strict_secretspec_subset_builds_a_deterministic_catalog() {
        let scope = crate::test_scope("dev");
        let (project, catalog) = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            defaults = { required = false }
            OPTIONAL = { description = "Optional fixture" }
            REQUIRED = { description = "Required fixture", required = true }
            "#,
            "default",
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(project.as_str(), "janus");
        assert_eq!(catalog.entries().len(), 2);
        assert_eq!(catalog.entries()[0].name.as_str(), "OPTIONAL");
        assert!(!catalog.entries()[0].required);
        assert_eq!(catalog.entries()[1].name.as_str(), "REQUIRED");
        assert!(catalog.entries()[1].required);
    }

    #[test]
    fn strict_secretspec_subset_rejects_generator_and_provider_expansion() {
        let scope = crate::test_scope("dev");
        for unsupported in [
            r#"
            [project]
            name = "janus"
            revision = "1.0"
            provider = "dotenv:.env"
            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", generate = "rsa_private_key" }
            "#,
        ] {
            let err = parse_secretspec_manifest_catalog(unsupported, "default", &scope, None)
                .unwrap_err();
            assert!(matches!(err, JanusError::InvalidManifest { .. }));
        }
    }
}

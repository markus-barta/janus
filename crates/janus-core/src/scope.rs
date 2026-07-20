//! Canonical authorization scope identities.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{JanusError, JanusResult, ProjectId};

const SCOPE_SCHEMA_VERSION: u8 = 1;
const MAX_COMPONENT_LEN: usize = 64;
const SCOPE_REF_HEX_LEN: usize = 40;

pub(crate) fn validate_scope_component(
    kind: &'static str,
    value: impl Into<String>,
) -> JanusResult<String> {
    let value = value.into();
    if value.is_empty()
        || value.len() > MAX_COMPONENT_LEN
        || value.trim().len() != value.len()
        || !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
        })
        || !value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        || !value
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        || value.contains("..")
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(value)
}

macro_rules! scope_component {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Construct a strict scope component.
            pub fn new(value: impl Into<String>) -> JanusResult<Self> {
                Ok(Self(validate_scope_component($kind, value)?))
            }

            /// Internal component text. Do not expose on model-facing surfaces.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

scope_component!(
    /// Organization component in a scope path.
    OrganizationId,
    "organization_id"
);
scope_component!(
    /// Repository component in a scope path.
    RepositoryId,
    "repository_id"
);
scope_component!(
    /// Environment component in a scope path.
    EnvironmentId,
    "environment_id"
);
scope_component!(
    /// Optional namespace component in a scope path.
    NamespaceId,
    "namespace_id"
);
scope_component!(
    /// Optional workload component in a scope path.
    WorkloadId,
    "workload_id"
);

/// Opaque, privacy-safe reference to one exact canonical scope path.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeRef(String);

impl ScopeRef {
    /// Rehydrate an already-derived opaque scope reference.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("scp_") else {
            return Err(JanusError::InvalidIdentifier { kind: "scope_ref" });
        };
        if hex.len() != SCOPE_REF_HEX_LEN
            || !hex
                .chars()
                .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        {
            return Err(JanusError::InvalidIdentifier { kind: "scope_ref" });
        }
        Ok(Self(value))
    }

    /// Safe opaque text for comparisons, audit, and model-facing metadata.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScopeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ScopeRef").field(&self.0).finish()
    }
}

/// Strict version-one authorization scope path.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopePathV1 {
    organization: OrganizationId,
    project: ProjectId,
    repository: RepositoryId,
    environment: EnvironmentId,
    namespace: Option<NamespaceId>,
    workload: Option<WorkloadId>,
}

impl fmt::Debug for ScopePathV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopePathV1")
            .field("schema_version", &SCOPE_SCHEMA_VERSION)
            .field("scope_ref", &self.scope_ref())
            .finish()
    }
}

impl ScopePathV1 {
    /// Construct a repository/environment scope directly from validated text.
    pub fn for_repository(
        organization: impl Into<String>,
        project: impl Into<String>,
        repository: impl Into<String>,
        environment: impl Into<String>,
    ) -> JanusResult<Self> {
        Ok(Self::new(
            OrganizationId::new(organization)?,
            ProjectId::new(project)?,
            RepositoryId::new(repository)?,
            EnvironmentId::new(environment)?,
        ))
    }

    /// Construct a complete use-capable organization/project/repository/environment path.
    pub fn new(
        organization: OrganizationId,
        project: ProjectId,
        repository: RepositoryId,
        environment: EnvironmentId,
    ) -> Self {
        Self {
            organization,
            project,
            repository,
            environment,
            namespace: None,
            workload: None,
        }
    }

    /// Add a namespace leaf.
    pub fn with_namespace(mut self, namespace: NamespaceId) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Add a workload below an existing namespace.
    pub fn with_workload(mut self, workload: WorkloadId) -> JanusResult<Self> {
        if self.namespace.is_none() {
            return Err(JanusError::InvalidIdentifier { kind: "scope_path" });
        }
        self.workload = Some(workload);
        Ok(self)
    }

    /// Parse a strict JSON scope document with no unknown fields.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let wire: ScopePathWire =
            serde_json::from_str(contents).map_err(|error| JanusError::InvalidManifest {
                detail: format!("scope manifest parse failed: {error}"),
            })?;
        Self::try_from(wire)
    }

    /// Organization component.
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// Project component.
    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    /// Repository component.
    pub fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Environment component.
    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    /// Optional namespace component.
    pub fn namespace(&self) -> Option<&NamespaceId> {
        self.namespace.as_ref()
    }

    /// Optional workload component.
    pub fn workload(&self) -> Option<&WorkloadId> {
        self.workload.as_ref()
    }

    /// Derive the privacy-safe exact scope reference.
    pub fn scope_ref(&self) -> ScopeRef {
        let digest = Sha256::digest(self.canonical_bytes());
        ScopeRef(format!(
            "scp_{}",
            hex::encode(&digest[..SCOPE_REF_HEX_LEN / 2])
        ))
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        fn field(output: &mut Vec<u8>, value: &str) {
            output.extend_from_slice(&(value.len() as u64).to_be_bytes());
            output.extend_from_slice(value.as_bytes());
        }

        fn optional_field(output: &mut Vec<u8>, value: Option<&str>) {
            match value {
                Some(value) => {
                    output.push(1);
                    field(output, value);
                }
                None => output.push(0),
            }
        }

        let mut output = Vec::new();
        field(&mut output, "janus-scope-v1");
        field(&mut output, self.organization.as_str());
        field(&mut output, self.project.as_str());
        field(&mut output, self.repository.as_str());
        field(&mut output, self.environment.as_str());
        optional_field(
            &mut output,
            self.namespace.as_ref().map(NamespaceId::as_str),
        );
        optional_field(&mut output, self.workload.as_ref().map(WorkloadId::as_str));
        output
    }
}

impl Serialize for ScopePathV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ScopePathWire {
            schema_version: SCOPE_SCHEMA_VERSION,
            organization: self.organization.as_str().to_string(),
            project: self.project.as_str().to_string(),
            repository: self.repository.as_str().to_string(),
            environment: self.environment.as_str().to_string(),
            namespace: self
                .namespace
                .as_ref()
                .map(|value| value.as_str().to_string()),
            workload: self
                .workload
                .as_ref()
                .map(|value| value.as_str().to_string()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopePathV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ScopePathWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopePathWire {
    schema_version: u8,
    organization: String,
    project: String,
    repository: String,
    environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload: Option<String>,
}

impl TryFrom<ScopePathWire> for ScopePathV1 {
    type Error = JanusError;

    fn try_from(wire: ScopePathWire) -> Result<Self, Self::Error> {
        if wire.schema_version != SCOPE_SCHEMA_VERSION {
            return Err(JanusError::InvalidManifest {
                detail: "unsupported scope schema version".to_string(),
            });
        }
        let mut path = Self::new(
            OrganizationId::new(wire.organization)?,
            ProjectId::new(wire.project)?,
            RepositoryId::new(wire.repository)?,
            EnvironmentId::new(wire.environment)?,
        );
        if let Some(namespace) = wire.namespace {
            path = path.with_namespace(NamespaceId::new(namespace)?);
        }
        if let Some(workload) = wire.workload {
            path = path.with_workload(WorkloadId::new(workload)?)?;
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(environment: &str) -> ScopePathV1 {
        ScopePathV1::new(
            OrganizationId::new("markus-barta").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new(environment).unwrap(),
        )
    }

    #[test]
    fn exact_paths_have_stable_distinct_opaque_refs() {
        let dev = path("dev").scope_ref();
        let prod = path("prod").scope_ref();
        assert_eq!(dev.as_str().len(), 44);
        assert_ne!(dev, prod);
        assert_eq!(ScopeRef::from_opaque(dev.as_str()).unwrap(), dev);
        assert!(!format!("{dev:?}").contains("markus-barta"));
        assert!(!format!("{:?}", path("dev")).contains("markus-barta"));
    }

    #[test]
    fn strict_json_rejects_unknown_versions_fields_gaps_and_path_syntax() {
        let valid = r#"{
            "schema_version": 1,
            "organization": "markus-barta",
            "project": "janus",
            "repository": "janus",
            "environment": "prod",
            "namespace": "runtime",
            "workload": "warden"
        }"#;
        assert!(ScopePathV1::parse_json(valid).is_ok());
        for invalid in [
            valid.replace("\"schema_version\": 1", "\"schema_version\": 2"),
            valid.replace("\"workload\": \"warden\"", "\"unknown\": true"),
            valid.replace("\"namespace\": \"runtime\",", ""),
            valid.replace("\"repository\": \"janus\"", "\"repository\": \"org/janus\""),
        ] {
            assert!(ScopePathV1::parse_json(&invalid).is_err());
        }
    }
}

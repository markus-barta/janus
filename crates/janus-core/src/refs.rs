//! Opaque references and safe labels.

use std::fmt;

use crate::{JanusError, JanusResult};
use sha2::{Digest, Sha256};

fn non_empty(kind: &'static str, value: impl Into<String>) -> JanusResult<String> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(value)
}

macro_rules! id_type {
    (
        $(#[$meta:meta])*
        $name:ident,
        $kind:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Construct a non-empty identifier.
            pub fn new(value: impl Into<String>) -> JanusResult<Self> {
                Ok(Self(non_empty($kind, value)?))
            }

            /// Safe string form for internal comparisons and audited refs.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

id_type!(
    /// Project/scope identifier used by manifests and stores.
    ProjectId,
    "project_id"
);

/// Manifest-declared secret name.
///
/// Unlike [`SecretRef`], this may carry operational meaning and is not the
/// default model-facing shape.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// Construct a non-empty manifest secret name.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        Ok(Self(non_empty("secret_name", value)?))
    }

    /// Internal name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretName").field(&"<redacted>").finish()
    }
}

/// Opaque, non-authorizing reference to a declared secret.
///
/// A `SecretRef` may be shown to an LLM because it grants no access by itself.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef(String);

impl SecretRef {
    /// Construct a non-empty opaque secret reference.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        Ok(Self(non_empty("secret_ref", value)?))
    }

    /// Generate a deterministic opaque ref for a manifest entry.
    ///
    /// The ref is stable for a project/name pair but does not expose the raw
    /// name in its text form.
    pub fn for_manifest_entry(project: &ProjectId, name: &SecretName) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(project.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(name.as_str().as_bytes());
        let digest = hasher.finalize();
        Self(format!("sec_{}", hex::encode(&digest[..10])))
    }

    /// Safe string form for audit and model-facing metadata.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretRef").field(&self.0).finish()
    }
}

id_type!(
    /// Human-safe label curated for UI/model-facing display.
    SafeLabel,
    "safe_label"
);

id_type!(
    /// Opaque consumer identifier.
    ConsumerRef,
    "consumer_ref"
);

id_type!(
    /// Opaque executor identifier. A permit is bound to exactly one executor.
    ExecutorRef,
    "executor_ref"
);

id_type!(
    /// Approved destination for a secret-bearing use path.
    Destination,
    "destination"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_reject_empty_or_trimmed_values() {
        assert!(SecretRef::new("").is_err());
        assert!(SecretRef::new(" sec_prod ").is_err());
        assert_eq!(SecretRef::new("sec_prod").unwrap().as_str(), "sec_prod");
    }

    #[test]
    fn generated_secret_refs_are_stable_and_opaque() {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("prod/api/token").unwrap();
        let first = SecretRef::for_manifest_entry(&project, &name);
        let second = SecretRef::for_manifest_entry(&project, &name);
        assert_eq!(first, second);
        assert!(first.as_str().starts_with("sec_"));
        assert!(!first.as_str().contains("prod"));
        assert!(!first.as_str().contains("token"));
    }
}

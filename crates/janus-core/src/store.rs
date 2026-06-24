//! Backend-neutral secret store contract.

use async_trait::async_trait;

use crate::{
    JanusResult, ProfileId, RotationOutcome, RotationSpec, SafeLabel, ScopeRef, SecretName,
    SecretRef, SecretValue, TrustLevel,
};

/// Backend capabilities used by manifest/profile requirements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreCapabilities {
    /// Store supports writes.
    pub write: bool,
    /// Store supports deletes.
    pub delete: bool,
    /// Store supports generated rotation through Janus.
    pub generated_rotate: bool,
    /// Store can rotate without Janus generating the new value.
    pub rotate_native: bool,
    /// Store supports version history.
    pub versioning: bool,
    /// Store supports leased/dynamic secrets.
    pub leasing: bool,
    /// Store has native audit evidence in addition to Janus audit.
    pub native_audit: bool,
    /// Store owns backend key custody, e.g. HSM/KMS/OpenBao-class custody.
    pub backend_key_custody: bool,
}

/// Value-free backend health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthStatus {
    /// Backend name.
    pub backend: &'static str,
    /// Whether the backend is ready for use.
    pub ok: bool,
    /// Value-free reason/status text.
    pub detail: String,
}

/// Manifest/catalog metadata for one secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    /// Manifest name. Internal, not the model-facing default.
    pub name: SecretName,
    /// Opaque ref.
    pub secret_ref: SecretRef,
    /// Curated safe label.
    pub label: SafeLabel,
    /// Scope boundary.
    pub scope: ScopeRef,
    /// Whether the manifest marks this secret required.
    pub required: bool,
    /// Minimum trust level for literal-producing use paths.
    pub trust_level: TrustLevel,
    /// Allowed profile ids for model-facing descriptions.
    pub allowed_uses: Vec<ProfileId>,
}

impl SecretMeta {
    /// Convert metadata into a value-free descriptor with backend presence.
    pub fn descriptor(&self, present: bool) -> SecretDescriptor {
        SecretDescriptor {
            name: self.name.clone(),
            secret_ref: self.secret_ref.clone(),
            label: self.label.clone(),
            scope: self.scope.clone(),
            required: self.required,
            trust_level: self.trust_level,
            allowed_uses: self.allowed_uses.clone(),
            present,
        }
    }
}

/// Value-free descriptor of a manifest/catalog secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretDescriptor {
    /// Manifest name. Internal, not the model-facing default.
    pub name: SecretName,
    /// Opaque ref.
    pub secret_ref: SecretRef,
    /// Curated safe label.
    pub label: SafeLabel,
    /// Scope boundary.
    pub scope: ScopeRef,
    /// Whether the manifest marks this secret required.
    pub required: bool,
    /// Minimum trust level for literal-producing use paths.
    pub trust_level: TrustLevel,
    /// Allowed profile ids for model-facing descriptions.
    pub allowed_uses: Vec<ProfileId>,
    /// Whether the backend reports the value present.
    pub present: bool,
}

/// Secret backend contract. Implementations must not log or return values except
/// through explicit `SecretValue` results guarded by broker policy and audit.
#[async_trait]
pub trait SecretStore {
    /// Backend capabilities.
    fn capabilities(&self) -> StoreCapabilities;

    /// Value-free health.
    async fn health(&self) -> JanusResult<HealthStatus>;

    /// Value-free descriptor list, normally derived from the manifest/catalog.
    async fn list(&self) -> JanusResult<Vec<SecretDescriptor>>;

    /// Read a secret value by manifest name. Callers must already have passed
    /// policy/audit gates.
    async fn get(&self, name: &SecretName) -> JanusResult<SecretValue>;

    /// Write a secret value by manifest name. Callers must already have passed
    /// policy/audit gates.
    async fn set(&mut self, name: &SecretName, value: SecretValue) -> JanusResult<()>;

    /// Rotate a secret value. The result must never return old/new literals.
    async fn rotate(
        &mut self,
        name: &SecretName,
        spec: &RotationSpec,
    ) -> JanusResult<RotationOutcome>;

    /// Delete a secret value. Callers must already have passed policy/audit gates.
    async fn delete(&mut self, name: &SecretName) -> JanusResult<()>;
}

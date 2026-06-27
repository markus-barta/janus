//! Backend-neutral secret store contract.

use async_trait::async_trait;

use crate::{
    JanusResult, OwnerRef, ProfileId, RotationOutcome, RotationSpec, SafeLabel, ScopeRef,
    SecretName, SecretRef, SecretValue, TrustLevel,
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

/// Secret risk classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretClass {
    /// Low-risk local/dev secret.
    Low,
    /// Normal production secret.
    Normal,
    /// High-value secret that needs stricter policy and audit.
    HighValue,
    /// Emergency-only break-glass secret.
    BreakGlass,
}

impl SecretClass {
    /// Stable manifest/API text for the class. This is internal/admin-facing,
    /// not the default model-facing shape.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::HighValue => "high_value",
            Self::BreakGlass => "break_glass",
        }
    }

    /// Safe model-facing risk hint. This avoids exposing raw class labels where
    /// classification itself may reveal sensitive structure.
    pub fn risk_hint(self) -> &'static str {
        match self {
            Self::Low | Self::Normal => "standard",
            Self::HighValue => "elevated_controls",
            Self::BreakGlass => "emergency_only",
        }
    }
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
    /// Owning team/service. Missing owner blocks normal approved use.
    pub owner: Option<OwnerRef>,
    /// Risk classification. Missing classification blocks normal approved use.
    pub classification: Option<SecretClass>,
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
            owner: self.owner.clone(),
            classification: self.classification,
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
    /// Owning team/service. Internal/admin-facing, not model-facing by default.
    pub owner: Option<OwnerRef>,
    /// Risk classification. Internal/admin-facing, not model-facing by default.
    pub classification: Option<SecretClass>,
    /// Whether the manifest marks this secret required.
    pub required: bool,
    /// Minimum trust level for literal-producing use paths.
    pub trust_level: TrustLevel,
    /// Allowed profile ids for model-facing descriptions.
    pub allowed_uses: Vec<ProfileId>,
    /// Whether the backend reports the value present.
    pub present: bool,
}

impl SecretDescriptor {
    /// Whether owner and classification are complete enough for normal use.
    pub fn metadata_complete(&self) -> bool {
        self.owner.is_some() && self.classification.is_some()
    }

    /// Stable denial for normal approved-use paths when metadata is incomplete.
    pub fn metadata_use_denial(&self) -> Option<(&'static str, &'static str)> {
        match (&self.owner, self.classification) {
            (Some(_), Some(_)) => None,
            (None, None) => Some((
                "denied_metadata_incomplete",
                "secret owner and classification are required before approved use",
            )),
            (None, Some(_)) => Some((
                "denied_missing_owner",
                "secret owner is required before approved use",
            )),
            (Some(_), None) => Some((
                "denied_missing_classification",
                "secret classification is required before approved use",
            )),
        }
    }

    /// Safe model-facing metadata state.
    pub fn metadata_state(&self) -> &'static str {
        if self.metadata_complete() {
            "complete"
        } else {
            "incomplete"
        }
    }

    /// Safe model-facing risk hint.
    pub fn risk_hint(&self) -> &'static str {
        self.classification
            .map(SecretClass::risk_hint)
            .unwrap_or("blocked_metadata_incomplete")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_classes_have_stable_text_and_safe_risk_hints() {
        assert_eq!(SecretClass::Low.as_str(), "low");
        assert_eq!(SecretClass::Normal.as_str(), "normal");
        assert_eq!(SecretClass::HighValue.as_str(), "high_value");
        assert_eq!(SecretClass::BreakGlass.as_str(), "break_glass");

        assert_eq!(SecretClass::Low.risk_hint(), "standard");
        assert_eq!(SecretClass::Normal.risk_hint(), "standard");
        assert_eq!(SecretClass::HighValue.risk_hint(), "elevated_controls");
        assert_eq!(SecretClass::BreakGlass.risk_hint(), "emergency_only");
    }
}

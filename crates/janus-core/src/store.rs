//! Backend-neutral secret store contract.

use async_trait::async_trait;

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, OwnerRef,
    PrincipalChain, ProfileId, RotationOutcome, RotationSpec, SafeLabel, ScopeRef, SecretName,
    SecretRef, SecretValue, Severity, TrustLevel,
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
    /// Parse stable manifest/API text for the class.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "high_value" => Ok(Self::HighValue),
            "break_glass" => Ok(Self::BreakGlass),
            _ => Err(crate::JanusError::InvalidIdentifier {
                kind: "secret_class",
            }),
        }
    }

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

/// Lifecycle state for a manifest/catalog secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretLifecycle {
    /// Draft secret metadata exists, but normal use is blocked.
    Draft,
    /// Active secret available for normal approved use.
    Active,
    /// Secret is actively rotating; existing approved-use paths may continue.
    Rotating,
    /// Deprecated secret should be migrated away and is blocked from normal use.
    Deprecated,
    /// Disabled secret cannot be used through normal paths.
    Disabled,
    /// Secret is awaiting deletion and cannot be used through normal paths.
    PendingDelete,
    /// Destroyed secret is represented only by value-free metadata/tombstone.
    Destroyed,
}

impl SecretLifecycle {
    /// Parse stable manifest/API text for the lifecycle state.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "rotating" => Ok(Self::Rotating),
            "deprecated" => Ok(Self::Deprecated),
            "disabled" => Ok(Self::Disabled),
            "pending_delete" => Ok(Self::PendingDelete),
            "destroyed" => Ok(Self::Destroyed),
            _ => Err(crate::JanusError::InvalidIdentifier {
                kind: "secret_lifecycle",
            }),
        }
    }

    /// Stable manifest/API text for the lifecycle state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
            Self::PendingDelete => "pending_delete",
            Self::Destroyed => "destroyed",
        }
    }

    /// Whether this lifecycle state permits normal approved-use paths.
    pub fn allows_normal_use(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }

    fn use_denial(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Active | Self::Rotating => None,
            Self::Draft => Some((
                "denied_lifecycle_draft",
                "secret lifecycle is draft and not active for approved use",
            )),
            Self::Deprecated => Some((
                "denied_lifecycle_deprecated",
                "secret lifecycle is deprecated and blocked from approved use",
            )),
            Self::Disabled => Some((
                "denied_lifecycle_disabled",
                "secret lifecycle is disabled and blocked from approved use",
            )),
            Self::PendingDelete => Some((
                "denied_lifecycle_pending_delete",
                "secret lifecycle is pending delete and blocked from approved use",
            )),
            Self::Destroyed => Some((
                "denied_lifecycle_destroyed",
                "secret lifecycle is destroyed and blocked from approved use",
            )),
        }
    }
}

/// Value-free record of an accepted lifecycle transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleTransition {
    /// Secret ref being transitioned.
    secret_ref: SecretRef,
    /// Prior lifecycle state.
    from: SecretLifecycle,
    /// New lifecycle state.
    to: SecretLifecycle,
    /// Value-free reason label supplied by the operator/admin path.
    reason: SafeLabel,
}

impl LifecycleTransition {
    fn new(
        secret_ref: SecretRef,
        from: SecretLifecycle,
        to: SecretLifecycle,
        reason: SafeLabel,
    ) -> Self {
        Self {
            secret_ref,
            from,
            to,
            reason,
        }
    }

    /// Secret ref being transitioned.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Prior lifecycle state.
    pub fn from(&self) -> SecretLifecycle {
        self.from
    }

    /// New lifecycle state.
    pub fn to(&self) -> SecretLifecycle {
        self.to
    }

    /// Value-free transition reason.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }
}

/// Core lifecycle transition validator/auditor.
pub struct LifecycleTransitionPolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LifecycleTransitionDecision {
    outcome: AuditOutcome,
    reason_code: &'static str,
    detail: &'static str,
    severity: Severity,
}

impl LifecycleTransitionPolicy {
    /// Validate and audit a lifecycle transition without mutating backend state.
    pub fn transition<A>(
        descriptor: &SecretDescriptor,
        to: SecretLifecycle,
        reason: SafeLabel,
        principal: &PrincipalChain,
        audit: &mut A,
    ) -> JanusResult<LifecycleTransition>
    where
        A: AuditSink,
    {
        if descriptor.scope != principal.scope {
            audit.record(
                AuditEvent::new(
                    AuditAction::SecretLifecycle,
                    AuditOutcome::Denied,
                    "denied_scope_mismatch",
                    Severity::Warning,
                    Some(descriptor.secret_ref.clone()),
                    principal,
                )
                .with_evidence(reason),
            )?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "descriptor scope does not match caller scope",
            ));
        }
        let from = descriptor.lifecycle;
        let decision = decide_lifecycle_transition(descriptor, to);
        audit.record(
            AuditEvent::new(
                AuditAction::SecretLifecycle,
                decision.outcome,
                decision.reason_code,
                decision.severity,
                Some(descriptor.secret_ref.clone()),
                principal,
            )
            .with_evidence(reason.clone()),
        )?;
        if decision.outcome == AuditOutcome::Denied {
            return Err(JanusError::policy_denied(
                decision.reason_code,
                decision.detail,
            ));
        }
        Ok(LifecycleTransition::new(
            descriptor.secret_ref.clone(),
            from,
            to,
            reason,
        ))
    }
}

fn decide_lifecycle_transition(
    descriptor: &SecretDescriptor,
    to: SecretLifecycle,
) -> LifecycleTransitionDecision {
    let from = descriptor.lifecycle;
    if from == SecretLifecycle::Destroyed {
        return lifecycle_transition_deny(
            "denied_lifecycle_destroyed_final",
            "destroyed lifecycle cannot transition",
            Severity::Critical,
        );
    }
    if from == to {
        return lifecycle_transition_deny(
            "denied_lifecycle_transition_noop",
            "lifecycle transition must change state",
            Severity::Warning,
        );
    }
    if to.allows_normal_use() {
        if let Some((reason_code, detail)) = descriptor.metadata_use_denial() {
            return lifecycle_transition_deny(reason_code, detail, Severity::Warning);
        }
    }

    match (from, to) {
        (SecretLifecycle::Draft, SecretLifecycle::Active) => lifecycle_transition_allow(
            "lifecycle_transition_ok",
            "lifecycle transition allowed",
            Severity::Notice,
        ),
        (SecretLifecycle::Active, SecretLifecycle::Disabled) => lifecycle_transition_allow(
            "lifecycle_transition_ok",
            "lifecycle transition allowed",
            Severity::High,
        ),
        (SecretLifecycle::Disabled, SecretLifecycle::PendingDelete) => lifecycle_transition_allow(
            "lifecycle_transition_ok",
            "lifecycle transition allowed",
            Severity::High,
        ),
        _ => lifecycle_transition_deny(
            "denied_lifecycle_transition_unsupported",
            "lifecycle transition is not supported by this policy",
            Severity::Warning,
        ),
    }
}

fn lifecycle_transition_allow(
    reason_code: &'static str,
    detail: &'static str,
    severity: Severity,
) -> LifecycleTransitionDecision {
    LifecycleTransitionDecision {
        outcome: AuditOutcome::Allowed,
        reason_code,
        detail,
        severity,
    }
}

fn lifecycle_transition_deny(
    reason_code: &'static str,
    detail: &'static str,
    severity: Severity,
) -> LifecycleTransitionDecision {
    LifecycleTransitionDecision {
        outcome: AuditOutcome::Denied,
        reason_code,
        detail,
        severity,
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
    /// Lifecycle state. Normal approved use requires an active/rotating state.
    pub lifecycle: SecretLifecycle,
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
            lifecycle: self.lifecycle,
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
    /// Lifecycle state. Internal/admin-facing state, exposed to Warden as safe text.
    pub lifecycle: SecretLifecycle,
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

    /// Stable denial for normal approved-use paths when lifecycle blocks use.
    pub fn lifecycle_use_denial(&self) -> Option<(&'static str, &'static str)> {
        self.lifecycle.use_denial()
    }

    /// Stable denial for normal approved-use paths.
    pub fn normal_use_denial(&self) -> Option<(&'static str, &'static str)> {
        self.metadata_use_denial()
            .or_else(|| self.lifecycle_use_denial())
    }

    /// Whether normal approved-use paths are currently allowed.
    pub fn normal_use_allowed(&self) -> bool {
        self.metadata_complete() && self.lifecycle.allows_normal_use()
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
    use crate::{AuditAction, AuditWrite, Principal, PrincipalId, PrincipalKind};

    fn lifecycle_principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-cli").unwrap(),
            ),
            crate::test_scope("dev"),
        )
    }

    fn lifecycle_descriptor(
        lifecycle: SecretLifecycle,
        owner: Option<OwnerRef>,
        classification: Option<SecretClass>,
    ) -> SecretDescriptor {
        SecretDescriptor {
            name: SecretName::new("CANARY").unwrap(),
            secret_ref: SecretRef::new("sec_lifecycle").unwrap(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: crate::test_scope("dev"),
            owner,
            classification,
            lifecycle,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            present: true,
        }
    }

    #[test]
    fn secret_classes_have_stable_text_and_safe_risk_hints() {
        assert_eq!(SecretClass::parse("low").unwrap(), SecretClass::Low);
        assert_eq!(SecretClass::parse("normal").unwrap(), SecretClass::Normal);
        assert_eq!(
            SecretClass::parse("high_value").unwrap(),
            SecretClass::HighValue
        );
        assert_eq!(
            SecretClass::parse("break_glass").unwrap(),
            SecretClass::BreakGlass
        );
        assert!(SecretClass::parse("critical").is_err());

        assert_eq!(SecretClass::Low.as_str(), "low");
        assert_eq!(SecretClass::Normal.as_str(), "normal");
        assert_eq!(SecretClass::HighValue.as_str(), "high_value");
        assert_eq!(SecretClass::BreakGlass.as_str(), "break_glass");

        assert_eq!(SecretClass::Low.risk_hint(), "standard");
        assert_eq!(SecretClass::Normal.risk_hint(), "standard");
        assert_eq!(SecretClass::HighValue.risk_hint(), "elevated_controls");
        assert_eq!(SecretClass::BreakGlass.risk_hint(), "emergency_only");
    }

    #[test]
    fn secret_lifecycle_has_stable_text_and_use_gates() {
        assert_eq!(
            SecretLifecycle::parse("draft").unwrap(),
            SecretLifecycle::Draft
        );
        assert_eq!(
            SecretLifecycle::parse("active").unwrap(),
            SecretLifecycle::Active
        );
        assert_eq!(
            SecretLifecycle::parse("rotating").unwrap(),
            SecretLifecycle::Rotating
        );
        assert_eq!(
            SecretLifecycle::parse("deprecated").unwrap(),
            SecretLifecycle::Deprecated
        );
        assert_eq!(
            SecretLifecycle::parse("disabled").unwrap(),
            SecretLifecycle::Disabled
        );
        assert_eq!(
            SecretLifecycle::parse("pending_delete").unwrap(),
            SecretLifecycle::PendingDelete
        );
        assert_eq!(
            SecretLifecycle::parse("destroyed").unwrap(),
            SecretLifecycle::Destroyed
        );
        assert!(SecretLifecycle::parse("deleted").is_err());

        assert_eq!(SecretLifecycle::Draft.as_str(), "draft");
        assert_eq!(SecretLifecycle::Active.as_str(), "active");
        assert_eq!(SecretLifecycle::Rotating.as_str(), "rotating");
        assert_eq!(SecretLifecycle::Deprecated.as_str(), "deprecated");
        assert_eq!(SecretLifecycle::Disabled.as_str(), "disabled");
        assert_eq!(SecretLifecycle::PendingDelete.as_str(), "pending_delete");
        assert_eq!(SecretLifecycle::Destroyed.as_str(), "destroyed");

        assert!(!SecretLifecycle::Draft.allows_normal_use());
        assert!(SecretLifecycle::Active.allows_normal_use());
        assert!(SecretLifecycle::Rotating.allows_normal_use());
        assert!(!SecretLifecycle::Deprecated.allows_normal_use());
        assert!(!SecretLifecycle::Disabled.allows_normal_use());
        assert!(!SecretLifecycle::PendingDelete.allows_normal_use());
        assert!(!SecretLifecycle::Destroyed.allows_normal_use());
    }

    #[test]
    fn lifecycle_transition_policy_allows_initial_reasoned_paths() {
        for (from, to, expected_severity) in [
            (
                SecretLifecycle::Draft,
                SecretLifecycle::Active,
                Severity::Notice,
            ),
            (
                SecretLifecycle::Active,
                SecretLifecycle::Disabled,
                Severity::High,
            ),
            (
                SecretLifecycle::Disabled,
                SecretLifecycle::PendingDelete,
                Severity::High,
            ),
        ] {
            let descriptor = lifecycle_descriptor(
                from,
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
            );
            let principal = lifecycle_principal();
            let mut audit = AuditWrite::accepting();
            let reason = SafeLabel::new("reviewed lifecycle change").unwrap();

            let transition = LifecycleTransitionPolicy::transition(
                &descriptor,
                to,
                reason.clone(),
                &principal,
                &mut audit,
            )
            .unwrap();

            assert_eq!(transition.secret_ref(), &descriptor.secret_ref);
            assert_eq!(transition.from(), from);
            assert_eq!(transition.to(), to);
            assert_eq!(transition.reason(), &reason);
            assert_eq!(audit.events().len(), 1);
            let event = &audit.events()[0];
            assert_eq!(event.action, AuditAction::SecretLifecycle);
            assert_eq!(event.outcome, AuditOutcome::Allowed);
            assert_eq!(event.reason_code, "lifecycle_transition_ok");
            assert_eq!(event.severity, expected_severity);
            assert_eq!(event.secret_ref.as_ref(), Some(&descriptor.secret_ref));
            assert_eq!(event.evidence.as_ref(), Some(&reason));
            assert!(!event.value_returned);
            assert!(event
                .event_hash
                .as_ref()
                .is_some_and(|hash| hash.len() == 64));
        }
    }

    #[test]
    fn lifecycle_transition_policy_denies_invalid_paths_with_audit() {
        for (from, to, expected_reason, expected_severity) in [
            (
                SecretLifecycle::Active,
                SecretLifecycle::Active,
                "denied_lifecycle_transition_noop",
                Severity::Warning,
            ),
            (
                SecretLifecycle::Disabled,
                SecretLifecycle::Active,
                "denied_lifecycle_transition_unsupported",
                Severity::Warning,
            ),
            (
                SecretLifecycle::Destroyed,
                SecretLifecycle::Disabled,
                "denied_lifecycle_destroyed_final",
                Severity::Critical,
            ),
        ] {
            let descriptor = lifecycle_descriptor(
                from,
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
            );
            let principal = lifecycle_principal();
            let mut audit = AuditWrite::accepting();
            let reason = SafeLabel::new("reviewed lifecycle change").unwrap();

            let err = LifecycleTransitionPolicy::transition(
                &descriptor,
                to,
                reason.clone(),
                &principal,
                &mut audit,
            )
            .unwrap_err();

            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected_reason
            ));
            assert_eq!(audit.events().len(), 1);
            let event = &audit.events()[0];
            assert_eq!(event.action, AuditAction::SecretLifecycle);
            assert_eq!(event.outcome, AuditOutcome::Denied);
            assert_eq!(event.reason_code, expected_reason);
            assert_eq!(event.severity, expected_severity);
            assert_eq!(event.evidence.as_ref(), Some(&reason));
            assert!(!event.value_returned);
        }
    }

    #[test]
    fn lifecycle_transition_policy_requires_metadata_before_activation() {
        let descriptor =
            lifecycle_descriptor(SecretLifecycle::Draft, None, Some(SecretClass::Normal));
        let principal = lifecycle_principal();
        let mut audit = AuditWrite::accepting();
        let reason = SafeLabel::new("metadata review attempted").unwrap();

        let err = LifecycleTransitionPolicy::transition(
            &descriptor,
            SecretLifecycle::Active,
            reason.clone(),
            &principal,
            &mut audit,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_missing_owner",
                ..
            }
        ));
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::SecretLifecycle);
        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert_eq!(event.reason_code, "denied_missing_owner");
        assert_eq!(event.evidence.as_ref(), Some(&reason));
        assert!(!event.value_returned);
    }
}

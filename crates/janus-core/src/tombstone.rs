//! Value-free destroy tombstone policy.

use std::time::SystemTime;

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    SafeLabel, SecretDescriptor, SecretLifecycle, SecretRef, Severity,
};

/// Value-free request to record a secret as destroyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretTombstoneRequest {
    secret_ref: SecretRef,
    reason: SafeLabel,
    destroyed_at: SystemTime,
    retain_until: SystemTime,
}

impl SecretTombstoneRequest {
    /// Build a value-free tombstone request.
    pub fn new(
        secret_ref: SecretRef,
        reason: SafeLabel,
        destroyed_at: SystemTime,
        retain_until: SystemTime,
    ) -> Self {
        Self {
            secret_ref,
            reason,
            destroyed_at,
            retain_until,
        }
    }

    /// Secret ref being tombstoned.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Operator/admin reason label.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }

    /// Timestamp when Janus recorded the destroy tombstone.
    pub fn destroyed_at(&self) -> SystemTime {
        self.destroyed_at
    }

    /// Timestamp until which the value-free tombstone must be retained.
    pub fn retain_until(&self) -> SystemTime {
        self.retain_until
    }
}

/// Value-free record of a secret destroy tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretTombstone {
    secret_ref: SecretRef,
    from: SecretLifecycle,
    to: SecretLifecycle,
    reason: SafeLabel,
    destroyed_at: SystemTime,
    retain_until: SystemTime,
}

impl SecretTombstone {
    fn new(
        secret_ref: SecretRef,
        from: SecretLifecycle,
        reason: SafeLabel,
        destroyed_at: SystemTime,
        retain_until: SystemTime,
    ) -> Self {
        Self {
            secret_ref,
            from,
            to: SecretLifecycle::Destroyed,
            reason,
            destroyed_at,
            retain_until,
        }
    }

    /// Secret ref being tombstoned.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Prior lifecycle state.
    pub fn from(&self) -> SecretLifecycle {
        self.from
    }

    /// New lifecycle state represented by the tombstone.
    pub fn to(&self) -> SecretLifecycle {
        self.to
    }

    /// Operator/admin reason label.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }

    /// Timestamp when Janus recorded the destroy tombstone.
    pub fn destroyed_at(&self) -> SystemTime {
        self.destroyed_at
    }

    /// Timestamp until which the value-free tombstone must be retained.
    pub fn retain_until(&self) -> SystemTime {
        self.retain_until
    }
}

/// Core tombstone validator/auditor.
pub struct TombstonePolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TombstoneDecision {
    outcome: AuditOutcome,
    reason_code: &'static str,
    detail: &'static str,
    severity: Severity,
}

impl TombstonePolicy {
    /// Validate and audit a destroy tombstone without deleting provider values.
    pub fn record<A>(
        descriptor: &SecretDescriptor,
        request: SecretTombstoneRequest,
        principal: &PrincipalChain,
        audit: &mut A,
    ) -> JanusResult<SecretTombstone>
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
                .with_evidence(request.reason.clone()),
            )?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "descriptor scope does not match caller scope",
            ));
        }
        let decision = decide_tombstone(descriptor, &request);
        audit.record(
            AuditEvent::new(
                AuditAction::SecretLifecycle,
                decision.outcome,
                decision.reason_code,
                decision.severity,
                Some(descriptor.secret_ref.clone()),
                principal,
            )
            .with_evidence(request.reason.clone()),
        )?;
        if decision.outcome == AuditOutcome::Denied {
            return Err(JanusError::policy_denied(
                decision.reason_code,
                decision.detail,
            ));
        }

        Ok(SecretTombstone::new(
            request.secret_ref,
            descriptor.lifecycle,
            request.reason,
            request.destroyed_at,
            request.retain_until,
        ))
    }
}

fn decide_tombstone(
    descriptor: &SecretDescriptor,
    request: &SecretTombstoneRequest,
) -> TombstoneDecision {
    if descriptor.secret_ref != request.secret_ref {
        return tombstone_deny(
            "denied_tombstone_ref_mismatch",
            "tombstone request does not match descriptor secret ref",
            Severity::Critical,
        );
    }
    if descriptor.lifecycle == SecretLifecycle::Destroyed {
        return tombstone_deny(
            "denied_lifecycle_destroyed_final",
            "destroyed lifecycle cannot transition",
            Severity::Critical,
        );
    }
    if descriptor.lifecycle != SecretLifecycle::PendingDelete {
        return tombstone_deny(
            "denied_destroy_requires_pending_delete",
            "destroy tombstone requires pending_delete lifecycle",
            Severity::High,
        );
    }
    if request.retain_until <= request.destroyed_at {
        return tombstone_deny(
            "denied_tombstone_retention_window",
            "tombstone retention must extend beyond destroyed_at",
            Severity::Warning,
        );
    }

    TombstoneDecision {
        outcome: AuditOutcome::Allowed,
        reason_code: "tombstone_recorded",
        detail: "destroy tombstone recorded",
        severity: Severity::Critical,
    }
}

fn tombstone_deny(
    reason_code: &'static str,
    detail: &'static str,
    severity: Severity,
) -> TombstoneDecision {
    TombstoneDecision {
        outcome: AuditOutcome::Denied,
        reason_code,
        detail,
        severity,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::{
        AuditOutcome, AuditWrite, OwnerRef, Principal, PrincipalId, PrincipalKind, ProfileId,
        SecretClass, SecretName, TrustLevel,
    };

    use super::*;

    fn tombstone_principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-cli").unwrap(),
            ),
            crate::test_scope("dev"),
        )
    }

    fn tombstone_descriptor(lifecycle: SecretLifecycle) -> SecretDescriptor {
        SecretDescriptor {
            name: SecretName::new("CANARY").unwrap(),
            secret_ref: SecretRef::new("sec_tombstone").unwrap(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: crate::test_scope("dev"),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            present: true,
        }
    }

    #[test]
    fn tombstone_policy_allows_pending_delete_with_retention() {
        let descriptor = tombstone_descriptor(SecretLifecycle::PendingDelete);
        let principal = tombstone_principal();
        let mut audit = AuditWrite::accepting();
        let reason = SafeLabel::new("reviewed destroy record").unwrap();
        let destroyed_at = UNIX_EPOCH + Duration::from_secs(10);
        let retain_until = UNIX_EPOCH + Duration::from_secs(20);
        let request = SecretTombstoneRequest::new(
            descriptor.secret_ref.clone(),
            reason.clone(),
            destroyed_at,
            retain_until,
        );

        let tombstone = TombstonePolicy::record(&descriptor, request, &principal, &mut audit)
            .expect("pending_delete tombstone should be allowed");

        assert_eq!(tombstone.secret_ref(), &descriptor.secret_ref);
        assert_eq!(tombstone.from(), SecretLifecycle::PendingDelete);
        assert_eq!(tombstone.to(), SecretLifecycle::Destroyed);
        assert_eq!(tombstone.reason(), &reason);
        assert_eq!(tombstone.destroyed_at(), destroyed_at);
        assert_eq!(tombstone.retain_until(), retain_until);
        assert_eq!(audit.events().len(), 1);
        let event = &audit.events()[0];
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "tombstone_recorded");
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.secret_ref.as_ref(), Some(&descriptor.secret_ref));
        assert_eq!(event.evidence.as_ref(), Some(&reason));
        assert!(!event.value_returned);
    }

    #[test]
    fn tombstone_policy_denies_destroy_without_pending_delete() {
        for (lifecycle, expected_reason, expected_severity) in [
            (
                SecretLifecycle::Draft,
                "denied_destroy_requires_pending_delete",
                Severity::High,
            ),
            (
                SecretLifecycle::Active,
                "denied_destroy_requires_pending_delete",
                Severity::High,
            ),
            (
                SecretLifecycle::Disabled,
                "denied_destroy_requires_pending_delete",
                Severity::High,
            ),
            (
                SecretLifecycle::Destroyed,
                "denied_lifecycle_destroyed_final",
                Severity::Critical,
            ),
        ] {
            let descriptor = tombstone_descriptor(lifecycle);
            let principal = tombstone_principal();
            let mut audit = AuditWrite::accepting();
            let request = SecretTombstoneRequest::new(
                descriptor.secret_ref.clone(),
                SafeLabel::new("reviewed destroy attempt").unwrap(),
                UNIX_EPOCH + Duration::from_secs(10),
                UNIX_EPOCH + Duration::from_secs(20),
            );

            let err =
                TombstonePolicy::record(&descriptor, request, &principal, &mut audit).unwrap_err();

            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected_reason
            ));
            assert_eq!(audit.events().len(), 1);
            let event = &audit.events()[0];
            assert_eq!(event.outcome, AuditOutcome::Denied);
            assert_eq!(event.reason_code, expected_reason);
            assert_eq!(event.severity, expected_severity);
            assert!(!event.value_returned);
        }
    }

    #[test]
    fn tombstone_policy_denies_mismatch_and_invalid_retention() {
        for (request_ref, retain_until, expected_reason) in [
            (
                SecretRef::new("sec_other").unwrap(),
                UNIX_EPOCH + Duration::from_secs(20),
                "denied_tombstone_ref_mismatch",
            ),
            (
                SecretRef::new("sec_tombstone").unwrap(),
                UNIX_EPOCH + Duration::from_secs(10),
                "denied_tombstone_retention_window",
            ),
        ] {
            let descriptor = tombstone_descriptor(SecretLifecycle::PendingDelete);
            let principal = tombstone_principal();
            let mut audit = AuditWrite::accepting();
            let request = SecretTombstoneRequest::new(
                request_ref,
                SafeLabel::new("reviewed destroy attempt").unwrap(),
                UNIX_EPOCH + Duration::from_secs(10),
                retain_until,
            );

            let err =
                TombstonePolicy::record(&descriptor, request, &principal, &mut audit).unwrap_err();

            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected_reason
            ));
            assert_eq!(audit.events().len(), 1);
            assert_eq!(audit.events()[0].outcome, AuditOutcome::Denied);
            assert_eq!(audit.events()[0].reason_code, expected_reason);
            assert!(!audit.events()[0].value_returned);
        }
    }
}

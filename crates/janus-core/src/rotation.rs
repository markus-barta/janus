//! Rotation lifecycle model.

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, ConsumerRef, ConsumerRegistry, JanusError,
    JanusResult, PrincipalChain, SafeLabel, SecretRef, SecretValue, Severity, StoreCapabilities,
};

/// Backend/broker rotation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Janus can generate and store a replacement value.
    Generated,
    /// Provider/connector can rotate at the source.
    ProviderApi,
    /// Consumers can accept old and new during rollout.
    DualValue,
    /// Manual/admin work is required.
    Manual,
    /// Rotation is unsupported.
    Unsupported,
}

/// Rotation lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationPhase {
    /// Plan was created.
    Planned,
    /// Preconditions were prepared.
    Prepared,
    /// New encrypted value was stored.
    NewValueStored,
    /// Validation ran.
    Validated,
    /// Consumers were updated/reloaded.
    ConsumersUpdated,
    /// Old value was revoked.
    OldRevoked,
    /// Post-rotation verification succeeded.
    Verified,
    /// Rotation completed.
    Done,
    /// Rotation failed.
    Failed,
    /// Rollback completed or was attempted.
    RolledBack,
}

/// Validation probe label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationProbe(String);

impl ValidationProbe {
    /// Construct a non-empty probe.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.trim().len() != value.len() {
            return Err(JanusError::InvalidIdentifier {
                kind: "validation_probe",
            });
        }
        Ok(Self(value))
    }

    /// Safe value-free probe label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Backend rotation request. The generated value is internal to Janus and must
/// never be returned by a store outcome.
pub struct RotationSpec {
    /// Strategy being attempted.
    pub strategy: RotationStrategy,
    /// Optional generated value supplied by the broker to the backend.
    pub generated_value: Option<SecretValue>,
}

impl RotationSpec {
    /// Generated-value rotation spec.
    pub fn generated(value: SecretValue) -> Self {
        Self {
            strategy: RotationStrategy::Generated,
            generated_value: Some(value),
        }
    }
}

/// Rollback strategy metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackPlan {
    /// Value-free summary.
    pub label: SafeLabel,
}

/// Broker-level rotation plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    /// Opaque plan id.
    pub id: String,
    /// Secret being rotated.
    pub secret_ref: SecretRef,
    /// Chosen strategy.
    pub strategy: RotationStrategy,
    /// Consumers included in the plan.
    pub consumers: Vec<ConsumerRef>,
    /// Required validation probes.
    pub validation: Vec<ValidationProbe>,
    /// Rollback story.
    pub rollback: RollbackPlan,
}

/// Value-free backend rotation outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationOutcome {
    /// Secret that changed.
    pub secret_ref: SecretRef,
    /// Final phase reached.
    pub phase: RotationPhase,
    /// Stable reason code.
    pub reason_code: &'static str,
    /// Values were never returned.
    pub value_returned: bool,
}

impl RotationOutcome {
    /// Successful value-free generated rotation outcome.
    pub fn rotated(secret_ref: SecretRef) -> Self {
        Self {
            secret_ref,
            phase: RotationPhase::NewValueStored,
            reason_code: "ok",
            value_returned: false,
        }
    }
}

/// Rotation planner decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationDecision {
    /// One-click rotation is safe to offer.
    Safe(RotationPlan),
    /// Rotation must not be offered as one-click.
    Unsafe {
        /// Stable reason code.
        reason_code: &'static str,
        /// Value-free detail.
        detail: String,
    },
}

/// Broker-level planner: stores can change values, but this decides whether
/// user-visible rotation is safe.
#[derive(Clone, Debug)]
pub struct RotationPlanner {
    consumers: ConsumerRegistry,
}

impl RotationPlanner {
    /// Construct a planner.
    pub fn new(consumers: ConsumerRegistry) -> Self {
        Self { consumers }
    }

    /// Plan generated rotation. Unknown, undeclared, unvalidated, or manually
    /// reloaded consumers block one-click rotation.
    pub fn plan_generated(
        &self,
        secret_ref: &SecretRef,
        capabilities: &StoreCapabilities,
    ) -> RotationDecision {
        if !capabilities.generated_rotate || !capabilities.write {
            return RotationDecision::Unsafe {
                reason_code: "rotation_unsupported",
                detail: "backend cannot perform generated rotation".to_string(),
            };
        }

        let consumers = self.consumers.consumers_for(secret_ref);
        if consumers.is_empty() || consumers.iter().any(|consumer| !consumer.declared) {
            return RotationDecision::Unsafe {
                reason_code: "unknown_consumers",
                detail: "all consumers must be declared before one-click rotation".to_string(),
            };
        }
        if consumers
            .iter()
            .any(|consumer| !consumer.reload.is_automation_ready())
        {
            return RotationDecision::Unsafe {
                reason_code: "consumer_reload_failed",
                detail: "consumer reload is manual or unsupported".to_string(),
            };
        }
        if consumers
            .iter()
            .any(|consumer| consumer.validation.is_empty())
        {
            return RotationDecision::Unsafe {
                reason_code: "consumer_validation_missing",
                detail: "consumer validation is required for one-click rotation".to_string(),
            };
        }

        RotationDecision::Safe(RotationPlan {
            id: format!("rot_{}", secret_ref.as_str()),
            secret_ref: secret_ref.clone(),
            strategy: RotationStrategy::Generated,
            consumers: consumers
                .iter()
                .map(|consumer| consumer.consumer_ref.clone())
                .collect(),
            validation: consumers
                .iter()
                .flat_map(|consumer| consumer.validation.clone())
                .collect(),
            rollback: RollbackPlan {
                label: SafeLabel::new("encrypted rollback material").expect("static label"),
            },
        })
    }

    /// Plan generated rotation and write value-free audit evidence.
    pub fn plan_generated_with_audit<A>(
        &self,
        secret_ref: &SecretRef,
        capabilities: &StoreCapabilities,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<RotationDecision>
    where
        A: AuditSink,
    {
        let decision = self.plan_generated(secret_ref, capabilities);
        let (outcome, reason_code, severity) = match &decision {
            RotationDecision::Safe(_) => (AuditOutcome::Allowed, "ok", Severity::Notice),
            RotationDecision::Unsafe { reason_code, .. } => {
                (AuditOutcome::Denied, *reason_code, Severity::Warning)
            }
        };
        audit.record(AuditEvent::new(
            AuditAction::RotationPlan,
            outcome,
            reason_code,
            severity,
            Some(secret_ref.clone()),
            principal,
        ))?;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRef, Environment, OwnerRef,
        ReloadMethod,
    };

    fn capabilities() -> StoreCapabilities {
        StoreCapabilities {
            write: true,
            delete: true,
            generated_rotate: true,
            rotate_native: false,
            versioning: false,
            leasing: false,
            native_audit: false,
            backend_key_custody: false,
        }
    }

    fn declared_consumer(secret_ref: SecretRef) -> ConsumerDescriptor {
        ConsumerDescriptor {
            consumer_ref: ConsumerRef::new("consumer.deploy").unwrap(),
            secret_ref,
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new("infra").unwrap(),
            environment: Environment::new("prod").unwrap(),
            reload: ReloadMethod::None,
            validation: vec![ValidationProbe::new("deploy-smoke").unwrap()],
            supports_dual_value: false,
            blast_radius: BlastRadius::new("release-publishing").unwrap(),
            declared: true,
        }
    }

    #[test]
    fn unknown_consumers_block_generated_rotation() {
        let planner = RotationPlanner::new(ConsumerRegistry::default());
        let decision = planner.plan_generated(&SecretRef::new("sec_api").unwrap(), &capabilities());
        assert!(matches!(
            decision,
            RotationDecision::Unsafe {
                reason_code: "unknown_consumers",
                ..
            }
        ));
    }

    #[test]
    fn declared_validated_consumers_allow_generated_rotation() {
        let secret_ref = SecretRef::new("sec_api").unwrap();
        let planner = RotationPlanner::new(ConsumerRegistry::new(vec![declared_consumer(
            secret_ref.clone(),
        )]));
        let decision = planner.plan_generated(&secret_ref, &capabilities());
        assert!(matches!(decision, RotationDecision::Safe(_)));
    }
}

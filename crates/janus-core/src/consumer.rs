//! Consumer registry for rotation and approved-use evidence.

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, ConsumerRef, JanusError, JanusResult,
    PrincipalChain, SafeLabel, ScopeRef, SecretRef, Severity,
};

/// Kind of consumer that may use a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerKind {
    /// Long-running service.
    Service,
    /// CI or release job.
    CiJob,
    /// Developer shell or local task.
    DevShell,
    /// Managed command profile.
    ManagedCommand,
    /// Janus-owned connector.
    Connector,
    /// Human-guided workflow.
    HumanWorkflow,
}

/// Owner reference for a consumer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnerRef(String);

impl OwnerRef {
    /// Construct a non-empty owner ref.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.trim().len() != value.len() {
            return Err(JanusError::InvalidIdentifier { kind: "owner_ref" });
        }
        Ok(Self(value))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Environment label for consumer state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Environment(String);

impl Environment {
    /// Construct a non-empty environment ref.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.trim().len() != value.len() {
            return Err(JanusError::InvalidIdentifier {
                kind: "environment",
            });
        }
        Ok(Self(value))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How Janus can reload a consumer after a value changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReloadMethod {
    /// No reload needed.
    None,
    /// Restart a declared service.
    RestartService { service: SafeLabel },
    /// Send a signal to a declared process.
    Signal { signal: SafeLabel },
    /// Run a reviewed hook.
    ExecHook { hook: SafeLabel },
    /// Ask a Janus-owned connector to reload.
    ConnectorAction { action: SafeLabel },
    /// Human/admin manual step.
    Manual,
    /// Reload is unsupported or unknown.
    Unsupported,
}

impl ReloadMethod {
    /// Whether this reload method can support one-click rotation when paired
    /// with validation.
    pub fn is_automation_ready(&self) -> bool {
        !matches!(self, Self::Manual | Self::Unsupported)
    }
}

/// Blast-radius descriptor for human review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlastRadius(String);

impl BlastRadius {
    /// Construct a non-empty blast radius label.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.trim().len() != value.len() {
            return Err(JanusError::InvalidIdentifier {
                kind: "blast_radius",
            });
        }
        Ok(Self(value))
    }
}

/// Declared or observed consumer metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerDescriptor {
    /// Opaque consumer ref.
    pub consumer_ref: ConsumerRef,
    /// Secret this consumer uses.
    pub secret_ref: SecretRef,
    /// Exact authorization scope of this consumer.
    pub scope: ScopeRef,
    /// Consumer kind.
    pub kind: ConsumerKind,
    /// Owning team/service.
    pub owner: OwnerRef,
    /// Environment.
    pub environment: Environment,
    /// Reload story.
    pub reload: ReloadMethod,
    /// Validation probe labels.
    pub validation: Vec<crate::ValidationProbe>,
    /// Whether the consumer can accept dual values during rollout.
    pub supports_dual_value: bool,
    /// Human-readable blast radius.
    pub blast_radius: BlastRadius,
    /// Whether this came from declared config rather than runtime observation.
    pub declared: bool,
}

/// Value-free consumer registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsumerRegistry {
    consumers: Vec<ConsumerDescriptor>,
}

impl ConsumerRegistry {
    /// Construct a registry.
    pub fn new(consumers: Vec<ConsumerDescriptor>) -> Self {
        Self { consumers }
    }

    /// Return all known consumers for a secret.
    pub fn consumers_for(&self, secret_ref: &SecretRef) -> Vec<&ConsumerDescriptor> {
        self.consumers
            .iter()
            .filter(|consumer| &consumer.secret_ref == secret_ref)
            .collect()
    }

    /// Record one observed consumer event without granting rotation safety.
    pub fn record_observed(&mut self, mut consumer: ConsumerDescriptor) {
        consumer.declared = false;
        self.consumers.push(consumer);
    }

    /// Record one observed consumer with value-free audit evidence.
    pub fn record_observed_with_audit<A>(
        &mut self,
        consumer: ConsumerDescriptor,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<()>
    where
        A: AuditSink,
    {
        if consumer.scope != principal.scope {
            audit.record(AuditEvent::new(
                AuditAction::ConsumerObserve,
                AuditOutcome::Denied,
                "denied_scope_mismatch",
                Severity::Warning,
                Some(consumer.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "consumer scope does not match caller scope",
            ));
        }
        audit.record(consumer_observe_event(&consumer, principal)?)?;
        self.record_observed(consumer);
        Ok(())
    }
}

pub(crate) fn consumer_observe_event(
    consumer: &ConsumerDescriptor,
    principal: &PrincipalChain,
) -> JanusResult<AuditEvent> {
    Ok(AuditEvent::new(
        AuditAction::ConsumerObserve,
        AuditOutcome::Allowed,
        "ok",
        Severity::Notice,
        Some(consumer.secret_ref.clone()),
        principal,
    )
    .with_evidence(SafeLabel::new(consumer.consumer_ref.as_str())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_and_unsupported_reload_are_not_automation_ready() {
        assert!(!ReloadMethod::Manual.is_automation_ready());
        assert!(!ReloadMethod::Unsupported.is_automation_ready());
        assert!(ReloadMethod::None.is_automation_ready());
    }
}

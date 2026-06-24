//! Audit-as-evidence contracts.

use crate::{JanusError, JanusResult, PrincipalChain, SecretRef};
use sha2::{Digest, Sha256};

/// Actions Janus core can audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    /// Secret metadata was listed.
    SecretList,
    /// A secret descriptor was read.
    SecretDescribe,
    /// A secret value was used by an approved internal path.
    SecretUse,
    /// A permit was requested.
    PermitRequest,
    /// A permit was issued.
    PermitIssue,
    /// Policy denied a permit.
    PermitDeny,
    /// A consumer was declared.
    ConsumerDeclare,
    /// A consumer use event was observed.
    ConsumerObserve,
    /// A rotation plan was created.
    RotationPlan,
    /// Backend health was checked.
    BackendHealth,
}

/// Value-free audit outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Action was allowed.
    Allowed,
    /// Action was denied.
    Denied,
    /// Action was blocked because evidence could not be written.
    AuditUnavailable,
}

/// Audit event severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Routine information.
    Info,
    /// Security-relevant notice.
    Notice,
    /// Denial or suspicious condition.
    Warning,
    /// High-risk state.
    High,
    /// Critical state.
    Critical,
}

/// A single value-free audit event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Action being recorded.
    pub action: AuditAction,
    /// Outcome.
    pub outcome: AuditOutcome,
    /// Stable reason code.
    pub reason_code: &'static str,
    /// Severity.
    pub severity: Severity,
    /// Optional secret reference. This is not a value and grants no access.
    pub secret_ref: Option<SecretRef>,
    /// Principal binding, not raw tokens/cookies/env.
    pub principal_binding: String,
    /// Monotonic sequence assigned by the sink.
    pub sequence: Option<u64>,
    /// Previous event hash assigned by the sink.
    pub prev_hash: Option<String>,
    /// Event hash assigned by the sink.
    pub event_hash: Option<String>,
    /// Whether any secret value was returned. Core events should keep this false.
    pub value_returned: bool,
}

impl AuditEvent {
    /// Construct a value-free audit event from a principal chain.
    pub fn new(
        action: AuditAction,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
        secret_ref: Option<SecretRef>,
        principal: &PrincipalChain,
    ) -> Self {
        Self {
            action,
            outcome,
            reason_code,
            severity,
            secret_ref,
            principal_binding: principal.binding_key(),
            sequence: None,
            prev_hash: None,
            event_hash: None,
            value_returned: false,
        }
    }

    fn hash_material(&self) -> String {
        format!(
            "{:?}|{:?}|{}|{:?}|{:?}|{}|{}|{}",
            self.action,
            self.outcome,
            self.reason_code,
            self.severity,
            self.secret_ref,
            self.principal_binding,
            self.sequence.unwrap_or_default(),
            self.prev_hash.as_deref().unwrap_or("genesis"),
        )
    }
}

/// Audit sink contract. Secret-bearing decisions fail closed if required audit
/// cannot be written.
pub trait AuditSink {
    /// Record one value-free event.
    fn record(&mut self, event: AuditEvent) -> JanusResult<()>;
}

impl<T> AuditSink for &mut T
where
    T: AuditSink + ?Sized,
{
    fn record(&mut self, event: AuditEvent) -> JanusResult<()> {
        (**self).record(event)
    }
}

/// A small in-memory sink for tests and conformance fixtures.
#[derive(Default)]
pub struct AuditWrite {
    events: Vec<AuditEvent>,
    fail: bool,
}

impl AuditWrite {
    /// Construct a sink that accepts writes.
    pub fn accepting() -> Self {
        Self::default()
    }

    /// Construct a sink that rejects writes.
    pub fn failing() -> Self {
        Self {
            events: Vec::new(),
            fail: true,
        }
    }

    /// Recorded events.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

impl AuditSink for AuditWrite {
    fn record(&mut self, mut event: AuditEvent) -> JanusResult<()> {
        if self.fail {
            return Err(JanusError::AuditUnavailable {
                detail: "audit sink rejected write".to_string(),
            });
        }
        let sequence = self.events.len() as u64 + 1;
        let prev_hash = self
            .events
            .last()
            .and_then(|event| event.event_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        event.sequence = Some(sequence);
        event.prev_hash = Some(prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(event.hash_material().as_bytes());
        event.event_hash = Some(hex::encode(hasher.finalize()));
        self.events.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutorRef, Principal, PrincipalId, PrincipalKind, ScopeRef};

    #[test]
    fn audit_events_are_value_free() {
        let principal = PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new("runner").unwrap()),
            ScopeRef::new("scope").unwrap(),
        );
        let event = AuditEvent::new(
            AuditAction::PermitIssue,
            AuditOutcome::Allowed,
            "ok",
            Severity::Notice,
            None,
            &principal,
        );
        assert!(!event.value_returned);
        assert_eq!(event.principal_binding, "executor:runner|scope:scope");
        let _executor = ExecutorRef::new("runner").unwrap();
    }

    #[test]
    fn audit_write_adds_integrity_metadata() {
        let principal = PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new("runner").unwrap()),
            ScopeRef::new("scope").unwrap(),
        );
        let mut audit = AuditWrite::accepting();
        audit
            .record(AuditEvent::new(
                AuditAction::SecretList,
                AuditOutcome::Allowed,
                "ok",
                Severity::Info,
                None,
                &principal,
            ))
            .unwrap();
        let event = &audit.events()[0];
        assert_eq!(event.sequence, Some(1));
        assert_eq!(event.prev_hash.as_deref(), Some("genesis"));
        assert_eq!(event.event_hash.as_ref().unwrap().len(), 64);
    }
}

//! Audit-as-evidence contracts.

use crate::{DelegatedUseContext, JanusError, JanusResult, PrincipalChain, SafeLabel, SecretRef};
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
    /// A high-risk permit was explicitly approved.
    PermitApprove,
    /// Policy denied a permit.
    PermitDeny,
    /// A narrow temporary delegation grant was issued.
    DelegationGrant,
    /// A delegation request or validation was denied.
    DelegationDeny,
    /// A delegation grant was revoked.
    DelegationRevoke,
    /// Expiry of a delegation grant was observed.
    DelegationExpire,
    /// A consumer was declared.
    ConsumerDeclare,
    /// A consumer use event was observed.
    ConsumerObserve,
    /// A declared consumer validation probe ran.
    ConsumerValidate,
    /// A declared consumer reload hook ran.
    ConsumerReload,
    /// A rotation plan was created.
    RotationPlan,
    /// A high-risk rotation was explicitly approved.
    RotationApprove,
    /// A rotation lifecycle phase advanced or failed.
    RotationLifecycle,
    /// A secret lifecycle state transition was allowed or denied.
    SecretLifecycle,
    /// A value-free stale lifecycle report row was emitted.
    SecretStalenessReport,
    /// A unified value-free lifecycle action queue snapshot was emitted.
    SecretLifecycleQueue,
    /// Backend health was checked.
    BackendHealth,
    /// A running artifact was admitted or rejected by release policy.
    ReleaseAdmission,
    /// An upgrade or migration preflight was accepted or rejected.
    UpgradePreflight,
    /// A reviewed migration changed persisted metadata.
    MigrationApply,
    /// Migration postflight verified or rejected the changed state.
    UpgradePostflight,
    /// A migration rollback restored its reviewed snapshot.
    UpgradeRollback,
    /// High-risk backend custody material was re-encrypted.
    AdminReencrypt,
    /// Backend recoverability or restore readiness was checked.
    AdminRestore,
    /// An offline clean-state recovery drill phase ran.
    RecoveryDrill,
    /// A scope-bound recovery or transfer plan was admitted or denied.
    ScopeTransferPreflight,
    /// A scope-bound recovery or transfer changed persisted metadata.
    ScopeTransferApply,
    /// Scope-transfer postflight verified or rejected installed metadata.
    ScopeTransferPostflight,
    /// A scope-transfer rollback restored its reviewed target snapshot.
    ScopeTransferRollback,
    /// A runtime action was admitted to or denied from a process plane.
    RuntimePlane,
}

impl AuditAction {
    /// Stable JSONL/integrity representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretList => "secret.list",
            Self::SecretDescribe => "secret.describe",
            Self::SecretUse => "secret.use",
            Self::PermitRequest => "permit.request",
            Self::PermitIssue => "permit.issue",
            Self::PermitApprove => "permit.approve",
            Self::PermitDeny => "permit.deny",
            Self::DelegationGrant => "delegation.grant",
            Self::DelegationDeny => "delegation.deny",
            Self::DelegationRevoke => "delegation.revoke",
            Self::DelegationExpire => "delegation.expire",
            Self::ConsumerDeclare => "consumer.declare",
            Self::ConsumerObserve => "consumer.observe",
            Self::ConsumerValidate => "consumer.validate",
            Self::ConsumerReload => "consumer.reload",
            Self::RotationPlan => "rotation.plan",
            Self::RotationApprove => "rotation.approve",
            Self::RotationLifecycle => "rotation.lifecycle",
            Self::SecretLifecycle => "secret.lifecycle",
            Self::SecretStalenessReport => "secret.staleness_report",
            Self::SecretLifecycleQueue => "secret.lifecycle_queue",
            Self::BackendHealth => "backend.health",
            Self::ReleaseAdmission => "release.admission",
            Self::UpgradePreflight => "upgrade.preflight",
            Self::MigrationApply => "migration.apply",
            Self::UpgradePostflight => "upgrade.postflight",
            Self::UpgradeRollback => "upgrade.rollback",
            Self::AdminReencrypt => "admin.reencrypt",
            Self::AdminRestore => "admin.restore",
            Self::RecoveryDrill => "recovery.drill",
            Self::ScopeTransferPreflight => "scope_transfer.preflight",
            Self::ScopeTransferApply => "scope_transfer.apply",
            Self::ScopeTransferPostflight => "scope_transfer.postflight",
            Self::ScopeTransferRollback => "scope_transfer.rollback",
            Self::RuntimePlane => "runtime.plane",
        }
    }

    /// Parse a stable JSONL/integrity representation.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "secret.list" => Self::SecretList,
            "secret.describe" => Self::SecretDescribe,
            "secret.use" => Self::SecretUse,
            "permit.request" => Self::PermitRequest,
            "permit.issue" => Self::PermitIssue,
            "permit.approve" => Self::PermitApprove,
            "permit.deny" => Self::PermitDeny,
            "delegation.grant" => Self::DelegationGrant,
            "delegation.deny" => Self::DelegationDeny,
            "delegation.revoke" => Self::DelegationRevoke,
            "delegation.expire" => Self::DelegationExpire,
            "consumer.declare" => Self::ConsumerDeclare,
            "consumer.observe" => Self::ConsumerObserve,
            "consumer.validate" => Self::ConsumerValidate,
            "consumer.reload" => Self::ConsumerReload,
            "rotation.plan" => Self::RotationPlan,
            "rotation.approve" => Self::RotationApprove,
            "rotation.lifecycle" => Self::RotationLifecycle,
            "secret.lifecycle" => Self::SecretLifecycle,
            "secret.staleness_report" => Self::SecretStalenessReport,
            "secret.lifecycle_queue" => Self::SecretLifecycleQueue,
            "backend.health" => Self::BackendHealth,
            "release.admission" => Self::ReleaseAdmission,
            "upgrade.preflight" => Self::UpgradePreflight,
            "migration.apply" => Self::MigrationApply,
            "upgrade.postflight" => Self::UpgradePostflight,
            "upgrade.rollback" => Self::UpgradeRollback,
            "admin.reencrypt" => Self::AdminReencrypt,
            "admin.restore" => Self::AdminRestore,
            "recovery.drill" => Self::RecoveryDrill,
            "scope_transfer.preflight" => Self::ScopeTransferPreflight,
            "scope_transfer.apply" => Self::ScopeTransferApply,
            "scope_transfer.postflight" => Self::ScopeTransferPostflight,
            "scope_transfer.rollback" => Self::ScopeTransferRollback,
            "runtime.plane" => Self::RuntimePlane,
            _ => return None,
        })
    }
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

impl AuditOutcome {
    /// Stable JSONL/integrity representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }

    /// Parse a stable JSONL/integrity representation.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "allowed" => Self::Allowed,
            "denied" => Self::Denied,
            "audit_unavailable" => Self::AuditUnavailable,
            _ => return None,
        })
    }
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

impl Severity {
    /// Stable JSONL/integrity representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parse a stable JSONL/integrity representation.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "info" => Self::Info,
            "notice" => Self::Notice,
            "warning" => Self::Warning,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => return None,
        })
    }
}

/// Canonical fields covered by the audit event hash.
///
/// Length-prefixed fields avoid delimiter ambiguity even when principal or
/// evidence labels contain punctuation.
#[derive(Clone, Copy, Debug)]
pub struct AuditIntegrityInput<'a> {
    /// Stable action text.
    pub action: &'a str,
    /// Stable outcome text.
    pub outcome: &'a str,
    /// Stable reason code.
    pub reason_code: &'a str,
    /// Stable severity text.
    pub severity: &'a str,
    /// Optional opaque secret reference.
    pub secret_ref: Option<&'a str>,
    /// Value-free principal binding.
    pub principal_binding: &'a str,
    /// Monotonic sink sequence.
    pub sequence: u64,
    /// Previous event hash or `genesis`.
    pub prev_hash: &'a str,
    /// Whether a secret value was returned.
    pub value_returned: bool,
    /// Optional value-free evidence label.
    pub evidence: Option<&'a str>,
    /// Optional exact value-free acting-as context.
    pub delegation: Option<&'a DelegatedUseContext>,
}

/// Calculate the canonical SHA-256 hash for one audit record.
pub fn audit_integrity_hash(input: AuditIntegrityInput<'_>) -> String {
    fn field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn optional_field(hasher: &mut Sha256, value: Option<&str>) {
        match value {
            Some(value) => {
                hasher.update([1]);
                field(hasher, value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }

    let mut hasher = Sha256::new();
    field(&mut hasher, b"janus-audit-v1");
    field(&mut hasher, input.action.as_bytes());
    field(&mut hasher, input.outcome.as_bytes());
    field(&mut hasher, input.reason_code.as_bytes());
    field(&mut hasher, input.severity.as_bytes());
    optional_field(&mut hasher, input.secret_ref);
    field(&mut hasher, input.principal_binding.as_bytes());
    field(&mut hasher, &input.sequence.to_be_bytes());
    field(&mut hasher, input.prev_hash.as_bytes());
    field(&mut hasher, &[u8::from(input.value_returned)]);
    optional_field(&mut hasher, input.evidence);
    if let Some(delegation) = input.delegation {
        field(&mut hasher, b"delegation-v1");
        field(&mut hasher, delegation.integrity_text().as_bytes());
    }
    hex::encode(hasher.finalize())
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
    /// Optional value-free evidence label, such as an approval reason.
    pub evidence: Option<SafeLabel>,
    /// Optional exact acting-as context.
    pub delegation: Option<DelegatedUseContext>,
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
            evidence: None,
            delegation: None,
        }
    }

    /// Attach value-free evidence to an event.
    pub fn with_evidence(mut self, evidence: SafeLabel) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Attach exact value-free acting-as context.
    pub fn with_delegation(mut self, delegation: DelegatedUseContext) -> Self {
        self.delegation = Some(delegation);
        self
    }

    /// Assign sequence/chain metadata and calculate the canonical event hash.
    pub fn seal_integrity(&mut self, sequence: u64, prev_hash: impl Into<String>) {
        let prev_hash = prev_hash.into();
        let event_hash = audit_integrity_hash(AuditIntegrityInput {
            action: self.action.as_str(),
            outcome: self.outcome.as_str(),
            reason_code: self.reason_code,
            severity: self.severity.as_str(),
            secret_ref: self.secret_ref.as_ref().map(SecretRef::as_str),
            principal_binding: &self.principal_binding,
            sequence,
            prev_hash: &prev_hash,
            value_returned: self.value_returned,
            evidence: self.evidence.as_ref().map(SafeLabel::as_str),
            delegation: self.delegation.as_ref(),
        });
        self.sequence = Some(sequence);
        self.prev_hash = Some(prev_hash);
        self.event_hash = Some(event_hash);
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
        event.seal_integrity(sequence, prev_hash);
        self.events.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutorRef, Principal, PrincipalId, PrincipalKind};

    #[test]
    fn audit_events_are_value_free() {
        let principal = PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new("runner").unwrap()),
            crate::test_scope("dev"),
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
        assert!(event
            .principal_binding
            .starts_with("executor:runner|scope:scp_"));
        let _executor = ExecutorRef::new("runner").unwrap();
    }

    #[test]
    fn audit_write_adds_integrity_metadata() {
        let principal = PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new("runner").unwrap()),
            crate::test_scope("dev"),
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

    #[test]
    fn audit_integrity_text_is_stable_and_value_returned_is_covered() {
        for action in [
            AuditAction::SecretList,
            AuditAction::SecretUse,
            AuditAction::PermitIssue,
            AuditAction::DelegationGrant,
            AuditAction::DelegationDeny,
            AuditAction::DelegationRevoke,
            AuditAction::DelegationExpire,
            AuditAction::RotationLifecycle,
            AuditAction::AdminRestore,
            AuditAction::RecoveryDrill,
        ] {
            assert_eq!(AuditAction::parse(action.as_str()), Some(action));
        }
        for outcome in [AuditOutcome::Allowed, AuditOutcome::Denied] {
            assert_eq!(AuditOutcome::parse(outcome.as_str()), Some(outcome));
        }
        for severity in [Severity::Info, Severity::Warning, Severity::Critical] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }

        let base = AuditIntegrityInput {
            action: AuditAction::SecretUse.as_str(),
            outcome: AuditOutcome::Allowed.as_str(),
            reason_code: "ok",
            severity: Severity::Notice.as_str(),
            secret_ref: Some("sec_fixture"),
            principal_binding: "executor:runner|scope:scope",
            sequence: 1,
            prev_hash: "genesis",
            value_returned: false,
            evidence: None,
            delegation: None,
        };
        let value_free_hash = audit_integrity_hash(base);
        let value_bearing_hash = audit_integrity_hash(AuditIntegrityInput {
            value_returned: true,
            ..base
        });
        assert_ne!(value_free_hash, value_bearing_hash);
    }
}

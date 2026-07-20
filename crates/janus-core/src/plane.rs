//! Runtime process-plane separation.

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    SafeLabel, Severity,
};

/// Operational process planes. A running process belongs to exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimePlane {
    /// Permit-bound secret use and reference-only discovery.
    Use,
    /// Approval, lifecycle, rotation, migration, and recovery administration.
    Admin,
}

impl RuntimePlane {
    /// Stable audit and configuration text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Use => "use",
            Self::Admin => "admin",
        }
    }
}

/// Closed catalog of operations exposed by the Rust runtime processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAction {
    /// Warden descriptor listing.
    WardenListSecrets,
    /// Warden descriptor lookup.
    WardenDescribeSecret,
    /// Warden permit request.
    WardenRequestUse,
    /// Warden redacted health.
    WardenHealth,
    /// Managed-command preflight.
    ManagedRunPreflight,
    /// Permit-bound managed-command execution.
    ManagedRun,
    /// Private env-file handoff preflight.
    EnvFilePreflight,
    /// Permit-bound private env-file handoff.
    EnvFile,
    /// Approval grant creation.
    ApprovalIssue,
    /// Permit issuance from an approval.
    ApprovalPermit,
    /// Approval inventory listing.
    ApprovalList,
    /// Approval revocation.
    ApprovalRevoke,
    /// Lifecycle transition.
    LifecycleTransition,
    /// Lifecycle staleness report.
    LifecycleStaleReport,
    /// Destroy tombstone recording.
    LifecycleDestroyRecord,
    /// Destroy metadata finalization.
    LifecycleDestroyFinalize,
    /// Destroy metadata reconciliation.
    LifecycleDestroyReconcile,
    /// Generated-value rotation.
    ForgeRotateGenerated,
    /// Versioned approval migration.
    Migration,
    /// Offline scope transfer.
    ScopeTransfer,
    /// Pharos credential retirement.
    PharosRetire,
    /// Pharos retirement reconciliation.
    PharosReconcile,
}

impl RuntimeAction {
    /// Every known action, used by release-blocking completeness tests.
    pub const ALL: [Self; 22] = [
        Self::WardenListSecrets,
        Self::WardenDescribeSecret,
        Self::WardenRequestUse,
        Self::WardenHealth,
        Self::ManagedRunPreflight,
        Self::ManagedRun,
        Self::EnvFilePreflight,
        Self::EnvFile,
        Self::ApprovalIssue,
        Self::ApprovalPermit,
        Self::ApprovalList,
        Self::ApprovalRevoke,
        Self::LifecycleTransition,
        Self::LifecycleStaleReport,
        Self::LifecycleDestroyRecord,
        Self::LifecycleDestroyFinalize,
        Self::LifecycleDestroyReconcile,
        Self::ForgeRotateGenerated,
        Self::Migration,
        Self::ScopeTransfer,
        Self::PharosRetire,
        Self::PharosReconcile,
    ];

    /// The only process plane allowed to expose this action.
    pub const fn required_plane(self) -> RuntimePlane {
        match self {
            Self::WardenListSecrets
            | Self::WardenDescribeSecret
            | Self::WardenRequestUse
            | Self::WardenHealth
            | Self::ManagedRunPreflight
            | Self::ManagedRun
            | Self::EnvFilePreflight
            | Self::EnvFile => RuntimePlane::Use,
            Self::ApprovalIssue
            | Self::ApprovalPermit
            | Self::ApprovalList
            | Self::ApprovalRevoke
            | Self::LifecycleTransition
            | Self::LifecycleStaleReport
            | Self::LifecycleDestroyRecord
            | Self::LifecycleDestroyFinalize
            | Self::LifecycleDestroyReconcile
            | Self::ForgeRotateGenerated
            | Self::Migration
            | Self::ScopeTransfer
            | Self::PharosRetire
            | Self::PharosReconcile => RuntimePlane::Admin,
        }
    }

    /// Stable audit text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WardenListSecrets => "warden.list_secrets",
            Self::WardenDescribeSecret => "warden.describe_secret",
            Self::WardenRequestUse => "warden.request_use",
            Self::WardenHealth => "warden.health",
            Self::ManagedRunPreflight => "use.run_preflight",
            Self::ManagedRun => "use.run",
            Self::EnvFilePreflight => "use.env_file_preflight",
            Self::EnvFile => "use.env_file",
            Self::ApprovalIssue => "admin.approval_issue",
            Self::ApprovalPermit => "admin.approval_permit",
            Self::ApprovalList => "admin.approval_list",
            Self::ApprovalRevoke => "admin.approval_revoke",
            Self::LifecycleTransition => "admin.lifecycle_transition",
            Self::LifecycleStaleReport => "admin.lifecycle_stale_report",
            Self::LifecycleDestroyRecord => "admin.lifecycle_destroy_record",
            Self::LifecycleDestroyFinalize => "admin.lifecycle_destroy_finalize",
            Self::LifecycleDestroyReconcile => "admin.lifecycle_destroy_reconcile",
            Self::ForgeRotateGenerated => "admin.forge_rotate_generated",
            Self::Migration => "admin.migration",
            Self::ScopeTransfer => "admin.scope_transfer",
            Self::PharosRetire => "admin.pharos_retire",
            Self::PharosReconcile => "admin.pharos_reconcile",
        }
    }
}

/// Enforce that one runtime action belongs to the selected process plane.
///
/// `None` represents the retired mixed `janusd` entry point. A denial is
/// audited before the caller may open provider, permit, approval, lifecycle,
/// or migration state. If required audit fails, the audit error wins.
pub fn authorize_runtime_action<A>(
    selected_plane: Option<RuntimePlane>,
    action: RuntimeAction,
    principal: &PrincipalChain,
    audit: &mut A,
) -> JanusResult<()>
where
    A: AuditSink,
{
    if selected_plane == Some(action.required_plane()) {
        return Ok(());
    }

    let selected = selected_plane.map_or("legacy", RuntimePlane::as_str);
    let evidence = SafeLabel::new(format!(
        "selected_plane={selected};required_plane={};action={}",
        action.required_plane().as_str(),
        action.as_str()
    ))?;
    audit.record(
        AuditEvent::new(
            AuditAction::RuntimePlane,
            AuditOutcome::Denied,
            "denied_wrong_plane",
            Severity::Warning,
            None,
            principal,
        )
        .with_evidence(evidence),
    )?;
    Err(JanusError::policy_denied(
        "denied_wrong_plane",
        "runtime action belongs to another process plane",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditWrite, Principal, PrincipalId, PrincipalKind, ScopePathV1};

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runtime-fixture").unwrap(),
            ),
            ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
                .unwrap()
                .scope_ref(),
        )
    }

    #[test]
    fn every_action_has_exactly_one_operational_plane() {
        assert_eq!(RuntimeAction::ALL.len(), 22);
        assert_eq!(
            RuntimeAction::ALL
                .iter()
                .filter(|action| action.required_plane() == RuntimePlane::Use)
                .count(),
            8
        );
        assert_eq!(
            RuntimeAction::ALL
                .iter()
                .filter(|action| action.required_plane() == RuntimePlane::Admin)
                .count(),
            14
        );
        assert!(RuntimeAction::ALL
            .iter()
            .all(|action| !action.as_str().trim().is_empty()));
    }

    #[test]
    fn matching_plane_allows_without_audit_noise() {
        let mut audit = AuditWrite::accepting();
        authorize_runtime_action(
            Some(RuntimePlane::Use),
            RuntimeAction::ManagedRun,
            &principal(),
            &mut audit,
        )
        .unwrap();
        assert!(audit.events().is_empty());
    }

    #[test]
    fn cross_plane_and_legacy_calls_fail_closed_with_value_free_audit() {
        for selected in [Some(RuntimePlane::Admin), None] {
            let mut audit = AuditWrite::accepting();
            let error = authorize_runtime_action(
                selected,
                RuntimeAction::ManagedRun,
                &principal(),
                &mut audit,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                JanusError::PolicyDenied {
                    reason_code: "denied_wrong_plane",
                    ..
                }
            ));
            let event = &audit.events()[0];
            assert_eq!(event.action, AuditAction::RuntimePlane);
            assert_eq!(event.outcome, AuditOutcome::Denied);
            assert_eq!(event.reason_code, "denied_wrong_plane");
            assert!(!event.value_returned);
            assert!(event
                .evidence
                .as_ref()
                .unwrap()
                .as_str()
                .contains("action=use.run"));
        }
    }

    #[test]
    fn audit_failure_wins_over_plane_denial() {
        let mut audit = AuditWrite::failing();
        let error = authorize_runtime_action(
            Some(RuntimePlane::Use),
            RuntimeAction::ApprovalIssue,
            &principal(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));
    }
}

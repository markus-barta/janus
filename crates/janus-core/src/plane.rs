//! Runtime process-plane separation.

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    SafeLabel, Severity,
};
use serde_json::{json, Value};

/// Maximum serialized JSON argument bytes accepted by one Warden MCP tool call.
pub const WARDEN_MAX_ARGUMENT_BYTES: usize = 8 * 1024;
/// Maximum duration of one Warden MCP tool call.
pub const WARDEN_CALL_TIMEOUT_MS: u64 = 30_000;
/// Maximum Warden calls admitted in one fixed abuse-control window.
pub const WARDEN_RATE_REQUESTS: u32 = 120;
/// Warden abuse-control window duration.
pub const WARDEN_RATE_WINDOW_MS: u64 = 60_000;
/// Maximum aggregate argv bytes accepted by one split-plane CLI invocation.
pub const CLI_MAX_ARGUMENT_BYTES: usize = 64 * 1024;

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
    /// Manifest-first draft secret create/import transaction.
    LifecycleEntry,
    /// Unified read-only lifecycle action queue.
    LifecycleActionQueue,
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
    pub const ALL: [Self; 24] = [
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
        Self::LifecycleEntry,
        Self::LifecycleActionQueue,
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
            | Self::LifecycleEntry
            | Self::LifecycleActionQueue
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
            Self::LifecycleEntry => "admin.lifecycle_entry",
            Self::LifecycleActionQueue => "admin.lifecycle_action_queue",
            Self::Migration => "admin.migration",
            Self::ScopeTransfer => "admin.scope_transfer",
            Self::PharosRetire => "admin.pharos_retire",
            Self::PharosReconcile => "admin.pharos_reconcile",
        }
    }
}

/// Transport that exposes one runtime action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTransport {
    /// Model Context Protocol over local process stdio.
    McpStdio,
    /// One local process invocation using argv.
    ProcessArgv,
}

impl RuntimeTransport {
    /// Stable endpoint-matrix text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::McpStdio => "mcp_stdio",
            Self::ProcessArgv => "process_argv",
        }
    }
}

/// Input encoding accepted by one runtime endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeInputEncoding {
    /// A JSON object validated against the static MCP tool schema.
    JsonObject,
    /// Operating-system argv parsed by the dedicated process plane.
    Argv,
}

impl RuntimeInputEncoding {
    /// Stable endpoint-matrix text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonObject => "json_object",
            Self::Argv => "argv",
        }
    }
}

/// Timeout contract for one runtime endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTimeoutPolicy {
    /// Each call is cancelled after the declared duration.
    PerCallMillis(u64),
    /// The endpoint is one process invocation; operation-specific child-work
    /// timeouts remain inside the reviewed command implementation.
    ProcessLifetime,
}

impl RuntimeTimeoutPolicy {
    /// Stable endpoint-matrix mode.
    pub const fn mode(self) -> &'static str {
        match self {
            Self::PerCallMillis(_) => "per_call",
            Self::ProcessLifetime => "process_lifetime",
        }
    }

    /// Per-call duration when the mode is [`Self::PerCallMillis`].
    pub const fn milliseconds(self) -> Option<u64> {
        match self {
            Self::PerCallMillis(milliseconds) => Some(milliseconds),
            Self::ProcessLifetime => None,
        }
    }
}

/// Abuse-control contract for one runtime endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbuseBudget {
    /// A bounded number of requests in a fixed window.
    FixedWindow { requests: u32, window_ms: u64 },
    /// The operating system creates one bounded process invocation per call.
    ProcessInvocation,
}

impl RuntimeAbuseBudget {
    /// Stable endpoint-matrix mode.
    pub const fn mode(self) -> &'static str {
        match self {
            Self::FixedWindow { .. } => "fixed_window",
            Self::ProcessInvocation => "process_invocation",
        }
    }

    /// Fixed-window request count, when applicable.
    pub const fn requests(self) -> Option<u32> {
        match self {
            Self::FixedWindow { requests, .. } => Some(requests),
            Self::ProcessInvocation => None,
        }
    }

    /// Fixed-window duration, when applicable.
    pub const fn window_ms(self) -> Option<u64> {
        match self {
            Self::FixedWindow { window_ms, .. } => Some(window_ms),
            Self::ProcessInvocation => None,
        }
    }
}

/// Whether a protocol-specific control applies to the current local transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeControlApplicability {
    /// The control is enforced at this endpoint.
    Enforced,
    /// The control does not exist on the declared local transport.
    NotApplicable,
}

impl RuntimeControlApplicability {
    /// Stable endpoint-matrix text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Closed runtime endpoint policy for one operational action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeEndpointPolicy {
    /// Action covered by this policy.
    pub action: RuntimeAction,
    /// Only process plane allowed to expose the action.
    pub plane: RuntimePlane,
    /// Local transport that exposes the action.
    pub transport: RuntimeTransport,
    /// Accepted input encoding.
    pub input_encoding: RuntimeInputEncoding,
    /// Maximum aggregate serialized argument bytes.
    pub max_serialized_arguments_bytes: usize,
    /// Maximum concurrently active calls inside this endpoint instance.
    pub concurrency_limit: usize,
    /// Timeout contract.
    pub timeout: RuntimeTimeoutPolicy,
    /// Abuse-control contract.
    pub abuse_budget: RuntimeAbuseBudget,
    /// Whether every operational call or denial requires value-free audit evidence.
    pub audit_required: bool,
    /// Whether errors must pass the value-free redaction boundary.
    pub value_free_errors: bool,
    /// Browser origin policy applicability.
    pub origin: RuntimeControlApplicability,
    /// Browser CSRF policy applicability.
    pub csrf: RuntimeControlApplicability,
    /// HTTP cache policy applicability.
    pub cache: RuntimeControlApplicability,
    /// HTTP response security-header applicability.
    pub response_security_headers: RuntimeControlApplicability,
    /// Whether bind, proxy, or forwarded-client identity input is accepted.
    pub remote_identity_accepted: bool,
}

const fn warden_endpoint_policy(action: RuntimeAction) -> RuntimeEndpointPolicy {
    RuntimeEndpointPolicy {
        action,
        plane: RuntimePlane::Use,
        transport: RuntimeTransport::McpStdio,
        input_encoding: RuntimeInputEncoding::JsonObject,
        max_serialized_arguments_bytes: WARDEN_MAX_ARGUMENT_BYTES,
        concurrency_limit: 1,
        timeout: RuntimeTimeoutPolicy::PerCallMillis(WARDEN_CALL_TIMEOUT_MS),
        abuse_budget: RuntimeAbuseBudget::FixedWindow {
            requests: WARDEN_RATE_REQUESTS,
            window_ms: WARDEN_RATE_WINDOW_MS,
        },
        audit_required: true,
        value_free_errors: true,
        origin: RuntimeControlApplicability::NotApplicable,
        csrf: RuntimeControlApplicability::NotApplicable,
        cache: RuntimeControlApplicability::NotApplicable,
        response_security_headers: RuntimeControlApplicability::NotApplicable,
        remote_identity_accepted: false,
    }
}

const fn cli_endpoint_policy(action: RuntimeAction) -> RuntimeEndpointPolicy {
    RuntimeEndpointPolicy {
        action,
        plane: action.required_plane(),
        transport: RuntimeTransport::ProcessArgv,
        input_encoding: RuntimeInputEncoding::Argv,
        max_serialized_arguments_bytes: CLI_MAX_ARGUMENT_BYTES,
        concurrency_limit: 1,
        timeout: RuntimeTimeoutPolicy::ProcessLifetime,
        abuse_budget: RuntimeAbuseBudget::ProcessInvocation,
        audit_required: true,
        value_free_errors: true,
        origin: RuntimeControlApplicability::NotApplicable,
        csrf: RuntimeControlApplicability::NotApplicable,
        cache: RuntimeControlApplicability::NotApplicable,
        response_security_headers: RuntimeControlApplicability::NotApplicable,
        remote_identity_accepted: false,
    }
}

/// Return the reviewed endpoint policy for one closed runtime action.
pub const fn runtime_endpoint_policy(action: RuntimeAction) -> RuntimeEndpointPolicy {
    match action {
        RuntimeAction::WardenListSecrets
        | RuntimeAction::WardenDescribeSecret
        | RuntimeAction::WardenRequestUse
        | RuntimeAction::WardenHealth => warden_endpoint_policy(action),
        RuntimeAction::ManagedRunPreflight
        | RuntimeAction::ManagedRun
        | RuntimeAction::EnvFilePreflight
        | RuntimeAction::EnvFile
        | RuntimeAction::ApprovalIssue
        | RuntimeAction::ApprovalPermit
        | RuntimeAction::ApprovalList
        | RuntimeAction::ApprovalRevoke
        | RuntimeAction::LifecycleTransition
        | RuntimeAction::LifecycleStaleReport
        | RuntimeAction::LifecycleDestroyRecord
        | RuntimeAction::LifecycleDestroyFinalize
        | RuntimeAction::LifecycleDestroyReconcile
        | RuntimeAction::ForgeRotateGenerated
        | RuntimeAction::LifecycleEntry
        | RuntimeAction::LifecycleActionQueue
        | RuntimeAction::Migration
        | RuntimeAction::ScopeTransfer
        | RuntimeAction::PharosRetire
        | RuntimeAction::PharosReconcile => cli_endpoint_policy(action),
    }
}

/// Closed endpoint-policy catalog. Adding an action requires extending both
/// [`RuntimeAction::ALL`] and this release-reviewed matrix.
pub const RUNTIME_ENDPOINT_POLICIES: [RuntimeEndpointPolicy; 24] = [
    runtime_endpoint_policy(RuntimeAction::WardenListSecrets),
    runtime_endpoint_policy(RuntimeAction::WardenDescribeSecret),
    runtime_endpoint_policy(RuntimeAction::WardenRequestUse),
    runtime_endpoint_policy(RuntimeAction::WardenHealth),
    runtime_endpoint_policy(RuntimeAction::ManagedRunPreflight),
    runtime_endpoint_policy(RuntimeAction::ManagedRun),
    runtime_endpoint_policy(RuntimeAction::EnvFilePreflight),
    runtime_endpoint_policy(RuntimeAction::EnvFile),
    runtime_endpoint_policy(RuntimeAction::ApprovalIssue),
    runtime_endpoint_policy(RuntimeAction::ApprovalPermit),
    runtime_endpoint_policy(RuntimeAction::ApprovalList),
    runtime_endpoint_policy(RuntimeAction::ApprovalRevoke),
    runtime_endpoint_policy(RuntimeAction::LifecycleTransition),
    runtime_endpoint_policy(RuntimeAction::LifecycleStaleReport),
    runtime_endpoint_policy(RuntimeAction::LifecycleDestroyRecord),
    runtime_endpoint_policy(RuntimeAction::LifecycleDestroyFinalize),
    runtime_endpoint_policy(RuntimeAction::LifecycleDestroyReconcile),
    runtime_endpoint_policy(RuntimeAction::ForgeRotateGenerated),
    runtime_endpoint_policy(RuntimeAction::LifecycleEntry),
    runtime_endpoint_policy(RuntimeAction::LifecycleActionQueue),
    runtime_endpoint_policy(RuntimeAction::Migration),
    runtime_endpoint_policy(RuntimeAction::ScopeTransfer),
    runtime_endpoint_policy(RuntimeAction::PharosRetire),
    runtime_endpoint_policy(RuntimeAction::PharosReconcile),
];

/// Deterministic JSON value used by release assurance and the reviewed matrix.
pub fn runtime_endpoint_matrix() -> Value {
    Value::Array(
        RUNTIME_ENDPOINT_POLICIES
            .iter()
            .map(|policy| {
                json!({
                    "action": policy.action.as_str(),
                    "plane": policy.plane.as_str(),
                    "transport": policy.transport.as_str(),
                    "input_encoding": policy.input_encoding.as_str(),
                    "max_serialized_arguments_bytes": policy.max_serialized_arguments_bytes,
                    "concurrency_limit": policy.concurrency_limit,
                    "timeout": {
                        "mode": policy.timeout.mode(),
                        "milliseconds": policy.timeout.milliseconds(),
                    },
                    "abuse_budget": {
                        "mode": policy.abuse_budget.mode(),
                        "requests": policy.abuse_budget.requests(),
                        "window_ms": policy.abuse_budget.window_ms(),
                    },
                    "audit": if policy.audit_required { "required" } else { "optional" },
                    "error_redaction": if policy.value_free_errors { "value_free" } else { "unspecified" },
                    "origin": policy.origin.as_str(),
                    "csrf": policy.csrf.as_str(),
                    "cache": policy.cache.as_str(),
                    "response_security_headers": policy.response_security_headers.as_str(),
                    "remote_identity": if policy.remote_identity_accepted { "accepted" } else { "rejected" },
                })
            })
            .collect(),
    )
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
        assert_eq!(RuntimeAction::ALL.len(), 24);
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
            16
        );
        assert!(RuntimeAction::ALL
            .iter()
            .all(|action| !action.as_str().trim().is_empty()));
    }

    #[test]
    fn runtime_endpoint_policy_catalog_is_complete_closed_and_local_only() {
        assert_eq!(RUNTIME_ENDPOINT_POLICIES.len(), RuntimeAction::ALL.len());
        for action in RuntimeAction::ALL {
            let policies = RUNTIME_ENDPOINT_POLICIES
                .iter()
                .filter(|policy| policy.action == action)
                .collect::<Vec<_>>();
            assert_eq!(
                policies.len(),
                1,
                "missing or duplicate policy for {action:?}"
            );
            let policy = policies[0];
            assert_eq!(policy.plane, action.required_plane());
            assert!(policy.max_serialized_arguments_bytes > 0);
            assert_eq!(policy.concurrency_limit, 1);
            assert!(policy.audit_required);
            assert!(policy.value_free_errors);
            assert_eq!(policy.origin, RuntimeControlApplicability::NotApplicable);
            assert_eq!(policy.csrf, RuntimeControlApplicability::NotApplicable);
            assert_eq!(policy.cache, RuntimeControlApplicability::NotApplicable);
            assert_eq!(
                policy.response_security_headers,
                RuntimeControlApplicability::NotApplicable
            );
            assert!(!policy.remote_identity_accepted);
        }
    }

    #[test]
    fn runtime_endpoint_policy_matrix_matches_reviewed_snapshot() {
        let expected: Value =
            serde_json::from_str(include_str!("../../../config/runtime-endpoints/v1.json"))
                .expect("reviewed endpoint matrix should be valid JSON");
        assert_eq!(runtime_endpoint_matrix(), expected);
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

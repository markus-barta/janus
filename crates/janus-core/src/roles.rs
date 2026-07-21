//! Backend-neutral roles, permissions, and separation-of-duties decisions.
//!
//! The types in this module deliberately contain no storage or transport
//! assumptions. Durable registries live in `janus-local`; OIDC projection lives
//! in the Go envelope. This is the single closed vocabulary and immutable
//! authorization ceiling shared by both surfaces.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    RuntimeAction, SafeLabel, ScopeRef, SecretClass, SecretLifecycle, Severity,
};

/// Current strict role-policy snapshot schema.
pub const ROLE_POLICY_SNAPSHOT_VERSION: u8 = 1;
/// Current strict durable role-binding snapshot schema.
pub const ROLE_BINDING_SNAPSHOT_VERSION: u8 = 1;
/// Maximum accepted serialized policy bytes.
const MAX_POLICY_BYTES: usize = 64 * 1024;
/// Maximum accepted exact principal binding bytes.
const MAX_BINDING_BYTES: usize = 4 * 1024;
/// Maximum accepted source reference bytes before hashing.
const MAX_SOURCE_BYTES: usize = 4 * 1024;
/// Role bindings cannot outlive this reviewed bound.
pub const MAX_ROLE_BINDING_TTL: Duration = Duration::from_secs(366 * 24 * 60 * 60);

macro_rules! closed_text_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $name {
            /// Every member of this closed vocabulary.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Stable policy/audit text.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            /// Parse stable policy text, rejecting unknown values.
            pub fn parse(value: &str) -> JanusResult<Self> {
                match value {
                    $($text => Ok(Self::$variant)),+,
                    _ => Err(role_invalid(
                        "authorization_vocabulary_unknown",
                        format!("unknown {} value", stringify!($name)),
                    )),
                }
            }
        }
    };
}

closed_text_enum! {
    /// Closed role vocabulary. `BreakGlassAdmin` carries no ordinary authority.
    Role {
        /// Read value-free descriptors and posture.
        Viewer => "viewer",
        /// Execute reviewed normal-use paths, without approval or policy power.
        Operator => "operator",
        /// Own lifecycle and recovery decisions, without normal secret use.
        Owner => "owner",
        /// Approve exact uses, without executing them.
        Approver => "approver",
        /// Inspect value-free evidence, without secret use.
        Auditor => "auditor",
        /// Administer authorization policy and bindings, without secret use.
        SecurityAdmin => "security_admin",
        /// Eligibility marker only; activation is a separate reviewed workflow.
        BreakGlassAdmin => "break_glass_admin",
        /// Administer one exact service target only.
        ServiceAdmin => "service_admin",
        /// Administer one exact workload target only.
        WorkloadAdmin => "workload_admin"
    }
}

closed_text_enum! {
    /// Closed permission vocabulary representing actual Janus actions.
    Permission {
        DescriptorList => "descriptor.list",
        DescriptorRead => "descriptor.read",
        HealthRead => "health.read",
        SecretUse => "secret.use",
        ManagedRun => "managed_run.use",
        EnvFile => "env_file.use",
        ApprovalIssue => "approval.issue",
        ApprovalPermit => "approval.permit",
        ApprovalRead => "approval.read",
        ApprovalRevoke => "approval.revoke",
        DelegationIssue => "delegation.issue",
        DelegationRead => "delegation.read",
        DelegationRevoke => "delegation.revoke",
        LifecycleTransition => "lifecycle.transition",
        LifecycleRead => "lifecycle.read",
        DestroyRecord => "destroy.record",
        DestroyFinalize => "destroy.finalize",
        DestroyReconcile => "destroy.reconcile",
        RotateGenerated => "rotation.manage",
        LifecycleEntry => "lifecycle.entry",
        MigrationManage => "migration.manage",
        ScopeTransferManage => "scope_transfer.manage",
        RecoveryDrill => "recovery.drill",
        RetentionManage => "retention.manage",
        PharosRetire => "pharos.retire",
        PharosReconcile => "pharos.reconcile",
        RoleBindingIssue => "role_binding.issue",
        RoleBindingRead => "role_binding.read",
        RoleBindingRevoke => "role_binding.revoke",
        RoleBindingStatus => "role_binding.status",
        AuthorizationPolicyRead => "authorization_policy.read",
        AuthorizationPolicyManage => "authorization_policy.manage",
        BreakGlassActivate => "break_glass.activate",
        BreakGlassRead => "break_glass.read",
        BreakGlassRevoke => "break_glass.revoke",
        BreakGlassReview => "break_glass.review"
    }
}

impl Permission {
    /// Map every Rust runtime action to its reviewed role permission.
    pub const fn for_runtime_action(action: RuntimeAction) -> Self {
        match action {
            RuntimeAction::WardenListSecrets => Self::DescriptorList,
            RuntimeAction::WardenDescribeSecret => Self::DescriptorRead,
            RuntimeAction::WardenRequestUse => Self::SecretUse,
            RuntimeAction::WardenHealth => Self::HealthRead,
            RuntimeAction::ManagedRunPreflight | RuntimeAction::ManagedRun => Self::ManagedRun,
            RuntimeAction::EnvFilePreflight | RuntimeAction::EnvFile => Self::EnvFile,
            RuntimeAction::ApprovalIssue => Self::ApprovalIssue,
            RuntimeAction::ApprovalPermit => Self::ApprovalPermit,
            RuntimeAction::ApprovalList => Self::ApprovalRead,
            RuntimeAction::ApprovalRevoke => Self::ApprovalRevoke,
            RuntimeAction::DelegationIssue => Self::DelegationIssue,
            RuntimeAction::DelegationList | RuntimeAction::DelegationInspect => {
                Self::DelegationRead
            }
            RuntimeAction::DelegationRevoke => Self::DelegationRevoke,
            RuntimeAction::LifecycleTransition => Self::LifecycleTransition,
            RuntimeAction::LifecycleStaleReport | RuntimeAction::LifecycleActionQueue => {
                Self::LifecycleRead
            }
            RuntimeAction::LifecycleDestroyRecord => Self::DestroyRecord,
            RuntimeAction::LifecycleDestroyFinalize => Self::DestroyFinalize,
            RuntimeAction::LifecycleDestroyReconcile => Self::DestroyReconcile,
            RuntimeAction::ForgeRotateGenerated => Self::RotateGenerated,
            RuntimeAction::LifecycleEntry => Self::LifecycleEntry,
            RuntimeAction::Migration => Self::MigrationManage,
            RuntimeAction::ScopeTransfer => Self::ScopeTransferManage,
            RuntimeAction::RecoveryDrill => Self::RecoveryDrill,
            RuntimeAction::Retention => Self::RetentionManage,
            RuntimeAction::PharosRetire => Self::PharosRetire,
            RuntimeAction::PharosReconcile => Self::PharosReconcile,
            RuntimeAction::RoleBindingIssue => Self::RoleBindingIssue,
            RuntimeAction::RoleBindingList => Self::RoleBindingRead,
            RuntimeAction::RoleBindingRevoke => Self::RoleBindingRevoke,
            RuntimeAction::RoleBindingStatus => Self::RoleBindingStatus,
            RuntimeAction::AuthorizationPolicyStatus => Self::AuthorizationPolicyRead,
            RuntimeAction::BreakGlassRequest => Self::BreakGlassActivate,
            RuntimeAction::BreakGlassApprove => Self::ApprovalIssue,
            RuntimeAction::BreakGlassList | RuntimeAction::BreakGlassStatus => Self::BreakGlassRead,
            RuntimeAction::BreakGlassRevoke => Self::BreakGlassRevoke,
            RuntimeAction::BreakGlassReview => Self::BreakGlassReview,
        }
    }

    /// Permissions that can lead to secret-bearing execution.
    pub const fn is_use(self) -> bool {
        matches!(self, Self::SecretUse | Self::ManagedRun | Self::EnvFile)
    }
}

closed_text_enum! {
    /// Security-sensitive duties used to prevent one-person authority loops.
    Duty {
        RequestUse => "request_use",
        ExecuteUse => "execute_use",
        ApproveUse => "approve_use",
        GrantDelegation => "grant_delegation",
        ReceiveDelegation => "receive_delegation",
        ManageRolePolicy => "manage_role_policy",
        GrantRole => "grant_role",
        ReceiveRole => "receive_role",
        ActivateBreakGlass => "activate_break_glass",
        ApproveBreakGlass => "approve_break_glass",
        UseBreakGlass => "use_break_glass",
        ReviewBreakGlass => "review_break_glass",
        OperateRecovery => "operate_recovery",
        ReviewRecovery => "review_recovery"
    }
}

/// Opaque evidence that one actor performed one duty in one exact scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DutyEvidence {
    /// Performed duty.
    pub duty: Duty,
    /// Opaque hash of the exact principal binding.
    pub actor_fingerprint: String,
    /// Exact authorization scope.
    pub scope: ScopeRef,
}

impl DutyEvidence {
    /// Build value-free evidence from an exact principal binding.
    pub fn new(duty: Duty, principal_binding: &str, scope: ScopeRef) -> JanusResult<Self> {
        validate_bounded("principal_binding", principal_binding, MAX_BINDING_BYTES)?;
        Ok(Self {
            duty,
            actor_fingerprint: fingerprint("janus-duty-actor-v1", principal_binding),
            scope,
        })
    }
}

/// One immutable separation-of-duties conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DutyConflict {
    /// First incompatible duty.
    pub left: Duty,
    /// Second incompatible duty.
    pub right: Duty,
    /// Stable denial reason.
    pub reason_code: &'static str,
}

/// Closed hard-denial separation policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeparationPolicy {
    conflicts: &'static [DutyConflict],
}

const DUTY_CONFLICTS: &[DutyConflict] = &[
    DutyConflict {
        left: Duty::RequestUse,
        right: Duty::ApproveUse,
        reason_code: "separation_requester_approver",
    },
    DutyConflict {
        left: Duty::ApproveUse,
        right: Duty::ExecuteUse,
        reason_code: "separation_approver_executor",
    },
    DutyConflict {
        left: Duty::GrantDelegation,
        right: Duty::ReceiveDelegation,
        reason_code: "separation_self_delegation",
    },
    DutyConflict {
        left: Duty::GrantRole,
        right: Duty::ReceiveRole,
        reason_code: "separation_self_role_grant",
    },
    DutyConflict {
        left: Duty::ManageRolePolicy,
        right: Duty::ReceiveRole,
        reason_code: "separation_policy_self_benefit",
    },
    DutyConflict {
        left: Duty::ActivateBreakGlass,
        right: Duty::ApproveBreakGlass,
        reason_code: "separation_break_glass_self_approval",
    },
    DutyConflict {
        left: Duty::ActivateBreakGlass,
        right: Duty::UseBreakGlass,
        reason_code: "separation_break_glass_self_activation",
    },
    DutyConflict {
        left: Duty::UseBreakGlass,
        right: Duty::ReviewBreakGlass,
        reason_code: "separation_break_glass_self_review",
    },
    DutyConflict {
        left: Duty::OperateRecovery,
        right: Duty::ReviewRecovery,
        reason_code: "separation_recovery_self_review",
    },
];

impl Default for SeparationPolicy {
    fn default() -> Self {
        Self {
            conflicts: DUTY_CONFLICTS,
        }
    }
}

impl SeparationPolicy {
    /// Every immutable hard conflict.
    pub fn conflicts(&self) -> &'static [DutyConflict] {
        self.conflicts
    }

    fn conflict_for(&self, evidence: &[DutyEvidence]) -> Option<&'static str> {
        for (index, left) in evidence.iter().enumerate() {
            for right in &evidence[index + 1..] {
                if left.scope != right.scope || left.actor_fingerprint != right.actor_fingerprint {
                    continue;
                }
                for conflict in self.conflicts {
                    if (conflict.left == left.duty && conflict.right == right.duty)
                        || (conflict.left == right.duty && conflict.right == left.duty)
                    {
                        return Some(conflict.reason_code);
                    }
                }
            }
        }
        None
    }
}

closed_text_enum! {
    /// Provenance class for one role binding.
    RoleBindingSourceKind {
        LocalReviewed => "local_reviewed",
        OidcSubject => "oidc_subject",
        OidcGroup => "oidc_group",
        UnsafeBootstrap => "unsafe_bootstrap"
    }
}

/// Opaque integrity-bound source of one role binding.
#[derive(Clone, PartialEq, Eq)]
pub struct RoleBindingSource {
    /// Closed provenance class.
    pub kind: RoleBindingSourceKind,
    /// Opaque fingerprint of the reviewed source record.
    pub reference_fingerprint: String,
}

impl fmt::Debug for RoleBindingSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleBindingSource")
            .field("kind", &self.kind)
            .field("reference_fingerprint", &self.reference_fingerprint)
            .finish()
    }
}

impl RoleBindingSource {
    /// Construct a value-free source marker from exact source material.
    pub fn new(kind: RoleBindingSourceKind, source_reference: &str) -> JanusResult<Self> {
        validate_bounded("role_binding_source", source_reference, MAX_SOURCE_BYTES)?;
        Ok(Self {
            kind,
            reference_fingerprint: fingerprint("janus-role-source-v1", source_reference),
        })
    }
}

/// Opaque integrity identifier derived from every authorizing binding field.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleBindingId(String);

impl RoleBindingId {
    /// Rehydrate a strict opaque binding id.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        let Some(suffix) = value.strip_prefix("rbd_") else {
            return Err(role_invalid(
                "role_binding_id_invalid",
                "role binding id is malformed",
            ));
        };
        if suffix.len() != 24
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(role_invalid(
                "role_binding_id_invalid",
                "role binding id is malformed",
            ));
        }
        Ok(Self(value))
    }

    /// Safe opaque text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RoleBindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RoleBindingId")
            .field(&self.0)
            .finish()
    }
}

/// Strict private durable representation of one role binding.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBindingSnapshotV1 {
    pub schema_version: u8,
    pub binding_id: String,
    pub principal_binding: String,
    pub scope_ref: String,
    pub role: String,
    pub target_binding: Option<String>,
    pub valid_from_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub source_kind: String,
    pub source_reference_fingerprint: String,
}

impl fmt::Debug for RoleBindingSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleBindingSnapshotV1")
            .field("schema_version", &self.schema_version)
            .field("binding_id", &self.binding_id)
            .field("principal_binding", &"<redacted>")
            .field("scope_ref", &self.scope_ref)
            .field("role", &self.role)
            .field(
                "target_binding",
                &self.target_binding.as_ref().map(|_| "<redacted>"),
            )
            .field("valid_from_unix_secs", &self.valid_from_unix_secs)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .field("source_kind", &self.source_kind)
            .field(
                "source_reference_fingerprint",
                &self.source_reference_fingerprint,
            )
            .finish()
    }
}

/// One exact immutable role binding.
#[derive(Clone, PartialEq, Eq)]
pub struct RoleBinding {
    id: RoleBindingId,
    principal_binding: String,
    scope: ScopeRef,
    role: Role,
    target_binding: Option<String>,
    valid_from: SystemTime,
    expires_at: SystemTime,
    source: RoleBindingSource,
}

impl fmt::Debug for RoleBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleBinding")
            .field("id", &self.id)
            .field("principal_binding", &"<redacted>")
            .field("scope", &self.scope)
            .field("role", &self.role)
            .field(
                "target_binding",
                &self.target_binding.as_ref().map(|_| "<redacted>"),
            )
            .field("valid_from", &self.valid_from)
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .finish()
    }
}

impl RoleBinding {
    /// Create a strict integrity-bound binding.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        principal_binding: impl Into<String>,
        scope: ScopeRef,
        role: Role,
        target_binding: Option<String>,
        valid_from: SystemTime,
        expires_at: SystemTime,
        source: RoleBindingSource,
    ) -> JanusResult<Self> {
        let principal_binding = principal_binding.into();
        validate_bounded("principal_binding", &principal_binding, MAX_BINDING_BYTES)?;
        if let Some(target) = target_binding.as_deref() {
            validate_bounded("role_target_binding", target, MAX_BINDING_BYTES)?;
        }
        validate_role_target(role, target_binding.as_deref())?;
        validate_validity(valid_from, expires_at)?;
        let id = derive_binding_id(
            &principal_binding,
            &scope,
            role,
            target_binding.as_deref(),
            valid_from,
            expires_at,
            &source,
        )?;
        Ok(Self {
            id,
            principal_binding,
            scope,
            role,
            target_binding,
            valid_from,
            expires_at,
            source,
        })
    }

    pub fn id(&self) -> &RoleBindingId {
        &self.id
    }
    pub fn principal_binding(&self) -> &str {
        &self.principal_binding
    }
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn target_binding(&self) -> Option<&str> {
        self.target_binding.as_deref()
    }
    pub fn valid_from(&self) -> SystemTime {
        self.valid_from
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn source(&self) -> &RoleBindingSource {
        &self.source
    }

    /// Whether this binding is active for the exact actor, scope, target, and time.
    pub fn matches(
        &self,
        principal_binding: &str,
        scope: &ScopeRef,
        target_binding: Option<&str>,
        now: SystemTime,
    ) -> bool {
        self.principal_binding == principal_binding
            && &self.scope == scope
            && now >= self.valid_from
            && now < self.expires_at
            && match self.role {
                Role::ServiceAdmin | Role::WorkloadAdmin => {
                    self.target_binding.as_deref() == target_binding
                }
                _ => true,
            }
    }

    pub fn snapshot(&self) -> JanusResult<RoleBindingSnapshotV1> {
        Ok(RoleBindingSnapshotV1 {
            schema_version: ROLE_BINDING_SNAPSHOT_VERSION,
            binding_id: self.id.as_str().to_string(),
            principal_binding: self.principal_binding.clone(),
            scope_ref: self.scope.as_str().to_string(),
            role: self.role.as_str().to_string(),
            target_binding: self.target_binding.clone(),
            valid_from_unix_secs: unix_secs(self.valid_from)?,
            expires_at_unix_secs: unix_secs(self.expires_at)?,
            source_kind: self.source.kind.as_str().to_string(),
            source_reference_fingerprint: self.source.reference_fingerprint.clone(),
        })
    }

    pub fn from_snapshot(snapshot: RoleBindingSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != ROLE_BINDING_SNAPSHOT_VERSION {
            return Err(role_invalid(
                "role_binding_schema_unknown",
                "role binding schema is unsupported",
            ));
        }
        validate_fingerprint(&snapshot.source_reference_fingerprint)?;
        let source = RoleBindingSource {
            kind: RoleBindingSourceKind::parse(&snapshot.source_kind)?,
            reference_fingerprint: snapshot.source_reference_fingerprint,
        };
        let binding = Self::issue(
            snapshot.principal_binding,
            ScopeRef::from_opaque(snapshot.scope_ref)?,
            Role::parse(&snapshot.role)?,
            snapshot.target_binding,
            UNIX_EPOCH + Duration::from_secs(snapshot.valid_from_unix_secs),
            UNIX_EPOCH + Duration::from_secs(snapshot.expires_at_unix_secs),
            source,
        )?;
        if binding.id.as_str() != snapshot.binding_id {
            return Err(role_invalid(
                "role_binding_integrity_mismatch",
                "role binding integrity id does not match",
            ));
        }
        Ok(binding)
    }
}

/// Strict checked policy snapshot shared with other Janus surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolePolicySnapshotV1 {
    pub schema_version: u8,
    pub policy_id: String,
    pub roles: Vec<RolePolicyRoleSnapshotV1>,
}

/// One strict role row in a policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolePolicyRoleSnapshotV1 {
    pub role: String,
    pub permissions: Vec<String>,
}

/// Checked role policy. A snapshot may restrict immutable code ceilings but can
/// never broaden them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePolicyV1 {
    policy_id: SafeLabel,
    permissions: BTreeMap<Role, BTreeSet<Permission>>,
    separation: SeparationPolicy,
}

impl RolePolicyV1 {
    /// Parse and validate a strict policy snapshot.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        if contents.is_empty() || contents.len() > MAX_POLICY_BYTES {
            return Err(role_invalid(
                "role_policy_size_invalid",
                "role policy size is invalid",
            ));
        }
        let snapshot: RolePolicySnapshotV1 = serde_json::from_str(contents).map_err(|error| {
            role_invalid(
                "role_policy_parse_failed",
                format!("role policy parse failed: {error}"),
            )
        })?;
        Self::from_snapshot(snapshot)
    }

    /// Load the repository's checked shared policy snapshot.
    pub fn embedded() -> JanusResult<Self> {
        Self::parse_json(include_str!(
            "../../../config/authorization/role-matrix-v1.json"
        ))
    }

    /// Validate a parsed snapshot against immutable code ceilings.
    pub fn from_snapshot(snapshot: RolePolicySnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != ROLE_POLICY_SNAPSHOT_VERSION {
            return Err(role_invalid(
                "role_policy_schema_unknown",
                "role policy schema is unsupported",
            ));
        }
        let policy_id = SafeLabel::new(snapshot.policy_id)?;
        let mut permissions = BTreeMap::new();
        for row in snapshot.roles {
            let role = Role::parse(&row.role)?;
            if permissions.contains_key(&role) {
                return Err(role_invalid(
                    "role_policy_duplicate_role",
                    "role policy contains a duplicate role",
                ));
            }
            let ceiling: BTreeSet<_> = role_ceiling(role).iter().copied().collect();
            let mut allowed = BTreeSet::new();
            for permission in row.permissions {
                let permission = Permission::parse(&permission)?;
                if !ceiling.contains(&permission) {
                    return Err(role_invalid(
                        "role_policy_broadens_ceiling",
                        format!("{} cannot grant {}", role.as_str(), permission.as_str()),
                    ));
                }
                if !allowed.insert(permission) {
                    return Err(role_invalid(
                        "role_policy_duplicate_permission",
                        "role policy contains a duplicate permission",
                    ));
                }
            }
            permissions.insert(role, allowed);
        }
        if permissions.len() != Role::ALL.len()
            || Role::ALL.iter().any(|role| !permissions.contains_key(role))
        {
            return Err(role_invalid(
                "role_policy_role_missing",
                "role policy must contain every closed role exactly once",
            ));
        }
        Ok(Self {
            policy_id,
            permissions,
            separation: SeparationPolicy::default(),
        })
    }

    pub fn policy_id(&self) -> &SafeLabel {
        &self.policy_id
    }
    pub fn separation(&self) -> &SeparationPolicy {
        &self.separation
    }
    pub fn permissions_for(&self, role: Role) -> &BTreeSet<Permission> {
        self.permissions
            .get(&role)
            .expect("validated policies contain every role")
    }

    /// Produce a stable checked snapshot.
    pub fn snapshot(&self) -> RolePolicySnapshotV1 {
        RolePolicySnapshotV1 {
            schema_version: ROLE_POLICY_SNAPSHOT_VERSION,
            policy_id: self.policy_id.as_str().to_string(),
            roles: Role::ALL
                .iter()
                .map(|role| RolePolicyRoleSnapshotV1 {
                    role: role.as_str().to_string(),
                    permissions: self
                        .permissions_for(*role)
                        .iter()
                        .map(|permission| permission.as_str().to_string())
                        .collect(),
                })
                .collect(),
        }
    }

    /// Make one exact default-deny role decision from trusted bindings.
    pub fn decide(&self, input: &RoleDecisionInput<'_>) -> RoleDecision {
        if !input.audit_available {
            return RoleDecision::deny(input.permission, "authorization_audit_unavailable", false);
        }
        if input.scope != &input.principal.scope {
            return RoleDecision::deny(input.permission, "authorization_scope_mismatch", false);
        }
        if input.permission.is_use()
            && input
                .resource_lifecycle
                .is_some_and(|lifecycle| !lifecycle.allows_normal_use())
        {
            return RoleDecision::deny(
                input.permission,
                "authorization_resource_not_active",
                false,
            );
        }
        if let Some(reason) = self.separation.conflict_for(input.duties) {
            return RoleDecision::deny(input.permission, reason, true);
        }
        let principal_binding = input.principal.binding_key();
        let mut matched_role = None;
        let mut matched_binding_count = 0_u8;
        for binding in input.bindings {
            if binding.matches(
                &principal_binding,
                input.scope,
                input.target_binding,
                input.now,
            ) && self
                .permissions_for(binding.role)
                .contains(&input.permission)
            {
                matched_binding_count = matched_binding_count.saturating_add(1);
                if matched_binding_count > 1 {
                    return RoleDecision::deny(
                        input.permission,
                        "authorization_binding_ambiguous",
                        false,
                    );
                }
                matched_role = Some(binding.role);
            }
        }
        match matched_role {
            Some(role) => RoleDecision::allow(input.permission, role),
            None => RoleDecision::deny(input.permission, "authorization_role_missing", false),
        }
    }
}

/// Complete current facts for one role decision.
pub struct RoleDecisionInput<'a> {
    pub principal: &'a PrincipalChain,
    pub permission: Permission,
    pub scope: &'a ScopeRef,
    pub target_binding: Option<&'a str>,
    pub resource_owner_fingerprint: Option<&'a str>,
    pub resource_class: Option<SecretClass>,
    pub resource_lifecycle: Option<SecretLifecycle>,
    pub approval_fingerprint: Option<&'a str>,
    pub delegation_fingerprint: Option<&'a str>,
    pub audit_available: bool,
    pub duties: &'a [DutyEvidence],
    pub bindings: &'a [RoleBinding],
    pub now: SystemTime,
}

impl fmt::Debug for RoleDecisionInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleDecisionInput")
            .field("permission", &self.permission)
            .field("scope", &self.scope)
            .field("target_binding", &self.target_binding.map(|_| "<redacted>"))
            .field(
                "resource_owner_fingerprint",
                &self.resource_owner_fingerprint,
            )
            .field("resource_class", &self.resource_class)
            .field("resource_lifecycle", &self.resource_lifecycle)
            .field("approval_fingerprint", &self.approval_fingerprint)
            .field("delegation_fingerprint", &self.delegation_fingerprint)
            .field("audit_available", &self.audit_available)
            .field("duties", &self.duties)
            .field("binding_count", &self.bindings.len())
            .field("now", &self.now)
            .finish()
    }
}

/// Value-free result of one authorization decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleDecision {
    pub allowed: bool,
    pub permission: Permission,
    pub effective_role: Option<Role>,
    pub reason_code: &'static str,
    pub separation_denial: bool,
}

impl RoleDecision {
    fn allow(permission: Permission, role: Role) -> Self {
        Self {
            allowed: true,
            permission,
            effective_role: Some(role),
            reason_code: "authorization_allowed",
            separation_denial: false,
        }
    }

    fn deny(permission: Permission, reason_code: &'static str, separation_denial: bool) -> Self {
        Self {
            allowed: false,
            permission,
            effective_role: None,
            reason_code,
            separation_denial,
        }
    }

    /// Stable JSON-safe snapshot without principal or identity claim values.
    pub fn snapshot(&self, policy: &RolePolicyV1) -> RoleDecisionSnapshotV1 {
        RoleDecisionSnapshotV1 {
            schema_version: ROLE_POLICY_SNAPSHOT_VERSION,
            policy_id: policy.policy_id().as_str().to_string(),
            allowed: self.allowed,
            permission: self.permission.as_str().to_string(),
            effective_role: self.effective_role.map(|role| role.as_str().to_string()),
            reason_code: self.reason_code.to_string(),
            separation_denial: self.separation_denial,
        }
    }
}

/// Value-free serializable role decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDecisionSnapshotV1 {
    pub schema_version: u8,
    pub policy_id: String,
    pub allowed: bool,
    pub permission: String,
    pub effective_role: Option<String>,
    pub reason_code: String,
    pub separation_denial: bool,
}

/// Decide and record exactly one value-free authorization event. Audit failure
/// is returned and therefore cannot degrade to an allow.
pub fn authorize_role_action(
    policy: &RolePolicyV1,
    input: &RoleDecisionInput<'_>,
    audit: &mut impl AuditSink,
) -> JanusResult<RoleDecision> {
    let decision = policy.decide(input);
    let action = if decision.separation_denial {
        AuditAction::SeparationDeny
    } else {
        AuditAction::RoleCheck
    };
    let outcome = if decision.allowed {
        AuditOutcome::Allowed
    } else {
        AuditOutcome::Denied
    };
    let severity = if decision.allowed {
        Severity::Info
    } else {
        Severity::Warning
    };
    let evidence = SafeLabel::new(format!(
        "{} {}",
        policy.policy_id().as_str(),
        input.permission.as_str()
    ))?;
    audit.record(
        AuditEvent::new(
            action,
            outcome,
            decision.reason_code,
            severity,
            None,
            input.principal,
        )
        .with_evidence(evidence),
    )?;
    Ok(decision)
}

fn role_ceiling(role: Role) -> &'static [Permission] {
    use Permission as P;
    match role {
        Role::Viewer => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::LifecycleRead,
        ],
        Role::Operator => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::SecretUse,
            P::ManagedRun,
            P::EnvFile,
            P::ApprovalRead,
            P::LifecycleRead,
        ],
        Role::Owner => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::ApprovalRead,
            P::DelegationIssue,
            P::DelegationRead,
            P::DelegationRevoke,
            P::LifecycleTransition,
            P::LifecycleRead,
            P::DestroyRecord,
            P::DestroyFinalize,
            P::DestroyReconcile,
            P::RotateGenerated,
            P::LifecycleEntry,
            P::MigrationManage,
            P::ScopeTransferManage,
            P::RecoveryDrill,
            P::RetentionManage,
            P::PharosRetire,
            P::PharosReconcile,
            P::AuthorizationPolicyRead,
        ],
        Role::Approver => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::ApprovalIssue,
            P::ApprovalPermit,
            P::ApprovalRead,
            P::ApprovalRevoke,
            P::DelegationRead,
            P::LifecycleRead,
        ],
        Role::Auditor => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::ApprovalRead,
            P::DelegationRead,
            P::LifecycleRead,
            P::RoleBindingRead,
            P::RoleBindingStatus,
            P::AuthorizationPolicyRead,
            P::BreakGlassRead,
            P::BreakGlassReview,
        ],
        Role::SecurityAdmin => &[
            P::HealthRead,
            P::RoleBindingIssue,
            P::RoleBindingRead,
            P::RoleBindingRevoke,
            P::RoleBindingStatus,
            P::AuthorizationPolicyRead,
            P::AuthorizationPolicyManage,
            P::BreakGlassActivate,
            P::BreakGlassRead,
            P::BreakGlassRevoke,
            P::BreakGlassReview,
        ],
        Role::BreakGlassAdmin => &[],
        Role::ServiceAdmin => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::LifecycleTransition,
            P::LifecycleRead,
            P::RotateGenerated,
            P::LifecycleEntry,
        ],
        Role::WorkloadAdmin => &[
            P::DescriptorList,
            P::DescriptorRead,
            P::HealthRead,
            P::LifecycleTransition,
            P::LifecycleRead,
        ],
    }
}

fn validate_role_target(role: Role, target_binding: Option<&str>) -> JanusResult<()> {
    match (role, target_binding) {
        (Role::ServiceAdmin | Role::WorkloadAdmin, None) => Err(role_invalid(
            "role_target_required",
            "service and workload admin roles require one exact target",
        )),
        (Role::ServiceAdmin | Role::WorkloadAdmin, Some(_)) => Ok(()),
        (_, Some(_)) => Err(role_invalid(
            "role_target_forbidden",
            "only service and workload admin roles may carry a target",
        )),
        (_, None) => Ok(()),
    }
}

fn validate_validity(valid_from: SystemTime, expires_at: SystemTime) -> JanusResult<()> {
    let ttl = expires_at.duration_since(valid_from).map_err(|_| {
        role_invalid(
            "role_binding_validity_invalid",
            "role binding expiry must follow its start",
        )
    })?;
    if ttl.is_zero() || ttl > MAX_ROLE_BINDING_TTL {
        return Err(role_invalid(
            "role_binding_validity_invalid",
            "role binding validity is outside the reviewed bound",
        ));
    }
    unix_secs(valid_from)?;
    unix_secs(expires_at)?;
    Ok(())
}

fn derive_binding_id(
    principal_binding: &str,
    scope: &ScopeRef,
    role: Role,
    target_binding: Option<&str>,
    valid_from: SystemTime,
    expires_at: SystemTime,
    source: &RoleBindingSource,
) -> JanusResult<RoleBindingId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-role-binding-v1");
    hash_field(&mut hasher, principal_binding);
    hash_field(&mut hasher, scope.as_str());
    hash_field(&mut hasher, role.as_str());
    hash_optional(&mut hasher, target_binding);
    hasher.update(unix_secs(valid_from)?.to_be_bytes());
    hasher.update(unix_secs(expires_at)?.to_be_bytes());
    hash_field(&mut hasher, source.kind.as_str());
    hash_field(&mut hasher, &source.reference_fingerprint);
    let digest = hasher.finalize();
    Ok(RoleBindingId(format!("rbd_{}", hex::encode(&digest[..12]))))
}

fn unix_secs(value: SystemTime) -> JanusResult<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            role_invalid(
                "authorization_time_invalid",
                "authorization time predates Unix epoch",
            )
        })
}

fn validate_bounded(kind: &'static str, value: &str, max: usize) -> JanusResult<()> {
    if value.is_empty()
        || value.len() > max
        || value.trim().len() != value.len()
        || value.contains(['\n', '\r', '\0'])
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> JanusResult<()> {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return Err(role_invalid(
            "role_source_fingerprint_invalid",
            "role source fingerprint is malformed",
        ));
    };
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(role_invalid(
            "role_source_fingerprint_invalid",
            "role source fingerprint is malformed",
        ));
    }
    Ok(())
}

fn fingerprint(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain);
    hash_field(&mut hasher, value);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Create a domain-separated opaque fingerprint for an authorization fact.
pub fn authorization_fingerprint(domain: &str, value: &str) -> JanusResult<String> {
    validate_bounded("authorization_fact", domain, 128)?;
    validate_bounded("authorization_fact", value, MAX_BINDING_BYTES)?;
    Ok(fingerprint(domain, value))
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_field(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn role_invalid(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EnvironmentId, OrganizationId, Principal, PrincipalId, PrincipalKind, ProjectId,
        RepositoryId, ScopePathV1,
    };

    fn fixture() -> (PrincipalChain, ScopeRef) {
        let scope = ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("dev").unwrap(),
        )
        .scope_ref();
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope.clone(),
        );
        (principal, scope)
    }

    fn binding(principal: &PrincipalChain, role: Role, target: Option<String>) -> RoleBinding {
        RoleBinding::issue(
            principal.binding_key(),
            principal.scope.clone(),
            role,
            target,
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(101),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "change-42").unwrap(),
        )
        .unwrap()
    }

    fn input<'a>(
        principal: &'a PrincipalChain,
        scope: &'a ScopeRef,
        bindings: &'a [RoleBinding],
        duties: &'a [DutyEvidence],
        permission: Permission,
    ) -> RoleDecisionInput<'a> {
        RoleDecisionInput {
            principal,
            permission,
            scope,
            target_binding: None,
            resource_owner_fingerprint: None,
            resource_class: if permission.is_use() {
                Some(SecretClass::Normal)
            } else {
                None
            },
            resource_lifecycle: if permission.is_use() {
                Some(SecretLifecycle::Active)
            } else {
                None
            },
            approval_fingerprint: None,
            delegation_fingerprint: None,
            audit_available: true,
            duties,
            bindings,
            now: UNIX_EPOCH + Duration::from_secs(2),
        }
    }

    #[test]
    fn embedded_policy_matches_immutable_ceilings() {
        let policy = RolePolicyV1::embedded().unwrap();
        assert_eq!(policy.snapshot().roles.len(), Role::ALL.len());
        assert!(policy.permissions_for(Role::BreakGlassAdmin).is_empty());
    }

    #[test]
    fn snapshot_cannot_broaden_ceiling_or_hide_a_role() {
        let policy = RolePolicyV1::embedded().unwrap();
        let mut snapshot = policy.snapshot();
        snapshot.roles[0]
            .permissions
            .push(Permission::SecretUse.as_str().to_string());
        assert!(matches!(
            RolePolicyV1::from_snapshot(snapshot),
            Err(JanusError::PolicyDenied {
                reason_code: "role_policy_broadens_ceiling",
                ..
            })
        ));

        let mut snapshot = policy.snapshot();
        snapshot.roles.pop();
        assert!(matches!(
            RolePolicyV1::from_snapshot(snapshot),
            Err(JanusError::PolicyDenied {
                reason_code: "role_policy_role_missing",
                ..
            })
        ));
    }

    #[test]
    fn operator_can_use_but_owner_auditor_and_security_admin_cannot() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        for (role, expected) in [
            (Role::Operator, true),
            (Role::Owner, false),
            (Role::Auditor, false),
            (Role::SecurityAdmin, false),
        ] {
            let bindings = vec![binding(&principal, role, None)];
            assert_eq!(
                policy
                    .decide(&input(
                        &principal,
                        &scope,
                        &bindings,
                        &[],
                        Permission::SecretUse
                    ))
                    .allowed,
                expected,
                "{}",
                role.as_str()
            );
        }
    }

    #[test]
    fn break_glass_role_is_inert_until_separate_activation_workflow() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let bindings = vec![binding(&principal, Role::BreakGlassAdmin, None)];
        for permission in Permission::ALL {
            assert!(
                !policy
                    .decide(&input(&principal, &scope, &bindings, &[], *permission))
                    .allowed
            );
        }
    }

    #[test]
    fn exact_scope_time_and_target_are_required() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let target = "service:alpha".to_string();
        let bindings = vec![binding(
            &principal,
            Role::ServiceAdmin,
            Some(target.clone()),
        )];
        let mut decision_input = input(
            &principal,
            &scope,
            &bindings,
            &[],
            Permission::LifecycleTransition,
        );
        decision_input.target_binding = Some(&target);
        assert!(policy.decide(&decision_input).allowed);
        decision_input.target_binding = Some("service:beta");
        assert!(!policy.decide(&decision_input).allowed);
        decision_input.target_binding = None;
        assert!(!policy.decide(&decision_input).allowed);
    }

    #[test]
    fn ambiguous_effective_bindings_fail_closed() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let bindings = vec![
            binding(&principal, Role::Viewer, None),
            binding(&principal, Role::Operator, None),
        ];
        let decision = policy.decide(&input(
            &principal,
            &scope,
            &bindings,
            &[],
            Permission::DescriptorRead,
        ));
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "authorization_binding_ambiguous");
    }

    #[test]
    fn one_person_loops_are_hard_denials() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let bindings = vec![binding(&principal, Role::Approver, None)];
        let duties = vec![
            DutyEvidence::new(Duty::RequestUse, &principal.binding_key(), scope.clone()).unwrap(),
            DutyEvidence::new(Duty::ApproveUse, &principal.binding_key(), scope.clone()).unwrap(),
        ];
        let decision = policy.decide(&input(
            &principal,
            &scope,
            &bindings,
            &duties,
            Permission::ApprovalIssue,
        ));
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "separation_requester_approver");
        assert!(decision.separation_denial);
    }

    #[test]
    fn role_binding_snapshot_detects_any_authority_change() {
        let (principal, _) = fixture();
        let original = binding(&principal, Role::Operator, None);
        let mut snapshot = original.snapshot().unwrap();
        assert_eq!(
            RoleBinding::from_snapshot(snapshot.clone()).unwrap(),
            original
        );
        snapshot.role = Role::Viewer.as_str().to_string();
        assert!(matches!(
            RoleBinding::from_snapshot(snapshot),
            Err(JanusError::PolicyDenied {
                reason_code: "role_binding_integrity_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn decision_snapshot_and_debug_omit_identity_values() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let bindings = vec![binding(&principal, Role::Viewer, None)];
        let decision_input = input(
            &principal,
            &scope,
            &bindings,
            &[],
            Permission::DescriptorRead,
        );
        let decision = policy.decide(&decision_input);
        let json = serde_json::to_string(&decision.snapshot(&policy)).unwrap();
        let debug = format!("{decision_input:?}");
        assert!(!json.contains("runner-a"));
        assert!(!debug.contains("runner-a"));
        assert!(decision.allowed);
    }

    #[test]
    fn every_runtime_action_has_a_closed_permission() {
        for action in RuntimeAction::ALL {
            assert!(Permission::ALL.contains(&Permission::for_runtime_action(action)));
        }
    }

    #[test]
    fn required_audit_failure_blocks_an_otherwise_allowed_decision() {
        let policy = RolePolicyV1::embedded().unwrap();
        let (principal, scope) = fixture();
        let bindings = vec![binding(&principal, Role::Viewer, None)];
        let decision_input = input(
            &principal,
            &scope,
            &bindings,
            &[],
            Permission::DescriptorRead,
        );
        let mut audit = crate::AuditWrite::failing();
        assert!(matches!(
            authorize_role_action(&policy, &decision_input, &mut audit),
            Err(JanusError::AuditUnavailable { .. })
        ));
    }

    #[test]
    fn strict_policy_rejects_unknown_fields_and_unknown_vocabulary() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../config/authorization/role-matrix-v1.json"
        ))
        .unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(RolePolicyV1::parse_json(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../config/authorization/role-matrix-v1.json"
        ))
        .unwrap();
        value["roles"][0]["permissions"][0] = serde_json::json!("secret.reveal");
        assert!(RolePolicyV1::parse_json(&value.to_string()).is_err());
    }
}

//! Exact, short-lived, separately approved emergency authority.
//!
//! A `break_glass_admin` role binding is only an eligibility marker. This
//! module turns one active eligibility binding into a distinct, single-action
//! activation. It never changes normal role membership or permission ceilings.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, Permission,
    PrincipalChain, Role, RoleBinding, RoleBindingId, SafeLabel, ScopeRef, SecretRef, Severity,
};

/// Current strict durable break-glass record schema.
pub const BREAK_GLASS_SNAPSHOT_VERSION: u8 = 1;
/// Longest permitted activation lifetime.
pub const MAX_BREAK_GLASS_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_BREAK_GLASS_TEXT_BYTES: usize = 1_024;
const MAX_PRINCIPAL_BINDING_BYTES: usize = 4 * 1024;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Rehydrate a strict opaque identifier.
            pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
                let value = value.into();
                let Some(suffix) = value.strip_prefix($prefix) else {
                    return Err(break_glass_error(
                        "break_glass_id_invalid",
                        "break-glass identifier is malformed",
                    ));
                };
                if suffix.len() != 24
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(break_glass_error(
                        "break_glass_id_invalid",
                        "break-glass identifier is malformed",
                    ));
                }
                Ok(Self(value))
            }

            /// Safe opaque text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

opaque_id!(BreakGlassRequestId, "bgr_");
opaque_id!(BreakGlassActivationId, "bga_");
opaque_id!(BreakGlassAttemptId, "bgt_");
opaque_id!(BreakGlassCompletionId, "bgc_");
opaque_id!(BreakGlassRevocationId, "bgv_");
opaque_id!(BreakGlassReviewId, "bgw_");

/// Review closure vocabulary. There is no open or suppressed terminal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakGlassReviewClosure {
    /// Review found no remediation requirement and was independently closed.
    ClosedNoFindings,
    /// Review verified documented remediation and was independently closed.
    ClosedRemediated,
}

impl BreakGlassReviewClosure {
    /// Stable durable/operator text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClosedNoFindings => "closed_no_findings",
            Self::ClosedRemediated => "closed_remediated",
        }
    }

    /// Parse strict durable/operator text.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "closed_no_findings" => Ok(Self::ClosedNoFindings),
            "closed_remediated" => Ok(Self::ClosedRemediated),
            _ => Err(break_glass_error(
                "break_glass_review_closure_invalid",
                "break-glass review closure is unsupported",
            )),
        }
    }
}

/// Actual completion result of an admitted emergency action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakGlassCompletionOutcome {
    /// The exact admitted action completed successfully.
    Succeeded,
    /// The exact admitted action returned a failure.
    Failed,
}

impl BreakGlassCompletionOutcome {
    /// Stable durable/operator text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Parse strict durable/operator text.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(break_glass_error(
                "break_glass_completion_outcome_invalid",
                "break-glass completion outcome is unsupported",
            )),
        }
    }
}

/// Strict private durable request snapshot.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassRequestSnapshotV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub eligibility_binding_id: String,
    pub activator_binding: String,
    pub beneficiary_binding: String,
    pub scope_ref: String,
    pub permission: String,
    pub target_ref: String,
    pub reason: String,
    pub requested_at_unix_secs: u64,
    pub requested_at_subsec_nanos: u32,
    pub expires_at_unix_secs: u64,
    pub expires_at_subsec_nanos: u32,
}

impl fmt::Debug for BreakGlassRequestSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassRequestSnapshotV1")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("eligibility_binding_id", &self.eligibility_binding_id)
            .field("activator_binding", &"<redacted>")
            .field("beneficiary_binding", &"<redacted>")
            .field("scope_ref", &self.scope_ref)
            .field("permission", &self.permission)
            .field("target_ref", &self.target_ref)
            .field("reason", &"<redacted>")
            .field("requested_at_unix_secs", &self.requested_at_unix_secs)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .finish()
    }
}

/// Pending exact emergency authority request.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassRequest {
    id: BreakGlassRequestId,
    eligibility_binding_id: RoleBindingId,
    activator_binding: String,
    beneficiary_binding: String,
    scope: ScopeRef,
    permission: Permission,
    target: SecretRef,
    reason: SafeLabel,
    requested_at: SystemTime,
    expires_at: SystemTime,
}

impl fmt::Debug for BreakGlassRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassRequest")
            .field("id", &self.id)
            .field("eligibility_binding_id", &self.eligibility_binding_id)
            .field("activator_binding", &"<redacted>")
            .field("beneficiary_binding", &"<redacted>")
            .field("scope", &self.scope)
            .field("permission", &self.permission)
            .field("target", &self.target)
            .field("reason", &"<redacted>")
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl BreakGlassRequest {
    /// Request one exact activation from an active eligibility binding.
    ///
    /// The activator must be distinct from the eligible beneficiary. Every
    /// allowed or denied request writes critical value-free evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        eligibility: &RoleBinding,
        activator: &PrincipalChain,
        permission: Permission,
        target: SecretRef,
        reason: SafeLabel,
        requested_at: SystemTime,
        ttl: Duration,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let result = Self::build(
            eligibility,
            activator,
            permission,
            target.clone(),
            reason,
            requested_at,
            ttl,
        );
        let (outcome, reason_code) = match &result {
            Ok(_) => (AuditOutcome::Allowed, "break_glass_request_recorded"),
            Err(error) => (AuditOutcome::Denied, break_glass_reason(error)),
        };
        audit_break_glass(
            audit,
            AuditAction::BreakGlassActivate,
            outcome,
            reason_code,
            Some(target),
            activator,
        )?;
        result
    }

    fn build(
        eligibility: &RoleBinding,
        activator: &PrincipalChain,
        permission: Permission,
        target: SecretRef,
        reason: SafeLabel,
        requested_at: SystemTime,
        ttl: Duration,
    ) -> JanusResult<Self> {
        if eligibility.role() != Role::BreakGlassAdmin {
            return Err(break_glass_error(
                "break_glass_eligibility_missing",
                "an active break-glass eligibility binding is required",
            ));
        }
        if eligibility.scope() != &activator.scope
            || !eligibility.matches(
                eligibility.principal_binding(),
                &activator.scope,
                None,
                requested_at,
            )
        {
            return Err(break_glass_error(
                "break_glass_eligibility_inactive",
                "break-glass eligibility is outside its exact scope or validity",
            ));
        }
        if activator.binding_key() == eligibility.principal_binding() {
            return Err(break_glass_error(
                "separation_break_glass_self_activation",
                "activator and beneficiary must be separate identities",
            ));
        }
        if !permission.is_use() {
            return Err(break_glass_error(
                "break_glass_action_forbidden",
                "break-glass authority is limited to one exact use action",
            ));
        }
        if ttl.is_zero() || ttl > MAX_BREAK_GLASS_TTL {
            return Err(break_glass_error(
                "break_glass_ttl_invalid",
                "break-glass lifetime is outside the short reviewed bound",
            ));
        }
        validate_private_text("break_glass_reason", reason.as_str())?;
        let expires_at = requested_at.checked_add(ttl).ok_or_else(|| {
            break_glass_error("break_glass_time_invalid", "break-glass expiry overflowed")
        })?;
        let activator_binding = activator.binding_key();
        let beneficiary_binding = eligibility.principal_binding().to_string();
        validate_principal_binding(&activator_binding)?;
        validate_principal_binding(&beneficiary_binding)?;
        let id = derive_request_id(
            eligibility.id().as_str(),
            &activator_binding,
            &beneficiary_binding,
            &activator.scope,
            permission,
            &target,
            reason.as_str(),
            requested_at,
            expires_at,
        )?;
        Ok(Self {
            id,
            eligibility_binding_id: eligibility.id().clone(),
            activator_binding,
            beneficiary_binding,
            scope: activator.scope.clone(),
            permission,
            target,
            reason,
            requested_at,
            expires_at,
        })
    }

    pub fn id(&self) -> &BreakGlassRequestId {
        &self.id
    }
    pub fn eligibility_binding_id(&self) -> &RoleBindingId {
        &self.eligibility_binding_id
    }
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn permission(&self) -> Permission {
        self.permission
    }
    pub fn target(&self) -> &SecretRef {
        &self.target
    }
    pub fn requested_at(&self) -> SystemTime {
        self.requested_at
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn activator_binding(&self) -> &str {
        &self.activator_binding
    }
    pub fn beneficiary_binding(&self) -> &str {
        &self.beneficiary_binding
    }

    /// Strict private durable representation.
    pub fn snapshot(&self) -> JanusResult<BreakGlassRequestSnapshotV1> {
        let requested_at = timestamp(self.requested_at)?;
        let expires_at = timestamp(self.expires_at)?;
        Ok(BreakGlassRequestSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            request_id: self.id.as_str().to_string(),
            eligibility_binding_id: self.eligibility_binding_id.as_str().to_string(),
            activator_binding: self.activator_binding.clone(),
            beneficiary_binding: self.beneficiary_binding.clone(),
            scope_ref: self.scope.as_str().to_string(),
            permission: self.permission.as_str().to_string(),
            target_ref: self.target.as_str().to_string(),
            reason: self.reason.as_str().to_string(),
            requested_at_unix_secs: requested_at.0,
            requested_at_subsec_nanos: requested_at.1,
            expires_at_unix_secs: expires_at.0,
            expires_at_subsec_nanos: expires_at.1,
        })
    }

    /// Rehydrate and integrity-check a private durable snapshot.
    pub fn from_snapshot(snapshot: BreakGlassRequestSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION {
            return Err(break_glass_error(
                "break_glass_schema_unknown",
                "break-glass snapshot schema is unsupported",
            ));
        }
        let requested_at = from_timestamp(
            snapshot.requested_at_unix_secs,
            snapshot.requested_at_subsec_nanos,
        )?;
        let expires_at = from_timestamp(
            snapshot.expires_at_unix_secs,
            snapshot.expires_at_subsec_nanos,
        )?;
        let eligibility_binding_id = RoleBindingId::from_opaque(snapshot.eligibility_binding_id)?;
        let permission = Permission::parse(&snapshot.permission)?;
        if !permission.is_use() {
            return Err(break_glass_error(
                "break_glass_action_forbidden",
                "break-glass snapshot contains a forbidden action",
            ));
        }
        let scope = ScopeRef::from_opaque(snapshot.scope_ref)?;
        let target = SecretRef::new(snapshot.target_ref)?;
        let reason = SafeLabel::new(snapshot.reason)?;
        validate_private_text("break_glass_reason", reason.as_str())?;
        validate_principal_binding(&snapshot.activator_binding)?;
        validate_principal_binding(&snapshot.beneficiary_binding)?;
        if snapshot.activator_binding == snapshot.beneficiary_binding
            || expires_at <= requested_at
            || expires_at.duration_since(requested_at).unwrap_or_default() > MAX_BREAK_GLASS_TTL
        {
            return Err(break_glass_error(
                "break_glass_snapshot_invalid",
                "break-glass request snapshot is inconsistent",
            ));
        }
        let expected = derive_request_id(
            eligibility_binding_id.as_str(),
            &snapshot.activator_binding,
            &snapshot.beneficiary_binding,
            &scope,
            permission,
            &target,
            reason.as_str(),
            requested_at,
            expires_at,
        )?;
        if expected.as_str() != snapshot.request_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass request integrity does not match",
            ));
        }
        Ok(Self {
            id: expected,
            eligibility_binding_id,
            activator_binding: snapshot.activator_binding,
            beneficiary_binding: snapshot.beneficiary_binding,
            scope,
            permission,
            target,
            reason,
            requested_at,
            expires_at,
        })
    }
}

/// Strict private durable approved activation snapshot.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassActivationSnapshotV1 {
    pub schema_version: u8,
    pub activation_id: String,
    pub request_id: String,
    pub approver_binding: String,
    pub approved_at_unix_secs: u64,
    pub approved_at_subsec_nanos: u32,
}

impl fmt::Debug for BreakGlassActivationSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassActivationSnapshotV1")
            .field("schema_version", &self.schema_version)
            .field("activation_id", &self.activation_id)
            .field("request_id", &self.request_id)
            .field("approver_binding", &"<redacted>")
            .field("approved_at_unix_secs", &self.approved_at_unix_secs)
            .finish()
    }
}

/// Separately approved, exact, short-lived emergency authority.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassActivation {
    id: BreakGlassActivationId,
    request: BreakGlassRequest,
    approver_binding: String,
    approved_at: SystemTime,
}

impl fmt::Debug for BreakGlassActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassActivation")
            .field("id", &self.id)
            .field("request", &self.request)
            .field("approver_binding", &"<redacted>")
            .field("approved_at", &self.approved_at)
            .finish()
    }
}

impl BreakGlassActivation {
    /// Approve a pending activation as an identity distinct from activator and
    /// beneficiary. Approval never extends the original expiry.
    pub fn approve(
        request: BreakGlassRequest,
        approver: &PrincipalChain,
        approved_at: SystemTime,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let result = Self::build(request.clone(), approver, approved_at);
        let (outcome, reason_code) = match &result {
            Ok(_) => (AuditOutcome::Allowed, "break_glass_approved"),
            Err(error) => (AuditOutcome::Denied, break_glass_reason(error)),
        };
        audit_break_glass(
            audit,
            AuditAction::BreakGlassActivate,
            outcome,
            reason_code,
            Some(request.target().clone()),
            approver,
        )?;
        result
    }

    fn build(
        request: BreakGlassRequest,
        approver: &PrincipalChain,
        approved_at: SystemTime,
    ) -> JanusResult<Self> {
        if approver.scope != *request.scope() {
            return Err(break_glass_error(
                "break_glass_scope_mismatch",
                "approver scope does not match the exact request",
            ));
        }
        if approved_at < request.requested_at() || approved_at >= request.expires_at() {
            return Err(break_glass_error(
                "break_glass_request_expired",
                "break-glass request is not approvable at this time",
            ));
        }
        let approver_binding = approver.binding_key();
        validate_principal_binding(&approver_binding)?;
        if approver_binding == request.activator_binding()
            || approver_binding == request.beneficiary_binding()
        {
            return Err(break_glass_error(
                "separation_break_glass_self_approval",
                "approver must be separate from activator and beneficiary",
            ));
        }
        let id = derive_activation_id(request.id(), &approver_binding, approved_at)?;
        Ok(Self {
            id,
            request,
            approver_binding,
            approved_at,
        })
    }

    pub fn id(&self) -> &BreakGlassActivationId {
        &self.id
    }
    pub fn request(&self) -> &BreakGlassRequest {
        &self.request
    }
    pub fn approver_binding(&self) -> &str {
        &self.approver_binding
    }
    pub fn approved_at(&self) -> SystemTime {
        self.approved_at
    }
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now >= self.request.expires_at()
    }

    /// Strict private durable representation. The request is persisted as its
    /// own immutable record and referenced by opaque id.
    pub fn snapshot(&self) -> JanusResult<BreakGlassActivationSnapshotV1> {
        let approved_at = timestamp(self.approved_at)?;
        Ok(BreakGlassActivationSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            activation_id: self.id.as_str().to_string(),
            request_id: self.request.id().as_str().to_string(),
            approver_binding: self.approver_binding.clone(),
            approved_at_unix_secs: approved_at.0,
            approved_at_subsec_nanos: approved_at.1,
        })
    }

    /// Rehydrate an activation against its exact immutable request.
    pub fn from_snapshot(
        request: BreakGlassRequest,
        snapshot: BreakGlassActivationSnapshotV1,
    ) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION
            || snapshot.request_id != request.id().as_str()
        {
            return Err(break_glass_error(
                "break_glass_activation_snapshot_invalid",
                "break-glass activation snapshot is inconsistent",
            ));
        }
        validate_principal_binding(&snapshot.approver_binding)?;
        let approved_at = from_timestamp(
            snapshot.approved_at_unix_secs,
            snapshot.approved_at_subsec_nanos,
        )?;
        if approved_at < request.requested_at()
            || approved_at >= request.expires_at()
            || snapshot.approver_binding == request.activator_binding()
            || snapshot.approver_binding == request.beneficiary_binding()
        {
            return Err(break_glass_error(
                "break_glass_activation_snapshot_invalid",
                "break-glass activation snapshot is inconsistent",
            ));
        }
        let id = derive_activation_id(request.id(), &snapshot.approver_binding, approved_at)?;
        if id.as_str() != snapshot.activation_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass activation integrity does not match",
            ));
        }
        Ok(Self {
            id,
            request,
            approver_binding: snapshot.approver_binding,
            approved_at,
        })
    }
}

/// Strict immutable revocation snapshot.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassRevocationSnapshotV1 {
    pub schema_version: u8,
    pub revocation_id: String,
    pub activation_id: String,
    pub revoker_binding: String,
    pub reason: String,
    pub revoked_at_unix_secs: u64,
    pub revoked_at_subsec_nanos: u32,
}

impl fmt::Debug for BreakGlassRevocationSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassRevocationSnapshotV1")
            .field("revocation_id", &self.revocation_id)
            .field("activation_id", &self.activation_id)
            .field("revoker_binding", &"<redacted>")
            .field("reason", &"<redacted>")
            .field("revoked_at_unix_secs", &self.revoked_at_unix_secs)
            .finish()
    }
}

/// Immutable revocation of one activation.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassRevocation {
    id: BreakGlassRevocationId,
    activation_id: BreakGlassActivationId,
    revoker_binding: String,
    reason: SafeLabel,
    revoked_at: SystemTime,
}

impl fmt::Debug for BreakGlassRevocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassRevocation")
            .field("id", &self.id)
            .field("activation_id", &self.activation_id)
            .field("revoker_binding", &"<redacted>")
            .field("reason", &"<redacted>")
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl BreakGlassRevocation {
    /// Revoke one activation and emit critical evidence before returning it.
    pub fn revoke(
        activation: &BreakGlassActivation,
        revoker: &PrincipalChain,
        reason: SafeLabel,
        revoked_at: SystemTime,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let result = Self::build(activation, revoker, reason, revoked_at);
        let (outcome, reason_code) = match &result {
            Ok(_) => (AuditOutcome::Allowed, "break_glass_revoked"),
            Err(error) => (AuditOutcome::Denied, break_glass_reason(error)),
        };
        audit_break_glass(
            audit,
            AuditAction::BreakGlassRevoke,
            outcome,
            reason_code,
            Some(activation.request().target().clone()),
            revoker,
        )?;
        result
    }

    fn build(
        activation: &BreakGlassActivation,
        revoker: &PrincipalChain,
        reason: SafeLabel,
        revoked_at: SystemTime,
    ) -> JanusResult<Self> {
        if revoker.scope != *activation.request().scope() {
            return Err(break_glass_error(
                "break_glass_scope_mismatch",
                "revoker scope does not match activation scope",
            ));
        }
        validate_private_text("break_glass_revocation_reason", reason.as_str())?;
        let revoker_binding = revoker.binding_key();
        validate_principal_binding(&revoker_binding)?;
        let id = derive_event_id(
            "janus-break-glass-revocation-v1",
            "bgv_",
            activation.id().as_str(),
            &revoker_binding,
            reason.as_str(),
            revoked_at,
        )?;
        Ok(Self {
            id: BreakGlassRevocationId::from_opaque(id)?,
            activation_id: activation.id().clone(),
            revoker_binding,
            reason,
            revoked_at,
        })
    }

    pub fn id(&self) -> &BreakGlassRevocationId {
        &self.id
    }
    pub fn activation_id(&self) -> &BreakGlassActivationId {
        &self.activation_id
    }
    pub fn revoked_at(&self) -> SystemTime {
        self.revoked_at
    }

    pub fn snapshot(&self) -> JanusResult<BreakGlassRevocationSnapshotV1> {
        let revoked_at = timestamp(self.revoked_at)?;
        Ok(BreakGlassRevocationSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            revocation_id: self.id.as_str().to_string(),
            activation_id: self.activation_id.as_str().to_string(),
            revoker_binding: self.revoker_binding.clone(),
            reason: self.reason.as_str().to_string(),
            revoked_at_unix_secs: revoked_at.0,
            revoked_at_subsec_nanos: revoked_at.1,
        })
    }

    pub fn from_snapshot(snapshot: BreakGlassRevocationSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION {
            return Err(break_glass_error(
                "break_glass_schema_unknown",
                "break-glass revocation schema is unsupported",
            ));
        }
        let activation_id = BreakGlassActivationId::from_opaque(snapshot.activation_id)?;
        validate_principal_binding(&snapshot.revoker_binding)?;
        let reason = SafeLabel::new(snapshot.reason)?;
        validate_private_text("break_glass_revocation_reason", reason.as_str())?;
        let revoked_at = from_timestamp(
            snapshot.revoked_at_unix_secs,
            snapshot.revoked_at_subsec_nanos,
        )?;
        let id = derive_event_id(
            "janus-break-glass-revocation-v1",
            "bgv_",
            activation_id.as_str(),
            &snapshot.revoker_binding,
            reason.as_str(),
            revoked_at,
        )?;
        if id != snapshot.revocation_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass revocation integrity does not match",
            ));
        }
        Ok(Self {
            id: BreakGlassRevocationId::from_opaque(id)?,
            activation_id,
            revoker_binding: snapshot.revoker_binding,
            reason,
            revoked_at,
        })
    }
}

/// Strict durable record of every admitted or denied emergency use attempt.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassAttemptSnapshotV1 {
    pub schema_version: u8,
    pub attempt_id: String,
    pub activation_id: String,
    pub actor_binding: String,
    pub scope_ref: String,
    pub permission: String,
    pub target_ref: String,
    pub attempted_at_unix_secs: u64,
    pub attempted_at_subsec_nanos: u32,
    pub allowed: bool,
    pub reason_code: String,
}

impl fmt::Debug for BreakGlassAttemptSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassAttemptSnapshotV1")
            .field("attempt_id", &self.attempt_id)
            .field("activation_id", &self.activation_id)
            .field("actor_binding", &"<redacted>")
            .field("scope_ref", &self.scope_ref)
            .field("permission", &self.permission)
            .field("target_ref", &self.target_ref)
            .field("allowed", &self.allowed)
            .field("reason_code", &self.reason_code)
            .finish()
    }
}

/// One exact emergency-use authorization attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassAttempt {
    id: BreakGlassAttemptId,
    activation_id: BreakGlassActivationId,
    actor_binding: String,
    scope: ScopeRef,
    permission: Permission,
    target: SecretRef,
    attempted_at: SystemTime,
    allowed: bool,
    reason_code: &'static str,
}

impl fmt::Debug for BreakGlassAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassAttempt")
            .field("id", &self.id)
            .field("activation_id", &self.activation_id)
            .field("actor_binding", &"<redacted>")
            .field("scope", &self.scope)
            .field("permission", &self.permission)
            .field("target", &self.target)
            .field("attempted_at", &self.attempted_at)
            .field("allowed", &self.allowed)
            .field("reason_code", &self.reason_code)
            .finish()
    }
}

impl BreakGlassAttempt {
    /// Evaluate one attempt from complete current facts and always emit a
    /// critical value-free audit event. A policy denial is returned as a
    /// record with `allowed=false` so durable registries can retain it.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        activation: &BreakGlassActivation,
        actor: &PrincipalChain,
        scope: ScopeRef,
        permission: Permission,
        target: SecretRef,
        attempted_at: SystemTime,
        revocation: Option<&BreakGlassRevocation>,
        already_completed: bool,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let actor_binding = actor.binding_key();
        validate_principal_binding(&actor_binding)?;
        let reason_code = if revocation.is_some() {
            "break_glass_revoked"
        } else if already_completed {
            "break_glass_already_consumed"
        } else if attempted_at < activation.approved_at()
            || attempted_at >= activation.request().expires_at()
        {
            "break_glass_expired"
        } else if actor_binding != activation.request().beneficiary_binding() {
            "break_glass_beneficiary_mismatch"
        } else if actor_binding == activation.request().activator_binding()
            || actor_binding == activation.approver_binding()
        {
            "separation_break_glass_self_activation"
        } else if actor.scope != scope || &scope != activation.request().scope() {
            "break_glass_scope_mismatch"
        } else if permission != activation.request().permission() {
            "break_glass_action_mismatch"
        } else if target != *activation.request().target() {
            "break_glass_target_mismatch"
        } else {
            "break_glass_use_admitted"
        };
        let allowed = reason_code == "break_glass_use_admitted";
        let id = derive_attempt_id(
            activation.id(),
            &actor_binding,
            &scope,
            permission,
            &target,
            attempted_at,
            allowed,
            reason_code,
        )?;
        audit_break_glass(
            audit,
            AuditAction::BreakGlassUse,
            if allowed {
                AuditOutcome::Allowed
            } else {
                AuditOutcome::Denied
            },
            reason_code,
            Some(target.clone()),
            actor,
        )?;
        Ok(Self {
            id,
            activation_id: activation.id().clone(),
            actor_binding,
            scope,
            permission,
            target,
            attempted_at,
            allowed,
            reason_code,
        })
    }

    pub fn id(&self) -> &BreakGlassAttemptId {
        &self.id
    }
    pub fn activation_id(&self) -> &BreakGlassActivationId {
        &self.activation_id
    }
    pub fn allowed(&self) -> bool {
        self.allowed
    }
    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }
    pub fn actor_binding(&self) -> &str {
        &self.actor_binding
    }
    pub fn attempted_at(&self) -> SystemTime {
        self.attempted_at
    }

    pub fn snapshot(&self) -> JanusResult<BreakGlassAttemptSnapshotV1> {
        let attempted_at = timestamp(self.attempted_at)?;
        Ok(BreakGlassAttemptSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            attempt_id: self.id.as_str().to_string(),
            activation_id: self.activation_id.as_str().to_string(),
            actor_binding: self.actor_binding.clone(),
            scope_ref: self.scope.as_str().to_string(),
            permission: self.permission.as_str().to_string(),
            target_ref: self.target.as_str().to_string(),
            attempted_at_unix_secs: attempted_at.0,
            attempted_at_subsec_nanos: attempted_at.1,
            allowed: self.allowed,
            reason_code: self.reason_code.to_string(),
        })
    }

    pub fn from_snapshot(snapshot: BreakGlassAttemptSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION {
            return Err(break_glass_error(
                "break_glass_schema_unknown",
                "break-glass attempt schema is unsupported",
            ));
        }
        let activation_id = BreakGlassActivationId::from_opaque(snapshot.activation_id)?;
        validate_principal_binding(&snapshot.actor_binding)?;
        let scope = ScopeRef::from_opaque(snapshot.scope_ref)?;
        let permission = Permission::parse(&snapshot.permission)?;
        if !permission.is_use() {
            return Err(break_glass_error(
                "break_glass_action_forbidden",
                "break-glass attempt contains a forbidden action",
            ));
        }
        let target = SecretRef::new(snapshot.target_ref)?;
        let attempted_at = from_timestamp(
            snapshot.attempted_at_unix_secs,
            snapshot.attempted_at_subsec_nanos,
        )?;
        let reason_code = parse_attempt_reason(&snapshot.reason_code, snapshot.allowed)?;
        let id = derive_attempt_id(
            &activation_id,
            &snapshot.actor_binding,
            &scope,
            permission,
            &target,
            attempted_at,
            snapshot.allowed,
            reason_code,
        )?;
        if id.as_str() != snapshot.attempt_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass attempt integrity does not match",
            ));
        }
        Ok(Self {
            id,
            activation_id,
            actor_binding: snapshot.actor_binding,
            scope,
            permission,
            target,
            attempted_at,
            allowed: snapshot.allowed,
            reason_code,
        })
    }
}

/// Strict immutable completion snapshot.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassCompletionSnapshotV1 {
    pub schema_version: u8,
    pub completion_id: String,
    pub activation_id: String,
    pub attempt_id: String,
    pub actor_binding: String,
    pub outcome: String,
    pub completed_at_unix_secs: u64,
    pub completed_at_subsec_nanos: u32,
}

impl fmt::Debug for BreakGlassCompletionSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassCompletionSnapshotV1")
            .field("completion_id", &self.completion_id)
            .field("activation_id", &self.activation_id)
            .field("attempt_id", &self.attempt_id)
            .field("actor_binding", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("completed_at_unix_secs", &self.completed_at_unix_secs)
            .finish()
    }
}

/// Completion evidence for one admitted emergency action.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassCompletion {
    id: BreakGlassCompletionId,
    activation_id: BreakGlassActivationId,
    attempt_id: BreakGlassAttemptId,
    actor_binding: String,
    outcome: BreakGlassCompletionOutcome,
    completed_at: SystemTime,
}

impl fmt::Debug for BreakGlassCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassCompletion")
            .field("id", &self.id)
            .field("activation_id", &self.activation_id)
            .field("attempt_id", &self.attempt_id)
            .field("actor_binding", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

impl BreakGlassCompletion {
    /// Record the actual completion of one admitted attempt. Both success and
    /// failure are critical evidence and require independent post-use review.
    pub fn complete(
        activation: &BreakGlassActivation,
        attempt: &BreakGlassAttempt,
        actor: &PrincipalChain,
        outcome: BreakGlassCompletionOutcome,
        completed_at: SystemTime,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let actor_binding = actor.binding_key();
        let result = (|| {
            validate_principal_binding(&actor_binding)?;
            if !attempt.allowed()
                || attempt.activation_id() != activation.id()
                || attempt.actor_binding() != actor_binding
                || completed_at < attempt.attempted_at()
            {
                return Err(break_glass_error(
                    "break_glass_completion_invalid",
                    "only the exact admitted attempt can be completed",
                ));
            }
            let id = derive_completion_id(
                activation.id(),
                attempt.id(),
                &actor_binding,
                outcome,
                completed_at,
            )?;
            Ok(Self {
                id,
                activation_id: activation.id().clone(),
                attempt_id: attempt.id().clone(),
                actor_binding: actor_binding.clone(),
                outcome,
                completed_at,
            })
        })();
        let (audit_outcome, reason_code) = match (&result, outcome) {
            (Ok(_), BreakGlassCompletionOutcome::Succeeded) => {
                (AuditOutcome::Allowed, "break_glass_action_completed")
            }
            (Ok(_), BreakGlassCompletionOutcome::Failed) => {
                (AuditOutcome::Denied, "break_glass_action_failed")
            }
            (Err(error), _) => (AuditOutcome::Denied, break_glass_reason(error)),
        };
        audit_break_glass(
            audit,
            AuditAction::BreakGlassUse,
            audit_outcome,
            reason_code,
            Some(activation.request().target().clone()),
            actor,
        )?;
        result
    }

    pub fn id(&self) -> &BreakGlassCompletionId {
        &self.id
    }
    pub fn activation_id(&self) -> &BreakGlassActivationId {
        &self.activation_id
    }
    pub fn outcome(&self) -> BreakGlassCompletionOutcome {
        self.outcome
    }
    pub fn completed_at(&self) -> SystemTime {
        self.completed_at
    }

    pub fn snapshot(&self) -> JanusResult<BreakGlassCompletionSnapshotV1> {
        let completed_at = timestamp(self.completed_at)?;
        Ok(BreakGlassCompletionSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            completion_id: self.id.as_str().to_string(),
            activation_id: self.activation_id.as_str().to_string(),
            attempt_id: self.attempt_id.as_str().to_string(),
            actor_binding: self.actor_binding.clone(),
            outcome: self.outcome.as_str().to_string(),
            completed_at_unix_secs: completed_at.0,
            completed_at_subsec_nanos: completed_at.1,
        })
    }

    pub fn from_snapshot(snapshot: BreakGlassCompletionSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION {
            return Err(break_glass_error(
                "break_glass_schema_unknown",
                "break-glass completion schema is unsupported",
            ));
        }
        let activation_id = BreakGlassActivationId::from_opaque(snapshot.activation_id)?;
        let attempt_id = BreakGlassAttemptId::from_opaque(snapshot.attempt_id)?;
        validate_principal_binding(&snapshot.actor_binding)?;
        let outcome = BreakGlassCompletionOutcome::parse(&snapshot.outcome)?;
        let completed_at = from_timestamp(
            snapshot.completed_at_unix_secs,
            snapshot.completed_at_subsec_nanos,
        )?;
        let id = derive_completion_id(
            &activation_id,
            &attempt_id,
            &snapshot.actor_binding,
            outcome,
            completed_at,
        )?;
        if id.as_str() != snapshot.completion_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass completion integrity does not match",
            ));
        }
        Ok(Self {
            id,
            activation_id,
            attempt_id,
            actor_binding: snapshot.actor_binding,
            outcome,
            completed_at,
        })
    }
}

/// Strict immutable independent review snapshot.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassReviewSnapshotV1 {
    pub schema_version: u8,
    pub review_id: String,
    pub activation_id: String,
    pub completion_id: String,
    pub reviewer_binding: String,
    pub findings: String,
    pub remediation: String,
    pub closure: String,
    pub reviewed_at_unix_secs: u64,
    pub reviewed_at_subsec_nanos: u32,
}

impl fmt::Debug for BreakGlassReviewSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassReviewSnapshotV1")
            .field("review_id", &self.review_id)
            .field("activation_id", &self.activation_id)
            .field("completion_id", &self.completion_id)
            .field("reviewer_binding", &"<redacted>")
            .field("findings", &"<redacted>")
            .field("remediation", &"<redacted>")
            .field("closure", &self.closure)
            .field("reviewed_at_unix_secs", &self.reviewed_at_unix_secs)
            .finish()
    }
}

/// Mandatory independent post-use review and closure.
#[derive(Clone, PartialEq, Eq)]
pub struct BreakGlassReview {
    id: BreakGlassReviewId,
    activation_id: BreakGlassActivationId,
    completion_id: BreakGlassCompletionId,
    reviewer_binding: String,
    findings: SafeLabel,
    remediation: SafeLabel,
    closure: BreakGlassReviewClosure,
    reviewed_at: SystemTime,
}

impl fmt::Debug for BreakGlassReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BreakGlassReview")
            .field("id", &self.id)
            .field("activation_id", &self.activation_id)
            .field("completion_id", &self.completion_id)
            .field("reviewer_binding", &"<redacted>")
            .field("findings", &"<redacted>")
            .field("remediation", &"<redacted>")
            .field("closure", &self.closure)
            .field("reviewed_at", &self.reviewed_at)
            .finish()
    }
}

impl BreakGlassReview {
    /// Close the mandatory review as a principal distinct from every emergency
    /// participant. Self-review is always denied and audited critically.
    #[allow(clippy::too_many_arguments)]
    pub fn review(
        activation: &BreakGlassActivation,
        completion: &BreakGlassCompletion,
        reviewer: &PrincipalChain,
        findings: SafeLabel,
        remediation: SafeLabel,
        closure: BreakGlassReviewClosure,
        reviewed_at: SystemTime,
        audit: &mut impl AuditSink,
    ) -> JanusResult<Self> {
        let result = Self::build(
            activation,
            completion,
            reviewer,
            findings,
            remediation,
            closure,
            reviewed_at,
        );
        let (outcome, reason_code) = match &result {
            Ok(_) => (AuditOutcome::Allowed, "break_glass_review_closed"),
            Err(error) => (AuditOutcome::Denied, break_glass_reason(error)),
        };
        audit_break_glass(
            audit,
            AuditAction::BreakGlassReview,
            outcome,
            reason_code,
            Some(activation.request().target().clone()),
            reviewer,
        )?;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        activation: &BreakGlassActivation,
        completion: &BreakGlassCompletion,
        reviewer: &PrincipalChain,
        findings: SafeLabel,
        remediation: SafeLabel,
        closure: BreakGlassReviewClosure,
        reviewed_at: SystemTime,
    ) -> JanusResult<Self> {
        if completion.activation_id() != activation.id()
            || reviewed_at < completion.completed_at()
            || reviewer.scope != *activation.request().scope()
        {
            return Err(break_glass_error(
                "break_glass_review_invalid",
                "review does not match the completed emergency action",
            ));
        }
        validate_private_text("break_glass_findings", findings.as_str())?;
        validate_private_text("break_glass_remediation", remediation.as_str())?;
        let reviewer_binding = reviewer.binding_key();
        validate_principal_binding(&reviewer_binding)?;
        if reviewer_binding == activation.request().activator_binding()
            || reviewer_binding == activation.request().beneficiary_binding()
            || reviewer_binding == activation.approver_binding()
        {
            return Err(break_glass_error(
                "separation_break_glass_self_review",
                "reviewer must be independent of emergency participants",
            ));
        }
        let id = derive_review_id(
            activation.id(),
            completion.id(),
            &reviewer_binding,
            findings.as_str(),
            remediation.as_str(),
            closure,
            reviewed_at,
        )?;
        Ok(Self {
            id,
            activation_id: activation.id().clone(),
            completion_id: completion.id().clone(),
            reviewer_binding,
            findings,
            remediation,
            closure,
            reviewed_at,
        })
    }

    pub fn id(&self) -> &BreakGlassReviewId {
        &self.id
    }
    pub fn activation_id(&self) -> &BreakGlassActivationId {
        &self.activation_id
    }
    pub fn closure(&self) -> BreakGlassReviewClosure {
        self.closure
    }
    pub fn reviewed_at(&self) -> SystemTime {
        self.reviewed_at
    }

    pub fn snapshot(&self) -> JanusResult<BreakGlassReviewSnapshotV1> {
        let reviewed_at = timestamp(self.reviewed_at)?;
        Ok(BreakGlassReviewSnapshotV1 {
            schema_version: BREAK_GLASS_SNAPSHOT_VERSION,
            review_id: self.id.as_str().to_string(),
            activation_id: self.activation_id.as_str().to_string(),
            completion_id: self.completion_id.as_str().to_string(),
            reviewer_binding: self.reviewer_binding.clone(),
            findings: self.findings.as_str().to_string(),
            remediation: self.remediation.as_str().to_string(),
            closure: self.closure.as_str().to_string(),
            reviewed_at_unix_secs: reviewed_at.0,
            reviewed_at_subsec_nanos: reviewed_at.1,
        })
    }

    pub fn from_snapshot(snapshot: BreakGlassReviewSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != BREAK_GLASS_SNAPSHOT_VERSION {
            return Err(break_glass_error(
                "break_glass_schema_unknown",
                "break-glass review schema is unsupported",
            ));
        }
        let activation_id = BreakGlassActivationId::from_opaque(snapshot.activation_id)?;
        let completion_id = BreakGlassCompletionId::from_opaque(snapshot.completion_id)?;
        validate_principal_binding(&snapshot.reviewer_binding)?;
        let findings = SafeLabel::new(snapshot.findings)?;
        let remediation = SafeLabel::new(snapshot.remediation)?;
        validate_private_text("break_glass_findings", findings.as_str())?;
        validate_private_text("break_glass_remediation", remediation.as_str())?;
        let closure = BreakGlassReviewClosure::parse(&snapshot.closure)?;
        let reviewed_at = from_timestamp(
            snapshot.reviewed_at_unix_secs,
            snapshot.reviewed_at_subsec_nanos,
        )?;
        let id = derive_review_id(
            &activation_id,
            &completion_id,
            &snapshot.reviewer_binding,
            findings.as_str(),
            remediation.as_str(),
            closure,
            reviewed_at,
        )?;
        if id.as_str() != snapshot.review_id {
            return Err(break_glass_error(
                "break_glass_integrity_mismatch",
                "break-glass review integrity does not match",
            ));
        }
        Ok(Self {
            id,
            activation_id,
            completion_id,
            reviewer_binding: snapshot.reviewer_binding,
            findings,
            remediation,
            closure,
            reviewed_at,
        })
    }
}

fn audit_break_glass(
    audit: &mut impl AuditSink,
    action: AuditAction,
    outcome: AuditOutcome,
    reason_code: &'static str,
    target: Option<SecretRef>,
    principal: &PrincipalChain,
) -> JanusResult<()> {
    audit.record(AuditEvent::new(
        action,
        outcome,
        reason_code,
        Severity::Critical,
        target,
        principal,
    ))
}

fn parse_attempt_reason(value: &str, allowed: bool) -> JanusResult<&'static str> {
    let reason = match value {
        "break_glass_use_admitted" => "break_glass_use_admitted",
        "break_glass_revoked" => "break_glass_revoked",
        "break_glass_already_consumed" => "break_glass_already_consumed",
        "break_glass_expired" => "break_glass_expired",
        "break_glass_beneficiary_mismatch" => "break_glass_beneficiary_mismatch",
        "separation_break_glass_self_activation" => "separation_break_glass_self_activation",
        "break_glass_scope_mismatch" => "break_glass_scope_mismatch",
        "break_glass_action_mismatch" => "break_glass_action_mismatch",
        "break_glass_target_mismatch" => "break_glass_target_mismatch",
        _ => {
            return Err(break_glass_error(
                "break_glass_reason_unknown",
                "break-glass attempt reason is unsupported",
            ))
        }
    };
    if allowed != (reason == "break_glass_use_admitted") {
        return Err(break_glass_error(
            "break_glass_attempt_snapshot_invalid",
            "break-glass attempt outcome is inconsistent",
        ));
    }
    Ok(reason)
}

#[allow(clippy::too_many_arguments)]
fn derive_request_id(
    eligibility_binding_id: &str,
    activator_binding: &str,
    beneficiary_binding: &str,
    scope: &ScopeRef,
    permission: Permission,
    target: &SecretRef,
    reason: &str,
    requested_at: SystemTime,
    expires_at: SystemTime,
) -> JanusResult<BreakGlassRequestId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-break-glass-request-v1");
    for field in [
        eligibility_binding_id,
        activator_binding,
        beneficiary_binding,
        scope.as_str(),
        permission.as_str(),
        target.as_str(),
        reason,
    ] {
        hash_field(&mut hasher, field);
    }
    hash_time(&mut hasher, requested_at)?;
    hash_time(&mut hasher, expires_at)?;
    BreakGlassRequestId::from_opaque(format!("bgr_{}", hex::encode(&hasher.finalize()[..12])))
}

fn derive_activation_id(
    request_id: &BreakGlassRequestId,
    approver_binding: &str,
    approved_at: SystemTime,
) -> JanusResult<BreakGlassActivationId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-break-glass-activation-v1");
    hash_field(&mut hasher, request_id.as_str());
    hash_field(&mut hasher, approver_binding);
    hash_time(&mut hasher, approved_at)?;
    BreakGlassActivationId::from_opaque(format!("bga_{}", hex::encode(&hasher.finalize()[..12])))
}

#[allow(clippy::too_many_arguments)]
fn derive_attempt_id(
    activation_id: &BreakGlassActivationId,
    actor_binding: &str,
    scope: &ScopeRef,
    permission: Permission,
    target: &SecretRef,
    attempted_at: SystemTime,
    allowed: bool,
    reason_code: &str,
) -> JanusResult<BreakGlassAttemptId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-break-glass-attempt-v1");
    for field in [
        activation_id.as_str(),
        actor_binding,
        scope.as_str(),
        permission.as_str(),
        target.as_str(),
        reason_code,
    ] {
        hash_field(&mut hasher, field);
    }
    hash_time(&mut hasher, attempted_at)?;
    hasher.update([u8::from(allowed)]);
    BreakGlassAttemptId::from_opaque(format!("bgt_{}", hex::encode(&hasher.finalize()[..12])))
}

fn derive_completion_id(
    activation_id: &BreakGlassActivationId,
    attempt_id: &BreakGlassAttemptId,
    actor_binding: &str,
    outcome: BreakGlassCompletionOutcome,
    completed_at: SystemTime,
) -> JanusResult<BreakGlassCompletionId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-break-glass-completion-v1");
    for field in [
        activation_id.as_str(),
        attempt_id.as_str(),
        actor_binding,
        outcome.as_str(),
    ] {
        hash_field(&mut hasher, field);
    }
    hash_time(&mut hasher, completed_at)?;
    BreakGlassCompletionId::from_opaque(format!("bgc_{}", hex::encode(&hasher.finalize()[..12])))
}

#[allow(clippy::too_many_arguments)]
fn derive_review_id(
    activation_id: &BreakGlassActivationId,
    completion_id: &BreakGlassCompletionId,
    reviewer_binding: &str,
    findings: &str,
    remediation: &str,
    closure: BreakGlassReviewClosure,
    reviewed_at: SystemTime,
) -> JanusResult<BreakGlassReviewId> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-break-glass-review-v1");
    for field in [
        activation_id.as_str(),
        completion_id.as_str(),
        reviewer_binding,
        findings,
        remediation,
        closure.as_str(),
    ] {
        hash_field(&mut hasher, field);
    }
    hash_time(&mut hasher, reviewed_at)?;
    BreakGlassReviewId::from_opaque(format!("bgw_{}", hex::encode(&hasher.finalize()[..12])))
}

fn derive_event_id(
    domain: &str,
    prefix: &str,
    activation_id: &str,
    actor_binding: &str,
    reason: &str,
    at: SystemTime,
) -> JanusResult<String> {
    let mut hasher = Sha256::new();
    for field in [domain, activation_id, actor_binding, reason] {
        hash_field(&mut hasher, field);
    }
    hash_time(&mut hasher, at)?;
    Ok(format!("{prefix}{}", hex::encode(&hasher.finalize()[..12])))
}

fn validate_private_text(kind: &'static str, value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.trim().len() != value.len()
        || value.len() > MAX_BREAK_GLASS_TEXT_BYTES
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_principal_binding(value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.trim().len() != value.len()
        || value.len() > MAX_PRINCIPAL_BINDING_BYTES
    {
        return Err(JanusError::InvalidIdentifier {
            kind: "principal_binding",
        });
    }
    Ok(())
}

fn timestamp(value: SystemTime) -> JanusResult<(u64, u32)> {
    let duration = value.duration_since(UNIX_EPOCH).map_err(|_| {
        break_glass_error(
            "break_glass_time_invalid",
            "break-glass time predates the epoch",
        )
    })?;
    Ok((duration.as_secs(), duration.subsec_nanos()))
}

fn from_timestamp(seconds: u64, nanos: u32) -> JanusResult<SystemTime> {
    if nanos >= 1_000_000_000 {
        return Err(break_glass_error(
            "break_glass_time_invalid",
            "break-glass timestamp is malformed",
        ));
    }
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos))
        .ok_or_else(|| {
            break_glass_error(
                "break_glass_time_invalid",
                "break-glass timestamp overflowed",
            )
        })
}

fn hash_time(hasher: &mut Sha256, value: SystemTime) -> JanusResult<()> {
    let (seconds, nanos) = timestamp(value)?;
    hasher.update(seconds.to_be_bytes());
    hasher.update(nanos.to_be_bytes());
    Ok(())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn break_glass_error(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn break_glass_reason(error: &JanusError) -> &'static str {
    match error {
        JanusError::PolicyDenied { reason_code, .. }
        | JanusError::PermitInvalid { reason_code, .. }
        | JanusError::ApprovalInvalid { reason_code, .. } => reason_code,
        JanusError::InvalidIdentifier { .. } => "break_glass_input_invalid",
        JanusError::AuditUnavailable { .. } => "break_glass_audit_unavailable",
        JanusError::StoreUnavailable { .. } => "break_glass_store_unavailable",
        JanusError::InvalidManifest { .. }
        | JanusError::NotInManifest { .. }
        | JanusError::NotFound { .. }
        | JanusError::Unsupported { .. } => "break_glass_invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditWrite, EnvironmentId, OrganizationId, Principal, PrincipalId, PrincipalKind,
        ProjectId, RepositoryId, RoleBindingSource, RoleBindingSourceKind, ScopePathV1,
    };

    fn scope() -> ScopeRef {
        ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("prod").unwrap(),
        )
        .scope_ref()
    }

    fn principal(id: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(id).unwrap()),
            scope(),
        )
    }

    fn eligibility(beneficiary: &PrincipalChain) -> RoleBinding {
        RoleBinding::issue(
            beneficiary.binding_key(),
            beneficiary.scope.clone(),
            Role::BreakGlassAdmin,
            None,
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(10_000),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "reviewed-eligibility")
                .unwrap(),
        )
        .unwrap()
    }

    fn approved() -> (
        BreakGlassActivation,
        PrincipalChain,
        PrincipalChain,
        PrincipalChain,
    ) {
        let activator = principal("security-admin");
        let approver = principal("approver");
        let beneficiary = principal("emergency-operator");
        let request = BreakGlassRequest::request(
            &eligibility(&beneficiary),
            &activator,
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            SafeLabel::new("restore production availability").unwrap(),
            UNIX_EPOCH + Duration::from_secs(10),
            Duration::from_secs(300),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        let activation = BreakGlassActivation::approve(
            request,
            &approver,
            UNIX_EPOCH + Duration::from_secs(20),
            &mut AuditWrite::accepting(),
        )
        .unwrap();
        (activation, activator, approver, beneficiary)
    }

    #[test]
    fn exact_separate_short_lived_activation_round_trips() {
        let (activation, _, _, _) = approved();
        let request_snapshot = activation.request().snapshot().unwrap();
        let activation_snapshot = activation.snapshot().unwrap();
        let restored_request = BreakGlassRequest::from_snapshot(request_snapshot).unwrap();
        let restored =
            BreakGlassActivation::from_snapshot(restored_request, activation_snapshot).unwrap();
        assert_eq!(restored, activation);
        assert!(restored.is_expired_at(UNIX_EPOCH + Duration::from_secs(310)));
        assert!(!format!("{restored:?}").contains("emergency-operator"));
    }

    #[test]
    fn activation_denies_self_roles_broad_actions_and_long_ttl_with_critical_audit() {
        let beneficiary = principal("eligible-beneficiary");
        let activator = principal("separate-activator");
        let binding = eligibility(&beneficiary);
        for (actor, permission, ttl, reason) in [
            (
                &beneficiary,
                Permission::SecretUse,
                Duration::from_secs(1),
                "separation_break_glass_self_activation",
            ),
            (
                &activator,
                Permission::RoleBindingIssue,
                Duration::from_secs(1),
                "break_glass_action_forbidden",
            ),
            (
                &activator,
                Permission::SecretUse,
                MAX_BREAK_GLASS_TTL + Duration::from_secs(1),
                "break_glass_ttl_invalid",
            ),
        ] {
            let mut audit = AuditWrite::accepting();
            assert!(BreakGlassRequest::request(
                &binding,
                actor,
                permission,
                SecretRef::new("sec_emergency").unwrap(),
                SafeLabel::new("incident").unwrap(),
                UNIX_EPOCH + Duration::from_secs(10),
                ttl,
                &mut audit,
            )
            .is_err());
            assert_eq!(audit.events().len(), 1);
            assert_eq!(audit.events()[0].severity, Severity::Critical);
            assert_eq!(audit.events()[0].reason_code, reason);
        }
    }

    #[test]
    fn every_use_attempt_and_completion_is_critical_and_single_use() {
        let (activation, _, _, beneficiary) = approved();
        let mut audit = AuditWrite::accepting();
        let denied = BreakGlassAttempt::authorize(
            &activation,
            &principal("wrong-beneficiary"),
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(30),
            None,
            false,
            &mut audit,
        )
        .unwrap();
        assert!(!denied.allowed());
        let allowed = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(31),
            None,
            false,
            &mut audit,
        )
        .unwrap();
        assert!(allowed.allowed());
        let completion = BreakGlassCompletion::complete(
            &activation,
            &allowed,
            &beneficiary,
            BreakGlassCompletionOutcome::Succeeded,
            UNIX_EPOCH + Duration::from_secs(32),
            &mut audit,
        )
        .unwrap();
        assert_eq!(completion.outcome(), BreakGlassCompletionOutcome::Succeeded);
        let consumed = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(33),
            None,
            true,
            &mut audit,
        )
        .unwrap();
        assert!(!consumed.allowed());
        assert_eq!(consumed.reason_code(), "break_glass_already_consumed");
        assert!(audit
            .events()
            .iter()
            .all(|event| event.severity == Severity::Critical && !event.value_returned));
    }

    #[test]
    fn revocation_expiry_and_self_review_fail_closed() {
        let (activation, activator, approver, beneficiary) = approved();
        let mut audit = AuditWrite::accepting();
        let revocation = BreakGlassRevocation::revoke(
            &activation,
            &activator,
            SafeLabel::new("incident contained").unwrap(),
            UNIX_EPOCH + Duration::from_secs(30),
            &mut audit,
        )
        .unwrap();
        let denied = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(31),
            Some(&revocation),
            false,
            &mut audit,
        )
        .unwrap();
        assert_eq!(denied.reason_code(), "break_glass_revoked");

        let allowed = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(29),
            None,
            false,
            &mut audit,
        )
        .unwrap();
        let completion = BreakGlassCompletion::complete(
            &activation,
            &allowed,
            &beneficiary,
            BreakGlassCompletionOutcome::Failed,
            UNIX_EPOCH + Duration::from_secs(29),
            &mut audit,
        )
        .unwrap();
        for reviewer in [&activator, &approver, &beneficiary] {
            assert!(BreakGlassReview::review(
                &activation,
                &completion,
                reviewer,
                SafeLabel::new("reviewed incident").unwrap(),
                SafeLabel::new("control updated").unwrap(),
                BreakGlassReviewClosure::ClosedRemediated,
                UNIX_EPOCH + Duration::from_secs(40),
                &mut audit,
            )
            .is_err());
        }
        let review = BreakGlassReview::review(
            &activation,
            &completion,
            &principal("independent-auditor"),
            SafeLabel::new("reviewed incident").unwrap(),
            SafeLabel::new("control updated").unwrap(),
            BreakGlassReviewClosure::ClosedRemediated,
            UNIX_EPOCH + Duration::from_secs(40),
            &mut audit,
        )
        .unwrap();
        assert_eq!(review.closure(), BreakGlassReviewClosure::ClosedRemediated);
    }

    #[test]
    fn snapshot_integrity_and_audit_failure_are_fail_closed() {
        let (activation, _, _, beneficiary) = approved();
        let mut snapshot = activation.request().snapshot().unwrap();
        snapshot.permission = Permission::RoleBindingIssue.as_str().to_string();
        assert!(BreakGlassRequest::from_snapshot(snapshot).is_err());

        let result = BreakGlassAttempt::authorize(
            &activation,
            &beneficiary,
            scope(),
            Permission::SecretUse,
            SecretRef::new("sec_emergency").unwrap(),
            UNIX_EPOCH + Duration::from_secs(30),
            None,
            false,
            &mut AuditWrite::failing(),
        );
        assert!(matches!(result, Err(JanusError::AuditUnavailable { .. })));
    }
}

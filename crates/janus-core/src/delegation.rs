//! Exact, short-lived delegation contracts.
//!
//! A delegation grant is value-free evidence that one already-authorized
//! principal may temporarily let one other exact principal request the same
//! reviewed use. It is not a permit, approval, role, or secret value.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, Destination, EgressMode, ExecutorRef,
    JanusError, JanusResult, PrincipalChain, ProfileId, ProfilePolicy, SafeLabel, ScopeRef,
    SecretClass, SecretDescriptor, SecretLifecycle, SecretRef, Severity, TrustLevel, UseProfile,
    UseRequest,
};

/// Current delegation snapshot schema.
pub const DELEGATION_SNAPSHOT_VERSION: u8 = 1;
/// The shortest reviewed delegation lifetime.
pub const MIN_DELEGATION_TTL: Duration = Duration::from_secs(1);
/// The longest reviewed delegation lifetime.
pub const MAX_DELEGATION_TTL: Duration = Duration::from_secs(60 * 60);

const MAX_BINDING_BYTES: usize = 4 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 256;

/// Closed set of actions supported by the first delegation slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationAction {
    /// Request the same exact reviewed normal-use path as the grantor.
    Use,
}

impl DelegationAction {
    /// Stable snapshot representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Use => "use",
        }
    }

    fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "use" => Ok(Self::Use),
            _ => Err(delegation_invalid(
                "delegation_action_unsupported",
                "delegation action is unsupported",
            )),
        }
    }
}

/// Opaque identifier derived from every authorization-relevant grant field.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DelegationId(String);

impl DelegationId {
    fn derive(
        scope: &DelegationScope,
        issued_at: SystemTime,
        expires_at: SystemTime,
        reason: &SafeLabel,
    ) -> JanusResult<Self> {
        let issued_at = time_parts(issued_at)?;
        let expires_at = time_parts(expires_at)?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "janus-delegation-v1");
        hash_scope(&mut hasher, scope);
        hasher.update(issued_at.0.to_be_bytes());
        hasher.update(issued_at.1.to_be_bytes());
        hasher.update(expires_at.0.to_be_bytes());
        hasher.update(expires_at.1.to_be_bytes());
        hash_field(&mut hasher, reason.as_str());
        let digest = hasher.finalize();
        Ok(Self(format!("dlg_{}", hex::encode(&digest[..12]))))
    }

    /// Rehydrate one strict opaque delegation id.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        let suffix = value.strip_prefix("dlg_").ok_or_else(|| {
            delegation_invalid("delegation_id_invalid", "delegation id is malformed")
        })?;
        if suffix.len() != 24
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(delegation_invalid(
                "delegation_id_invalid",
                "delegation id is malformed",
            ));
        }
        Ok(Self(value))
    }

    /// Safe opaque text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DelegationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DelegationId").field(&self.0).finish()
    }
}

/// Exact authority delegated for one reviewed use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationScope {
    /// Exact original authority binding.
    pub grantor_binding: String,
    /// Exact temporary actor binding.
    pub delegate_binding: String,
    /// Closed delegated action.
    pub action: DelegationAction,
    /// Exact secret target.
    pub secret_ref: SecretRef,
    /// Exact authorization scope.
    pub scope_ref: ScopeRef,
    /// Secret class observed when issued.
    pub class: SecretClass,
    /// Lifecycle observed when issued.
    pub lifecycle: SecretLifecycle,
    /// Reviewed profile.
    pub profile_id: ProfileId,
    /// Reviewed executor.
    pub executor: ExecutorRef,
    /// Reviewed destination.
    pub destination: Destination,
    /// Reviewed egress posture.
    pub egress: EgressMode,
    /// Opaque hash of the exact purpose, never the purpose text.
    pub purpose_fingerprint: String,
    /// Opaque hash of current descriptor/profile/grantor authority.
    pub policy_fingerprint: String,
}

/// Strict, value-free durable representation of a delegation grant.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrantSnapshotV1 {
    /// Exact schema version.
    pub schema_version: u8,
    /// Opaque derived grant id.
    pub delegation_id: String,
    /// Exact original authority binding.
    pub grantor_binding: String,
    /// Exact temporary actor binding.
    pub delegate_binding: String,
    /// Closed action text.
    pub action: String,
    /// Exact opaque secret target.
    pub secret_ref: String,
    /// Exact opaque authorization scope.
    pub scope_ref: String,
    /// Stable secret class.
    pub class: String,
    /// Stable lifecycle state.
    pub lifecycle: String,
    /// Reviewed profile id.
    pub profile_id: String,
    /// Reviewed executor ref.
    pub executor: String,
    /// Reviewed destination ref.
    pub destination: String,
    /// Stable egress posture.
    pub egress: String,
    /// Opaque hash of the exact use purpose.
    pub purpose_fingerprint: String,
    /// Opaque hash of current policy inputs.
    pub policy_fingerprint: String,
    /// Issue timestamp seconds since Unix epoch.
    pub issued_at_unix_secs: u64,
    /// Issue timestamp nanoseconds.
    pub issued_at_subsec_nanos: u32,
    /// Expiry timestamp seconds since Unix epoch.
    pub expires_at_unix_secs: u64,
    /// Expiry timestamp nanoseconds.
    pub expires_at_subsec_nanos: u32,
    /// Curated value-free reason.
    pub reason: String,
}

/// One exact, non-chainable delegation grant.
#[derive(Clone, PartialEq, Eq)]
pub struct DelegationGrant {
    id: DelegationId,
    scope: DelegationScope,
    issued_at: SystemTime,
    expires_at: SystemTime,
    reason: SafeLabel,
}

impl DelegationGrant {
    /// Opaque delegation id.
    pub fn id(&self) -> &DelegationId {
        &self.id
    }

    /// Exact delegated authority.
    pub fn scope(&self) -> &DelegationScope {
        &self.scope
    }

    /// Time the grant was issued.
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Time the grant expires.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Curated value-free reason.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }

    /// Return the current grant status.
    pub fn status_at(
        &self,
        revocation: Option<&DelegationRevocation>,
        now: SystemTime,
    ) -> JanusResult<DelegationStatus> {
        if let Some(revocation) = revocation {
            revocation.validate_for(self)?;
            return Ok(DelegationStatus::Revoked);
        }
        if now < self.issued_at {
            return Err(delegation_invalid(
                "delegation_not_yet_valid",
                "delegation is not yet valid",
            ));
        }
        if now >= self.expires_at {
            Ok(DelegationStatus::Expired)
        } else {
            Ok(DelegationStatus::Active)
        }
    }

    /// Export a strict, value-free durable snapshot.
    pub fn snapshot(&self) -> DelegationGrantSnapshotV1 {
        let issued_at = self
            .issued_at
            .duration_since(UNIX_EPOCH)
            .expect("validated delegation issue time");
        let expires_at = self
            .expires_at
            .duration_since(UNIX_EPOCH)
            .expect("validated delegation expiry");
        DelegationGrantSnapshotV1 {
            schema_version: DELEGATION_SNAPSHOT_VERSION,
            delegation_id: self.id.as_str().to_string(),
            grantor_binding: self.scope.grantor_binding.clone(),
            delegate_binding: self.scope.delegate_binding.clone(),
            action: self.scope.action.as_str().to_string(),
            secret_ref: self.scope.secret_ref.as_str().to_string(),
            scope_ref: self.scope.scope_ref.as_str().to_string(),
            class: self.scope.class.as_str().to_string(),
            lifecycle: self.scope.lifecycle.as_str().to_string(),
            profile_id: self.scope.profile_id.as_str().to_string(),
            executor: self.scope.executor.as_str().to_string(),
            destination: self.scope.destination.as_str().to_string(),
            egress: self.scope.egress.as_str().to_string(),
            purpose_fingerprint: self.scope.purpose_fingerprint.clone(),
            policy_fingerprint: self.scope.policy_fingerprint.clone(),
            issued_at_unix_secs: issued_at.as_secs(),
            issued_at_subsec_nanos: issued_at.subsec_nanos(),
            expires_at_unix_secs: expires_at.as_secs(),
            expires_at_subsec_nanos: expires_at.subsec_nanos(),
            reason: self.reason.as_str().to_string(),
        }
    }

    /// Rehydrate and verify a strict durable snapshot.
    pub fn from_snapshot(snapshot: DelegationGrantSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != DELEGATION_SNAPSHOT_VERSION {
            return Err(delegation_invalid(
                "delegation_schema_unsupported",
                "delegation snapshot version is unsupported",
            ));
        }
        validate_bounded(
            "delegation_grantor_binding",
            &snapshot.grantor_binding,
            MAX_BINDING_BYTES,
        )
        .map_err(|_| malformed_snapshot())?;
        validate_bounded(
            "delegation_delegate_binding",
            &snapshot.delegate_binding,
            MAX_BINDING_BYTES,
        )
        .map_err(|_| malformed_snapshot())?;
        validate_bounded("delegation_profile", &snapshot.profile_id, MAX_FIELD_BYTES)
            .map_err(|_| malformed_snapshot())?;
        validate_bounded("delegation_executor", &snapshot.executor, MAX_FIELD_BYTES)
            .map_err(|_| malformed_snapshot())?;
        validate_bounded(
            "delegation_destination",
            &snapshot.destination,
            MAX_FIELD_BYTES,
        )
        .map_err(|_| malformed_snapshot())?;
        validate_bounded("delegation_reason", &snapshot.reason, MAX_REASON_BYTES)
            .map_err(|_| malformed_snapshot())?;
        validate_fingerprint(&snapshot.purpose_fingerprint)?;
        validate_fingerprint(&snapshot.policy_fingerprint)?;

        let issued_at = time_from_parts(
            snapshot.issued_at_unix_secs,
            snapshot.issued_at_subsec_nanos,
        )?;
        let expires_at = time_from_parts(
            snapshot.expires_at_unix_secs,
            snapshot.expires_at_subsec_nanos,
        )?;
        validate_ttl(issued_at, expires_at)?;
        let scope = DelegationScope {
            grantor_binding: snapshot.grantor_binding,
            delegate_binding: snapshot.delegate_binding,
            action: DelegationAction::parse(&snapshot.action)?,
            secret_ref: parse_exact_secret_ref(snapshot.secret_ref)?,
            scope_ref: ScopeRef::from_opaque(snapshot.scope_ref).map_err(|_| {
                delegation_invalid("delegation_scope_invalid", "delegation scope is malformed")
            })?,
            class: SecretClass::parse(&snapshot.class).map_err(|_| {
                delegation_invalid("delegation_class_invalid", "delegation class is malformed")
            })?,
            lifecycle: SecretLifecycle::parse(&snapshot.lifecycle).map_err(|_| {
                delegation_invalid(
                    "delegation_lifecycle_invalid",
                    "delegation lifecycle is malformed",
                )
            })?,
            profile_id: ProfileId::new(snapshot.profile_id).map_err(|_| {
                delegation_invalid(
                    "delegation_profile_invalid",
                    "delegation profile is malformed",
                )
            })?,
            executor: ExecutorRef::new(snapshot.executor).map_err(|_| {
                delegation_invalid(
                    "delegation_executor_invalid",
                    "delegation executor is malformed",
                )
            })?,
            destination: Destination::new(snapshot.destination).map_err(|_| {
                delegation_invalid(
                    "delegation_destination_invalid",
                    "delegation destination is malformed",
                )
            })?,
            egress: EgressMode::parse(&snapshot.egress).map_err(|_| {
                delegation_invalid(
                    "delegation_egress_invalid",
                    "delegation egress is malformed",
                )
            })?,
            purpose_fingerprint: snapshot.purpose_fingerprint,
            policy_fingerprint: snapshot.policy_fingerprint,
        };
        let reason = SafeLabel::new(snapshot.reason).map_err(|_| {
            delegation_invalid(
                "delegation_reason_invalid",
                "delegation reason is malformed",
            )
        })?;
        let expected_id = DelegationId::derive(&scope, issued_at, expires_at, &reason)?;
        let supplied_id = DelegationId::from_opaque(snapshot.delegation_id)?;
        if supplied_id != expected_id {
            return Err(delegation_invalid(
                "delegation_id_mismatch",
                "delegation id does not match the exact grant",
            ));
        }
        Ok(Self {
            id: supplied_id,
            scope,
            issued_at,
            expires_at,
            reason,
        })
    }
}

impl fmt::Debug for DelegationGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegationGrant")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("reason", &self.reason)
            .finish()
    }
}

/// Strict durable revocation evidence.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRevocationSnapshotV1 {
    /// Exact schema version.
    pub schema_version: u8,
    /// Revoked opaque grant id.
    pub delegation_id: String,
    /// Revocation timestamp seconds since Unix epoch.
    pub revoked_at_unix_secs: u64,
    /// Revocation timestamp nanoseconds.
    pub revoked_at_subsec_nanos: u32,
    /// Exact principal binding that authorized revocation.
    pub revoked_by_binding: String,
    /// Curated value-free revocation reason.
    pub reason: String,
}

/// Immutable value-free evidence that a delegation was revoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationRevocation {
    delegation_id: DelegationId,
    revoked_at: SystemTime,
    revoked_by_binding: String,
    reason: SafeLabel,
}

impl DelegationRevocation {
    /// Revoked grant id.
    pub fn delegation_id(&self) -> &DelegationId {
        &self.delegation_id
    }

    /// Revocation time.
    pub fn revoked_at(&self) -> SystemTime {
        self.revoked_at
    }

    /// Exact revoking principal binding.
    pub fn revoked_by_binding(&self) -> &str {
        &self.revoked_by_binding
    }

    /// Curated reason.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }

    /// Export strict durable evidence.
    pub fn snapshot(&self) -> DelegationRevocationSnapshotV1 {
        let revoked_at = self
            .revoked_at
            .duration_since(UNIX_EPOCH)
            .expect("validated delegation revocation time");
        DelegationRevocationSnapshotV1 {
            schema_version: DELEGATION_SNAPSHOT_VERSION,
            delegation_id: self.delegation_id.as_str().to_string(),
            revoked_at_unix_secs: revoked_at.as_secs(),
            revoked_at_subsec_nanos: revoked_at.subsec_nanos(),
            revoked_by_binding: self.revoked_by_binding.clone(),
            reason: self.reason.as_str().to_string(),
        }
    }

    /// Rehydrate strict durable revocation evidence.
    pub fn from_snapshot(snapshot: DelegationRevocationSnapshotV1) -> JanusResult<Self> {
        if snapshot.schema_version != DELEGATION_SNAPSHOT_VERSION {
            return Err(delegation_invalid(
                "delegation_revocation_schema_unsupported",
                "delegation revocation version is unsupported",
            ));
        }
        validate_bounded(
            "delegation_revoker_binding",
            &snapshot.revoked_by_binding,
            MAX_BINDING_BYTES,
        )
        .map_err(|_| {
            delegation_invalid(
                "delegation_revocation_malformed",
                "delegation revocation is malformed",
            )
        })?;
        validate_bounded("delegation_reason", &snapshot.reason, MAX_REASON_BYTES).map_err(
            |_| {
                delegation_invalid(
                    "delegation_revocation_malformed",
                    "delegation revocation is malformed",
                )
            },
        )?;
        Ok(Self {
            delegation_id: DelegationId::from_opaque(snapshot.delegation_id)?,
            revoked_at: time_from_parts(
                snapshot.revoked_at_unix_secs,
                snapshot.revoked_at_subsec_nanos,
            )?,
            revoked_by_binding: snapshot.revoked_by_binding,
            reason: SafeLabel::new(snapshot.reason).map_err(|_| {
                delegation_invalid(
                    "delegation_reason_invalid",
                    "delegation revocation reason is malformed",
                )
            })?,
        })
    }

    fn validate_for(&self, grant: &DelegationGrant) -> JanusResult<()> {
        if self.delegation_id != grant.id {
            return Err(delegation_invalid(
                "delegation_revocation_mismatch",
                "revocation does not match the delegation grant",
            ));
        }
        if self.revoked_at < grant.issued_at {
            return Err(delegation_invalid(
                "delegation_revocation_invalid",
                "revocation predates the delegation grant",
            ));
        }
        if self.revoked_by_binding != grant.scope.grantor_binding
            && self.revoked_by_binding != grant.scope.delegate_binding
        {
            return Err(delegation_invalid(
                "delegation_revoker_unauthorized",
                "revocation actor is not authorized for the delegation grant",
            ));
        }
        Ok(())
    }
}

/// Current status of one grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationStatus {
    /// Grant is within its validity window and has no revocation evidence.
    Active,
    /// Grant lifetime has elapsed.
    Expired,
    /// Immutable revocation evidence exists.
    Revoked,
}

impl DelegationStatus {
    /// Stable status text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// Pure policy decision for a delegation check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationDecision {
    /// Exact current policy allows the delegation.
    Allow,
    /// Delegation is denied with a stable value-free reason.
    Deny {
        /// Stable machine-readable reason.
        reason_code: &'static str,
        /// Fixed safe detail.
        detail: &'static str,
    },
}

impl DelegationDecision {
    /// Stable reason code for a denial.
    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason_code, .. } => Some(reason_code),
        }
    }
}

/// Default-deny exact-use delegation policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationPolicy;

impl DelegationPolicy {
    /// Issue one exact, non-chainable use delegation after current policy and
    /// required audit both accept it.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_use<A: AuditSink>(
        profiles: &ProfilePolicy,
        descriptor: &SecretDescriptor,
        request: &UseRequest,
        grantor: &PrincipalChain,
        delegate: &PrincipalChain,
        parent_delegation: Option<&DelegationGrant>,
        issued_at: SystemTime,
        expires_at: SystemTime,
        reason: SafeLabel,
        audit: &mut A,
    ) -> JanusResult<DelegationGrant> {
        if validate_bounded("delegation_reason", reason.as_str(), MAX_REASON_BYTES).is_err() {
            return record_denial(
                audit,
                descriptor.secret_ref.clone(),
                grantor,
                None,
                deny(
                    "delegation_reason_invalid",
                    "delegation reason is outside the reviewed bound",
                ),
            );
        }
        if let Err(error) = validate_ttl(issued_at, expires_at) {
            let decision = match error {
                JanusError::PolicyDenied { reason_code, .. } => DelegationDecision::Deny {
                    reason_code,
                    detail: match reason_code {
                        "delegation_ttl_out_of_bounds" => {
                            "delegation ttl is outside the reviewed bound"
                        }
                        "delegation_expiry_invalid" => "delegation expiry must follow issue time",
                        _ => "delegation timestamp is invalid",
                    },
                },
                _ => deny("delegation_time_invalid", "delegation timestamp is invalid"),
            };
            return record_denial(
                audit,
                descriptor.secret_ref.clone(),
                grantor,
                None,
                decision,
            );
        }
        let scope = match build_current_scope(
            profiles,
            descriptor,
            request,
            grantor,
            delegate,
            parent_delegation,
        ) {
            Ok(scope) => scope,
            Err(decision) => {
                return record_denial(
                    audit,
                    descriptor.secret_ref.clone(),
                    grantor,
                    None,
                    decision,
                )
            }
        };
        let id = DelegationId::derive(&scope, issued_at, expires_at, &reason)?;
        let grant = DelegationGrant {
            id,
            scope,
            issued_at,
            expires_at,
            reason,
        };
        audit.record(
            AuditEvent::new(
                AuditAction::DelegationGrant,
                AuditOutcome::Allowed,
                "delegation_granted",
                Severity::High,
                Some(descriptor.secret_ref.clone()),
                grantor,
            )
            .with_evidence(delegation_reason_evidence(grant.id(), grant.reason())),
        )?;
        Ok(grant)
    }

    /// Make a pure current-policy decision for one exact delegated use.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_use(
        grant: &DelegationGrant,
        revocation: Option<&DelegationRevocation>,
        profiles: &ProfilePolicy,
        descriptor: &SecretDescriptor,
        request: &UseRequest,
        grantor: &PrincipalChain,
        delegate: &PrincipalChain,
        now: SystemTime,
    ) -> DelegationDecision {
        if let Some(revocation) = revocation {
            if revocation.validate_for(grant).is_err() {
                return deny(
                    "delegation_revocation_mismatch",
                    "revocation does not match the delegation grant",
                );
            }
            return deny("delegation_revoked", "delegation grant is revoked");
        }
        if now < grant.issued_at {
            return deny(
                "delegation_not_yet_valid",
                "delegation grant is not yet valid",
            );
        }
        if now >= grant.expires_at {
            return deny("delegation_expired", "delegation grant is expired");
        }
        if grant.scope.grantor_binding != grantor.binding_key() {
            return deny(
                "delegation_wrong_grantor",
                "delegation grantor binding does not match",
            );
        }
        if grant.scope.delegate_binding != delegate.binding_key() {
            return deny(
                "delegation_wrong_delegate",
                "delegation delegate binding does not match",
            );
        }
        if grant.scope.secret_ref != request.secret_ref
            || grant.scope.secret_ref != descriptor.secret_ref
        {
            return deny(
                "delegation_target_mismatch",
                "delegation target does not match",
            );
        }
        if grant.scope.scope_ref != request.scope
            || grant.scope.scope_ref != descriptor.scope
            || grant.scope.scope_ref != grantor.scope
            || grant.scope.scope_ref != delegate.scope
        {
            return deny(
                "delegation_scope_mismatch",
                "delegation scope does not match exactly",
            );
        }
        if Some(grant.scope.class) != descriptor.classification {
            return deny(
                "delegation_class_changed",
                "delegation secret class changed",
            );
        }
        if grant.scope.lifecycle != descriptor.lifecycle {
            return deny(
                "delegation_lifecycle_changed",
                "delegation lifecycle changed",
            );
        }
        if grant.scope.profile_id != request.profile_id {
            return deny(
                "delegation_profile_mismatch",
                "delegation profile does not match",
            );
        }
        if grant.scope.destination != request.destination {
            return deny(
                "delegation_destination_mismatch",
                "delegation destination does not match",
            );
        }
        if grant.scope.purpose_fingerprint
            != fingerprint_text("janus-delegation-purpose-v1", request.purpose.as_str())
        {
            return deny(
                "delegation_purpose_mismatch",
                "delegation purpose does not match",
            );
        }

        let current =
            match build_current_scope(profiles, descriptor, request, grantor, delegate, None) {
                Ok(scope) => scope,
                Err(decision) => return decision,
            };
        if current.executor != grant.scope.executor {
            return deny("delegation_executor_changed", "delegation executor changed");
        }
        if current.egress != grant.scope.egress {
            return deny("delegation_egress_changed", "delegation egress changed");
        }
        if current.policy_fingerprint != grant.scope.policy_fingerprint {
            return deny("delegation_policy_changed", "delegation policy changed");
        }
        DelegationDecision::Allow
    }

    /// Validate one exact delegated use and record required denial/expiry
    /// evidence. This deliberately does not issue or consume a permit.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_use<A: AuditSink>(
        grant: &DelegationGrant,
        revocation: Option<&DelegationRevocation>,
        profiles: &ProfilePolicy,
        descriptor: &SecretDescriptor,
        request: &UseRequest,
        grantor: &PrincipalChain,
        delegate: &PrincipalChain,
        now: SystemTime,
        audit: &mut A,
    ) -> JanusResult<()> {
        let decision = Self::decide_use(
            grant, revocation, profiles, descriptor, request, grantor, delegate, now,
        );
        match decision {
            DelegationDecision::Allow => Ok(()),
            DelegationDecision::Deny {
                reason_code,
                detail,
            } if reason_code == "delegation_expired" => {
                audit.record(
                    AuditEvent::new(
                        AuditAction::DelegationExpire,
                        AuditOutcome::Denied,
                        reason_code,
                        Severity::Warning,
                        Some(descriptor.secret_ref.clone()),
                        delegate,
                    )
                    .with_evidence(delegation_evidence(grant.id())),
                )?;
                Err(delegation_invalid(reason_code, detail))
            }
            decision => record_denial(
                audit,
                descriptor.secret_ref.clone(),
                delegate,
                Some(grant.id()),
                decision,
            ),
        }
    }

    /// Authorize immutable revocation evidence. Grantor and delegate may
    /// revoke; future administrator revocation belongs to the role-aware slice.
    pub fn authorize_revocation<A: AuditSink>(
        grant: &DelegationGrant,
        actor: &PrincipalChain,
        revoked_at: SystemTime,
        reason: SafeLabel,
        audit: &mut A,
    ) -> JanusResult<DelegationRevocation> {
        if validate_bounded("delegation_reason", reason.as_str(), MAX_REASON_BYTES).is_err() {
            return record_denial(
                audit,
                grant.scope.secret_ref.clone(),
                actor,
                Some(grant.id()),
                deny(
                    "delegation_reason_invalid",
                    "delegation reason is outside the reviewed bound",
                ),
            );
        }
        let actor_binding = actor.binding_key();
        if actor_binding != grant.scope.grantor_binding
            && actor_binding != grant.scope.delegate_binding
        {
            return record_denial(
                audit,
                grant.scope.secret_ref.clone(),
                actor,
                Some(grant.id()),
                deny(
                    "delegation_revoker_unauthorized",
                    "principal may not revoke this delegation",
                ),
            );
        }
        if revoked_at < grant.issued_at {
            return record_denial(
                audit,
                grant.scope.secret_ref.clone(),
                actor,
                Some(grant.id()),
                deny(
                    "delegation_revocation_invalid",
                    "revocation predates the delegation grant",
                ),
            );
        }
        let revocation = DelegationRevocation {
            delegation_id: grant.id.clone(),
            revoked_at,
            revoked_by_binding: actor_binding,
            reason,
        };
        audit.record(
            AuditEvent::new(
                AuditAction::DelegationRevoke,
                AuditOutcome::Allowed,
                "delegation_revoked",
                Severity::High,
                Some(grant.scope.secret_ref.clone()),
                actor,
            )
            .with_evidence(delegation_reason_evidence(grant.id(), &revocation.reason)),
        )?;
        Ok(revocation)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_current_scope(
    profiles: &ProfilePolicy,
    descriptor: &SecretDescriptor,
    request: &UseRequest,
    grantor: &PrincipalChain,
    delegate: &PrincipalChain,
    parent_delegation: Option<&DelegationGrant>,
) -> Result<DelegationScope, DelegationDecision> {
    if parent_delegation.is_some() {
        return Err(deny(
            "delegation_chaining_denied",
            "delegation grants cannot be chained",
        ));
    }
    let grantor_binding = grantor.binding_key();
    let delegate_binding = delegate.binding_key();
    if validate_bounded(
        "delegation_grantor_binding",
        &grantor_binding,
        MAX_BINDING_BYTES,
    )
    .is_err()
        || validate_bounded(
            "delegation_delegate_binding",
            &delegate_binding,
            MAX_BINDING_BYTES,
        )
        .is_err()
        || contains_wildcard(&grantor_binding)
        || contains_wildcard(&delegate_binding)
    {
        return Err(deny(
            "delegation_binding_invalid",
            "delegation principal binding is invalid",
        ));
    }
    if grantor_binding == delegate_binding {
        return Err(deny(
            "delegation_same_principal",
            "delegation requires a distinct delegate",
        ));
    }
    if descriptor.secret_ref != request.secret_ref {
        return Err(deny(
            "delegation_target_mismatch",
            "delegation target does not match",
        ));
    }
    if !is_exact_secret_ref(request.secret_ref.as_str()) {
        return Err(deny(
            "delegation_target_invalid",
            "delegation target must be one exact opaque secret ref",
        ));
    }
    if descriptor.scope != request.scope
        || descriptor.scope != grantor.scope
        || descriptor.scope != delegate.scope
    {
        return Err(deny(
            "delegation_scope_mismatch",
            "delegation scope does not match exactly",
        ));
    }
    if !descriptor.present {
        return Err(deny(
            "delegation_target_unavailable",
            "delegation target is not present",
        ));
    }
    if let Some((reason_code, _)) = descriptor.normal_use_denial() {
        return Err(if reason_code.starts_with("denied_lifecycle_") {
            deny(
                "delegation_lifecycle_blocked",
                "delegation lifecycle blocks normal use",
            )
        } else {
            deny(
                "delegation_metadata_incomplete",
                "delegation target metadata is incomplete",
            )
        });
    }
    let Some(class) = descriptor.classification else {
        return Err(deny(
            "delegation_metadata_incomplete",
            "delegation target metadata is incomplete",
        ));
    };
    if !matches!(class, SecretClass::Low | SecretClass::Normal) {
        return Err(deny(
            "delegation_class_unsupported",
            "high-risk delegation is not supported by this policy slice",
        ));
    }
    if !descriptor
        .allowed_uses
        .iter()
        .any(|profile_id| profile_id == &request.profile_id)
    {
        return Err(deny(
            "delegation_profile_not_declared",
            "delegation profile is not declared for the target",
        ));
    }
    if !matches!(
        profiles.decide(request, grantor),
        crate::PolicyDecision::Allow
    ) {
        return Err(deny(
            "delegation_exceeds_grantor_rights",
            "grantor does not currently hold the exact delegated right",
        ));
    }
    let Some(profile) = profiles.profile_for(&request.secret_ref, &request.profile_id) else {
        return Err(deny(
            "delegation_profile_missing",
            "delegation profile is unavailable",
        ));
    };
    if delegate.executor.id.as_str() != profile.executor.as_str() {
        return Err(deny(
            "delegation_wrong_delegate_executor",
            "delegate executor does not match the reviewed profile",
        ));
    }
    for (kind, value) in [
        ("delegation_profile", profile.id.as_str()),
        ("delegation_executor", profile.executor.as_str()),
        ("delegation_destination", profile.destination.as_str()),
        ("delegation_purpose", request.purpose.as_str()),
    ] {
        if validate_bounded(kind, value, MAX_FIELD_BYTES).is_err() || contains_wildcard(value) {
            return Err(deny(
                "delegation_binding_invalid",
                "delegation binding exceeds the reviewed limit",
            ));
        }
    }
    let purpose_fingerprint =
        fingerprint_text("janus-delegation-purpose-v1", request.purpose.as_str());
    let policy_fingerprint = policy_fingerprint(descriptor, profile, request, &grantor_binding);
    Ok(DelegationScope {
        grantor_binding,
        delegate_binding,
        action: DelegationAction::Use,
        secret_ref: request.secret_ref.clone(),
        scope_ref: request.scope.clone(),
        class,
        lifecycle: descriptor.lifecycle,
        profile_id: request.profile_id.clone(),
        executor: profile.executor.clone(),
        destination: request.destination.clone(),
        egress: profile.egress,
        purpose_fingerprint,
        policy_fingerprint,
    })
}

fn policy_fingerprint(
    descriptor: &SecretDescriptor,
    profile: &UseProfile,
    request: &UseRequest,
    grantor_binding: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "janus-delegation-policy-v1");
    hash_field(&mut hasher, grantor_binding);
    hash_field(&mut hasher, descriptor.secret_ref.as_str());
    hash_field(&mut hasher, descriptor.scope.as_str());
    hash_field(
        &mut hasher,
        descriptor
            .owner
            .as_ref()
            .map(crate::OwnerRef::as_str)
            .unwrap_or("unassigned"),
    );
    hash_field(
        &mut hasher,
        descriptor
            .classification
            .map(SecretClass::as_str)
            .unwrap_or("unclassified"),
    );
    hash_field(&mut hasher, descriptor.lifecycle.as_str());
    hash_field(&mut hasher, trust_text(descriptor.trust_level));
    hash_field(
        &mut hasher,
        if descriptor.required {
            "required"
        } else {
            "optional"
        },
    );
    hash_field(
        &mut hasher,
        if descriptor.present {
            "present"
        } else {
            "missing"
        },
    );
    let mut allowed_uses = descriptor
        .allowed_uses
        .iter()
        .map(ProfileId::as_str)
        .collect::<Vec<_>>();
    allowed_uses.sort_unstable();
    for allowed_use in allowed_uses {
        hash_field(&mut hasher, allowed_use);
    }
    hash_field(&mut hasher, profile.id.as_str());
    hash_field(&mut hasher, profile.secret_ref.as_str());
    hash_field(&mut hasher, profile.scope.as_str());
    hash_field(&mut hasher, profile.executor.as_str());
    hash_field(&mut hasher, profile.destination.as_str());
    hash_field(&mut hasher, profile.egress.as_str());
    hash_field(&mut hasher, trust_text(profile.trust_level));
    hasher.update(profile.ttl.as_secs().to_be_bytes());
    hasher.update(profile.ttl.subsec_nanos().to_be_bytes());
    hash_field(
        &mut hasher,
        if profile.single_use {
            "single"
        } else {
            "multiple"
        },
    );
    hash_field(
        &mut hasher,
        if profile.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    hash_field(&mut hasher, request.purpose.as_str());
    hex::encode(hasher.finalize())
}

fn trust_text(trust: TrustLevel) -> &'static str {
    match trust {
        TrustLevel::L0 => "l0",
        TrustLevel::L1 => "l1",
        TrustLevel::L2 => "l2",
    }
}

fn hash_scope(hasher: &mut Sha256, scope: &DelegationScope) {
    hash_field(hasher, &scope.grantor_binding);
    hash_field(hasher, &scope.delegate_binding);
    hash_field(hasher, scope.action.as_str());
    hash_field(hasher, scope.secret_ref.as_str());
    hash_field(hasher, scope.scope_ref.as_str());
    hash_field(hasher, scope.class.as_str());
    hash_field(hasher, scope.lifecycle.as_str());
    hash_field(hasher, scope.profile_id.as_str());
    hash_field(hasher, scope.executor.as_str());
    hash_field(hasher, scope.destination.as_str());
    hash_field(hasher, scope.egress.as_str());
    hash_field(hasher, &scope.purpose_fingerprint);
    hash_field(hasher, &scope.policy_fingerprint);
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn fingerprint_text(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain);
    hash_field(&mut hasher, value);
    hex::encode(hasher.finalize())
}

fn validate_fingerprint(value: &str) -> JanusResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(delegation_invalid(
            "delegation_fingerprint_invalid",
            "delegation fingerprint is malformed",
        ));
    }
    Ok(())
}

fn parse_exact_secret_ref(value: String) -> JanusResult<SecretRef> {
    if !is_exact_secret_ref(&value) {
        return Err(delegation_invalid(
            "delegation_target_invalid",
            "delegation target is malformed",
        ));
    }
    SecretRef::new(value).map_err(|_| {
        delegation_invalid(
            "delegation_target_invalid",
            "delegation target is malformed",
        )
    })
}

fn is_exact_secret_ref(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sec_") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 128
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn contains_wildcard(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character, '*' | '?'))
}

fn validate_bounded(kind: &'static str, value: &str, max_bytes: usize) -> JanusResult<()> {
    if value.is_empty() || value.trim().len() != value.len() || value.len() > max_bytes {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_ttl(issued_at: SystemTime, expires_at: SystemTime) -> JanusResult<()> {
    time_parts(issued_at)?;
    time_parts(expires_at)?;
    let ttl = expires_at.duration_since(issued_at).map_err(|_| {
        delegation_invalid(
            "delegation_expiry_invalid",
            "delegation expiry must follow issue time",
        )
    })?;
    if ttl < MIN_DELEGATION_TTL || ttl > MAX_DELEGATION_TTL {
        return Err(delegation_invalid(
            "delegation_ttl_out_of_bounds",
            "delegation ttl is outside the reviewed bound",
        ));
    }
    Ok(())
}

fn time_parts(value: SystemTime) -> JanusResult<(u64, u32)> {
    let duration = value.duration_since(UNIX_EPOCH).map_err(|_| {
        delegation_invalid("delegation_time_invalid", "delegation timestamp is invalid")
    })?;
    Ok((duration.as_secs(), duration.subsec_nanos()))
}

fn time_from_parts(seconds: u64, nanos: u32) -> JanusResult<SystemTime> {
    if nanos >= 1_000_000_000 {
        return Err(delegation_invalid(
            "delegation_time_invalid",
            "delegation timestamp is malformed",
        ));
    }
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos))
        .ok_or_else(|| {
            delegation_invalid(
                "delegation_time_invalid",
                "delegation timestamp is malformed",
            )
        })
}

fn deny(reason_code: &'static str, detail: &'static str) -> DelegationDecision {
    DelegationDecision::Deny {
        reason_code,
        detail,
    }
}

fn delegation_invalid(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn malformed_snapshot() -> JanusError {
    delegation_invalid(
        "delegation_snapshot_malformed",
        "delegation snapshot is malformed",
    )
}

fn delegation_evidence(id: &DelegationId) -> SafeLabel {
    SafeLabel::new(format!("delegation {}", id.as_str()))
        .expect("derived delegation evidence is a safe non-empty label")
}

fn delegation_reason_evidence(id: &DelegationId, reason: &SafeLabel) -> SafeLabel {
    SafeLabel::new(format!(
        "delegation {} reason {}",
        id.as_str(),
        reason.as_str()
    ))
    .expect("validated delegation reason produces safe evidence")
}

fn record_denial<T, A: AuditSink>(
    audit: &mut A,
    secret_ref: SecretRef,
    principal: &PrincipalChain,
    delegation_id: Option<&DelegationId>,
    decision: DelegationDecision,
) -> JanusResult<T> {
    let DelegationDecision::Deny {
        reason_code,
        detail,
    } = decision
    else {
        unreachable!("record_denial requires a denial")
    };
    let event = AuditEvent::new(
        AuditAction::DelegationDeny,
        AuditOutcome::Denied,
        reason_code,
        Severity::Warning,
        Some(secret_ref),
        principal,
    );
    audit.record(match delegation_id {
        Some(id) => event.with_evidence(delegation_evidence(id)),
        None => event,
    })?;
    Err(delegation_invalid(reason_code, detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditWrite, OwnerRef, Principal, PrincipalId, PrincipalKind, SecretName, TrustLevel,
    };

    struct Fixture {
        scope: ScopeRef,
        descriptor: SecretDescriptor,
        profile: UseProfile,
        request: UseRequest,
        grantor: PrincipalChain,
        delegate: PrincipalChain,
    }

    fn fixture() -> Fixture {
        let scope = crate::test_scope("dev");
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let profile_id = ProfileId::new("profile.fixture").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let executor = ExecutorRef::new("runner-a").unwrap();
        let descriptor = SecretDescriptor {
            name: SecretName::new("FIXTURE").unwrap(),
            secret_ref: secret_ref.clone(),
            label: SafeLabel::new("Fixture").unwrap(),
            scope: scope.clone(),
            owner: Some(OwnerRef::new("security").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L2,
            allowed_uses: vec![profile_id.clone()],
            present: true,
        };
        let profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            scope: scope.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let request = UseRequest {
            secret_ref,
            scope: scope.clone(),
            profile_id,
            destination,
            purpose: crate::Purpose::new("deploy reviewed release").unwrap(),
        };
        let mut grantor = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope.clone(),
        );
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("human-grantor").unwrap(),
        ));
        let mut delegate = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            scope.clone(),
        );
        delegate.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("human-delegate").unwrap(),
        ));
        Fixture {
            scope,
            descriptor,
            profile,
            request,
            grantor,
            delegate,
        }
    }

    fn issue(fixture: &Fixture, audit: &mut AuditWrite) -> DelegationGrant {
        DelegationPolicy::issue_use(
            &ProfilePolicy::new(vec![fixture.profile.clone()]),
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(610),
            SafeLabel::new("vacation coverage").unwrap(),
            audit,
        )
        .unwrap()
    }

    #[test]
    fn exact_use_grant_round_trips_and_validates_current_policy() {
        let fixture = fixture();
        let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
        let mut audit = AuditWrite::accepting();
        let grant = issue(&fixture, &mut audit);
        let encoded = serde_json::to_vec(&grant.snapshot()).unwrap();
        let snapshot: DelegationGrantSnapshotV1 = serde_json::from_slice(&encoded).unwrap();
        let restored = DelegationGrant::from_snapshot(snapshot).unwrap();
        assert_eq!(restored, grant);
        assert_eq!(
            grant
                .status_at(None, UNIX_EPOCH + Duration::from_secs(11))
                .unwrap(),
            DelegationStatus::Active
        );

        DelegationPolicy::validate_use(
            &restored,
            None,
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(11),
            &mut audit,
        )
        .unwrap();
        assert_eq!(audit.events()[0].action, AuditAction::DelegationGrant);
        assert!(!audit.events()[0].value_returned);
    }

    #[test]
    fn strict_snapshot_rejects_unknown_version_fields_and_id_tamper() {
        let fixture = fixture();
        let mut audit = AuditWrite::accepting();
        let grant = issue(&fixture, &mut audit);
        let mut value = serde_json::to_value(grant.snapshot()).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DelegationGrantSnapshotV1>(value).is_err());

        let mut snapshot = grant.snapshot();
        snapshot.schema_version = 2;
        assert!(matches!(
            DelegationGrant::from_snapshot(snapshot),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_schema_unsupported",
                ..
            })
        ));

        let mut snapshot = grant.snapshot();
        snapshot.destination = "other-api".to_string();
        assert!(matches!(
            DelegationGrant::from_snapshot(snapshot),
            Err(JanusError::PolicyDenied {
                reason_code: "delegation_id_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn issuance_denies_high_risk_chained_overbroad_and_bad_ttl() {
        let mut fixture = fixture();
        let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
        let mut audit = AuditWrite::accepting();
        fixture.descriptor.classification = Some(SecretClass::HighValue);
        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_class_unsupported",
                ..
            }
        ));

        fixture.descriptor.classification = Some(SecretClass::Normal);
        fixture.descriptor.secret_ref = SecretRef::new("*").unwrap();
        fixture.request.secret_ref = SecretRef::new("*").unwrap();
        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_target_invalid",
                ..
            }
        ));

        fixture.descriptor.secret_ref = SecretRef::new("sec_fixture").unwrap();
        fixture.request.secret_ref = SecretRef::new("sec_fixture").unwrap();
        let parent = issue(&fixture, &mut audit);
        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            Some(&parent),
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_chaining_denied",
                ..
            }
        ));

        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(10 + MAX_DELEGATION_TTL.as_secs() + 1),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_ttl_out_of_bounds",
                ..
            }
        ));
        assert_eq!(
            audit.events().last().unwrap().action,
            AuditAction::DelegationDeny
        );

        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("x".repeat(MAX_REASON_BYTES + 1)).unwrap(),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_reason_invalid",
                ..
            }
        ));
    }

    #[test]
    fn validation_denies_wrong_actor_scope_binding_and_policy_drift() {
        let fixture = fixture();
        let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
        let mut audit = AuditWrite::accepting();
        let grant = issue(&fixture, &mut audit);

        let mut wrong_delegate = fixture.delegate.clone();
        wrong_delegate.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("other-human").unwrap(),
        ));
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &wrong_delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_wrong_delegate"));

        let mut wrong_grantor = fixture.grantor.clone();
        wrong_grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("other-grantor").unwrap(),
        ));
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &wrong_grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_wrong_grantor"));

        let mut wrong_scope = fixture.request.clone();
        wrong_scope.scope = crate::test_scope("prod");
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &wrong_scope,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_scope_mismatch"));

        let mut wrong_target = fixture.request.clone();
        wrong_target.secret_ref = SecretRef::new("sec_other").unwrap();
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &wrong_target,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_target_mismatch"));

        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(9),
        );
        assert_eq!(decision.reason_code(), Some("delegation_not_yet_valid"));

        let mut changed = fixture.descriptor.clone();
        changed.lifecycle = SecretLifecycle::Rotating;
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &profiles,
            &changed,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_lifecycle_changed"));

        let mut changed_profile = fixture.profile.clone();
        changed_profile.ttl = Duration::from_secs(30);
        let decision = DelegationPolicy::decide_use(
            &grant,
            None,
            &ProfilePolicy::new(vec![changed_profile]),
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
        );
        assert_eq!(decision.reason_code(), Some("delegation_policy_changed"));
    }

    #[test]
    fn revocation_and_expiry_are_audited_and_block_use() {
        let fixture = fixture();
        let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
        let mut audit = AuditWrite::accepting();
        let grant = issue(&fixture, &mut audit);
        let revocation = DelegationPolicy::authorize_revocation(
            &grant,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage ended").unwrap(),
            &mut audit,
        )
        .unwrap();
        let restored = DelegationRevocation::from_snapshot(revocation.snapshot()).unwrap();
        assert_eq!(restored, revocation);
        let mut unauthorized_snapshot = revocation.snapshot();
        unauthorized_snapshot.revoked_by_binding = "principal:intruder".to_string();
        let unauthorized = DelegationRevocation::from_snapshot(unauthorized_snapshot).unwrap();
        let error = grant
            .status_at(Some(&unauthorized), UNIX_EPOCH + Duration::from_secs(20))
            .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_revoker_unauthorized",
                ..
            }
        ));
        let mut revocation_value = serde_json::to_value(revocation.snapshot()).unwrap();
        revocation_value["unknown"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<DelegationRevocationSnapshotV1>(revocation_value).is_err()
        );
        assert_eq!(
            grant
                .status_at(Some(&revocation), UNIX_EPOCH + Duration::from_secs(20))
                .unwrap(),
            DelegationStatus::Revoked
        );

        let error = DelegationPolicy::validate_use(
            &grant,
            Some(&revocation),
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(21),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_revoked",
                ..
            }
        ));

        let error = DelegationPolicy::validate_use(
            &grant,
            None,
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            UNIX_EPOCH + Duration::from_secs(611),
            &mut audit,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_expired",
                ..
            }
        ));
        assert!(audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::DelegationExpire));
    }

    #[test]
    fn required_audit_failure_blocks_grant_and_revocation() {
        let fixture = fixture();
        let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
        let mut failing = AuditWrite::failing();
        let error = DelegationPolicy::issue_use(
            &profiles,
            &fixture.descriptor,
            &fixture.request,
            &fixture.grantor,
            &fixture.delegate,
            None,
            UNIX_EPOCH + Duration::from_secs(10),
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage").unwrap(),
            &mut failing,
        )
        .unwrap_err();
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));

        let mut accepting = AuditWrite::accepting();
        let grant = issue(&fixture, &mut accepting);
        let error = DelegationPolicy::authorize_revocation(
            &grant,
            &fixture.grantor,
            UNIX_EPOCH + Duration::from_secs(20),
            SafeLabel::new("coverage ended").unwrap(),
            &mut failing,
        )
        .unwrap_err();
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));
    }

    #[test]
    fn malformed_inputs_do_not_cross_error_or_snapshot_boundaries() {
        let fixture = fixture();
        let mut audit = AuditWrite::accepting();
        let grant = issue(&fixture, &mut audit);
        let canary = "delegation-secret-canary";
        let mut snapshot = grant.snapshot();
        snapshot.delegation_id = canary.to_string();
        let error = DelegationGrant::from_snapshot(snapshot).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(canary));
        let encoded = serde_json::to_string(&grant.snapshot()).unwrap();
        assert!(!encoded.contains(fixture.request.purpose.as_str()));
        assert_eq!(fixture.scope, grant.scope.scope_ref);
    }
}

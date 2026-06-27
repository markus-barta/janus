//! Default-deny policy and use-permit model.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, Destination, ExecutorRef, JanusError,
    JanusResult, PrincipalChain, SafeLabel, SecretClass, SecretRef, Severity,
};
use sha2::{Digest, Sha256};

/// Trust tier required for a use path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Janus absent or unmanaged.
    L0,
    /// Metadata only; no literal can leave Janus.
    L1,
    /// Human-reveal or secret-bearing use path after stronger approval.
    L2,
}

/// Egress enforcement posture for a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressMode {
    /// Janus-owned connector performs a narrow operation.
    Connector,
    /// Sandboxed runner enforces destination.
    Sandboxed,
    /// Network proxy enforces destination.
    ProxyEnforced,
    /// Hook guard only; not enough for high-value enterprise use.
    HookGuarded,
    /// Declaration only; local/dev or low-risk use only.
    DeclaredOnly,
}

impl EgressMode {
    /// Parse stable manifest/API text for the egress mode.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "connector" => Ok(Self::Connector),
            "sandboxed" => Ok(Self::Sandboxed),
            "proxy_enforced" => Ok(Self::ProxyEnforced),
            "hook_guarded" => Ok(Self::HookGuarded),
            "declared_only" => Ok(Self::DeclaredOnly),
            _ => Err(JanusError::InvalidIdentifier {
                kind: "egress_mode",
            }),
        }
    }

    /// Stable manifest/API text for the egress mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connector => "connector",
            Self::Sandboxed => "sandboxed",
            Self::ProxyEnforced => "proxy_enforced",
            Self::HookGuarded => "hook_guarded",
            Self::DeclaredOnly => "declared_only",
        }
    }

    /// Whether the egress posture is strong enough for high-risk classes.
    pub fn is_strong(self) -> bool {
        matches!(
            self,
            Self::Connector | Self::Sandboxed | Self::ProxyEnforced
        )
    }
}

/// Stable profile identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    /// Construct a non-empty profile id.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() != value.len() {
            return Err(JanusError::InvalidIdentifier { kind: "profile_id" });
        }
        Ok(Self(value))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Purpose/reason category for an approved use request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Purpose(String);

impl Purpose {
    /// Construct a non-empty purpose.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() != value.len() {
            return Err(JanusError::InvalidIdentifier { kind: "purpose" });
        }
        Ok(Self(value))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A reviewed approved-use profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseProfile {
    /// Profile id.
    pub id: ProfileId,
    /// Secret this profile can use.
    pub secret_ref: SecretRef,
    /// Executor allowed to consume the permit.
    pub executor: ExecutorRef,
    /// Destination allowed for this profile.
    pub destination: Destination,
    /// Egress enforcement mode.
    pub egress: EgressMode,
    /// Required trust level.
    pub trust_level: TrustLevel,
    /// Permit lifetime.
    pub ttl: Duration,
    /// Whether a permit is intended for one use.
    pub single_use: bool,
    /// Whether the profile is enabled.
    pub enabled: bool,
}

/// Request to issue a permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseRequest {
    /// Secret requested.
    pub secret_ref: SecretRef,
    /// Profile requested.
    pub profile_id: ProfileId,
    /// Destination requested.
    pub destination: Destination,
    /// Purpose entered by the caller.
    pub purpose: Purpose,
}

/// Opaque id for an exact approval grant.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ApprovalId(String);

impl ApprovalId {
    fn derive(scope: &ApprovalGrantScope, expires_at: SystemTime, reason: &SafeLabel) -> Self {
        let expires_at = expires_at.duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"janus-approval-v1\0");
        hasher.update(scope.secret_ref.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.profile_id.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.executor.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.destination.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.class.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.egress.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(scope.purpose.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(expires_at.as_secs().to_le_bytes());
        hasher.update(expires_at.subsec_nanos().to_le_bytes());
        hasher.update(b"\0");
        hasher.update(reason.as_str().as_bytes());
        let digest = hasher.finalize();
        Self(format!("appr_{}", hex::encode(&digest[..12])))
    }

    /// Rehydrate an opaque approval id.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty()
            || value.trim().len() != value.len()
            || !value.starts_with("appr_")
            || value.len() <= "appr_".len()
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(JanusError::InvalidIdentifier {
                kind: "approval_id",
            });
        }
        Ok(Self(value))
    }

    /// Opaque approval id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApprovalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApprovalId").field(&"<redacted>").finish()
    }
}

/// Exact use scope approved by an approval grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalGrantScope {
    /// Secret ref this grant is scoped to.
    pub secret_ref: SecretRef,
    /// Profile id this grant is scoped to.
    pub profile_id: ProfileId,
    /// Executor this grant is scoped to.
    pub executor: ExecutorRef,
    /// Destination this grant is scoped to.
    pub destination: Destination,
    /// Secret class this grant is scoped to.
    pub class: SecretClass,
    /// Egress mode this grant is scoped to.
    pub egress: EgressMode,
    /// Purpose this grant is scoped to.
    pub purpose: Purpose,
}

impl ApprovalGrantScope {
    /// Build the exact approval scope for a reviewed request/profile pair.
    pub fn for_request(req: &UseRequest, profile: &UseProfile, class: SecretClass) -> Self {
        Self {
            secret_ref: req.secret_ref.clone(),
            profile_id: req.profile_id.clone(),
            executor: profile.executor.clone(),
            destination: req.destination.clone(),
            class,
            egress: profile.egress,
            purpose: req.purpose.clone(),
        }
    }

    fn for_permit(permit: &UsePermit, class: SecretClass) -> Self {
        Self {
            secret_ref: permit.secret_ref.clone(),
            profile_id: permit.profile_id.clone(),
            executor: permit.executor.clone(),
            destination: permit.destination.clone(),
            class,
            egress: permit.egress,
            purpose: permit.purpose.clone(),
        }
    }
}

/// Exact, short-lived approval for a high-risk use path.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    id: ApprovalId,
    scope: ApprovalGrantScope,
    expires_at: SystemTime,
    reason: SafeLabel,
}

/// Durable, value-free snapshot of an approval grant bound into a permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalGrantSnapshot {
    /// Opaque approval id.
    pub approval_id: String,
    /// Secret ref this grant is scoped to.
    pub secret_ref: String,
    /// Profile id this grant is scoped to.
    pub profile_id: String,
    /// Executor this grant is scoped to.
    pub executor: String,
    /// Destination this grant is scoped to.
    pub destination: String,
    /// Secret class this grant is scoped to.
    pub class: String,
    /// Egress mode this grant is scoped to.
    pub egress: String,
    /// Purpose this grant is scoped to.
    pub purpose: String,
    /// Grant expiry seconds since Unix epoch.
    pub expires_at_unix_secs: u64,
    /// Grant expiry nanoseconds within the epoch second.
    pub expires_at_subsec_nanos: u32,
    /// Value-free approval reason.
    pub reason: String,
}

impl ApprovalGrant {
    /// Construct an exact approval grant.
    pub fn new(scope: ApprovalGrantScope, expires_at: SystemTime, reason: SafeLabel) -> Self {
        let id = ApprovalId::derive(&scope, expires_at, &reason);
        Self {
            id,
            scope,
            expires_at,
            reason,
        }
    }

    /// Construct a grant for a reviewed request/profile pair.
    pub fn for_request(
        req: &UseRequest,
        profile: &UseProfile,
        class: SecretClass,
        expires_at: SystemTime,
        reason: SafeLabel,
    ) -> Self {
        Self::new(
            ApprovalGrantScope::for_request(req, profile, class),
            expires_at,
            reason,
        )
    }

    /// Opaque approval id.
    pub fn id(&self) -> &ApprovalId {
        &self.id
    }

    /// Exact grant scope.
    pub fn scope(&self) -> &ApprovalGrantScope {
        &self.scope
    }

    /// Value-free approval reason.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }

    /// Whether the grant is expired at the supplied instant.
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    fn validate_request(
        &self,
        req: &UseRequest,
        profile: &UseProfile,
        class: SecretClass,
        now: SystemTime,
    ) -> PolicyDecision {
        if self.is_expired_at(now) {
            return approval_denied("approval_expired", "approval grant is expired");
        }
        if self.scope != ApprovalGrantScope::for_request(req, profile, class) {
            return approval_denied(
                "approval_scope_mismatch",
                "approval grant does not match the exact requested use",
            );
        }
        PolicyDecision::Allow
    }

    fn validate_permit(
        &self,
        permit: &UsePermit,
        class: SecretClass,
        now: SystemTime,
    ) -> PolicyDecision {
        if self.is_expired_at(now) {
            return approval_denied("approval_expired", "approval grant is expired");
        }
        if self.scope != ApprovalGrantScope::for_permit(permit, class) {
            return approval_denied(
                "approval_scope_mismatch",
                "approval grant does not match the exact permit use",
            );
        }
        PolicyDecision::Allow
    }

    /// Export a durable value-free approval snapshot.
    pub fn snapshot(&self) -> ApprovalGrantSnapshot {
        let expires_at = self
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        ApprovalGrantSnapshot {
            approval_id: self.id.as_str().to_string(),
            secret_ref: self.scope.secret_ref.as_str().to_string(),
            profile_id: self.scope.profile_id.as_str().to_string(),
            executor: self.scope.executor.as_str().to_string(),
            destination: self.scope.destination.as_str().to_string(),
            class: self.scope.class.as_str().to_string(),
            egress: self.scope.egress.as_str().to_string(),
            purpose: self.scope.purpose.as_str().to_string(),
            expires_at_unix_secs: expires_at.as_secs(),
            expires_at_subsec_nanos: expires_at.subsec_nanos(),
            reason: self.reason.as_str().to_string(),
        }
    }

    /// Rehydrate a value-free approval snapshot.
    pub fn from_snapshot(snapshot: ApprovalGrantSnapshot) -> JanusResult<Self> {
        if snapshot.expires_at_subsec_nanos >= 1_000_000_000 {
            return Err(JanusError::InvalidIdentifier {
                kind: "approval_expiry",
            });
        }
        Ok(Self {
            id: ApprovalId::from_opaque(snapshot.approval_id)?,
            scope: ApprovalGrantScope {
                secret_ref: SecretRef::new(snapshot.secret_ref)?,
                profile_id: ProfileId::new(snapshot.profile_id)?,
                executor: ExecutorRef::new(snapshot.executor)?,
                destination: Destination::new(snapshot.destination)?,
                class: SecretClass::parse(&snapshot.class)?,
                egress: EgressMode::parse(&snapshot.egress)?,
                purpose: Purpose::new(snapshot.purpose)?,
            },
            expires_at: UNIX_EPOCH
                + Duration::new(
                    snapshot.expires_at_unix_secs,
                    snapshot.expires_at_subsec_nanos,
                ),
            reason: SafeLabel::new(snapshot.reason)?,
        })
    }
}

impl fmt::Debug for ApprovalGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalGrant")
            .field("id", &"<redacted>")
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field("reason", &self.reason)
            .finish()
    }
}

fn approval_denied(reason_code: &'static str, detail: &'static str) -> PolicyDecision {
    PolicyDecision::Deny {
        reason_code,
        detail: detail.to_string(),
    }
}

/// Secret-class policy requirements for permit-bearing paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassPermitPolicy {
    class: SecretClass,
    max_ttl: Option<Duration>,
    requires_strong_egress: bool,
    requires_approval: bool,
    allow_severity: Severity,
    deny_severity: Severity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClassPermitDecision {
    decision: PolicyDecision,
    approval_used: bool,
}

impl ClassPermitPolicy {
    /// Build permit requirements for one secret classification.
    pub fn for_class(class: SecretClass) -> Self {
        match class {
            SecretClass::Low | SecretClass::Normal => Self {
                class,
                max_ttl: None,
                requires_strong_egress: false,
                requires_approval: false,
                allow_severity: Severity::Notice,
                deny_severity: Severity::Warning,
            },
            SecretClass::HighValue => Self {
                class,
                max_ttl: Some(Duration::from_secs(300)),
                requires_strong_egress: true,
                requires_approval: false,
                allow_severity: Severity::High,
                deny_severity: Severity::High,
            },
            SecretClass::BreakGlass => Self {
                class,
                max_ttl: Some(Duration::from_secs(60)),
                requires_strong_egress: true,
                requires_approval: true,
                allow_severity: Severity::High,
                deny_severity: Severity::High,
            },
        }
    }

    /// Secret classification this policy was derived from.
    pub fn class(self) -> SecretClass {
        self.class
    }

    /// Maximum permit lifetime for this class, if capped.
    pub fn max_ttl(self) -> Option<Duration> {
        self.max_ttl
    }

    /// Whether this class requires connector/sandbox/proxy-grade egress.
    pub fn requires_strong_egress(self) -> bool {
        self.requires_strong_egress
    }

    /// Whether this class requires an explicit approval grant.
    pub fn requires_approval(self) -> bool {
        self.requires_approval
    }

    /// Audit severity for approved use of this class.
    pub fn allow_severity(self) -> Severity {
        self.allow_severity
    }

    /// Audit severity for denied use of this class.
    pub fn deny_severity(self) -> Severity {
        self.deny_severity
    }

    fn decide_profile_with_approval(
        self,
        req: &UseRequest,
        profile: &UseProfile,
        approval: Option<&ApprovalGrant>,
        now: SystemTime,
    ) -> ClassPermitDecision {
        let approval_valid = match approval {
            Some(grant) => match grant.validate_request(req, profile, self.class, now) {
                PolicyDecision::Allow => true,
                decision @ PolicyDecision::Deny { .. } => {
                    return ClassPermitDecision {
                        decision,
                        approval_used: false,
                    }
                }
            },
            None => false,
        };
        self.decide_bound_use(profile.egress, profile.ttl, approval_valid)
    }

    /// Decide whether a current permit remains acceptable for this class.
    pub fn decide_permit(self, permit: &UsePermit, now: SystemTime) -> PolicyDecision {
        let approval_valid = match permit.approval() {
            Some(grant) => match grant.validate_permit(permit, self.class, now) {
                PolicyDecision::Allow => true,
                decision @ PolicyDecision::Deny { .. } => return decision,
            },
            None => false,
        };
        self.decide_bound_use(
            permit.egress(),
            permit.remaining_ttl_at(now),
            approval_valid,
        )
        .decision
    }

    fn decide_bound_use(
        self,
        egress: EgressMode,
        ttl: Duration,
        approval_valid: bool,
    ) -> ClassPermitDecision {
        if self.requires_approval && !approval_valid {
            return ClassPermitDecision {
                decision: PolicyDecision::Deny {
                    reason_code: "approval_missing",
                    detail: "break-glass use requires an explicit approval grant".to_string(),
                },
                approval_used: false,
            };
        }
        if let Some(max_ttl) = self.max_ttl {
            if ttl > max_ttl {
                return ClassPermitDecision {
                    decision: PolicyDecision::Deny {
                        reason_code: "denied_ttl_exceeds_class_limit",
                        detail: "profile permit TTL exceeds secret class limit".to_string(),
                    },
                    approval_used: false,
                };
            }
        }
        let weak_egress_override = self.requires_strong_egress && !egress.is_strong();
        if weak_egress_override && !approval_valid {
            return ClassPermitDecision {
                decision: PolicyDecision::Deny {
                    reason_code: "denied_egress_mode_insufficient",
                    detail: "secret class requires stronger egress enforcement".to_string(),
                },
                approval_used: false,
            };
        }
        ClassPermitDecision {
            decision: PolicyDecision::Allow,
            approval_used: approval_valid && (self.requires_approval || weak_egress_override),
        }
    }
}

/// Policy decision before audit write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request can proceed to audit and permit issuance.
    Allow,
    /// Request is denied.
    Deny {
        /// Stable reason code.
        reason_code: &'static str,
        /// Human-readable value-free detail.
        detail: String,
    },
}

/// Short-lived, principal/profile/destination/executor-bound approval.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PermitId(String);

impl PermitId {
    fn derive(
        profile: &UseProfile,
        principal: &PrincipalChain,
        purpose: &Purpose,
        now: SystemTime,
    ) -> Self {
        let timestamp = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(profile.id.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(profile.secret_ref.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(purpose.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(principal.binding_key().as_bytes());
        hasher.update(b"\0");
        hasher.update(timestamp);
        let digest = hasher.finalize();
        Self(format!("use_{}", hex::encode(&digest[..12])))
    }

    /// Rehydrate a previously issued opaque permit id.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        if value.trim().is_empty()
            || value.trim().len() != value.len()
            || !value.starts_with("use_")
            || value.len() <= "use_".len()
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(JanusError::InvalidIdentifier { kind: "permit_id" });
        }
        Ok(Self(value))
    }

    /// Opaque permit id text. This is power-bearing and should be handled as a
    /// token, not logged casually.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PermitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PermitId").field(&"<redacted>").finish()
    }
}

/// Short-lived, principal/profile/destination/executor-bound approval.
#[derive(Clone, PartialEq, Eq)]
pub struct UsePermit {
    id: PermitId,
    secret_ref: SecretRef,
    profile_id: ProfileId,
    destination: Destination,
    executor: ExecutorRef,
    egress: EgressMode,
    purpose: Purpose,
    approval: Option<ApprovalGrant>,
    principal_binding: String,
    expires_at: SystemTime,
}

/// Durable, value-free snapshot of a permit.
///
/// This is intentionally not model-facing: the permit id and principal binding
/// remain power-bearing. It exists so local runtimes can persist an issued
/// permit and later rehydrate it for the normal broker validation path.
#[derive(Clone, PartialEq, Eq)]
pub struct UsePermitSnapshot {
    /// Opaque permit id.
    pub permit_id: String,
    /// Secret ref this permit is bound to.
    pub secret_ref: String,
    /// Profile this permit is bound to.
    pub profile_id: String,
    /// Destination this permit is bound to.
    pub destination: String,
    /// Executor this permit is bound to.
    pub executor: String,
    /// Egress posture this permit was issued under.
    pub egress: String,
    /// Purpose this permit was issued for.
    pub purpose: String,
    /// Approval grant this permit was issued under, if any.
    pub approval: Option<ApprovalGrantSnapshot>,
    /// Principal binding key this permit is bound to.
    pub principal_binding: String,
    /// Permit expiry seconds since the Unix epoch.
    pub expires_at_unix_secs: u64,
    /// Permit expiry nanoseconds within the epoch second.
    pub expires_at_subsec_nanos: u32,
}

impl UsePermit {
    fn new(
        profile: &UseProfile,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
        approval: Option<&ApprovalGrant>,
    ) -> Self {
        Self {
            id: PermitId::derive(profile, principal, &req.purpose, now),
            secret_ref: profile.secret_ref.clone(),
            profile_id: profile.id.clone(),
            destination: profile.destination.clone(),
            executor: profile.executor.clone(),
            egress: profile.egress,
            purpose: req.purpose.clone(),
            approval: approval.cloned(),
            principal_binding: principal.binding_key(),
            expires_at: now + profile.ttl,
        }
    }

    /// Opaque permit id.
    pub fn id(&self) -> &PermitId {
        &self.id
    }

    /// Secret ref this permit is bound to.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Profile this permit is bound to.
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Destination this permit is bound to.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Executor this permit is bound to.
    pub fn executor(&self) -> &ExecutorRef {
        &self.executor
    }

    /// Egress posture this permit was issued under.
    pub fn egress(&self) -> EgressMode {
        self.egress
    }

    /// Purpose this permit was issued for.
    pub fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    /// Approval grant bound into this permit, if any.
    pub fn approval(&self) -> Option<&ApprovalGrant> {
        self.approval.as_ref()
    }

    /// Remaining permit lifetime at a supplied instant.
    pub fn remaining_ttl_at(&self, now: SystemTime) -> Duration {
        self.expires_at.duration_since(now).unwrap_or_default()
    }

    /// Whether the permit is expired at the supplied instant.
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Export a durable snapshot for local permit registries.
    pub fn snapshot(&self) -> UsePermitSnapshot {
        let expires_at = self
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        UsePermitSnapshot {
            permit_id: self.id.as_str().to_string(),
            secret_ref: self.secret_ref.as_str().to_string(),
            profile_id: self.profile_id.as_str().to_string(),
            destination: self.destination.as_str().to_string(),
            executor: self.executor.as_str().to_string(),
            egress: self.egress.as_str().to_string(),
            purpose: self.purpose.as_str().to_string(),
            approval: self.approval.as_ref().map(ApprovalGrant::snapshot),
            principal_binding: self.principal_binding.clone(),
            expires_at_unix_secs: expires_at.as_secs(),
            expires_at_subsec_nanos: expires_at.subsec_nanos(),
        }
    }

    /// Rehydrate a durable snapshot for broker-side validation.
    pub fn from_snapshot(snapshot: UsePermitSnapshot) -> JanusResult<Self> {
        if snapshot.principal_binding.trim().is_empty()
            || snapshot.principal_binding.trim().len() != snapshot.principal_binding.len()
        {
            return Err(JanusError::InvalidIdentifier {
                kind: "principal_binding",
            });
        }
        if snapshot.expires_at_subsec_nanos >= 1_000_000_000 {
            return Err(JanusError::InvalidIdentifier {
                kind: "permit_expiry",
            });
        }
        Ok(Self {
            id: PermitId::from_opaque(snapshot.permit_id)?,
            secret_ref: SecretRef::new(snapshot.secret_ref)?,
            profile_id: ProfileId::new(snapshot.profile_id)?,
            destination: Destination::new(snapshot.destination)?,
            executor: ExecutorRef::new(snapshot.executor)?,
            egress: EgressMode::parse(&snapshot.egress)?,
            purpose: Purpose::new(snapshot.purpose)?,
            approval: snapshot
                .approval
                .map(ApprovalGrant::from_snapshot)
                .transpose()?,
            principal_binding: snapshot.principal_binding,
            expires_at: UNIX_EPOCH
                + Duration::new(
                    snapshot.expires_at_unix_secs,
                    snapshot.expires_at_subsec_nanos,
                ),
        })
    }

    /// Check whether this permit can be consumed by a principal/executor/destination.
    pub fn matches(
        &self,
        principal: &PrincipalChain,
        executor: &ExecutorRef,
        destination: &Destination,
        now: SystemTime,
    ) -> JanusResult<()> {
        if self.is_expired_at(now) {
            return Err(JanusError::permit_invalid(
                "denied_expired_permit",
                "permit is expired",
            ));
        }
        if self.principal_binding != principal.binding_key() {
            return Err(JanusError::permit_invalid(
                "denied_wrong_principal",
                "permit principal binding does not match caller",
            ));
        }
        if &self.executor != executor {
            return Err(JanusError::permit_invalid(
                "denied_wrong_executor",
                "permit executor binding does not match caller",
            ));
        }
        if &self.destination != destination {
            return Err(JanusError::permit_invalid(
                "denied_unapproved_destination",
                "permit destination binding does not match caller",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for UsePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsePermit")
            .field("id", &"<redacted>")
            .field("secret_ref", &self.secret_ref)
            .field("profile_id", &self.profile_id)
            .field("destination", &self.destination)
            .field("executor", &self.executor)
            .field("egress", &self.egress)
            .field("purpose", &self.purpose)
            .field("approval", &self.approval)
            .field("principal_binding", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Debug for UsePermitSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsePermitSnapshot")
            .field("permit_id", &"<redacted>")
            .field("secret_ref", &self.secret_ref)
            .field("profile_id", &self.profile_id)
            .field("destination", &self.destination)
            .field("executor", &self.executor)
            .field("egress", &self.egress)
            .field("purpose", &self.purpose)
            .field("approval", &self.approval)
            .field("principal_binding", &"<redacted>")
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .field("expires_at_subsec_nanos", &self.expires_at_subsec_nanos)
            .finish()
    }
}

/// Default-deny profile policy.
#[derive(Clone, Debug, Default)]
pub struct ProfilePolicy {
    profiles: Vec<UseProfile>,
}

impl ProfilePolicy {
    /// Construct a policy from reviewed profiles.
    pub fn new(profiles: Vec<UseProfile>) -> Self {
        Self { profiles }
    }

    /// Decide whether a request matches an enabled profile.
    pub fn decide(&self, req: &UseRequest, principal: &PrincipalChain) -> PolicyDecision {
        let profile = self
            .profiles
            .iter()
            .find(|profile| profile.id == req.profile_id && profile.secret_ref == req.secret_ref);
        let Some(profile) = profile else {
            return PolicyDecision::Deny {
                reason_code: "denied_no_matching_profile",
                detail: "no enabled profile matched secret and profile id".to_string(),
            };
        };
        if !profile.enabled {
            return PolicyDecision::Deny {
                reason_code: "denied_profile_disabled",
                detail: "profile is disabled".to_string(),
            };
        }
        if profile.executor.as_str() != principal.executor.id.as_str() {
            return PolicyDecision::Deny {
                reason_code: "denied_wrong_executor",
                detail: "profile executor does not match principal chain".to_string(),
            };
        }
        if profile.destination != req.destination {
            return PolicyDecision::Deny {
                reason_code: "denied_unapproved_destination",
                detail: "requested destination is not approved by profile".to_string(),
            };
        }
        PolicyDecision::Allow
    }

    /// Decide whether a request matches policy plus secret-class requirements.
    pub fn decide_for_class(
        &self,
        req: &UseRequest,
        principal: &PrincipalChain,
        class: SecretClass,
    ) -> PolicyDecision {
        self.decide_for_class_with_approval(req, principal, class, None, UNIX_EPOCH)
            .decision
    }

    fn decide_for_class_with_approval(
        &self,
        req: &UseRequest,
        principal: &PrincipalChain,
        class: SecretClass,
        approval: Option<&ApprovalGrant>,
        now: SystemTime,
    ) -> ClassPermitDecision {
        let decision = self.decide(req, principal);
        if !matches!(decision, PolicyDecision::Allow) {
            return ClassPermitDecision {
                decision,
                approval_used: false,
            };
        }
        let profile = self
            .matching_profile(req)
            .expect("allow decision requires a matching profile");
        ClassPermitPolicy::for_class(class)
            .decide_profile_with_approval(req, profile, approval, now)
    }

    fn matching_profile(&self, req: &UseRequest) -> Option<&UseProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.id == req.profile_id && profile.secret_ref == req.secret_ref)
    }

    /// Return a reviewed profile by secret ref and profile id.
    ///
    /// This is used by model-facing surfaces that may name only a profile and
    /// purpose; destination, executor, TTL, and egress stay owned by the
    /// reviewed profile rather than caller input.
    pub fn profile_for(
        &self,
        secret_ref: &SecretRef,
        profile_id: &ProfileId,
    ) -> Option<&UseProfile> {
        self.profiles
            .iter()
            .find(|profile| &profile.id == profile_id && &profile.secret_ref == secret_ref)
    }
}

/// Issues permits only after policy allows and audit accepts the evidence.
pub struct PermitIssuer<P, A> {
    policy: P,
    audit: A,
}

struct IssueDecision<'a> {
    req: &'a UseRequest,
    principal: &'a PrincipalChain,
    now: SystemTime,
    decision: PolicyDecision,
    allow_severity: Severity,
    deny_severity: Severity,
    approval: Option<&'a ApprovalGrant>,
}

impl<P, A> PermitIssuer<P, A>
where
    P: AsRef<ProfilePolicy>,
    A: AuditSink,
{
    /// Construct a permit issuer.
    pub fn new(policy: P, audit: A) -> Self {
        Self { policy, audit }
    }

    /// Issue a permit for one approved use.
    pub fn issue(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> JanusResult<UsePermit> {
        self.issue_with_decision(IssueDecision {
            req,
            principal,
            now,
            decision: self.policy.as_ref().decide(req, principal),
            allow_severity: Severity::Notice,
            deny_severity: Severity::Warning,
            approval: None,
        })
    }

    /// Issue a permit with additional secret-class requirements.
    pub fn issue_for_class(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
        class: SecretClass,
    ) -> JanusResult<UsePermit> {
        self.issue_for_class_with_approval(req, principal, now, class, None)
    }

    /// Issue a permit with secret-class requirements and an optional exact approval grant.
    pub fn issue_for_class_with_approval(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
        class: SecretClass,
        approval: Option<&ApprovalGrant>,
    ) -> JanusResult<UsePermit> {
        let class_policy = ClassPermitPolicy::for_class(class);
        let class_decision = self
            .policy
            .as_ref()
            .decide_for_class_with_approval(req, principal, class, approval, now);
        let approval_to_bind = approval.filter(|_| class_decision.approval_used);
        self.issue_with_decision(IssueDecision {
            req,
            principal,
            now,
            decision: class_decision.decision,
            allow_severity: class_policy.allow_severity(),
            deny_severity: class_policy.deny_severity(),
            approval: approval_to_bind,
        })
    }

    fn issue_with_decision(&mut self, issue: IssueDecision<'_>) -> JanusResult<UsePermit> {
        let IssueDecision {
            req,
            principal,
            now,
            decision,
            allow_severity,
            deny_severity,
            approval,
        } = issue;
        match decision {
            PolicyDecision::Allow => {
                if let Some(grant) = approval {
                    self.audit.record(
                        AuditEvent::new(
                            AuditAction::PermitApprove,
                            AuditOutcome::Allowed,
                            "approved",
                            Severity::High,
                            Some(req.secret_ref.clone()),
                            principal,
                        )
                        .with_evidence(grant.reason().clone()),
                    )?;
                }
                self.audit.record(AuditEvent::new(
                    AuditAction::PermitRequest,
                    AuditOutcome::Allowed,
                    "ok",
                    allow_severity,
                    Some(req.secret_ref.clone()),
                    principal,
                ))?;
                self.audit.record(AuditEvent::new(
                    AuditAction::PermitIssue,
                    AuditOutcome::Allowed,
                    "ok",
                    allow_severity,
                    Some(req.secret_ref.clone()),
                    principal,
                ))?;
                let profile = self
                    .policy
                    .as_ref()
                    .matching_profile(req)
                    .expect("allow decision requires a matching profile");
                Ok(UsePermit::new(profile, req, principal, now, approval))
            }
            PolicyDecision::Deny {
                reason_code,
                detail,
            } => {
                self.audit.record(AuditEvent::new(
                    AuditAction::PermitDeny,
                    AuditOutcome::Denied,
                    reason_code,
                    deny_severity,
                    Some(req.secret_ref.clone()),
                    principal,
                ))?;
                Err(JanusError::policy_denied(reason_code, detail))
            }
        }
    }

    /// Consume and return the audit sink.
    pub fn into_audit(self) -> A {
        self.audit
    }
}

impl AsRef<ProfilePolicy> for ProfilePolicy {
    fn as_ref(&self) -> &ProfilePolicy {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditWrite, Principal, PrincipalId, PrincipalKind, SafeLabel, ScopeRef};

    fn principal(executor: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            ScopeRef::new("proj/dev").unwrap(),
        )
    }

    fn profile(enabled: bool) -> UseProfile {
        UseProfile {
            id: ProfileId::new("profile.deploy").unwrap(),
            secret_ref: SecretRef::new("sec_api").unwrap(),
            executor: ExecutorRef::new("runner-a").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled,
        }
    }

    fn request(destination: &str) -> UseRequest {
        UseRequest {
            secret_ref: SecretRef::new("sec_api").unwrap(),
            profile_id: ProfileId::new("profile.deploy").unwrap(),
            destination: Destination::new(destination).unwrap(),
            purpose: Purpose::new("deploy release").unwrap(),
        }
    }

    fn approval_for(
        profile: &UseProfile,
        req: &UseRequest,
        class: SecretClass,
        expires_at: SystemTime,
    ) -> ApprovalGrant {
        ApprovalGrant::for_request(
            req,
            profile,
            class,
            expires_at,
            SafeLabel::new("approved maintenance window").unwrap(),
        )
    }

    #[test]
    fn default_deny_without_matching_profile() {
        let policy = ProfilePolicy::default();
        let decision = policy.decide(&request("deploy-api"), &principal("runner-a"));
        assert_eq!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_no_matching_profile",
                detail: "no enabled profile matched secret and profile id".to_string()
            }
        );
    }

    #[test]
    fn disabled_profile_denies() {
        let policy = ProfilePolicy::new(vec![profile(false)]);
        let decision = policy.decide(&request("deploy-api"), &principal("runner-a"));
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_profile_disabled",
                ..
            }
        ));
    }

    #[test]
    fn wrong_destination_denies() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let decision = policy.decide(&request("other-api"), &principal("runner-a"));
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_unapproved_destination",
                ..
            }
        ));
    }

    #[test]
    fn audit_failure_blocks_permit_issue() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::failing());
        let err = issuer
            .issue(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
            )
            .unwrap_err();
        assert!(matches!(err, JanusError::AuditUnavailable { .. }));
    }

    #[test]
    fn permit_is_bound_to_principal_executor_and_destination() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        let permit = issuer
            .issue(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        assert!(permit
            .matches(
                &principal("runner-a"),
                &ExecutorRef::new("runner-a").unwrap(),
                &Destination::new("deploy-api").unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .is_ok());
        assert!(permit
            .matches(
                &principal("runner-b"),
                &ExecutorRef::new("runner-b").unwrap(),
                &Destination::new("deploy-api").unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .is_err());
    }

    #[test]
    fn permit_debug_does_not_expose_power_bearing_id_or_principal_binding() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        let permit = issuer
            .issue(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        let rendered = format!("{permit:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("permit:profile.deploy"));
        assert!(!rendered.contains("executor:runner-a|scope:proj/dev"));
    }

    #[test]
    fn permit_snapshot_round_trips_without_debug_leaking_bindings() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        let permit = issuer
            .issue(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        let snapshot = permit.snapshot();
        let rendered = format!("{snapshot:?}");

        let rehydrated = UsePermit::from_snapshot(snapshot).unwrap();

        assert_eq!(rehydrated, permit);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(permit.id().as_str()));
        assert!(!rendered.contains("executor:runner-a|scope:proj/dev"));
    }

    #[test]
    fn class_policy_has_stable_requirements() {
        let low = ClassPermitPolicy::for_class(SecretClass::Low);
        assert_eq!(low.class(), SecretClass::Low);
        assert_eq!(low.max_ttl(), None);
        assert!(!low.requires_strong_egress());
        assert!(!low.requires_approval());
        assert_eq!(low.allow_severity(), Severity::Notice);
        assert_eq!(low.deny_severity(), Severity::Warning);

        let high = ClassPermitPolicy::for_class(SecretClass::HighValue);
        assert_eq!(high.max_ttl(), Some(Duration::from_secs(300)));
        assert!(high.requires_strong_egress());
        assert!(!high.requires_approval());
        assert_eq!(high.allow_severity(), Severity::High);
        assert_eq!(high.deny_severity(), Severity::High);

        let break_glass = ClassPermitPolicy::for_class(SecretClass::BreakGlass);
        assert_eq!(break_glass.max_ttl(), Some(Duration::from_secs(60)));
        assert!(break_glass.requires_strong_egress());
        assert!(break_glass.requires_approval());
        assert_eq!(break_glass.allow_severity(), Severity::High);
        assert_eq!(break_glass.deny_severity(), Severity::High);
    }

    #[test]
    fn l2_trust_is_not_the_same_as_high_value_class() {
        let mut weak = profile(true);
        weak.egress = EgressMode::DeclaredOnly;
        let policy = ProfilePolicy::new(vec![weak]);
        let decision = policy.decide(&request("deploy-api"), &principal("runner-a"));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn high_value_class_rejects_weak_egress_and_long_ttl() {
        let mut weak = profile(true);
        weak.egress = EgressMode::DeclaredOnly;
        let policy = ProfilePolicy::new(vec![weak]);
        let decision = policy.decide_for_class(
            &request("deploy-api"),
            &principal("runner-a"),
            SecretClass::HighValue,
        );
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_egress_mode_insufficient",
                ..
            }
        ));

        let mut long_ttl = profile(true);
        long_ttl.ttl = Duration::from_secs(301);
        let policy = ProfilePolicy::new(vec![long_ttl]);
        let decision = policy.decide_for_class(
            &request("deploy-api"),
            &principal("runner-a"),
            SecretClass::HighValue,
        );
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_ttl_exceeds_class_limit",
                ..
            }
        ));
    }

    #[test]
    fn break_glass_class_requires_explicit_approval() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let decision = policy.decide_for_class(
            &request("deploy-api"),
            &principal("runner-a"),
            SecretClass::BreakGlass,
        );
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "approval_missing",
                ..
            }
        ));
    }

    #[test]
    fn approval_grants_are_exact_short_lived_and_value_free() {
        let profile = profile(true);
        let req = request("deploy-api");
        let grant = approval_for(
            &profile,
            &req,
            SecretClass::BreakGlass,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );

        let snapshot = grant.snapshot();
        let rehydrated = ApprovalGrant::from_snapshot(snapshot).unwrap();
        assert_eq!(rehydrated, grant);
        assert!(grant.id().as_str().starts_with("appr_"));
        assert_eq!(grant.reason().as_str(), "approved maintenance window");
        assert!(!format!("{grant:?}").contains(grant.id().as_str()));

        let mut wrong_purpose = req.clone();
        wrong_purpose.purpose = Purpose::new("different purpose").unwrap();
        let mismatch = grant.validate_request(
            &wrong_purpose,
            &profile,
            SecretClass::BreakGlass,
            SystemTime::UNIX_EPOCH,
        );
        assert!(matches!(
            mismatch,
            PolicyDecision::Deny {
                reason_code: "approval_scope_mismatch",
                ..
            }
        ));

        let expired = grant.validate_request(
            &req,
            &profile,
            SecretClass::BreakGlass,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        assert!(matches!(
            expired,
            PolicyDecision::Deny {
                reason_code: "approval_expired",
                ..
            }
        ));
    }

    #[test]
    fn break_glass_class_accepts_exact_approval_grant() {
        let profile = profile(true);
        let req = request("deploy-api");
        let grant = approval_for(
            &profile,
            &req,
            SecretClass::BreakGlass,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        let policy = ProfilePolicy::new(vec![profile]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());

        let permit = issuer
            .issue_for_class_with_approval(
                &req,
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
                SecretClass::BreakGlass,
                Some(&grant),
            )
            .unwrap();

        assert!(permit.approval().is_some());
        assert_eq!(permit.purpose().as_str(), "deploy release");
        assert!(matches!(
            ClassPermitPolicy::for_class(SecretClass::BreakGlass)
                .decide_permit(&permit, SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            PolicyDecision::Allow
        ));
        assert!(matches!(
            ClassPermitPolicy::for_class(SecretClass::BreakGlass)
                .decide_permit(&permit, SystemTime::UNIX_EPOCH + Duration::from_secs(31)),
            PolicyDecision::Deny {
                reason_code: "approval_expired",
                ..
            }
        ));

        let audit = issuer.into_audit();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitApprove
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "approved"
                && event.severity == Severity::High
                && event.evidence.as_ref().unwrap().as_str() == "approved maintenance window"
                && !event.value_returned
        }));
    }

    #[test]
    fn high_value_weak_egress_override_requires_exact_approval() {
        let mut weak = profile(true);
        weak.egress = EgressMode::DeclaredOnly;
        let req = request("deploy-api");
        let grant = approval_for(
            &weak,
            &req,
            SecretClass::HighValue,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        let policy = ProfilePolicy::new(vec![weak.clone()]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());

        let permit = issuer
            .issue_for_class_with_approval(
                &req,
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
                SecretClass::HighValue,
                Some(&grant),
            )
            .unwrap();
        assert_eq!(permit.egress(), EgressMode::DeclaredOnly);
        assert!(permit.approval().is_some());

        let policy = ProfilePolicy::new(vec![weak]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        let mut wrong_grant_req = req.clone();
        wrong_grant_req.destination = Destination::new("other-api").unwrap();
        let wrong_grant = approval_for(
            &profile(true),
            &wrong_grant_req,
            SecretClass::HighValue,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        let err = issuer
            .issue_for_class_with_approval(
                &req,
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
                SecretClass::HighValue,
                Some(&wrong_grant),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_scope_mismatch",
                ..
            }
        ));
    }

    #[test]
    fn issuer_uses_class_aware_audit_severity() {
        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        issuer
            .issue_for_class(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
                SecretClass::HighValue,
            )
            .unwrap();
        let audit = issuer.into_audit();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitIssue
                && event.outcome == AuditOutcome::Allowed
                && event.severity == Severity::High
                && !event.value_returned
        }));

        let policy = ProfilePolicy::new(vec![profile(true)]);
        let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
        let err = issuer
            .issue_for_class(
                &request("deploy-api"),
                &principal("runner-a"),
                SystemTime::UNIX_EPOCH,
                SecretClass::BreakGlass,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_missing",
                ..
            }
        ));
        let audit = issuer.into_audit();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitDeny
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "approval_missing"
                && event.severity == Severity::High
                && !event.value_returned
        }));
    }
}

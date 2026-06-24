//! Default-deny policy and use-permit model.

use std::fmt;
use std::time::{Duration, SystemTime};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, Destination, ExecutorRef, JanusError,
    JanusResult, PrincipalChain, SecretRef, Severity,
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
    fn derive(profile: &UseProfile, principal: &PrincipalChain, now: SystemTime) -> Self {
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
        hasher.update(principal.binding_key().as_bytes());
        hasher.update(b"\0");
        hasher.update(timestamp);
        let digest = hasher.finalize();
        Self(format!("use_{}", hex::encode(&digest[..12])))
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
    principal_binding: String,
    expires_at: SystemTime,
}

impl UsePermit {
    fn new(profile: &UseProfile, principal: &PrincipalChain, now: SystemTime) -> Self {
        Self {
            id: PermitId::derive(profile, principal, now),
            secret_ref: profile.secret_ref.clone(),
            profile_id: profile.id.clone(),
            destination: profile.destination.clone(),
            executor: profile.executor.clone(),
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

    /// Whether the permit is expired at the supplied instant.
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now >= self.expires_at
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
            .field("principal_binding", &"<redacted>")
            .field("expires_at", &self.expires_at)
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
        if matches!(
            (profile.trust_level, profile.egress),
            (
                TrustLevel::L2,
                EgressMode::DeclaredOnly | EgressMode::HookGuarded
            )
        ) {
            return PolicyDecision::Deny {
                reason_code: "denied_egress_mode_insufficient",
                detail: "high-value profile requires stronger egress enforcement".to_string(),
            };
        }
        PolicyDecision::Allow
    }

    fn matching_profile(&self, req: &UseRequest) -> Option<&UseProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.id == req.profile_id && profile.secret_ref == req.secret_ref)
    }
}

/// Issues permits only after policy allows and audit accepts the evidence.
pub struct PermitIssuer<P, A> {
    policy: P,
    audit: A,
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
        match self.policy.as_ref().decide(req, principal) {
            PolicyDecision::Allow => {
                self.audit.record(AuditEvent::new(
                    AuditAction::PermitRequest,
                    AuditOutcome::Allowed,
                    "ok",
                    Severity::Notice,
                    Some(req.secret_ref.clone()),
                    principal,
                ))?;
                self.audit.record(AuditEvent::new(
                    AuditAction::PermitIssue,
                    AuditOutcome::Allowed,
                    "ok",
                    Severity::Notice,
                    Some(req.secret_ref.clone()),
                    principal,
                ))?;
                let profile = self
                    .policy
                    .as_ref()
                    .matching_profile(req)
                    .expect("allow decision requires a matching profile");
                Ok(UsePermit::new(profile, principal, now))
            }
            PolicyDecision::Deny {
                reason_code,
                detail,
            } => {
                let _ = self.audit.record(AuditEvent::new(
                    AuditAction::PermitDeny,
                    AuditOutcome::Denied,
                    reason_code,
                    Severity::Warning,
                    Some(req.secret_ref.clone()),
                    principal,
                ));
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
    use crate::{AuditWrite, Principal, PrincipalId, PrincipalKind, ScopeRef};

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
    fn high_value_profiles_reject_weak_egress() {
        let mut weak = profile(true);
        weak.egress = EgressMode::DeclaredOnly;
        let policy = ProfilePolicy::new(vec![weak]);
        let decision = policy.decide(&request("deploy-api"), &principal("runner-a"));
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                reason_code: "denied_egress_mode_insufficient",
                ..
            }
        ));
    }
}

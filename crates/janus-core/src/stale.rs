//! Value-free stale secret lifecycle reporting.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusResult, OwnerRef, PrincipalChain,
    SafeLabel, SecretDescriptor, SecretLifecycle, SecretRef, Severity,
};

const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const DEFAULT_MISSING_EVIDENCE_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Value-free age evidence for stale lifecycle reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretAgeEvidence {
    /// Secret ref this evidence belongs to.
    pub secret_ref: SecretRef,
    /// When the secret first appeared in the reporting scope.
    pub declared_at: Option<SystemTime>,
    /// Last approved-use evidence timestamp.
    pub last_used_at: Option<SystemTime>,
    /// Last rotation evidence timestamp.
    pub last_rotated_at: Option<SystemTime>,
}

impl SecretAgeEvidence {
    /// Construct empty evidence for a secret ref.
    pub fn new(secret_ref: SecretRef) -> Self {
        Self {
            secret_ref,
            declared_at: None,
            last_used_at: None,
            last_rotated_at: None,
        }
    }

    /// Attach first-seen/declaration time.
    pub fn with_declared_at(mut self, declared_at: SystemTime) -> Self {
        self.declared_at = Some(declared_at);
        self
    }

    /// Attach last approved-use evidence.
    pub fn with_last_used_at(mut self, last_used_at: SystemTime) -> Self {
        self.last_used_at = Some(last_used_at);
        self
    }

    /// Attach last rotation evidence.
    pub fn with_last_rotated_at(mut self, last_rotated_at: SystemTime) -> Self {
        self.last_rotated_at = Some(last_rotated_at);
        self
    }

    fn last_activity_at(&self) -> Option<SystemTime> {
        match (self.last_used_at, self.last_rotated_at) {
            (Some(used), Some(rotated)) => Some(if used >= rotated { used } else { rotated }),
            (Some(used), None) => Some(used),
            (None, Some(rotated)) => Some(rotated),
            (None, None) => None,
        }
    }
}

/// Stale lifecycle reporting thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleSecretPolicy {
    /// Age after last activity that requires owner action.
    pub stale_after: Duration,
    /// Age after declaration before missing evidence requires owner action.
    pub missing_evidence_after: Duration,
}

impl StaleSecretPolicy {
    /// Build a stale reporting policy.
    pub fn new(stale_after: Duration, missing_evidence_after: Duration) -> Self {
        Self {
            stale_after,
            missing_evidence_after,
        }
    }
}

impl Default for StaleSecretPolicy {
    fn default() -> Self {
        Self {
            stale_after: DEFAULT_STALE_AFTER,
            missing_evidence_after: DEFAULT_MISSING_EVIDENCE_AFTER,
        }
    }
}

/// Admin-safe stale reporting status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleSecretStatus {
    /// Recent activity evidence exists, or missing evidence is still within grace.
    Fresh,
    /// Last activity exceeds policy threshold.
    Stale,
    /// Activity evidence is missing past policy threshold.
    MissingEvidence,
    /// Metadata is incomplete, so stale reporting cannot assign ownership safely.
    MetadataIncomplete,
    /// Lifecycle is already blocked from normal approved use.
    LifecycleBlocked,
}

impl StaleSecretStatus {
    /// Stable admin/reporting text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::MissingEvidence => "missing_evidence",
            Self::MetadataIncomplete => "metadata_incomplete",
            Self::LifecycleBlocked => "lifecycle_blocked",
        }
    }
}

/// One admin-safe stale report row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleSecretReportRow {
    /// Opaque, non-authorizing secret ref.
    pub secret_ref: SecretRef,
    /// Owner if metadata is complete enough to show it to admins.
    pub owner: Option<OwnerRef>,
    /// Current lifecycle state.
    pub lifecycle: SecretLifecycle,
    /// Report status.
    pub status: StaleSecretStatus,
    /// Stable reason code.
    pub reason_code: &'static str,
    /// Whether an owner/admin action is required.
    pub action_required: bool,
    /// Stable action hint.
    pub action: &'static str,
    /// Last activity age in seconds when available.
    pub last_activity_age_seconds: Option<u64>,
    /// Secret values are never returned by stale reporting.
    pub value_returned: bool,
}

/// Builds value-free stale lifecycle reports and audit evidence.
pub struct StaleSecretReporter {
    policy: StaleSecretPolicy,
}

impl StaleSecretReporter {
    /// Construct a reporter from a policy.
    pub fn new(policy: StaleSecretPolicy) -> Self {
        Self { policy }
    }

    /// Report one row per descriptor and audit each row as value-free evidence.
    pub fn report<A>(
        &self,
        descriptors: &[SecretDescriptor],
        evidence: &BTreeMap<SecretRef, SecretAgeEvidence>,
        now: SystemTime,
        principal: &PrincipalChain,
        audit: &mut A,
    ) -> JanusResult<Vec<StaleSecretReportRow>>
    where
        A: AuditSink,
    {
        let mut rows = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            if descriptor.scope != principal.scope {
                continue;
            }
            let row = self.classify(descriptor, evidence.get(&descriptor.secret_ref), now);
            audit.record(
                AuditEvent::new(
                    AuditAction::SecretStalenessReport,
                    AuditOutcome::Allowed,
                    row.reason_code,
                    severity_for_status(row.status),
                    Some(row.secret_ref.clone()),
                    principal,
                )
                .with_evidence(SafeLabel::new(row.status.as_str())?),
            )?;
            rows.push(row);
        }
        Ok(rows)
    }

    fn classify(
        &self,
        descriptor: &SecretDescriptor,
        evidence: Option<&SecretAgeEvidence>,
        now: SystemTime,
    ) -> StaleSecretReportRow {
        if let Some((reason_code, _)) = descriptor.metadata_use_denial() {
            return report_row(
                descriptor,
                StaleSecretStatus::MetadataIncomplete,
                reason_code,
                true,
                "complete_metadata",
                None,
            );
        }

        if let Some((reason_code, _)) = descriptor.lifecycle_use_denial() {
            return report_row(
                descriptor,
                StaleSecretStatus::LifecycleBlocked,
                reason_code,
                false,
                "none",
                None,
            );
        }

        let Some(evidence) = evidence else {
            return report_row(
                descriptor,
                StaleSecretStatus::MissingEvidence,
                "stale_missing_evidence",
                true,
                "record_activity_evidence",
                None,
            );
        };

        if let Some(last_activity_at) = evidence.last_activity_at() {
            let age = age_seconds(now, last_activity_at);
            let stale_after = self.policy.stale_after.as_secs();
            if age >= stale_after {
                return report_row(
                    descriptor,
                    StaleSecretStatus::Stale,
                    "stale_activity_age_exceeded",
                    true,
                    "review_rotate_or_disable",
                    Some(age),
                );
            }
            return report_row(
                descriptor,
                StaleSecretStatus::Fresh,
                "stale_activity_fresh",
                false,
                "none",
                Some(age),
            );
        }

        let declared_age = evidence
            .declared_at
            .map(|declared_at| age_seconds(now, declared_at));
        if declared_age.is_some_and(|age| age < self.policy.missing_evidence_after.as_secs()) {
            return report_row(
                descriptor,
                StaleSecretStatus::Fresh,
                "stale_evidence_grace",
                false,
                "none",
                None,
            );
        }

        report_row(
            descriptor,
            StaleSecretStatus::MissingEvidence,
            "stale_missing_evidence",
            true,
            "record_activity_evidence",
            None,
        )
    }
}

fn report_row(
    descriptor: &SecretDescriptor,
    status: StaleSecretStatus,
    reason_code: &'static str,
    action_required: bool,
    action: &'static str,
    last_activity_age_seconds: Option<u64>,
) -> StaleSecretReportRow {
    StaleSecretReportRow {
        secret_ref: descriptor.secret_ref.clone(),
        owner: descriptor.owner.clone(),
        lifecycle: descriptor.lifecycle,
        status,
        reason_code,
        action_required,
        action,
        last_activity_age_seconds,
        value_returned: false,
    }
}

fn severity_for_status(status: StaleSecretStatus) -> Severity {
    match status {
        StaleSecretStatus::Fresh | StaleSecretStatus::LifecycleBlocked => Severity::Info,
        StaleSecretStatus::MissingEvidence | StaleSecretStatus::MetadataIncomplete => {
            Severity::Warning
        }
        StaleSecretStatus::Stale => Severity::High,
    }
}

fn age_seconds(now: SystemTime, then: SystemTime) -> u64 {
    now.duration_since(then).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditWrite, Principal, PrincipalId, PrincipalKind, ProfileId, SafeLabel, SecretClass,
        SecretName, SecretRef, TrustLevel,
    };

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("admin-reporter").unwrap(),
            ),
            crate::test_scope("dev"),
        )
    }

    fn descriptor(
        name: &str,
        lifecycle: SecretLifecycle,
        owner: Option<OwnerRef>,
        class: Option<SecretClass>,
    ) -> SecretDescriptor {
        let scope = crate::test_scope("dev");
        let name = SecretName::new(name).unwrap();
        SecretDescriptor {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("Canary token").unwrap(),
            scope,
            owner,
            classification: class,
            lifecycle,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            present: true,
        }
    }

    #[test]
    fn stale_report_classifies_fresh_stale_missing_incomplete_and_blocked() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let policy = StaleSecretPolicy::new(Duration::from_secs(100), Duration::from_secs(50));
        let reporter = StaleSecretReporter::new(policy);
        let descriptors = vec![
            descriptor(
                "FRESH",
                SecretLifecycle::Active,
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
            ),
            descriptor(
                "STALE",
                SecretLifecycle::Rotating,
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
            ),
            descriptor(
                "MISSING",
                SecretLifecycle::Active,
                Some(OwnerRef::new("security").unwrap()),
                Some(SecretClass::HighValue),
            ),
            descriptor(
                "INCOMPLETE",
                SecretLifecycle::Active,
                None,
                Some(SecretClass::Normal),
            ),
            descriptor(
                "DISABLED",
                SecretLifecycle::Disabled,
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
            ),
        ];
        let mut evidence = BTreeMap::new();
        evidence.insert(
            descriptors[0].secret_ref.clone(),
            SecretAgeEvidence::new(descriptors[0].secret_ref.clone())
                .with_last_used_at(now - Duration::from_secs(10)),
        );
        evidence.insert(
            descriptors[1].secret_ref.clone(),
            SecretAgeEvidence::new(descriptors[1].secret_ref.clone())
                .with_last_rotated_at(now - Duration::from_secs(101)),
        );
        evidence.insert(
            descriptors[2].secret_ref.clone(),
            SecretAgeEvidence::new(descriptors[2].secret_ref.clone())
                .with_declared_at(now - Duration::from_secs(51)),
        );
        let mut audit = AuditWrite::accepting();

        let rows = reporter
            .report(&descriptors, &evidence, now, &principal(), &mut audit)
            .unwrap();

        assert_eq!(rows[0].status, StaleSecretStatus::Fresh);
        assert!(!rows[0].action_required);
        assert_eq!(rows[0].last_activity_age_seconds, Some(10));
        assert_eq!(rows[1].status, StaleSecretStatus::Stale);
        assert_eq!(rows[1].reason_code, "stale_activity_age_exceeded");
        assert!(rows[1].action_required);
        assert_eq!(rows[2].status, StaleSecretStatus::MissingEvidence);
        assert_eq!(rows[2].action, "record_activity_evidence");
        assert_eq!(rows[3].status, StaleSecretStatus::MetadataIncomplete);
        assert_eq!(rows[3].reason_code, "denied_missing_owner");
        assert_eq!(rows[4].status, StaleSecretStatus::LifecycleBlocked);
        assert_eq!(rows[4].reason_code, "denied_lifecycle_disabled");
        assert!(rows.iter().all(|row| !row.value_returned));
        assert_eq!(audit.events().len(), descriptors.len());
        assert_eq!(audit.events()[1].action, AuditAction::SecretStalenessReport);
        assert_eq!(audit.events()[1].reason_code, "stale_activity_age_exceeded");
        assert_eq!(audit.events()[1].severity, Severity::High);
        assert!(!audit.events()[1].value_returned);
    }

    #[test]
    fn stale_report_respects_missing_evidence_grace() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let descriptor = descriptor(
            "NEW",
            SecretLifecycle::Active,
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::Normal),
        );
        let mut evidence = BTreeMap::new();
        evidence.insert(
            descriptor.secret_ref.clone(),
            SecretAgeEvidence::new(descriptor.secret_ref.clone())
                .with_declared_at(now - Duration::from_secs(20)),
        );
        let mut audit = AuditWrite::accepting();

        let rows = StaleSecretReporter::new(StaleSecretPolicy::new(
            Duration::from_secs(100),
            Duration::from_secs(50),
        ))
        .report(&[descriptor], &evidence, now, &principal(), &mut audit)
        .unwrap();

        assert_eq!(rows[0].status, StaleSecretStatus::Fresh);
        assert_eq!(rows[0].reason_code, "stale_evidence_grace");
        assert!(!rows[0].action_required);
    }
}

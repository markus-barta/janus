use std::time::{Duration, SystemTime};

use janus_core::{
    AuditAction, AuditWrite, DelegationPolicy, DelegationStatus, Destination, EgressMode,
    ExecutorRef, JanusError, OwnerRef, Principal, PrincipalChain, PrincipalId, PrincipalKind,
    ProfileId, ProfilePolicy, Purpose, SafeLabel, ScopePathV1, SecretClass, SecretDescriptor,
    SecretLifecycle, SecretName, SecretRef, TrustLevel, UseProfile, UseRequest,
};
use janus_local::{DelegationRegistry, FileDelegationRegistry};

struct Fixture {
    descriptor: SecretDescriptor,
    profile: UseProfile,
    request: UseRequest,
    grantor: PrincipalChain,
    delegate: PrincipalChain,
}

fn fixture() -> Fixture {
    let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
        .unwrap()
        .scope_ref();
    let secret_ref = SecretRef::new("sec_conformance").unwrap();
    let profile_id = ProfileId::new("profile.conformance").unwrap();
    let executor = ExecutorRef::new("runner-conformance").unwrap();
    let destination = Destination::new("deploy-api").unwrap();
    let descriptor = SecretDescriptor {
        name: SecretName::new("CONFORMANCE").unwrap(),
        secret_ref: secret_ref.clone(),
        label: SafeLabel::new("Delegation conformance").unwrap(),
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
        ttl: Duration::from_secs(30),
        single_use: true,
        enabled: true,
    };
    let request = UseRequest {
        secret_ref,
        scope: scope.clone(),
        profile_id,
        destination,
        purpose: Purpose::new("conformance use").unwrap(),
    };
    let mut grantor = PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new(executor.as_str()).unwrap(),
        ),
        scope.clone(),
    );
    grantor.human = Some(Principal::new(
        PrincipalKind::Human,
        PrincipalId::new("grantor-conformance").unwrap(),
    ));
    let mut delegate = PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new(executor.as_str()).unwrap(),
        ),
        scope,
    );
    delegate.human = Some(Principal::new(
        PrincipalKind::Human,
        PrincipalId::new("delegate-conformance").unwrap(),
    ));
    Fixture {
        descriptor,
        profile,
        request,
        grantor,
        delegate,
    }
}

#[test]
fn exact_delegation_survives_restart_but_policy_drift_fails_closed() {
    let fixture = fixture();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
    let mut audit = AuditWrite::accepting();
    let grant = DelegationPolicy::issue_use(
        &profiles,
        &fixture.descriptor,
        &fixture.request,
        &fixture.grantor,
        &fixture.delegate,
        None,
        now,
        now + Duration::from_secs(300),
        SafeLabel::new("reviewed temporary coverage").unwrap(),
        &mut audit,
    )
    .unwrap();
    assert!(audit
        .events()
        .iter()
        .any(|event| { event.action == AuditAction::DelegationGrant && !event.value_returned }));

    let temp = tempfile::tempdir().unwrap();
    let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
    registry.store(&grant).unwrap();
    let restarted = FileDelegationRegistry::new(registry.dir());
    let record = restarted.get(grant.id().as_str()).unwrap();
    assert_eq!(
        record.status_at(now + Duration::from_secs(1)).unwrap(),
        DelegationStatus::Active
    );
    DelegationPolicy::validate_use(
        &record.grant,
        record.revocation.as_ref(),
        &profiles,
        &fixture.descriptor,
        &fixture.request,
        &fixture.grantor,
        &fixture.delegate,
        now + Duration::from_secs(1),
        &mut audit,
    )
    .unwrap();

    let mut changed_profile = fixture.profile.clone();
    changed_profile.egress = EgressMode::Sandboxed;
    let error = DelegationPolicy::validate_use(
        &record.grant,
        None,
        &ProfilePolicy::new(vec![changed_profile]),
        &fixture.descriptor,
        &fixture.request,
        &fixture.grantor,
        &fixture.delegate,
        now + Duration::from_secs(2),
        &mut audit,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        JanusError::PolicyDenied {
            reason_code: "delegation_egress_changed",
            ..
        }
    ));
}

#[test]
fn immutable_revocation_survives_restart_and_never_becomes_authority() {
    let fixture = fixture();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let profiles = ProfilePolicy::new(vec![fixture.profile.clone()]);
    let mut audit = AuditWrite::accepting();
    let grant = DelegationPolicy::issue_use(
        &profiles,
        &fixture.descriptor,
        &fixture.request,
        &fixture.grantor,
        &fixture.delegate,
        None,
        now,
        now + Duration::from_secs(300),
        SafeLabel::new("reviewed temporary coverage").unwrap(),
        &mut audit,
    )
    .unwrap();
    let revocation = DelegationPolicy::authorize_revocation(
        &grant,
        &fixture.grantor,
        now + Duration::from_secs(2),
        SafeLabel::new("coverage cancelled").unwrap(),
        &mut audit,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let registry = FileDelegationRegistry::new(temp.path().join("delegations"));
    registry.store(&grant).unwrap();
    registry.revoke(&revocation).unwrap();

    let record = FileDelegationRegistry::new(registry.dir())
        .get(grant.id().as_str())
        .unwrap();
    assert_eq!(
        record.status_at(now + Duration::from_secs(3)).unwrap(),
        DelegationStatus::Revoked
    );
    let error = DelegationPolicy::validate_use(
        &record.grant,
        record.revocation.as_ref(),
        &profiles,
        &fixture.descriptor,
        &fixture.request,
        &fixture.grantor,
        &fixture.delegate,
        now + Duration::from_secs(3),
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
    assert!(audit.events().iter().all(|event| !event.value_returned));
}

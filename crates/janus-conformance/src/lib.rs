//! Reusable JANUS-14 store and broker conformance checks.

use std::time::{Duration, SystemTime};

use janus_core::{
    AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef, JanusError, JanusResult,
    PermitIssuer, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy,
    Purpose, RotationSpec, SecretName, SecretStore, SecretValue, TrustLevel, UseProfile,
    UseRequest,
};

/// Store conformance fixture.
#[derive(Clone, Debug)]
pub struct StoreFixture {
    /// Manifest-declared canary.
    pub canary: SecretName,
    /// Expected canary value.
    pub expected_value: Vec<u8>,
    /// Secret name absent from the manifest.
    pub not_in_manifest: SecretName,
}

/// Run the reusable SecretStore contract battery.
pub async fn run_store_contract<S>(store: &mut S, fixture: &StoreFixture) -> JanusResult<()>
where
    S: SecretStore,
{
    let health = store.health().await?;
    assert!(health.ok, "store health should be ok: {health:?}");

    let listed = store.list().await?;
    let descriptor = listed
        .iter()
        .find(|descriptor| descriptor.name == fixture.canary)
        .expect("canary should be listed from manifest");
    assert!(descriptor.present, "canary should be present");
    assert!(
        descriptor.secret_ref.as_str().starts_with("sec_"),
        "descriptor should expose opaque SecretRef"
    );

    let value = store.get(&fixture.canary).await?;
    assert_eq!(value.expose_bytes(), fixture.expected_value.as_slice());

    let err = match store.get(&fixture.not_in_manifest).await {
        Ok(_) => panic!("non-manifest get should fail"),
        Err(err) => err,
    };
    assert!(matches!(err, JanusError::NotInManifest { .. }));

    store
        .rotate(
            &fixture.canary,
            &RotationSpec::generated(SecretValue::new(b"rotated-canary".to_vec())),
        )
        .await?;
    let rotated = store.get(&fixture.canary).await?;
    assert_eq!(rotated.expose_bytes(), b"rotated-canary");

    Ok(())
}

/// Permit/policy/audit fixture built from a listed descriptor.
pub fn run_permit_contract(
    descriptor_secret_ref: janus_core::SecretRef,
    executor: &str,
    destination: &str,
) -> JanusResult<()> {
    let profile_id = ProfileId::new("profile.canary")?;
    let principal = PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new(executor.to_string())?,
        ),
        janus_core::ScopeRef::new("janus/dev")?,
    );
    let profile = UseProfile {
        id: profile_id.clone(),
        secret_ref: descriptor_secret_ref.clone(),
        executor: ExecutorRef::new(executor.to_string())?,
        destination: Destination::new(destination.to_string())?,
        egress: EgressMode::Connector,
        trust_level: TrustLevel::L2,
        ttl: Duration::from_secs(60),
        single_use: true,
        enabled: true,
    };
    let request = UseRequest {
        secret_ref: descriptor_secret_ref,
        profile_id,
        destination: Destination::new(destination.to_string())?,
        purpose: Purpose::new("conformance canary")?,
    };

    let mut issuer = PermitIssuer::new(ProfilePolicy::new(vec![profile]), AuditWrite::accepting());
    let permit = issuer.issue(&request, &principal, SystemTime::UNIX_EPOCH)?;
    permit.matches(
        &principal,
        &ExecutorRef::new(executor.to_string())?,
        &Destination::new(destination.to_string())?,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    )?;

    let wrong = permit.matches(
        &PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new("other-runner")?),
            janus_core::ScopeRef::new("janus/dev")?,
        ),
        &ExecutorRef::new("other-runner")?,
        &Destination::new(destination.to_string())?,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    );
    assert!(matches!(wrong, Err(JanusError::PermitInvalid { .. })));

    let audit = issuer.into_audit();
    assert!(
        audit
            .events()
            .iter()
            .any(|event| event.outcome == AuditOutcome::Allowed
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
                && !event.value_returned),
        "permit issue should write value-free integrity-audited evidence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        AuditAction, ManifestCatalog, ProjectId, SafeLabel, ScopeRef, SecretBroker, SecretMeta,
        SecretRef, TrustLevel,
    };
    use janus_mock::MockStore;

    fn mock_store() -> (MockStore, StoreFixture) {
        let project = ProjectId::new("janus").unwrap();
        let canary = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &canary);
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref,
            name: canary.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }])
        .unwrap();
        let fixture = StoreFixture {
            canary: canary.clone(),
            expected_value: b"expected-canary".to_vec(),
            not_in_manifest: SecretName::new("OTHER").unwrap(),
        };
        let store = MockStore::new(catalog)
            .with_value(canary, fixture.expected_value.clone())
            .unwrap();
        (store, fixture)
    }

    #[tokio::test]
    async fn mock_store_passes_store_contract() {
        let (mut store, fixture) = mock_store();
        run_store_contract(&mut store, &fixture).await.unwrap();
    }

    #[tokio::test]
    async fn permit_contract_records_value_free_audit() {
        let (store, _) = mock_store();
        let descriptor = store.list().await.unwrap().remove(0);
        run_permit_contract(descriptor.secret_ref, "runner-a", "deploy-api").unwrap();
    }

    #[tokio::test]
    async fn tracer_points_1_to_6_work_through_broker() {
        let (store, fixture) = mock_store();
        let descriptor = store.list().await.unwrap().remove(0);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: descriptor.secret_ref.clone(),
            executor: ExecutorRef::new("runner-a").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            ScopeRef::new("janus/dev").unwrap(),
        );
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );

        let listed = broker.list(&principal).await.unwrap();
        let rendered_list = format!("{listed:?}");
        assert_eq!(listed.len(), 1);
        assert!(listed[0].secret_ref.as_str().starts_with("sec_"));
        assert_eq!(listed[0].label.as_str(), "Canary token");
        assert!(!rendered_list.contains("expected-canary"));

        let value = broker.get(&fixture.canary, &principal).await.unwrap();
        assert_eq!(value.expose_bytes(), b"expected-canary");

        let denied = broker.get(&fixture.not_in_manifest, &principal).await;
        assert!(matches!(denied, Err(JanusError::NotInManifest { .. })));

        let request = UseRequest {
            secret_ref: listed[0].secret_ref.clone(),
            profile_id,
            destination: Destination::new("deploy-api").unwrap(),
            purpose: Purpose::new("deploy canary").unwrap(),
        };
        let permit = broker
            .request_use(&request, &principal, SystemTime::UNIX_EPOCH)
            .unwrap();
        assert!(permit
            .matches(
                &principal,
                &ExecutorRef::new("runner-a").unwrap(),
                &Destination::new("deploy-api").unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .is_ok());
        assert!(permit
            .matches(
                &PrincipalChain::new(
                    Principal::new(
                        PrincipalKind::Executor,
                        PrincipalId::new("runner-b").unwrap(),
                    ),
                    ScopeRef::new("janus/dev").unwrap(),
                ),
                &ExecutorRef::new("runner-b").unwrap(),
                &Destination::new("deploy-api").unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .is_err());

        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)));
        assert!(audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_not_in_manifest"
                && !event.value_returned));
        assert!(audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::PermitIssue
                && event.outcome == AuditOutcome::Allowed
                && !event.value_returned));
    }
}

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
        AuditAction, BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRef, ConsumerRegistry,
        Environment, ManifestCatalog, OwnerRef, ProjectId, ReloadMethod, RotationDecision,
        RotationPlanner, SafeLabel, ScopeRef, SecretBroker, SecretMeta, SecretRef,
        StoreCapabilities, TrustLevel, ValidationProbe,
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

    fn principal(executor: &str, scope: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            ScopeRef::new(scope).unwrap(),
        )
    }

    fn use_profile(
        secret_ref: SecretRef,
        enabled: bool,
        executor: &str,
        destination: &str,
    ) -> UseProfile {
        UseProfile {
            id: ProfileId::new("profile.canary").unwrap(),
            secret_ref,
            executor: ExecutorRef::new(executor).unwrap(),
            destination: Destination::new(destination).unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled,
        }
    }

    fn use_request(secret_ref: SecretRef, destination: &str) -> UseRequest {
        UseRequest {
            secret_ref,
            profile_id: ProfileId::new("profile.canary").unwrap(),
            destination: Destination::new(destination).unwrap(),
            purpose: Purpose::new("deploy canary").unwrap(),
        }
    }

    fn consumer(
        secret_ref: SecretRef,
        consumer_ref: &str,
        reload: ReloadMethod,
        validation: Vec<ValidationProbe>,
        declared: bool,
    ) -> ConsumerDescriptor {
        ConsumerDescriptor {
            consumer_ref: ConsumerRef::new(consumer_ref).unwrap(),
            secret_ref,
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new("infra").unwrap(),
            environment: Environment::new("prod").unwrap(),
            reload,
            validation,
            supports_dual_value: false,
            blast_radius: BlastRadius::new("release-publishing").unwrap(),
            declared,
        }
    }

    fn generated_rotation_capabilities() -> StoreCapabilities {
        StoreCapabilities {
            write: true,
            delete: true,
            generated_rotate: true,
            rotate_native: false,
            versioning: false,
            leasing: false,
            native_audit: false,
            backend_key_custody: false,
        }
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
            .await
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

    #[tokio::test]
    async fn tracer_points_7_to_11_work_through_core_contracts() {
        let (store, fixture) = mock_store();
        let descriptor = store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let profile = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile.clone()]),
            AuditWrite::accepting(),
        );

        let permit = broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();
        let value = broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(value.expose_bytes(), fixture.expected_value.as_slice());

        let stale_ref = SecretRef::new("sec_stale_copied").unwrap();
        let stale_request = broker
            .request_use(
                &use_request(stale_ref, "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();
        assert!(matches!(stale_request, JanusError::NotInManifest { .. }));

        let wrong_principal = principal("runner-b", "janus/dev");
        let wrong_principal_use = match broker
            .use_permit(
                &permit,
                &wrong_principal,
                &ExecutorRef::new("runner-b").unwrap(),
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
        {
            Ok(_) => panic!("wrong principal permit use should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            wrong_principal_use,
            JanusError::PermitInvalid {
                reason_code: "denied_wrong_principal",
                ..
            }
        ));

        let expired_use = match broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(61),
            )
            .await
        {
            Ok(_) => panic!("expired permit use should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            expired_use,
            JanusError::PermitInvalid {
                reason_code: "denied_expired_permit",
                ..
            }
        ));

        let (_store, _policy, audit) = broker.into_parts();
        let rendered_audit = format!("{:?}", audit.events());
        assert!(!rendered_audit.contains("expected-canary"));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitDeny
                && event.reason_code == "denied_not_in_manifest"
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.reason_code == "denied_wrong_principal"
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.reason_code == "denied_expired_permit"
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));

        let (store, _) = mock_store();
        let mut failing_broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::failing(),
        );
        let audit_failure = match failing_broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
        {
            Ok(_) => panic!("audit failure should block permit use"),
            Err(err) => err,
        };
        assert!(matches!(audit_failure, JanusError::AuditUnavailable { .. }));

        let mut registry = ConsumerRegistry::new(vec![consumer(
            descriptor.secret_ref.clone(),
            "consumer.declared",
            ReloadMethod::None,
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
            true,
        )]);
        assert_eq!(registry.consumers_for(&descriptor.secret_ref).len(), 1);
        let mut consumer_audit = AuditWrite::accepting();
        registry
            .record_observed_with_audit(
                consumer(
                    descriptor.secret_ref.clone(),
                    "consumer.observed",
                    ReloadMethod::Manual,
                    Vec::new(),
                    true,
                ),
                &mut consumer_audit,
                &principal_chain,
            )
            .unwrap();
        let consumers = registry.consumers_for(&descriptor.secret_ref);
        assert_eq!(consumers.len(), 2);
        assert!(consumers.iter().any(|consumer| consumer.declared));
        assert!(consumers.iter().any(|consumer| !consumer.declared));
        assert!(consumer_audit.events().iter().any(|event| {
            event.action == AuditAction::ConsumerObserve
                && event.outcome == AuditOutcome::Allowed
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));

        let allow_result = {
            let mut issuer = PermitIssuer::new(
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                AuditWrite::accepting(),
            );
            let issued = issuer.issue(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            );
            (issued, issuer.into_audit())
        };
        assert!(allow_result.0.is_ok());
        assert!(allow_result.1.events().iter().any(|event| {
            event.action == AuditAction::PermitIssue && event.outcome == AuditOutcome::Allowed
        }));

        for (policy, req, actor, expected) in [
            (
                ProfilePolicy::default(),
                use_request(descriptor.secret_ref.clone(), "deploy-api"),
                principal("runner-a", "janus/dev"),
                "denied_no_matching_profile",
            ),
            (
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    false,
                    "runner-a",
                    "deploy-api",
                )]),
                use_request(descriptor.secret_ref.clone(), "deploy-api"),
                principal("runner-a", "janus/dev"),
                "denied_profile_disabled",
            ),
            (
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                use_request(descriptor.secret_ref.clone(), "deploy-api"),
                principal("runner-b", "janus/dev"),
                "denied_wrong_executor",
            ),
            (
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                use_request(descriptor.secret_ref.clone(), "other-api"),
                principal("runner-a", "janus/dev"),
                "denied_unapproved_destination",
            ),
        ] {
            let mut issuer = PermitIssuer::new(policy, AuditWrite::accepting());
            let err = issuer
                .issue(&req, &actor, SystemTime::UNIX_EPOCH)
                .unwrap_err();
            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected
            ));
            let audit = issuer.into_audit();
            assert!(audit.events().iter().any(|event| {
                event.action == AuditAction::PermitDeny
                    && event.reason_code == expected
                    && event.outcome == AuditOutcome::Denied
                    && !event.value_returned
            }));
        }

        let mut weak_egress = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        weak_egress.egress = EgressMode::DeclaredOnly;
        let mut issuer = PermitIssuer::new(
            ProfilePolicy::new(vec![weak_egress]),
            AuditWrite::accepting(),
        );
        let err = issuer
            .issue(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_egress_mode_insufficient",
                ..
            }
        ));

        let mut rotation_audit = AuditWrite::accepting();
        let safe_planner = RotationPlanner::new(ConsumerRegistry::new(vec![consumer(
            descriptor.secret_ref.clone(),
            "consumer.safe",
            ReloadMethod::None,
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
            true,
        )]));
        let safe = safe_planner
            .plan_generated_with_audit(
                &descriptor.secret_ref,
                &generated_rotation_capabilities(),
                &mut rotation_audit,
                &principal_chain,
            )
            .unwrap();
        assert!(matches!(safe, RotationDecision::Safe(_)));

        let unknown = RotationPlanner::new(ConsumerRegistry::default())
            .plan_generated_with_audit(
                &descriptor.secret_ref,
                &generated_rotation_capabilities(),
                &mut rotation_audit,
                &principal_chain,
            )
            .unwrap();
        assert!(matches!(
            unknown,
            RotationDecision::Unsafe {
                reason_code: "unknown_consumers",
                ..
            }
        ));

        for (reload, expected) in [
            (ReloadMethod::Manual, "consumer_reload_failed"),
            (ReloadMethod::Unsupported, "consumer_reload_failed"),
        ] {
            let decision = RotationPlanner::new(ConsumerRegistry::new(vec![consumer(
                descriptor.secret_ref.clone(),
                "consumer.reload-blocked",
                reload,
                vec![ValidationProbe::new("deploy-smoke").unwrap()],
                true,
            )]))
            .plan_generated_with_audit(
                &descriptor.secret_ref,
                &generated_rotation_capabilities(),
                &mut rotation_audit,
                &principal_chain,
            )
            .unwrap();
            assert!(matches!(
                decision,
                RotationDecision::Unsafe { reason_code, .. } if reason_code == expected
            ));
        }

        let missing_validation = RotationPlanner::new(ConsumerRegistry::new(vec![consumer(
            descriptor.secret_ref.clone(),
            "consumer.no-validation",
            ReloadMethod::None,
            Vec::new(),
            true,
        )]))
        .plan_generated_with_audit(
            &descriptor.secret_ref,
            &generated_rotation_capabilities(),
            &mut rotation_audit,
            &principal_chain,
        )
        .unwrap();
        assert!(matches!(
            missing_validation,
            RotationDecision::Unsafe {
                reason_code: "consumer_validation_missing",
                ..
            }
        ));

        let unsupported_capabilities = RotationPlanner::new(ConsumerRegistry::new(vec![consumer(
            descriptor.secret_ref.clone(),
            "consumer.safe-but-backend-blocked",
            ReloadMethod::None,
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
            true,
        )]))
        .plan_generated_with_audit(
            &descriptor.secret_ref,
            &StoreCapabilities {
                generated_rotate: false,
                ..generated_rotation_capabilities()
            },
            &mut rotation_audit,
            &principal_chain,
        )
        .unwrap();
        assert!(matches!(
            unsupported_capabilities,
            RotationDecision::Unsafe {
                reason_code: "rotation_unsupported",
                ..
            }
        ));
        assert!(rotation_audit.events().iter().all(|event| {
            event.action == AuditAction::RotationPlan
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));
    }
}

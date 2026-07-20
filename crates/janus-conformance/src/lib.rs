//! Reusable JANUS-14 store and broker conformance checks.

use std::time::{Duration, SystemTime};

use janus_core::{
    AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef, JanusError, JanusResult,
    PermitIssuer, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy,
    Purpose, RotationSpec, ScopePathV1, ScopeRef, SecretName, SecretStore, SecretValue, TrustLevel,
    UseProfile, UseRequest,
};

fn fixture_scope(environment: &str) -> ScopeRef {
    ScopePathV1::for_repository("fixture-org", "janus", "janus", environment)
        .expect("fixture scope is valid")
        .scope_ref()
}

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

/// Prove that every mutating and secret-bearing store operation enforces the
/// manifest as a hard allowlist.
///
/// Property suites can feed generated undeclared names through this helper for
/// any backend. The replacement bytes are intentionally accepted as an opaque
/// slice so test failures never need to format or log them.
pub async fn run_manifest_allowlist_contract<S>(
    store: &mut S,
    undeclared: &SecretName,
    replacement: &[u8],
) -> JanusResult<()>
where
    S: SecretStore,
{
    fn assert_denied<T>(result: JanusResult<T>, operation: &str, generated_literal: &[u8]) {
        let error = match result {
            Err(error @ JanusError::NotInManifest { .. }) => error,
            Err(_) => panic!("non-manifest {operation} returned the wrong error class"),
            Ok(_) => panic!("non-manifest {operation} did not fail closed"),
        };
        if let Ok(generated_literal) = std::str::from_utf8(generated_literal) {
            let rendered = format!("{error:?} {error}");
            assert!(
                !rendered.contains(generated_literal),
                "generated secret literal crossed the {operation} error boundary"
            );
        }
    }

    assert_denied(store.get(undeclared).await, "get", replacement);

    let set = store
        .set(undeclared, SecretValue::new(replacement.to_vec()))
        .await;
    assert_denied(set, "set", replacement);

    let rotate = store
        .rotate(
            undeclared,
            &RotationSpec::generated(SecretValue::new(replacement.to_vec())),
        )
        .await;
    assert_denied(rotate, "rotate", replacement);

    assert_denied(store.delete(undeclared).await, "delete", replacement);

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
        fixture_scope("dev"),
    );
    let profile = UseProfile {
        id: profile_id.clone(),
        scope: principal.scope.clone(),
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
        scope: principal.scope.clone(),
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
            fixture_scope("dev"),
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
        ApprovalGrant, AuditAction, BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRef,
        ConsumerRegistry, Environment, ManifestCatalog, OwnerRef, ReloadMethod, RotationDecision,
        RotationPlanner, SafeLabel, ScopeRef, SecretBroker, SecretClass, SecretLifecycle,
        SecretMeta, SecretRef, Severity, StoreCapabilities, TrustLevel, ValidationProbe,
    };
    use janus_mock::MockStore;

    fn mock_store() -> (MockStore, StoreFixture) {
        mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::Normal),
        )
    }

    fn mock_store_with_metadata(
        owner: Option<OwnerRef>,
        classification: Option<SecretClass>,
    ) -> (MockStore, StoreFixture) {
        mock_store_with_metadata_and_lifecycle(owner, classification, SecretLifecycle::Active)
    }

    fn mock_store_with_metadata_and_lifecycle(
        owner: Option<OwnerRef>,
        classification: Option<SecretClass>,
        lifecycle: SecretLifecycle,
    ) -> (MockStore, StoreFixture) {
        let scope = fixture_scope("dev");
        let canary = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&scope, &canary);
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref,
            name: canary.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: scope.clone(),
            owner,
            classification,
            lifecycle,
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

    fn principal(executor: &str, _scope: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            fixture_scope("dev"),
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
            scope: fixture_scope("dev"),
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
            scope: fixture_scope("dev"),
            secret_ref,
            profile_id: ProfileId::new("profile.canary").unwrap(),
            destination: Destination::new(destination).unwrap(),
            purpose: Purpose::new("deploy canary").unwrap(),
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
            SafeLabel::new("approved emergency window").unwrap(),
        )
    }

    fn consumer(
        secret_ref: SecretRef,
        consumer_ref: &str,
        reload: ReloadMethod,
        validation: Vec<ValidationProbe>,
        declared: bool,
    ) -> ConsumerDescriptor {
        ConsumerDescriptor {
            scope: fixture_scope("dev"),
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
    async fn broker_isolates_list_describe_get_and_permits_by_exact_scope() {
        let dev_scope = fixture_scope("dev");
        let prod_scope = fixture_scope("prod");
        let dev_name = SecretName::new("DEV_CANARY").unwrap();
        let prod_name = SecretName::new("PROD_CANARY").unwrap();
        let dev_ref = SecretRef::for_manifest_entry(&dev_scope, &dev_name);
        let prod_ref = SecretRef::for_manifest_entry(&prod_scope, &prod_name);
        let meta = |name: SecretName, secret_ref: SecretRef, scope: ScopeRef| SecretMeta {
            secret_ref,
            name,
            label: SafeLabel::new("Scoped canary").unwrap(),
            scope,
            owner: Some(OwnerRef::new("security").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        };
        let catalog = ManifestCatalog::new(vec![
            meta(dev_name.clone(), dev_ref.clone(), dev_scope.clone()),
            meta(prod_name.clone(), prod_ref.clone(), prod_scope.clone()),
        ])
        .unwrap();
        let store = MockStore::new(catalog)
            .with_value(dev_name.clone(), b"dev-canary".to_vec())
            .unwrap()
            .with_value(prod_name.clone(), b"prod-canary".to_vec())
            .unwrap();
        let profile = |secret_ref: SecretRef, scope: ScopeRef| UseProfile {
            id: ProfileId::new("profile.canary").unwrap(),
            scope,
            secret_ref,
            executor: ExecutorRef::new("runner-a").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![
                profile(dev_ref.clone(), dev_scope.clone()),
                profile(prod_ref.clone(), prod_scope.clone()),
            ]),
            AuditWrite::accepting(),
        );
        let principal = |scope: ScopeRef| {
            PrincipalChain::new(
                Principal::new(
                    PrincipalKind::Executor,
                    PrincipalId::new("runner-a").unwrap(),
                ),
                scope,
            )
        };
        let dev_principal = principal(dev_scope.clone());
        let prod_principal = principal(prod_scope.clone());

        let listed = broker.list(&dev_principal).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].secret_ref, dev_ref);
        assert!(matches!(
            broker.describe(&prod_ref, &dev_principal).await,
            Err(JanusError::PolicyDenied {
                reason_code: "denied_scope_mismatch",
                ..
            })
        ));
        assert!(matches!(
            broker.get(&prod_name, &dev_principal).await,
            Err(JanusError::PolicyDenied {
                reason_code: "denied_scope_mismatch",
                ..
            })
        ));

        let prod_request = UseRequest {
            scope: prod_scope,
            secret_ref: prod_ref,
            profile_id: ProfileId::new("profile.canary").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            purpose: Purpose::new("deploy prod canary").unwrap(),
        };
        assert!(matches!(
            broker
                .request_use(&prod_request, &dev_principal, SystemTime::UNIX_EPOCH)
                .await,
            Err(JanusError::PolicyDenied {
                reason_code: "denied_scope_mismatch",
                ..
            })
        ));
        let permit = broker
            .request_use(&prod_request, &prod_principal, SystemTime::UNIX_EPOCH)
            .await
            .unwrap();
        assert!(matches!(
            broker
                .use_permit(
                    &permit,
                    &dev_principal,
                    &ExecutorRef::new("runner-a").unwrap(),
                    &Destination::new("deploy-api").unwrap(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                )
                .await,
            Err(JanusError::PermitInvalid {
                reason_code: "denied_scope_mismatch",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn permit_contract_records_value_free_audit() {
        let (store, _) = mock_store();
        let descriptor = store.list().await.unwrap().remove(0);
        run_permit_contract(descriptor.secret_ref, "runner-a", "deploy-api").unwrap();
    }

    #[tokio::test]
    async fn broker_denies_permit_issue_for_incomplete_secret_metadata() {
        for (owner, classification, expected) in [
            (None, Some(SecretClass::Normal), "denied_missing_owner"),
            (
                Some(OwnerRef::new("infra").unwrap()),
                None,
                "denied_missing_classification",
            ),
            (None, None, "denied_metadata_incomplete"),
        ] {
            let (store, _) = mock_store_with_metadata(owner, classification);
            let descriptor = store.list().await.unwrap().remove(0);
            let principal_chain = principal("runner-a", "janus/dev");
            let mut broker = SecretBroker::new(
                store,
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                AuditWrite::accepting(),
            );

            let err = broker
                .request_use(
                    &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                    &principal_chain,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected
            ));
            let (_store, _policy, audit) = broker.into_parts();
            assert!(audit.events().iter().any(|event| {
                event.action == AuditAction::PermitDeny
                    && event.reason_code == expected
                    && event.outcome == AuditOutcome::Denied
                    && !event.value_returned
            }));
        }
    }

    #[tokio::test]
    async fn broker_denies_normal_use_for_blocked_lifecycle_states() {
        for (lifecycle, expected) in [
            (SecretLifecycle::Draft, "denied_lifecycle_draft"),
            (SecretLifecycle::Deprecated, "denied_lifecycle_deprecated"),
            (SecretLifecycle::Disabled, "denied_lifecycle_disabled"),
            (
                SecretLifecycle::PendingDelete,
                "denied_lifecycle_pending_delete",
            ),
            (SecretLifecycle::Destroyed, "denied_lifecycle_destroyed"),
        ] {
            let (store, _) = mock_store_with_metadata_and_lifecycle(
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
                lifecycle,
            );
            let descriptor = store.list().await.unwrap().remove(0);
            assert!(!descriptor.normal_use_allowed());
            let principal_chain = principal("runner-a", "janus/dev");
            let mut broker = SecretBroker::new(
                store,
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                AuditWrite::accepting(),
            );

            let err = broker
                .request_use(
                    &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                    &principal_chain,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                JanusError::PolicyDenied { reason_code, .. } if reason_code == expected
            ));
            let (_store, _policy, audit) = broker.into_parts();
            assert!(audit.events().iter().any(|event| {
                event.action == AuditAction::PermitDeny
                    && event.reason_code == expected
                    && event.outcome == AuditOutcome::Denied
                    && !event.value_returned
            }));
        }
    }

    #[tokio::test]
    async fn broker_allows_active_and_rotating_lifecycle_states() {
        for lifecycle in [SecretLifecycle::Active, SecretLifecycle::Rotating] {
            let (store, _) = mock_store_with_metadata_and_lifecycle(
                Some(OwnerRef::new("infra").unwrap()),
                Some(SecretClass::Normal),
                lifecycle,
            );
            let descriptor = store.list().await.unwrap().remove(0);
            assert!(descriptor.normal_use_allowed());
            let principal_chain = principal("runner-a", "janus/dev");
            let mut broker = SecretBroker::new(
                store,
                ProfilePolicy::new(vec![use_profile(
                    descriptor.secret_ref.clone(),
                    true,
                    "runner-a",
                    "deploy-api",
                )]),
                AuditWrite::accepting(),
            );

            broker
                .request_use(
                    &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                    &principal_chain,
                    SystemTime::UNIX_EPOCH,
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn broker_rechecks_metadata_before_permit_consumption() {
        let (complete_store, _) = mock_store();
        let descriptor = complete_store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let profile = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        let mut issuing_broker = SecretBroker::new(
            complete_store,
            ProfilePolicy::new(vec![profile.clone()]),
            AuditWrite::accepting(),
        );
        let permit = issuing_broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();

        let (incomplete_store, _) =
            mock_store_with_metadata(Some(OwnerRef::new("infra").unwrap()), None);
        let mut consuming_broker = SecretBroker::new(
            incomplete_store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );
        let err = match consuming_broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
        {
            Ok(_) => panic!("metadata-incomplete permit consumption should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_missing_classification",
                ..
            }
        ));
        let (_store, _policy, audit) = consuming_broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.reason_code == "denied_missing_classification"
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn broker_rechecks_lifecycle_before_permit_consumption() {
        let (active_store, _) = mock_store_with_metadata_and_lifecycle(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::Normal),
            SecretLifecycle::Active,
        );
        let descriptor = active_store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let profile = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        let mut issuing_broker = SecretBroker::new(
            active_store,
            ProfilePolicy::new(vec![profile.clone()]),
            AuditWrite::accepting(),
        );
        let permit = issuing_broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();

        let (disabled_store, _) = mock_store_with_metadata_and_lifecycle(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::Normal),
            SecretLifecycle::Disabled,
        );
        let mut consuming_broker = SecretBroker::new(
            disabled_store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );
        let err = match consuming_broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
        {
            Ok(_) => panic!("disabled lifecycle permit consumption should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_lifecycle_disabled",
                ..
            }
        ));
        let (_store, _policy, audit) = consuming_broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.reason_code == "denied_lifecycle_disabled"
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn broker_applies_class_policy_when_issuing_permits() {
        let (store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::HighValue),
        );
        let descriptor = store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![use_profile(
                descriptor.secret_ref.clone(),
                true,
                "runner-a",
                "deploy-api",
            )]),
            AuditWrite::accepting(),
        );
        broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();
        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitIssue
                && event.outcome == AuditOutcome::Allowed
                && event.severity == Severity::High
                && !event.value_returned
        }));

        let (store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::HighValue),
        );
        let descriptor = store.list().await.unwrap().remove(0);
        let mut weak_egress = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        weak_egress.egress = EgressMode::HookGuarded;
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![weak_egress]),
            AuditWrite::accepting(),
        );

        let err = broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_egress_mode_insufficient",
                ..
            }
        ));
        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitDeny
                && event.reason_code == "denied_egress_mode_insufficient"
                && event.severity == Severity::High
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));

        let (store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::HighValue),
        );
        let descriptor = store.list().await.unwrap().remove(0);
        let mut long_ttl = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        long_ttl.ttl = Duration::from_secs(301);
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![long_ttl]),
            AuditWrite::accepting(),
        );
        let err = broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_ttl_exceeds_class_limit",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn broker_blocks_break_glass_permit_issue_without_approval() {
        let (store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::BreakGlass),
        );
        let descriptor = store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![use_profile(
                descriptor.secret_ref.clone(),
                true,
                "runner-a",
                "deploy-api",
            )]),
            AuditWrite::accepting(),
        );

        let err = broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_missing",
                ..
            }
        ));
        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitDeny
                && event.reason_code == "approval_missing"
                && event.severity == Severity::High
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn broker_allows_break_glass_with_exact_approval_and_rechecks_expiry() {
        let (store, fixture) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::BreakGlass),
        );
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
        let request = use_request(descriptor.secret_ref.clone(), "deploy-api");
        let approval = approval_for(
            &profile,
            &request,
            SecretClass::BreakGlass,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );

        let permit = broker
            .request_use_with_approval(
                &request,
                &principal_chain,
                SystemTime::UNIX_EPOCH,
                Some(&approval),
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

        let err = match broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(31),
            )
            .await
        {
            Ok(_) => panic!("approval-backed permit use should fail after grant expiry"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_expired",
                ..
            }
        ));

        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitApprove
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "approved"
                && event.severity == Severity::High
                && event.evidence.as_ref().unwrap().as_str() == "approved emergency window"
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "approval_expired"
                && event.severity == Severity::High
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn broker_allows_high_value_weak_egress_only_with_exact_approval() {
        let (store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::HighValue),
        );
        let descriptor = store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let mut weak_profile = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        weak_profile.egress = EgressMode::DeclaredOnly;
        let request = use_request(descriptor.secret_ref.clone(), "deploy-api");
        let approval = approval_for(
            &weak_profile,
            &request,
            SecretClass::HighValue,
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        );
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![weak_profile]),
            AuditWrite::accepting(),
        );

        let permit = broker
            .request_use_with_approval(
                &request,
                &principal_chain,
                SystemTime::UNIX_EPOCH,
                Some(&approval),
            )
            .await
            .unwrap();
        assert!(permit.approval().is_some());
        assert_eq!(permit.egress(), EgressMode::DeclaredOnly);

        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitApprove
                && event.outcome == AuditOutcome::Allowed
                && event.severity == Severity::High
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn broker_rechecks_class_policy_before_permit_consumption() {
        let (normal_store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::Normal),
        );
        let descriptor = normal_store.list().await.unwrap().remove(0);
        let principal_chain = principal("runner-a", "janus/dev");
        let executor = ExecutorRef::new("runner-a").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let mut weak_profile = use_profile(
            descriptor.secret_ref.clone(),
            true,
            "runner-a",
            "deploy-api",
        );
        weak_profile.egress = EgressMode::DeclaredOnly;
        let mut issuing_broker = SecretBroker::new(
            normal_store,
            ProfilePolicy::new(vec![weak_profile.clone()]),
            AuditWrite::accepting(),
        );
        let permit = issuing_broker
            .request_use(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();

        let (high_value_store, _) = mock_store_with_metadata(
            Some(OwnerRef::new("infra").unwrap()),
            Some(SecretClass::HighValue),
        );
        let mut consuming_broker = SecretBroker::new(
            high_value_store,
            ProfilePolicy::new(vec![weak_profile]),
            AuditWrite::accepting(),
        );
        let err = match consuming_broker
            .use_permit(
                &permit,
                &principal_chain,
                &executor,
                &destination,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .await
        {
            Ok(_) => panic!("class policy should be rechecked before permit consumption"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_egress_mode_insufficient",
                ..
            }
        ));
        let (_store, _policy, audit) = consuming_broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.reason_code == "denied_egress_mode_insufficient"
                && event.severity == Severity::High
                && event.outcome == AuditOutcome::Denied
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn tracer_points_1_to_6_work_through_broker() {
        let (store, fixture) = mock_store();
        let descriptor = store.list().await.unwrap().remove(0);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: fixture_scope("dev"),
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
            fixture_scope("dev"),
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
            scope: fixture_scope("dev"),
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
                    fixture_scope("dev"),
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
            .issue_for_class(
                &use_request(descriptor.secret_ref.clone(), "deploy-api"),
                &principal_chain,
                SystemTime::UNIX_EPOCH,
                SecretClass::HighValue,
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

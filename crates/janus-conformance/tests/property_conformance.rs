use std::env;
use std::fmt;
use std::time::{Duration, SystemTime};

use janus_conformance::run_manifest_allowlist_contract;
use janus_core::{
    AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef, JanusError, ManifestCatalog,
    OwnerRef, PermitIssuer, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId,
    ProfilePolicy, Purpose, SafeLabel, ScopePathV1, ScopeRef, SecretBroker, SecretClass,
    SecretLifecycle, SecretMeta, SecretName, SecretRef, SecretStore, TrustLevel, UsePermit,
    UseProfile, UseRequest,
};
use janus_mock::MockStore;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

// Keep explicit source-file failure persistence enabled. Any minimized seed is
// written below the crate's `proptest-regressions` directory and is a source
// artifact that must be committed with the fix.

#[derive(Clone)]
struct RedactedCanary(String);

impl RedactedCanary {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedCanary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-generated-canary>")
    }
}

fn generated_canary() -> impl Strategy<Value = RedactedCanary> {
    "[A-Za-z0-9]{24,48}".prop_map(|suffix| RedactedCanary(format!("SENSITIVE_CANARY_{suffix}")))
}

fn property_config(local_cases: u32) -> ProptestConfig {
    let cases = env::var("JANUS_PROPERTY_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(local_cases);
    let max_shrink_iters = env::var("JANUS_PROPERTY_MAX_SHRINK_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(4096);
    ProptestConfig {
        cases,
        max_shrink_iters,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/property_conformance.txt"
        )))),
        ..ProptestConfig::default()
    }
}

fn identifier(prefix: &'static str) -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{2,24}".prop_map(move |suffix| format!("{prefix}{suffix}"))
}

fn undeclared_name() -> impl Strategy<Value = String> {
    "[A-Z][A-Z0-9_]{3,31}".prop_filter("generated name must remain undeclared", |name| {
        name != "CANARY"
    })
}

fn scope() -> ScopeRef {
    scope_for_project("janus")
}

fn scope_for_project(project: &str) -> ScopeRef {
    ScopePathV1::for_repository("fixture-org", project, "janus", "property")
        .unwrap()
        .scope_ref()
}

fn fixture_store(canary: &RedactedCanary) -> (MockStore, SecretRef) {
    let name = SecretName::new("CANARY").unwrap();
    let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
    let catalog = ManifestCatalog::new(vec![SecretMeta {
        secret_ref: secret_ref.clone(),
        name: name.clone(),
        label: SafeLabel::new("Property canary").unwrap(),
        scope: scope(),
        owner: Some(OwnerRef::new("security").unwrap()),
        classification: Some(SecretClass::Normal),
        lifecycle: SecretLifecycle::Active,
        required: true,
        trust_level: TrustLevel::L1,
        allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
    }])
    .unwrap();
    let store = MockStore::new(catalog)
        .with_value(name, canary.as_bytes().to_vec())
        .unwrap();
    (store, secret_ref)
}

fn principal(executor: &str, scope_label: &str) -> PrincipalChain {
    let scope = if scope_label.starts_with("other-scope/") {
        ScopePathV1::for_repository(
            "fixture-org",
            "janus",
            format!("{}-x", scope_label.replace('/', "-")),
            "property",
        )
        .unwrap()
        .scope_ref()
    } else {
        scope()
    };
    PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
        scope,
    )
}

fn profile(secret_ref: SecretRef, executor: &str, destination: &str, ttl: u64) -> UseProfile {
    UseProfile {
        id: ProfileId::new("profile.canary").unwrap(),
        scope: scope(),
        secret_ref,
        executor: ExecutorRef::new(executor).unwrap(),
        destination: Destination::new(destination).unwrap(),
        egress: EgressMode::Connector,
        trust_level: TrustLevel::L2,
        ttl: Duration::from_secs(ttl),
        single_use: true,
        enabled: true,
    }
}

fn request(secret_ref: SecretRef, destination: &str) -> UseRequest {
    UseRequest {
        scope: scope(),
        secret_ref,
        profile_id: ProfileId::new("profile.canary").unwrap(),
        destination: Destination::new(destination).unwrap(),
        purpose: Purpose::new("property conformance").unwrap(),
    }
}

fn assert_literal_absent(literal: &RedactedCanary, rendered: &str, surface: &str) {
    assert!(
        !rendered.contains(literal.as_str()),
        "generated secret literal crossed the {surface} boundary"
    );
}

proptest! {
    #![proptest_config(property_config(128))]

    #[test]
    fn generated_refs_are_stable_opaque_and_non_authorizing(
        project_text in "project-[a-z][a-z0-9_-]{1,20}[a-z0-9]",
        name_text in identifier("SECRET-"),
        unknown_suffix in "[a-z0-9]{8,40}",
        canary in generated_canary(),
    ) {
        let scope = scope_for_project(&project_text);
        let name = SecretName::new(name_text.clone()).unwrap();
        let first = SecretRef::for_manifest_entry(&scope, &name);
        let second = SecretRef::for_manifest_entry(&scope, &name);
        prop_assert_eq!(&first, &second);
        prop_assert!(first.as_str().starts_with("sec_"));
        prop_assert!(!first.as_str().contains(&project_text));
        prop_assert!(!first.as_str().contains(&name_text));

        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let (store, declared_ref) = fixture_store(&canary);
            let reviewed_profile = profile(declared_ref, "runner-a", "deploy-api", 60);
            let mut broker = SecretBroker::new(
                store,
                ProfilePolicy::new(vec![reviewed_profile]),
                AuditWrite::accepting(),
            );
            let caller = principal("runner-a", "janus/property");
            let unknown_ref = SecretRef::new(format!("sec_unknown_{unknown_suffix}")).unwrap();

            let describe = broker.describe(&unknown_ref, &caller).await.unwrap_err();
            assert!(matches!(describe, JanusError::NotInManifest { .. }));
            assert_literal_absent(
                &canary,
                &format!("{describe:?} {describe}"),
                "describe-error",
            );
            let permit = broker
                .request_use(&request(unknown_ref, "deploy-api"), &caller, SystemTime::UNIX_EPOCH)
                .await
                .unwrap_err();
            assert!(matches!(permit, JanusError::NotInManifest { .. }));
            assert_literal_absent(
                &canary,
                &format!("{permit:?} {permit}"),
                "permit-request-error",
            );

            let (_store, _policy, audit) = broker.into_parts();
            assert_eq!(audit.events().len(), 2);
            assert!(audit.events().iter().all(|event| {
                event.outcome == AuditOutcome::Denied && !event.value_returned
            }));
            assert_literal_absent(&canary, &format!("{:?}", audit.events()), "audit");
        });
    }

    #[test]
    fn malformed_ref_text_is_rejected_without_echoing_generated_values(
        canary in generated_canary(),
        body in "[A-Za-z0-9_./-]{1,40}",
    ) {
        for malformed in [String::new(), format!(" {body}"), format!("{body} ")] {
            let error = SecretRef::new(malformed).unwrap_err();
            let rendered = format!("{error:?} {error}");
            assert_literal_absent(&canary, &rendered, "identifier-error");
        }
    }

    #[test]
    fn mock_store_hard_allowlist_covers_every_store_operation(
        unknown_text in undeclared_name(),
        canary in generated_canary(),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let (mut store, _) = fixture_store(&canary);
            let unknown = SecretName::new(unknown_text).unwrap();
            run_manifest_allowlist_contract(&mut store, &unknown, canary.as_bytes())
                .await
                .unwrap();

            let listed = store.list().await.unwrap();
            assert_literal_absent(&canary, &format!("{listed:?}"), "descriptor-debug");
        });
    }

    #[test]
    fn copied_stale_and_cross_boundary_permits_fail_closed(
        executor in identifier("runner-"),
        wrong_executor in identifier("other-runner-"),
        destination in identifier("destination-"),
        wrong_destination in identifier("other-destination-"),
        scope in identifier("scope/"),
        wrong_scope in identifier("other-scope/"),
        ttl in 2_u64..600,
        unknown_suffix in "[a-z0-9]{8,40}",
        canary in generated_canary(),
    ) {
        let (store, secret_ref) = fixture_store(&canary);
        let reviewed_profile = profile(secret_ref.clone(), &executor, &destination, ttl);
        let caller = principal(&executor, &scope);
        let use_request = request(secret_ref, &destination);
        let mut issuer = PermitIssuer::new(
            ProfilePolicy::new(vec![reviewed_profile.clone()]),
            AuditWrite::accepting(),
        );
        let permit = issuer
            .issue(&use_request, &caller, SystemTime::UNIX_EPOCH)
            .unwrap();
        let copied = permit.clone();
        let valid_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);

        copied
            .matches(
                &caller,
                &ExecutorRef::new(executor.clone()).unwrap(),
                &Destination::new(destination.clone()).unwrap(),
                valid_at,
            )
            .unwrap();
        assert!(matches!(
            copied.matches(
                &principal(&executor, &wrong_scope),
                &ExecutorRef::new(executor.clone()).unwrap(),
                &Destination::new(destination.clone()).unwrap(),
                valid_at,
            ),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_scope_mismatch",
                ..
            })
        ));
        assert!(matches!(
            copied.matches(
                &caller,
                &ExecutorRef::new(wrong_executor).unwrap(),
                &Destination::new(destination.clone()).unwrap(),
                valid_at,
            ),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_wrong_executor",
                ..
            })
        ));
        assert!(matches!(
            copied.matches(
                &caller,
                &ExecutorRef::new(executor.clone()).unwrap(),
                &Destination::new(wrong_destination).unwrap(),
                valid_at,
            ),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_unapproved_destination",
                ..
            })
        ));
        assert!(matches!(
            copied.matches(
                &caller,
                &ExecutorRef::new(executor.clone()).unwrap(),
                &Destination::new(destination.clone()).unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(ttl),
            ),
            Err(JanusError::PermitInvalid {
                reason_code: "denied_expired_permit",
                ..
            })
        ));

        let mut tampered_snapshot = permit.snapshot();
        tampered_snapshot.secret_ref = format!("sec_unknown_{unknown_suffix}");
        let tampered = UsePermit::from_snapshot(tampered_snapshot).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let mut broker = SecretBroker::new(
                store,
                ProfilePolicy::new(vec![reviewed_profile]),
                AuditWrite::accepting(),
            );
            let denied = match broker
                .use_permit(
                    &tampered,
                    &caller,
                    &ExecutorRef::new(executor).unwrap(),
                    &Destination::new(destination).unwrap(),
                    valid_at,
                )
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("tampered permit unexpectedly returned a secret value"),
            };
            assert!(matches!(denied, JanusError::NotInManifest { .. }));
            assert_literal_absent(
                &canary,
                &format!("{denied:?} {denied}"),
                "permit-consumption-error",
            );

            let (_store, _policy, audit) = broker.into_parts();
            let rendered = format!("{copied:?} {tampered:?} {:?}", audit.events());
            assert_literal_absent(&canary, &rendered, "permit-debug-or-audit");
        });
    }
}

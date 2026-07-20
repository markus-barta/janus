//! Wrapped `secretspec` adapter for JANUS-14.

use std::path::Path;

use async_trait::async_trait;
use janus_core::{
    HealthStatus, JanusError, JanusResult, ManifestCatalog, ProfileId, ProjectId, RotationOutcome,
    RotationSpec, RotationStrategy, SafeLabel, ScopeRef, SecretDescriptor, SecretMeta,
    SecretMetadataOverlay, SecretName, SecretRef, SecretStore, SecretValue, StoreCapabilities,
    TrustLevel,
};
use secrecy::{ExposeSecret, SecretString};
use secretspec as secretspec_crate;

/// `secretspec`-backed Janus store.
///
/// Only this crate touches secretspec types. `janus-core` sees the stable
/// Janus `SecretStore` contract and opaque refs.
pub struct SecretspecStore {
    project: ProjectId,
    profile: String,
    provider: Box<dyn secretspec_crate::Provider>,
    catalog: ManifestCatalog,
}

impl SecretspecStore {
    /// Load `secretspec.toml` and wrap a concrete provider URI, for example
    /// `dotenv:/tmp/janus.env`.
    pub fn load_from(
        config_path: impl AsRef<Path>,
        profile: impl Into<String>,
        provider_uri: impl Into<String>,
        scope: ScopeRef,
    ) -> JanusResult<Self> {
        Self::load_from_with_metadata(config_path, profile, provider_uri, scope, None)
    }

    /// Load `secretspec.toml` with an optional Janus metadata overlay.
    pub fn load_from_with_metadata(
        config_path: impl AsRef<Path>,
        profile: impl Into<String>,
        provider_uri: impl Into<String>,
        scope: ScopeRef,
        metadata: Option<&SecretMetadataOverlay>,
    ) -> JanusResult<Self> {
        let profile = profile.into();
        let config = secretspec_crate::Config::try_from(config_path.as_ref()).map_err(|err| {
            JanusError::StoreUnavailable {
                detail: format!("secretspec config load failed: {err}"),
            }
        })?;
        config
            .validate()
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("secretspec config validation failed: {err}"),
            })?;

        let project = ProjectId::new(config.project.name.clone())?;
        let profile_config =
            config
                .get_profile(&profile)
                .ok_or_else(|| JanusError::InvalidManifest {
                    detail: format!("missing secretspec profile {profile}"),
                })?;

        let mut entries = Vec::new();
        for (name, secret) in profile_config.iter() {
            let name = SecretName::new(name.clone())?;
            let required = secret
                .required
                .or_else(|| {
                    profile_config
                        .defaults
                        .as_ref()
                        .and_then(|defaults| defaults.required)
                })
                .unwrap_or(true);
            entries.push(SecretMeta {
                secret_ref: SecretRef::for_manifest_entry(&scope, &name),
                name: name.clone(),
                label: SafeLabel::new(
                    secret
                        .description
                        .clone()
                        .unwrap_or_else(|| "Manifest-declared secret".to_string()),
                )?,
                scope: scope.clone(),
                owner: None,
                classification: None,
                lifecycle: janus_core::SecretLifecycle::Active,
                required,
                trust_level: TrustLevel::L1,
                allowed_uses: vec![ProfileId::new(format!("profile.{}", name.as_str()))?],
            });
        }
        if let Some(metadata) = metadata {
            metadata.apply_to_entries(&mut entries)?;
        }

        let provider_uri = provider_uri.into();
        let provider = Box::<dyn secretspec_crate::Provider>::try_from(provider_uri.as_str())
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("secretspec provider load failed: {err}"),
            })?;

        Ok(Self {
            project,
            profile,
            provider,
            catalog: ManifestCatalog::new(entries)?,
        })
    }

    fn ensure_manifest(&self, name: &SecretName) -> JanusResult<&SecretMeta> {
        self.catalog.meta_by_name(name)
    }

    fn map_provider_error(err: secretspec_crate::SecretSpecError) -> JanusError {
        JanusError::StoreUnavailable {
            detail: format!("secretspec provider operation failed: {err}"),
        }
    }
}

#[async_trait]
impl SecretStore for SecretspecStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            write: self.provider.allows_set(),
            delete: false,
            generated_rotate: self.provider.allows_set(),
            rotate_native: false,
            versioning: false,
            leasing: false,
            native_audit: false,
            backend_key_custody: false,
        }
    }

    async fn health(&self) -> JanusResult<HealthStatus> {
        Ok(HealthStatus {
            backend: self.provider.name(),
            ok: true,
            detail: "secretspec provider configured".to_string(),
        })
    }

    async fn list(&self) -> JanusResult<Vec<SecretDescriptor>> {
        let mut descriptors = Vec::new();
        for meta in self.catalog.entries() {
            let present = self
                .provider
                .get(self.project.as_str(), meta.name.as_str(), &self.profile)
                .map_err(Self::map_provider_error)?
                .is_some();
            descriptors.push(meta.descriptor(present));
        }
        Ok(descriptors)
    }

    async fn get(&self, name: &SecretName) -> JanusResult<SecretValue> {
        self.ensure_manifest(name)?;
        let value = self
            .provider
            .get(self.project.as_str(), name.as_str(), &self.profile)
            .map_err(Self::map_provider_error)?
            .ok_or_else(|| JanusError::NotFound {
                name: name.as_str().to_string(),
            })?;
        Ok(SecretValue::new(value.expose_secret().as_bytes().to_vec()))
    }

    async fn set(&mut self, name: &SecretName, value: SecretValue) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        if !self.provider.allows_set() {
            return Err(JanusError::Unsupported { capability: "set" });
        }
        let value = std::str::from_utf8(value.expose_bytes()).map_err(|_| {
            JanusError::StoreUnavailable {
                detail: "secretspec provider values must be utf-8".to_string(),
            }
        })?;
        self.provider
            .set(
                self.project.as_str(),
                name.as_str(),
                &SecretString::new(value.to_string().into()),
                &self.profile,
            )
            .map_err(Self::map_provider_error)
    }

    async fn rotate(
        &mut self,
        name: &SecretName,
        spec: &RotationSpec,
    ) -> JanusResult<RotationOutcome> {
        self.ensure_manifest(name)?;
        if spec.strategy != RotationStrategy::Generated {
            return Err(JanusError::Unsupported {
                capability: "rotation_strategy",
            });
        }
        let value = spec
            .generated_value
            .as_ref()
            .ok_or(JanusError::Unsupported {
                capability: "generated_value",
            })?;
        self.set(name, SecretValue::new(value.expose_bytes().to_vec()))
            .await?;
        let descriptor = self.catalog.descriptor_by_name(name, true)?;
        Ok(RotationOutcome::rotated(descriptor.secret_ref))
    }

    async fn delete(&mut self, name: &SecretName) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        Err(JanusError::Unsupported {
            capability: "delete",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef, Principal,
        PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy, Purpose, ScopePathV1,
        SecretBroker, UseProfile, UseRequest,
    };
    use proptest::prelude::*;
    use std::fmt;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    struct DotenvFixture {
        dir: std::path::PathBuf,
        manifest: std::path::PathBuf,
        env_file: std::path::PathBuf,
    }

    impl Drop for DotenvFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn dotenv_fixture() -> DotenvFixture {
        dotenv_fixture_with_value("expected-canary")
    }

    fn dotenv_fixture_with_value(canary: &str) -> DotenvFixture {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("janus-secretspec-{nonce}-{id}"));
        fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("secretspec.toml");
        let env_file = dir.join(".env");
        fs::write(
            &manifest,
            r#"
[project]
name = "janus"
revision = "1.0"

[profiles.default]
CANARY = { description = "Canary token", required = true }
"#,
        )
        .unwrap();
        fs::write(&env_file, format!("CANARY={canary}\n")).unwrap();
        DotenvFixture {
            dir,
            manifest,
            env_file,
        }
    }

    #[derive(Clone)]
    struct RedactedCanary(String);

    impl fmt::Debug for RedactedCanary {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("<redacted-generated-canary>")
        }
    }

    fn generated_canary() -> impl Strategy<Value = RedactedCanary> {
        "[A-Za-z0-9]{24,48}".prop_map(|suffix| RedactedCanary(format!("SENSITIVE_CANARY_{suffix}")))
    }

    fn property_config(local_cases: u32) -> ProptestConfig {
        let cases = std::env::var("JANUS_PROPERTY_CASES")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(local_cases);
        let max_shrink_iters = std::env::var("JANUS_PROPERTY_MAX_SHRINK_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(4096);
        ProptestConfig {
            cases,
            max_shrink_iters,
            ..ProptestConfig::default()
        }
    }

    fn metadata_overlay() -> SecretMetadataOverlay {
        SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            "#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn dotenv_secretspec_store_reads_manifest_declared_canary() {
        let fixture = dotenv_fixture();
        let metadata = metadata_overlay();
        let mut store = SecretspecStore::load_from_with_metadata(
            &fixture.manifest,
            "default",
            format!("dotenv:{}", fixture.env_file.display()),
            scope(),
            Some(&metadata),
        )
        .unwrap();
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        assert!(listed[0].secret_ref.as_str().starts_with("sec_"));
        assert_eq!(listed[0].label.as_str(), "Canary token");
        let rendered = format!("{listed:?}");
        assert!(!rendered.contains("expected-canary"));

        let value = store
            .get(&SecretName::new("CANARY").unwrap())
            .await
            .unwrap();
        assert_eq!(value.expose_bytes(), b"expected-canary");

        let err = match store.get(&SecretName::new("OTHER").unwrap()).await {
            Ok(_) => panic!("non-manifest get should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, JanusError::NotInManifest { .. }));

        janus_conformance::run_store_contract(
            &mut store,
            &janus_conformance::StoreFixture {
                canary: SecretName::new("CANARY").unwrap(),
                expected_value: b"expected-canary".to_vec(),
                not_in_manifest: SecretName::new("OTHER").unwrap(),
            },
        )
        .await
        .unwrap();
    }

    proptest! {
        #![proptest_config(property_config(48))]

        #[test]
        fn security_property_provider_allowlist_enforces_manifest_without_value_leakage(
            undeclared in "[A-Z][A-Z0-9_]{3,31}"
                .prop_filter("generated name must remain undeclared", |name| name != "CANARY"),
            canary in generated_canary(),
        ) {
            let fixture = dotenv_fixture_with_value(&canary.0);
            let metadata = metadata_overlay();
            let mut store = SecretspecStore::load_from_with_metadata(
                &fixture.manifest,
                "default",
                format!("dotenv:{}", fixture.env_file.display()),
                scope(),
                Some(&metadata),
            )
            .unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            runtime.block_on(async {
                janus_conformance::run_manifest_allowlist_contract(
                    &mut store,
                    &SecretName::new(undeclared).unwrap(),
                    canary.0.as_bytes(),
                )
                .await
                .unwrap();

                let descriptors = store.list().await.unwrap();
                assert!(
                    !format!("{descriptors:?}").contains(&canary.0),
                    "generated secret literal crossed the SecretspecStore descriptor boundary"
                );
            });
        }
    }

    #[tokio::test]
    async fn secretspec_store_without_metadata_lists_incomplete_descriptors() {
        let fixture = dotenv_fixture();
        let store = SecretspecStore::load_from(
            &fixture.manifest,
            "default",
            format!("dotenv:{}", fixture.env_file.display()),
            scope(),
        )
        .unwrap();
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        assert!(!listed[0].metadata_complete());
        assert_eq!(listed[0].metadata_state(), "incomplete");
        assert_eq!(listed[0].risk_hint(), "blocked_metadata_incomplete");
    }

    #[tokio::test]
    async fn dotenv_tracer_points_1_to_6_work_through_broker() {
        let fixture = dotenv_fixture();
        let metadata = metadata_overlay();
        let store = SecretspecStore::load_from_with_metadata(
            &fixture.manifest,
            "default",
            format!("dotenv:{}", fixture.env_file.display()),
            scope(),
            Some(&metadata),
        )
        .unwrap();
        let descriptor = store.list().await.unwrap().remove(0);
        let profile_id = ProfileId::new("profile.CANARY").unwrap();
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: scope(),
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
            scope(),
        );
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );

        let listed = broker.list(&principal).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        assert!(listed[0].secret_ref.as_str().starts_with("sec_"));
        assert_eq!(listed[0].label.as_str(), "Canary token");
        assert!(!format!("{listed:?}").contains("expected-canary"));

        let value = broker
            .get(&SecretName::new("CANARY").unwrap(), &principal)
            .await
            .unwrap();
        assert_eq!(value.expose_bytes(), b"expected-canary");

        assert!(matches!(
            broker
                .get(&SecretName::new("OTHER").unwrap(), &principal)
                .await,
            Err(JanusError::NotInManifest { .. })
        ));

        let request = UseRequest {
            scope: scope(),
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
                &principal,
                &ExecutorRef::new("runner-a").unwrap(),
                &Destination::new("other-api").unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .is_err());

        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
                && !event.value_returned));
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

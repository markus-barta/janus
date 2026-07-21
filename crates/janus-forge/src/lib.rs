//! # janus-forge — the rotation / write broker (admin + script facing)
//!
//! Vulcan's forge: **makes and rotates** secrets. Write-side, deliberately
//! **not MCP** and **not LLM-driven** (architecture-v1: Warden guards read,
//! Forge makes/rotates). Rotation decisions consult the consumer registry so an
//! unknown consumer blocks one-click rotation (goal 5); `SecretStore::rotate` is
//! the backend value-change primitive, but the user-visible operation is the
//! broker-level lifecycle: plan → prepare → rotate → validate → reload.
//!
//! ## Backlog
//! - **JANUS-219** — Janus-Forge: issue + rotate `pharos-beacon` agent tokens
//!   (the first real Forge consumer)

#![forbid(unsafe_code)]

use async_trait::async_trait;
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, ConsumerDescriptor, ConsumerRef,
    ConsumerRegistry, JanusError, JanusResult, PrincipalChain, ReloadMethod, RotationDecision,
    RotationOutcome, RotationPhase, RotationPlanner, SafeLabel, SecretDescriptor, SecretName,
    SecretRef, SecretStore, SecretValue, Severity, ValidationProbe,
};
use janus_provider_age::{AgeRollbackMaterial, AgeSecretStore};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;

const URL_SAFE_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ALPHANUMERIC_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX_ALPHABET: &[u8] = b"0123456789abcdef";
const MAX_GENERATED_VALUE_LEN: usize = 4096;

/// Alphabet for broker-generated secret values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratedAlphabet {
    /// URL-safe base64url-ish characters without padding.
    UrlSafe,
    /// ASCII letters and digits.
    Alphanumeric,
    /// Lowercase hexadecimal characters.
    Hex,
}

impl GeneratedAlphabet {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::UrlSafe => URL_SAFE_ALPHABET,
            Self::Alphanumeric => ALPHANUMERIC_ALPHABET,
            Self::Hex => HEX_ALPHABET,
        }
    }
}

/// Policy for a broker-generated replacement value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedValuePolicy {
    alphabet: GeneratedAlphabet,
    length: usize,
}

impl GeneratedValuePolicy {
    /// Construct a generation policy.
    pub fn new(alphabet: GeneratedAlphabet, length: usize) -> JanusResult<Self> {
        if length == 0 || length > MAX_GENERATED_VALUE_LEN {
            return Err(JanusError::InvalidIdentifier {
                kind: "generated_value_length",
            });
        }
        Ok(Self { alphabet, length })
    }

    /// URL-safe generated value policy.
    pub fn url_safe(length: usize) -> JanusResult<Self> {
        Self::new(GeneratedAlphabet::UrlSafe, length)
    }

    /// ASCII alphanumeric generated value policy.
    pub fn alphanumeric(length: usize) -> JanusResult<Self> {
        Self::new(GeneratedAlphabet::Alphanumeric, length)
    }

    /// Lowercase hexadecimal generated value policy.
    pub fn hex(length: usize) -> JanusResult<Self> {
        Self::new(GeneratedAlphabet::Hex, length)
    }

    /// Configured output length.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Configured alphabet.
    pub fn alphabet(&self) -> GeneratedAlphabet {
        self.alphabet
    }

    /// Generate one bounded value for an internal write-side transaction.
    ///
    /// The returned value retains [`SecretValue`]'s redaction and zeroization
    /// guarantees and must never be emitted by an operator-facing outcome.
    pub fn generate_value(&self) -> SecretValue {
        let alphabet = self.alphabet.bytes();
        let mut rng = OsRng;
        let mut bytes = Vec::with_capacity(self.length);
        for _ in 0..self.length {
            let byte = alphabet
                .choose(&mut rng)
                .expect("static generated alphabets are non-empty");
            bytes.push(*byte);
        }
        SecretValue::new(bytes)
    }
}

/// Exact approval for a high-risk generated rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationApproval {
    secret_ref: SecretRef,
    reason: SafeLabel,
}

impl RotationApproval {
    /// Construct an approval bound to one secret ref and safe reason label.
    pub fn new(secret_ref: SecretRef, reason: SafeLabel) -> Self {
        Self { secret_ref, reason }
    }

    /// Approved secret ref.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Safe approval reason.
    pub fn reason(&self) -> &SafeLabel {
        &self.reason
    }
}

/// Backend contract for broker-managed generated rotation.
#[async_trait]
pub trait GeneratedRotationBackend: SecretStore {
    /// Provider-specific encrypted rollback handle.
    type Rollback: Send + Sync;

    /// Store a generated value and retain encrypted rollback material.
    async fn prepare_generated_rotation(
        &mut self,
        name: &SecretName,
        value: SecretValue,
    ) -> JanusResult<Self::Rollback>;

    /// Discard encrypted rollback material after validation/reload succeeds.
    async fn commit_generated_rotation(&mut self, rollback: &Self::Rollback) -> JanusResult<()>;

    /// Restore encrypted rollback material after validation/reload fails.
    async fn rollback_generated_rotation(&mut self, rollback: &Self::Rollback) -> JanusResult<()>;
}

#[async_trait]
impl GeneratedRotationBackend for AgeSecretStore {
    type Rollback = AgeRollbackMaterial;

    async fn prepare_generated_rotation(
        &mut self,
        name: &SecretName,
        value: SecretValue,
    ) -> JanusResult<Self::Rollback> {
        AgeSecretStore::prepare_generated_rotation(self, name, value).await
    }

    async fn commit_generated_rotation(&mut self, rollback: &Self::Rollback) -> JanusResult<()> {
        AgeSecretStore::commit_generated_rotation(self, rollback)
            .await
            .map(|_| ())
    }

    async fn rollback_generated_rotation(&mut self, rollback: &Self::Rollback) -> JanusResult<()> {
        AgeSecretStore::rollback_generated_rotation(self, rollback)
            .await
            .map(|_| ())
    }
}

/// Reviewed consumer-side actions for a generated rotation.
#[async_trait]
pub trait ConsumerRotationHooks {
    /// Run one value-free validation probe.
    async fn validate(&mut self, probe: &ValidationProbe) -> JanusResult<()>;

    /// Reload one declared consumer.
    async fn reload(&mut self, consumer: &ConsumerRef, method: &ReloadMethod) -> JanusResult<()>;
}

/// Forge write-side broker for generated rotation.
pub struct GeneratedRotationBroker<S, A, H> {
    store: S,
    consumers: ConsumerRegistry,
    audit: A,
    hooks: H,
}

impl<S, A, H> GeneratedRotationBroker<S, A, H> {
    /// Construct a broker from an approved backend, consumer registry, audit
    /// sink, and reviewed consumer hooks.
    pub fn new(store: S, consumers: ConsumerRegistry, audit: A, hooks: H) -> Self {
        Self {
            store,
            consumers,
            audit,
            hooks,
        }
    }

    /// Return broker parts for tests or controlled teardown.
    pub fn into_parts(self) -> (S, ConsumerRegistry, A, H) {
        (self.store, self.consumers, self.audit, self.hooks)
    }
}

impl<S, A, H> GeneratedRotationBroker<S, A, H>
where
    S: GeneratedRotationBackend,
    A: AuditSink,
    H: ConsumerRotationHooks,
{
    /// Execute a generated rotation end-to-end:
    /// generate, plan, prepare encrypted rollback material, validate, reload,
    /// commit.
    pub async fn rotate_generated(
        &mut self,
        name: &SecretName,
        policy: &GeneratedValuePolicy,
        approval: &RotationApproval,
        principal: &PrincipalChain,
    ) -> JanusResult<RotationOutcome> {
        let value = policy.generate_value();
        self.rotate_generated_with_value(name, value, approval, principal)
            .await
    }

    /// Execute a generated rotation with a caller-supplied value that was
    /// already produced inside an approved Forge path.
    ///
    /// Public/admin surfaces should prefer [`Self::rotate_generated`] so they
    /// never accept a replacement literal from argv, JSON, or logs.
    ///
    /// plan, prepare encrypted rollback material, validate, reload, commit.
    pub async fn rotate_generated_with_value(
        &mut self,
        name: &SecretName,
        value: SecretValue,
        approval: &RotationApproval,
        principal: &PrincipalChain,
    ) -> JanusResult<RotationOutcome> {
        let descriptor = self.descriptor_for_name(name).await?;
        if descriptor.scope != principal.scope {
            self.audit.record(AuditEvent::new(
                AuditAction::RotationApprove,
                AuditOutcome::Denied,
                "denied_scope_mismatch",
                Severity::Warning,
                Some(descriptor.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "descriptor scope does not match caller scope",
            ));
        }
        let secret_ref = descriptor.secret_ref;
        self.record_approval(&secret_ref, approval, principal)?;
        let decision = RotationPlanner::new(self.consumers.clone()).plan_generated_with_audit(
            &secret_ref,
            &self.store.capabilities(),
            &mut self.audit,
            principal,
        )?;
        let plan = match decision {
            RotationDecision::Safe(plan) => plan,
            RotationDecision::Unsafe {
                reason_code,
                detail,
            } => return Err(JanusError::policy_denied(reason_code, detail)),
        };
        let consumers = self
            .consumers
            .consumers_for(&secret_ref)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        let rollback = self
            .store
            .prepare_generated_rotation(name, value)
            .await
            .inspect_err(|_| {
                self.record_phase(
                    &secret_ref,
                    principal,
                    RotationPhase::Failed,
                    AuditOutcome::Denied,
                    "prepare_failed",
                    Severity::Warning,
                )
                .unwrap_or(());
            })?;
        self.record_after_prepare(&secret_ref, &rollback, principal)
            .await?;

        if let Err(err) = self
            .run_validations(&secret_ref, &plan.validation, principal)
            .await
        {
            self.rollback_after_failure(&secret_ref, &rollback, principal, "validation_failed")
                .await?;
            return Err(err);
        }
        self.record_phase(
            &secret_ref,
            principal,
            RotationPhase::Validated,
            AuditOutcome::Allowed,
            "validated",
            Severity::Notice,
        )?;

        if let Err(err) = self
            .reload_consumers(&secret_ref, &consumers, principal)
            .await
        {
            self.rollback_after_failure(&secret_ref, &rollback, principal, "reload_failed")
                .await?;
            return Err(err);
        }
        self.record_phase(
            &secret_ref,
            principal,
            RotationPhase::ConsumersUpdated,
            AuditOutcome::Allowed,
            "consumers_updated",
            Severity::Notice,
        )?;

        if let Err(err) = self.store.commit_generated_rotation(&rollback).await {
            self.rollback_after_failure(&secret_ref, &rollback, principal, "commit_failed")
                .await?;
            return Err(err);
        }
        self.record_phase(
            &secret_ref,
            principal,
            RotationPhase::Done,
            AuditOutcome::Allowed,
            "done",
            Severity::Notice,
        )?;

        Ok(RotationOutcome {
            secret_ref,
            phase: RotationPhase::Done,
            reason_code: "ok",
            value_returned: false,
        })
    }

    async fn descriptor_for_name(&self, name: &SecretName) -> JanusResult<SecretDescriptor> {
        self.store
            .list()
            .await?
            .into_iter()
            .find(|descriptor| &descriptor.name == name)
            .ok_or_else(|| JanusError::NotInManifest {
                name: name.as_str().to_string(),
            })
    }

    fn record_approval(
        &mut self,
        secret_ref: &SecretRef,
        approval: &RotationApproval,
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        if approval.secret_ref() != secret_ref {
            self.audit.record(AuditEvent::new(
                AuditAction::RotationApprove,
                AuditOutcome::Denied,
                "approval_secret_ref_mismatch",
                Severity::Warning,
                Some(secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(
                "approval_secret_ref_mismatch",
                "rotation approval does not match the target secret",
            ));
        }
        self.audit.record(
            AuditEvent::new(
                AuditAction::RotationApprove,
                AuditOutcome::Allowed,
                "approved",
                Severity::High,
                Some(secret_ref.clone()),
                principal,
            )
            .with_evidence(approval.reason().clone()),
        )
    }

    async fn record_after_prepare(
        &mut self,
        secret_ref: &SecretRef,
        rollback: &S::Rollback,
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        if let Err(err) = self.record_phase(
            secret_ref,
            principal,
            RotationPhase::Prepared,
            AuditOutcome::Allowed,
            "prepared",
            Severity::Notice,
        ) {
            self.rollback_after_failure(secret_ref, rollback, principal, "audit_failed")
                .await?;
            return Err(err);
        }
        if let Err(err) = self.record_phase(
            secret_ref,
            principal,
            RotationPhase::NewValueStored,
            AuditOutcome::Allowed,
            "new_value_stored",
            Severity::Notice,
        ) {
            self.rollback_after_failure(secret_ref, rollback, principal, "audit_failed")
                .await?;
            return Err(err);
        }
        Ok(())
    }

    async fn run_validations(
        &mut self,
        secret_ref: &SecretRef,
        probes: &[ValidationProbe],
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        for probe in probes {
            let result = self.hooks.validate(probe).await;
            let (outcome, reason_code, severity) = match &result {
                Ok(()) => (AuditOutcome::Allowed, "validated", Severity::Notice),
                Err(_) => (AuditOutcome::Denied, "validation_failed", Severity::Warning),
            };
            self.audit.record(
                AuditEvent::new(
                    AuditAction::ConsumerValidate,
                    outcome,
                    reason_code,
                    severity,
                    Some(secret_ref.clone()),
                    principal,
                )
                .with_evidence(SafeLabel::new(probe.as_str())?),
            )?;
            result?;
        }
        Ok(())
    }

    async fn reload_consumers(
        &mut self,
        secret_ref: &SecretRef,
        consumers: &[ConsumerDescriptor],
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        for consumer in consumers {
            if consumer.reload != ReloadMethod::None {
                let result = self
                    .hooks
                    .reload(&consumer.consumer_ref, &consumer.reload)
                    .await;
                let (outcome, reason_code, severity) = match &result {
                    Ok(()) => (AuditOutcome::Allowed, "reloaded", Severity::Notice),
                    Err(_) => (AuditOutcome::Denied, "reload_failed", Severity::Warning),
                };
                self.audit.record(
                    AuditEvent::new(
                        AuditAction::ConsumerReload,
                        outcome,
                        reason_code,
                        severity,
                        Some(secret_ref.clone()),
                        principal,
                    )
                    .with_evidence(reload_evidence(consumer)?),
                )?;
                result?;
            }
        }
        Ok(())
    }

    async fn rollback_after_failure(
        &mut self,
        secret_ref: &SecretRef,
        rollback: &S::Rollback,
        principal: &PrincipalChain,
        reason_code: &'static str,
    ) -> JanusResult<()> {
        match self.store.rollback_generated_rotation(rollback).await {
            Ok(()) => self.record_phase(
                secret_ref,
                principal,
                RotationPhase::RolledBack,
                AuditOutcome::Allowed,
                reason_code,
                Severity::High,
            ),
            Err(err) => {
                self.record_phase(
                    secret_ref,
                    principal,
                    RotationPhase::Failed,
                    AuditOutcome::Denied,
                    "rollback_failed",
                    Severity::Critical,
                )?;
                Err(err)
            }
        }
    }

    fn record_phase(
        &mut self,
        secret_ref: &SecretRef,
        principal: &PrincipalChain,
        _phase: RotationPhase,
        outcome: AuditOutcome,
        reason_code: &'static str,
        severity: Severity,
    ) -> JanusResult<()> {
        self.audit.record(AuditEvent::new(
            AuditAction::RotationLifecycle,
            outcome,
            reason_code,
            severity,
            Some(secret_ref.clone()),
            principal,
        ))
    }
}

fn reload_evidence(consumer: &ConsumerDescriptor) -> JanusResult<SafeLabel> {
    let reload_label = match &consumer.reload {
        ReloadMethod::None => "none",
        ReloadMethod::RestartService { service } => service.as_str(),
        ReloadMethod::Signal { signal } => signal.as_str(),
        ReloadMethod::ExecHook { hook } => hook.as_str(),
        ReloadMethod::ConnectorAction { action } => action.as_str(),
        ReloadMethod::Manual => "manual",
        ReloadMethod::Unsupported => "unsupported",
    };
    SafeLabel::new(format!(
        "{} {}",
        consumer.consumer_ref.as_str(),
        reload_label
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        AuditWrite, BlastRadius, ConsumerKind, Environment, HealthStatus, OwnerRef, ProfileId,
        RotationSpec, SafeLabel, ScopePathV1, ScopeRef, SecretClass, SecretDescriptor,
        SecretLifecycle, SecretMeta, StoreCapabilities, TrustLevel,
    };

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestRollback;

    struct TestStore {
        descriptor: SecretDescriptor,
        value: Vec<u8>,
        rollback_value: Option<Vec<u8>>,
        prepare_count: usize,
        commit_count: usize,
        rollback_count: usize,
        fail_commit: bool,
    }

    impl TestStore {
        fn new() -> (Self, SecretName, SecretRef) {
            let name = SecretName::new("CANARY").unwrap();
            let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
            let meta = SecretMeta {
                name: name.clone(),
                secret_ref: secret_ref.clone(),
                label: SafeLabel::new("Canary token").unwrap(),
                scope: scope(),
                owner: Some(OwnerRef::new("infra").unwrap()),
                classification: Some(SecretClass::Normal),
                lifecycle: SecretLifecycle::Active,
                required: true,
                trust_level: TrustLevel::L1,
                allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            };
            (
                Self {
                    descriptor: meta.descriptor(true),
                    value: b"old-canary".to_vec(),
                    rollback_value: None,
                    prepare_count: 0,
                    commit_count: 0,
                    rollback_count: 0,
                    fail_commit: false,
                },
                name,
                secret_ref,
            )
        }
    }

    #[async_trait]
    impl SecretStore for TestStore {
        fn capabilities(&self) -> StoreCapabilities {
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

        async fn health(&self) -> JanusResult<HealthStatus> {
            Ok(HealthStatus {
                backend: "test",
                ok: true,
                detail: "ok".to_string(),
            })
        }

        async fn list(&self) -> JanusResult<Vec<SecretDescriptor>> {
            Ok(vec![self.descriptor.clone()])
        }

        async fn get(&self, name: &SecretName) -> JanusResult<SecretValue> {
            if name != &self.descriptor.name {
                return Err(JanusError::NotInManifest {
                    name: name.as_str().to_string(),
                });
            }
            Ok(SecretValue::new(self.value.clone()))
        }

        async fn set(&mut self, name: &SecretName, value: SecretValue) -> JanusResult<()> {
            if name != &self.descriptor.name {
                return Err(JanusError::NotInManifest {
                    name: name.as_str().to_string(),
                });
            }
            self.value = value.expose_bytes().to_vec();
            Ok(())
        }

        async fn rotate(
            &mut self,
            name: &SecretName,
            spec: &RotationSpec,
        ) -> JanusResult<RotationOutcome> {
            let value = spec
                .generated_value
                .as_ref()
                .ok_or(JanusError::Unsupported {
                    capability: "generated_value",
                })?;
            self.set(name, SecretValue::new(value.expose_bytes().to_vec()))
                .await?;
            Ok(RotationOutcome::rotated(self.descriptor.secret_ref.clone()))
        }

        async fn delete(&mut self, name: &SecretName) -> JanusResult<()> {
            if name != &self.descriptor.name {
                return Err(JanusError::NotInManifest {
                    name: name.as_str().to_string(),
                });
            }
            self.value.clear();
            Ok(())
        }
    }

    #[async_trait]
    impl GeneratedRotationBackend for TestStore {
        type Rollback = TestRollback;

        async fn prepare_generated_rotation(
            &mut self,
            name: &SecretName,
            value: SecretValue,
        ) -> JanusResult<Self::Rollback> {
            if name != &self.descriptor.name {
                return Err(JanusError::NotInManifest {
                    name: name.as_str().to_string(),
                });
            }
            self.prepare_count += 1;
            self.rollback_value = Some(self.value.clone());
            self.value = value.expose_bytes().to_vec();
            Ok(TestRollback)
        }

        async fn commit_generated_rotation(
            &mut self,
            _rollback: &Self::Rollback,
        ) -> JanusResult<()> {
            self.commit_count += 1;
            if self.fail_commit {
                return Err(JanusError::StoreUnavailable {
                    detail: "commit failed".to_string(),
                });
            }
            self.rollback_value = None;
            Ok(())
        }

        async fn rollback_generated_rotation(
            &mut self,
            _rollback: &Self::Rollback,
        ) -> JanusResult<()> {
            self.rollback_count += 1;
            let old = self
                .rollback_value
                .take()
                .ok_or_else(|| JanusError::NotFound {
                    name: self.descriptor.secret_ref.as_str().to_string(),
                })?;
            self.value = old;
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestHooks {
        validations: Vec<String>,
        reloads: Vec<String>,
        fail_validation: bool,
        fail_reload: bool,
    }

    #[async_trait]
    impl ConsumerRotationHooks for TestHooks {
        async fn validate(&mut self, probe: &ValidationProbe) -> JanusResult<()> {
            self.validations.push(probe.as_str().to_string());
            if self.fail_validation {
                return Err(JanusError::policy_denied(
                    "validation_failed",
                    "validation probe failed",
                ));
            }
            Ok(())
        }

        async fn reload(
            &mut self,
            consumer: &ConsumerRef,
            _method: &ReloadMethod,
        ) -> JanusResult<()> {
            self.reloads.push(consumer.as_str().to_string());
            if self.fail_reload {
                return Err(JanusError::policy_denied(
                    "reload_failed",
                    "consumer reload failed",
                ));
            }
            Ok(())
        }
    }

    fn principal() -> PrincipalChain {
        janus_core::PrincipalChain::new(
            janus_core::Principal::new(
                janus_core::PrincipalKind::Executor,
                janus_core::PrincipalId::new("forge-admin").unwrap(),
            ),
            scope(),
        )
    }

    fn approval(secret_ref: &SecretRef) -> RotationApproval {
        RotationApproval::new(
            secret_ref.clone(),
            SafeLabel::new("JANUS-21 generated rotation").unwrap(),
        )
    }

    fn consumer(secret_ref: SecretRef, validation: Vec<ValidationProbe>) -> ConsumerDescriptor {
        ConsumerDescriptor {
            scope: scope(),
            consumer_ref: ConsumerRef::new("consumer.deploy").unwrap(),
            secret_ref,
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new("infra").unwrap(),
            environment: Environment::new("prod").unwrap(),
            reload: ReloadMethod::ExecHook {
                hook: SafeLabel::new("reload deploy").unwrap(),
            },
            validation,
            supports_dual_value: false,
            blast_radius: BlastRadius::new("release-publishing").unwrap(),
            declared: true,
        }
    }

    fn lifecycle_reasons(audit: &AuditWrite) -> Vec<&'static str> {
        audit
            .events()
            .iter()
            .filter(|event| event.action == AuditAction::RotationLifecycle)
            .map(|event| event.reason_code)
            .collect()
    }

    fn reasons_for(audit: &AuditWrite, action: AuditAction) -> Vec<&'static str> {
        audit
            .events()
            .iter()
            .filter(|event| event.action == action)
            .map(|event| event.reason_code)
            .collect()
    }

    fn is_url_safe(bytes: &[u8]) -> bool {
        bytes
            .iter()
            .all(|byte| URL_SAFE_ALPHABET.iter().any(|allowed| allowed == byte))
    }

    #[tokio::test]
    async fn generated_rotation_generates_value_and_commits_after_validation_and_reload() {
        let (store, name, secret_ref) = TestStore::new();
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref.clone(),
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let mut broker = GeneratedRotationBroker::new(
            store,
            registry,
            AuditWrite::accepting(),
            TestHooks::default(),
        );

        let outcome = broker
            .rotate_generated(
                &name,
                &GeneratedValuePolicy::url_safe(48).unwrap(),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap();
        assert_eq!(outcome.secret_ref, secret_ref);
        assert_eq!(outcome.phase, RotationPhase::Done);
        assert!(!outcome.value_returned);

        let (store, _registry, audit, hooks) = broker.into_parts();
        assert_eq!(store.value.len(), 48);
        assert!(is_url_safe(&store.value));
        assert_ne!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 1);
        assert_eq!(store.commit_count, 1);
        assert_eq!(store.rollback_count, 0);
        assert_eq!(hooks.validations, vec!["deploy-smoke"]);
        assert_eq!(hooks.reloads, vec!["consumer.deploy"]);
        assert_eq!(
            reasons_for(&audit, AuditAction::ConsumerValidate),
            vec!["validated"]
        );
        assert_eq!(
            reasons_for(&audit, AuditAction::ConsumerReload),
            vec!["reloaded"]
        );
        assert_eq!(
            lifecycle_reasons(&audit),
            vec![
                "prepared",
                "new_value_stored",
                "validated",
                "consumers_updated",
                "done"
            ]
        );
        assert!(audit.events().iter().all(|event| {
            !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));
        let approval_event = audit
            .events()
            .iter()
            .find(|event| event.action == AuditAction::RotationApprove)
            .unwrap();
        assert_eq!(approval_event.outcome, AuditOutcome::Allowed);
        assert_eq!(approval_event.reason_code, "approved");
        assert_eq!(
            approval_event.evidence.as_ref().unwrap().as_str(),
            "JANUS-21 generated rotation"
        );
        let rendered_audit = format!("{:?}", audit.events());
        assert!(!rendered_audit.contains(std::str::from_utf8(&store.value).unwrap()));
    }

    #[tokio::test]
    async fn validation_failure_rolls_back_without_commit() {
        let (store, name, secret_ref) = TestStore::new();
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref.clone(),
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let hooks = TestHooks {
            fail_validation: true,
            ..TestHooks::default()
        };
        let mut broker =
            GeneratedRotationBroker::new(store, registry, AuditWrite::accepting(), hooks);

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-roll-back".to_vec()),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "validation_failed",
                ..
            }
        ));

        let (store, _registry, audit, hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 1);
        assert_eq!(store.commit_count, 0);
        assert_eq!(store.rollback_count, 1);
        assert_eq!(hooks.validations, vec!["deploy-smoke"]);
        assert!(hooks.reloads.is_empty());
        assert_eq!(
            reasons_for(&audit, AuditAction::ConsumerValidate),
            vec!["validation_failed"]
        );
        assert!(reasons_for(&audit, AuditAction::ConsumerReload).is_empty());
        assert_eq!(
            lifecycle_reasons(&audit),
            vec!["prepared", "new_value_stored", "validation_failed"]
        );
    }

    #[tokio::test]
    async fn reload_failure_rolls_back_without_commit() {
        let (store, name, secret_ref) = TestStore::new();
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref.clone(),
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let hooks = TestHooks {
            fail_reload: true,
            ..TestHooks::default()
        };
        let mut broker =
            GeneratedRotationBroker::new(store, registry, AuditWrite::accepting(), hooks);

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-roll-back".to_vec()),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "reload_failed",
                ..
            }
        ));

        let (store, _registry, audit, hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 1);
        assert_eq!(store.commit_count, 0);
        assert_eq!(store.rollback_count, 1);
        assert_eq!(hooks.validations, vec!["deploy-smoke"]);
        assert_eq!(hooks.reloads, vec!["consumer.deploy"]);
        assert_eq!(
            reasons_for(&audit, AuditAction::ConsumerValidate),
            vec!["validated"]
        );
        assert_eq!(
            reasons_for(&audit, AuditAction::ConsumerReload),
            vec!["reload_failed"]
        );
        assert_eq!(
            lifecycle_reasons(&audit),
            vec!["prepared", "new_value_stored", "validated", "reload_failed"]
        );
    }

    #[tokio::test]
    async fn commit_failure_rolls_back_without_done() {
        let (mut store, name, secret_ref) = TestStore::new();
        store.fail_commit = true;
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref.clone(),
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let mut broker = GeneratedRotationBroker::new(
            store,
            registry,
            AuditWrite::accepting(),
            TestHooks::default(),
        );

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-roll-back".to_vec()),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JanusError::StoreUnavailable { .. }));

        let (store, _registry, audit, hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 1);
        assert_eq!(store.commit_count, 1);
        assert_eq!(store.rollback_count, 1);
        assert_eq!(hooks.validations, vec!["deploy-smoke"]);
        assert_eq!(hooks.reloads, vec!["consumer.deploy"]);
        assert_eq!(
            lifecycle_reasons(&audit),
            vec![
                "prepared",
                "new_value_stored",
                "validated",
                "consumers_updated",
                "commit_failed"
            ]
        );
    }

    #[tokio::test]
    async fn unsafe_plan_blocks_before_prepare() {
        let (store, name, secret_ref) = TestStore::new();
        let mut broker = GeneratedRotationBroker::new(
            store,
            ConsumerRegistry::default(),
            AuditWrite::accepting(),
            TestHooks::default(),
        );

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-not-write".to_vec()),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "unknown_consumers",
                ..
            }
        ));
        let (store, _registry, audit, _hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 0);
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::RotationPlan
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "unknown_consumers"
        }));
    }

    #[tokio::test]
    async fn audit_failure_blocks_before_prepare() {
        let (store, name, secret_ref) = TestStore::new();
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref.clone(),
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let mut broker = GeneratedRotationBroker::new(
            store,
            registry,
            AuditWrite::failing(),
            TestHooks::default(),
        );

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-not-write".to_vec()),
                &approval(&secret_ref),
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JanusError::AuditUnavailable { .. }));
        let (store, _registry, _audit, hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 0);
        assert!(hooks.validations.is_empty());
        assert!(hooks.reloads.is_empty());
    }

    #[tokio::test]
    async fn approval_mismatch_blocks_before_prepare() {
        let (store, name, secret_ref) = TestStore::new();
        let registry = ConsumerRegistry::new(vec![consumer(
            secret_ref,
            vec![ValidationProbe::new("deploy-smoke").unwrap()],
        )]);
        let wrong_approval = RotationApproval::new(
            SecretRef::new("sec_wrong").unwrap(),
            SafeLabel::new("wrong ticket").unwrap(),
        );
        let mut broker = GeneratedRotationBroker::new(
            store,
            registry,
            AuditWrite::accepting(),
            TestHooks::default(),
        );

        let err = broker
            .rotate_generated_with_value(
                &name,
                SecretValue::new(b"should-not-write".to_vec()),
                &wrong_approval,
                &principal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "approval_secret_ref_mismatch",
                ..
            }
        ));
        let (store, _registry, audit, hooks) = broker.into_parts();
        assert_eq!(store.value, b"old-canary");
        assert_eq!(store.prepare_count, 0);
        assert!(hooks.validations.is_empty());
        assert!(hooks.reloads.is_empty());
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::RotationApprove
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "approval_secret_ref_mismatch"
        }));
    }

    #[test]
    fn generated_value_policy_validates_length_and_alphabet() {
        assert!(GeneratedValuePolicy::url_safe(0).is_err());
        assert!(GeneratedValuePolicy::url_safe(MAX_GENERATED_VALUE_LEN + 1).is_err());
        let policy = GeneratedValuePolicy::hex(32).unwrap();
        assert_eq!(policy.length(), 32);
        assert_eq!(policy.alphabet(), GeneratedAlphabet::Hex);
        let value = policy.generate_value();
        assert_eq!(value.expose_bytes().len(), 32);
        assert!(value
            .expose_bytes()
            .iter()
            .all(|byte| { HEX_ALPHABET.iter().any(|allowed| allowed == byte) }));
        assert!(!format!("{policy:?}").contains(std::str::from_utf8(value.expose_bytes()).unwrap()));
    }
}

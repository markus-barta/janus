//! Approved-use execution skeleton.
//!
//! This crate is the first JANUS-28 execution-layer shape: it consumes an
//! opaque [`janus_core::UsePermit`] through the broker, re-checks principal,
//! executor, destination, expiry, manifest membership, and required audit, then
//! hands the secret value only to managed-command internals. Public outcomes are
//! value-free.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::SystemTime;

use janus_core::{
    AuditSink, ConsumerDescriptor, ConsumerKind, ConsumerRef, Destination, ExecutorRef, JanusError,
    JanusResult, PrincipalChain, ProfileId, SafeLabel, SecretBroker, SecretRef, SecretStore,
    SecretValue, UsePermit,
};

/// Request to consume one approved-use permit.
pub struct ApprovedUseInvocation<'a> {
    /// Opaque permit issued by Warden/broker policy.
    pub permit: &'a UsePermit,
    /// Principal chain attempting execution.
    pub principal: &'a PrincipalChain,
    /// Executor identity for this execution path.
    pub executor: ExecutorRef,
    /// Destination this execution path is allowed to reach.
    pub destination: Destination,
    /// Environment variable used by the reviewed managed command profile.
    pub env_name: SafeLabel,
    /// Time used for permit expiry checks.
    pub now: SystemTime,
}

/// Secret-bearing binding visible only inside the managed execution callback.
pub struct SecretEnvBinding<'a> {
    env_name: SafeLabel,
    value: &'a SecretValue,
}

impl SecretEnvBinding<'_> {
    /// Reviewed environment variable name.
    pub fn env_name(&self) -> &SafeLabel {
        &self.env_name
    }

    /// Borrow the secret bytes for immediate child-process environment setup.
    ///
    /// This is intentionally available only inside the executor callback. The
    /// returned [`ApprovedUseOutcome`] is value-free.
    pub fn expose_value_bytes(&self) -> &[u8] {
        self.value.expose_bytes()
    }
}

/// Value-free result of an approved execution attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedUseOutcome {
    /// Secret used by opaque reference only.
    pub secret_ref: SecretRef,
    /// Reviewed profile bound to the permit.
    pub profile_id: ProfileId,
    /// Executor that successfully consumed the permit.
    pub executor: ExecutorRef,
    /// Destination bound to the execution.
    pub destination: Destination,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Minimal approved-use executor over a Janus broker.
pub struct ApprovedUseExecutor<S, A> {
    broker: SecretBroker<S, A>,
}

/// Reviewable managed-command profile config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandProfileSpec {
    /// Profile id also used by Warden permit requests.
    pub profile_id: ProfileId,
    /// Secret consumed by this profile.
    pub secret_ref: SecretRef,
    /// Executor allowed to run the profile.
    pub executor: ExecutorRef,
    /// Destination owned by the profile.
    pub destination: Destination,
    /// Environment variable that receives the secret inside the child process.
    pub env_name: SafeLabel,
    /// Reviewed executable path. Must be absolute.
    pub binary: PathBuf,
    /// Exact reviewed argv for this first skeleton.
    pub allowed_args: Vec<String>,
    /// Declared consumer metadata used by rotation evidence.
    pub consumer: ConsumerDescriptor,
}

/// A reviewed managed command profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandProfile {
    profile_id: ProfileId,
    secret_ref: SecretRef,
    executor: ExecutorRef,
    destination: Destination,
    env_name: SafeLabel,
    binary: PathBuf,
    allowed_args: Vec<String>,
    consumer: ConsumerDescriptor,
}

impl ManagedCommandProfile {
    /// Build a profile from reviewed typed config.
    pub fn new(spec: ManagedCommandProfileSpec) -> JanusResult<Self> {
        if !spec.binary.is_absolute() {
            return Err(JanusError::InvalidManifest {
                detail: "managed command binary must be an absolute path".to_string(),
            });
        }
        for arg in &spec.allowed_args {
            if arg.trim().is_empty() || arg.trim().len() != arg.len() {
                return Err(JanusError::InvalidIdentifier {
                    kind: "managed_command_arg",
                });
            }
        }
        if spec.consumer.kind != ConsumerKind::ManagedCommand {
            return Err(JanusError::InvalidManifest {
                detail: "managed command profile requires a managed-command consumer".to_string(),
            });
        }
        if spec.consumer.secret_ref != spec.secret_ref {
            return Err(JanusError::InvalidManifest {
                detail: "managed command consumer must reference the profile secret".to_string(),
            });
        }
        Ok(Self {
            profile_id: spec.profile_id,
            secret_ref: spec.secret_ref,
            executor: spec.executor,
            destination: spec.destination,
            env_name: spec.env_name,
            binary: spec.binary,
            allowed_args: spec.allowed_args,
            consumer: spec.consumer,
        })
    }

    /// Profile id bound to this managed command.
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Secret ref bound to this managed command.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Executor bound to this managed command.
    pub fn executor(&self) -> &ExecutorRef {
        &self.executor
    }

    /// Destination bound to this managed command.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Environment variable that receives the secret.
    pub fn env_name(&self) -> &SafeLabel {
        &self.env_name
    }

    /// Reviewed executable path.
    pub fn binary(&self) -> &PathBuf {
        &self.binary
    }

    /// Exact reviewed argv for this first skeleton.
    pub fn allowed_args(&self) -> &[String] {
        &self.allowed_args
    }

    /// Declared consumer ref for observation/rotation evidence.
    pub fn consumer_ref(&self) -> &ConsumerRef {
        &self.consumer.consumer_ref
    }

    /// Declared consumer metadata used for observation evidence.
    pub fn consumer(&self) -> &ConsumerDescriptor {
        &self.consumer
    }

    fn plan_for_args(&self, requested_args: &[String]) -> JanusResult<ManagedCommandPlan> {
        if requested_args != self.allowed_args.as_slice() {
            return Err(JanusError::policy_denied(
                "denied_unreviewed_command_args",
                "managed command arguments are not exactly reviewed by the profile",
            ));
        }
        Ok(ManagedCommandPlan {
            profile_id: self.profile_id.clone(),
            secret_ref: self.secret_ref.clone(),
            executor: self.executor.clone(),
            destination: self.destination.clone(),
            env_name: self.env_name.clone(),
            binary: self.binary.clone(),
            args: self.allowed_args.clone(),
            consumer_ref: self.consumer.consumer_ref.clone(),
            value_returned: false,
        })
    }
}

/// Caller request for a reviewed managed command.
pub struct ManagedCommandRequest<'a> {
    /// Reviewed profile.
    pub profile: &'a ManagedCommandProfile,
    /// Opaque permit to consume.
    pub permit: &'a UsePermit,
    /// Principal chain attempting execution.
    pub principal: &'a PrincipalChain,
    /// Caller-supplied argv candidate. Must exactly match the profile.
    pub requested_args: Vec<String>,
    /// Time used for permit expiry checks.
    pub now: SystemTime,
}

/// Value-free execution plan for a managed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandPlan {
    /// Reviewed profile id.
    pub profile_id: ProfileId,
    /// Opaque secret ref.
    pub secret_ref: SecretRef,
    /// Reviewed executor.
    pub executor: ExecutorRef,
    /// Reviewed destination.
    pub destination: Destination,
    /// Reviewed env var name.
    pub env_name: SafeLabel,
    /// Reviewed binary.
    pub binary: PathBuf,
    /// Reviewed argv.
    pub args: Vec<String>,
    /// Declared consumer.
    pub consumer_ref: ConsumerRef,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Secret-bearing execution context available only inside the executor callback.
pub struct ManagedCommandExecution<'a> {
    plan: &'a ManagedCommandPlan,
    binding: SecretEnvBinding<'a>,
}

impl ManagedCommandExecution<'_> {
    /// Value-free command plan.
    pub fn plan(&self) -> &ManagedCommandPlan {
        self.plan
    }

    /// Secret env binding for immediate child-process setup.
    pub fn binding(&self) -> &SecretEnvBinding<'_> {
        &self.binding
    }
}

/// Managed command output after Janus redaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandOutput {
    /// Redacted stdout.
    pub stdout: String,
    /// Redacted stderr.
    pub stderr: String,
    /// Invariant marker.
    pub value_returned: bool,
}

impl ManagedCommandOutput {
    /// Construct output from raw process text. The executor applies known-value
    /// redaction before returning it.
    pub fn from_raw(stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: stderr.into(),
            value_returned: false,
        }
    }

    fn redact_known_value(mut self, value: &SecretValue) -> Self {
        if let Ok(secret) = std::str::from_utf8(value.expose_bytes()) {
            if !secret.is_empty() {
                self.stdout = self.stdout.replace(secret, "[REDACTED]");
                self.stderr = self.stderr.replace(secret, "[REDACTED]");
            }
        }
        self.value_returned = false;
        self
    }
}

/// Value-free managed command execution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandOutcome {
    /// Value-free reviewed plan.
    pub plan: ManagedCommandPlan,
    /// Redacted command output.
    pub output: ManagedCommandOutput,
    /// Invariant marker.
    pub value_returned: bool,
}

impl<S, A> ApprovedUseExecutor<S, A>
where
    S: SecretStore,
    A: AuditSink,
{
    /// Construct from the policy/audit broker.
    pub fn new(broker: SecretBroker<S, A>) -> Self {
        Self { broker }
    }

    /// Consume a permit and run secret-bearing internals without returning a
    /// literal to the caller.
    pub async fn execute_with_secret<F>(
        &mut self,
        invocation: ApprovedUseInvocation<'_>,
        execute: F,
    ) -> JanusResult<ApprovedUseOutcome>
    where
        F: FnOnce(SecretEnvBinding<'_>) -> JanusResult<()>,
    {
        let value = self
            .broker
            .use_permit(
                invocation.permit,
                invocation.principal,
                &invocation.executor,
                &invocation.destination,
                invocation.now,
            )
            .await?;
        let outcome = ApprovedUseOutcome {
            secret_ref: invocation.permit.secret_ref().clone(),
            profile_id: invocation.permit.profile_id().clone(),
            executor: invocation.executor,
            destination: invocation.destination,
            value_returned: false,
        };
        execute(SecretEnvBinding {
            env_name: invocation.env_name,
            value: &value,
        })?;
        Ok(outcome)
    }

    /// Execute a reviewed managed-command profile without spawning a process in
    /// this skeleton. The callback stands in for child-process setup; Janus
    /// still validates the reviewed profile and redacts output.
    pub async fn execute_managed_command<F>(
        &mut self,
        request: ManagedCommandRequest<'_>,
        execute: F,
    ) -> JanusResult<ManagedCommandOutcome>
    where
        F: FnOnce(ManagedCommandExecution<'_>) -> JanusResult<ManagedCommandOutput>,
    {
        if request.permit.profile_id() != request.profile.profile_id() {
            return Err(JanusError::permit_invalid(
                "denied_profile_mismatch",
                "permit profile does not match managed command profile",
            ));
        }
        if request.permit.secret_ref() != request.profile.secret_ref() {
            return Err(JanusError::permit_invalid(
                "denied_secret_mismatch",
                "permit secret does not match managed command profile",
            ));
        }
        let plan = request.profile.plan_for_args(&request.requested_args)?;
        let value = self
            .broker
            .use_permit(
                request.permit,
                request.principal,
                request.profile.executor(),
                request.profile.destination(),
                request.now,
            )
            .await?;
        let output = execute(ManagedCommandExecution {
            plan: &plan,
            binding: SecretEnvBinding {
                env_name: request.profile.env_name().clone(),
                value: &value,
            },
        })?
        .redact_known_value(&value);
        self.broker
            .record_consumer_observe(request.profile.consumer(), request.principal)?;
        Ok(ManagedCommandOutcome {
            plan,
            output,
            value_returned: false,
        })
    }

    /// Consume and return the underlying broker for inspection or embedding.
    pub fn into_broker(self) -> SecretBroker<S, A> {
        self.broker
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, BlastRadius, ConsumerDescriptor, ConsumerKind,
        ConsumerRef, EgressMode, Environment, JanusError, ManifestCatalog, OwnerRef, Principal,
        PrincipalId, PrincipalKind, ProfilePolicy, ProjectId, Purpose, ReloadMethod, SafeLabel,
        ScopeRef, SecretMeta, SecretName, TrustLevel, UseProfile, UseRequest, ValidationProbe,
    };
    use janus_mock::MockStore;

    use super::*;

    const START: SystemTime = SystemTime::UNIX_EPOCH;

    fn run_at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1)
    }

    fn principal(executor: &str, scope: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            ScopeRef::new(scope).unwrap(),
        )
    }

    async fn executor_fixture() -> (
        ApprovedUseExecutor<MockStore, AuditWrite>,
        janus_core::UsePermit,
        PrincipalChain,
        ExecutorRef,
        Destination,
        ManagedCommandProfile,
    ) {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id.clone()],
        }])
        .unwrap();
        let store = MockStore::new(catalog)
            .with_value(name, b"expected-canary".to_vec())
            .unwrap();
        let executor = ExecutorRef::new("janus-run@m5").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let managed_profile = managed_command_profile(
            profile_id.clone(),
            secret_ref.clone(),
            executor.clone(),
            destination.clone(),
        );
        let profile = UseProfile {
            id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let principal = principal("janus-run@m5", "janus/dev");
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );
        let permit = broker
            .request_use(
                &UseRequest {
                    secret_ref,
                    profile_id,
                    destination: destination.clone(),
                    purpose: Purpose::new("deploy canary").unwrap(),
                },
                &principal,
                START,
            )
            .await
            .unwrap();
        (
            ApprovedUseExecutor::new(broker),
            permit,
            principal,
            executor,
            destination,
            managed_profile,
        )
    }

    fn managed_command_profile(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
    ) -> ManagedCommandProfile {
        ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id,
            secret_ref: secret_ref.clone(),
            executor,
            destination,
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("/usr/bin/gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            consumer: ConsumerDescriptor {
                consumer_ref: ConsumerRef::new("consumer.github_release_publish").unwrap(),
                secret_ref,
                kind: ConsumerKind::ManagedCommand,
                owner: OwnerRef::new("infra").unwrap(),
                environment: Environment::new("prod").unwrap(),
                reload: ReloadMethod::None,
                validation: vec![ValidationProbe::new("gh-auth-status").unwrap()],
                supports_dual_value: false,
                blast_radius: BlastRadius::new("release-publishing").unwrap(),
                declared: true,
            },
        })
        .unwrap()
    }

    fn invocation<'a>(
        permit: &'a UsePermit,
        principal: &'a PrincipalChain,
        executor: ExecutorRef,
        destination: Destination,
    ) -> ApprovedUseInvocation<'a> {
        ApprovedUseInvocation {
            permit,
            principal,
            executor,
            destination,
            env_name: SafeLabel::new("CANARY_TOKEN").unwrap(),
            now: run_at(),
        }
    }

    #[tokio::test]
    async fn approved_execution_consumes_permit_without_returning_literal() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let mut callback_saw_value = false;

        let outcome = executor
            .execute_with_secret(
                invocation(&permit, &principal, executor_ref, destination),
                |binding| {
                    assert_eq!(binding.env_name().as_str(), "CANARY_TOKEN");
                    assert_eq!(binding.expose_value_bytes(), b"expected-canary");
                    callback_saw_value = true;
                    Ok(())
                },
            )
            .await
            .unwrap();

        assert!(callback_saw_value);
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));
    }

    #[tokio::test]
    async fn wrong_destination_fails_before_secret_exposure() {
        let (mut executor, permit, principal, executor_ref, _destination, _profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(
                    &permit,
                    &principal,
                    executor_ref,
                    Destination::new("attacker-api").unwrap(),
                ),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_unapproved_destination",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_unapproved_destination"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn wrong_executor_fails_before_secret_exposure() {
        let (mut executor, permit, principal, _executor_ref, destination, _profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(
                    &permit,
                    &principal,
                    ExecutorRef::new("janus-run@other-host").unwrap(),
                    destination,
                ),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_wrong_executor",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_wrong_executor"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn wrong_principal_fails_before_secret_exposure() {
        let (mut executor, permit, _principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let wrong_principal = principal("janus-run@m5", "janus/prod");
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(&permit, &wrong_principal, executor_ref, destination),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_wrong_principal",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_wrong_principal"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn managed_command_profile_builds_reviewed_plan_and_redacts_output() {
        let (mut executor, permit, principal, _executor_ref, _destination, profile) =
            executor_fixture().await;
        let mut callback_saw_value = false;

        let outcome = executor
            .execute_managed_command(
                ManagedCommandRequest {
                    profile: &profile,
                    permit: &permit,
                    principal: &principal,
                    requested_args: vec!["release".to_string(), "upload".to_string()],
                    now: run_at(),
                },
                |execution| {
                    assert_eq!(execution.plan().binary, PathBuf::from("/usr/bin/gh"));
                    assert_eq!(
                        execution.plan().args,
                        vec!["release".to_string(), "upload".to_string()]
                    );
                    assert_eq!(&execution.plan().consumer_ref, profile.consumer_ref());
                    assert_eq!(execution.binding().env_name().as_str(), "GITHUB_TOKEN");
                    assert_eq!(execution.binding().expose_value_bytes(), b"expected-canary");
                    callback_saw_value = true;
                    Ok(ManagedCommandOutput::from_raw(
                        "uploaded with expected-canary",
                        "debug expected-canary",
                    ))
                },
            )
            .await
            .unwrap();

        assert!(callback_saw_value);
        assert!(!outcome.value_returned);
        assert!(!outcome.plan.value_returned);
        assert_eq!(outcome.output.stdout, "uploaded with [REDACTED]");
        assert_eq!(outcome.output.stderr, "debug [REDACTED]");
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::ConsumerObserve
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && event.secret_ref.as_ref() == Some(profile.secret_ref())
                && event
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.as_str() == profile.consumer_ref().as_str())
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));
    }

    #[tokio::test]
    async fn managed_command_rejects_unreviewed_args_before_secret_exposure() {
        let (mut executor, permit, principal, _executor_ref, _destination, profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_managed_command(
                ManagedCommandRequest {
                    profile: &profile,
                    permit: &permit,
                    principal: &principal,
                    requested_args: vec![
                        "release".to_string(),
                        "upload".to_string(),
                        "--repo".to_string(),
                        "attacker/repo".to_string(),
                    ],
                    now: run_at(),
                },
                |_execution| {
                    callback_called = true;
                    Ok(ManagedCommandOutput::from_raw("expected-canary", ""))
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_unreviewed_command_args",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse));
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::ConsumerObserve));
    }

    #[test]
    fn managed_command_profile_requires_absolute_binary_and_matching_consumer() {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let executor = ExecutorRef::new("janus-run@m5").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let wrong_consumer_secret = SecretRef::new("sec_other").unwrap();
        let consumer = ConsumerDescriptor {
            consumer_ref: ConsumerRef::new("consumer.github_release_publish").unwrap(),
            secret_ref: secret_ref.clone(),
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new("infra").unwrap(),
            environment: Environment::new("prod").unwrap(),
            reload: ReloadMethod::None,
            validation: vec![ValidationProbe::new("gh-auth-status").unwrap()],
            supports_dual_value: false,
            blast_radius: BlastRadius::new("release-publishing").unwrap(),
            declared: true,
        };

        let relative_binary = ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            consumer: consumer.clone(),
        });
        assert!(matches!(
            relative_binary,
            Err(JanusError::InvalidManifest { .. })
        ));

        let wrong_consumer = ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id,
            secret_ref,
            executor,
            destination,
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("/usr/bin/gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            consumer: ConsumerDescriptor {
                secret_ref: wrong_consumer_secret,
                ..consumer
            },
        });
        assert!(matches!(
            wrong_consumer,
            Err(JanusError::InvalidManifest { .. })
        ));
    }
}

//! Approved-use execution skeleton.
//!
//! This crate is the first JANUS-28 execution-layer shape: it consumes an
//! opaque [`janus_core::UsePermit`] through the broker, re-checks principal,
//! executor, destination, expiry, manifest membership, and required audit, then
//! hands the secret value only to managed-command internals. Public outcomes are
//! value-free.

#![forbid(unsafe_code)]

use std::time::SystemTime;

use janus_core::{
    AuditSink, Destination, ExecutorRef, JanusResult, PrincipalChain, ProfileId, SafeLabel,
    SecretBroker, SecretRef, SecretStore, SecretValue, UsePermit,
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

    /// Consume and return the underlying broker for inspection or embedding.
    pub fn into_broker(self) -> SecretBroker<S, A> {
        self.broker
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, EgressMode, JanusError, ManifestCatalog, Principal,
        PrincipalId, PrincipalKind, ProfilePolicy, ProjectId, Purpose, SafeLabel, ScopeRef,
        SecretMeta, SecretName, TrustLevel, UseProfile, UseRequest,
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
        )
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
        let (mut executor, permit, principal, executor_ref, destination) = executor_fixture().await;
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
        let (mut executor, permit, principal, executor_ref, _destination) =
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
        let (mut executor, permit, principal, _executor_ref, destination) =
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
        let (mut executor, permit, _principal, executor_ref, destination) =
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
}

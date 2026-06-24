//! Minimal core broker tying store, policy, and audit together.

use std::time::SystemTime;

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PermitIssuer,
    PrincipalChain, ProfilePolicy, SecretDescriptor, SecretName, SecretStore, SecretValue,
    Severity, UsePermit, UseRequest,
};

/// Policy/audit wrapper around a backend store.
pub struct SecretBroker<S, A> {
    store: S,
    policy: ProfilePolicy,
    audit: A,
}

impl<S, A> SecretBroker<S, A>
where
    S: SecretStore,
    A: AuditSink,
{
    /// Construct a broker from a store, policy, and audit sink.
    pub fn new(store: S, policy: ProfilePolicy, audit: A) -> Self {
        Self {
            store,
            policy,
            audit,
        }
    }

    /// Value-free list operation with audit evidence.
    pub async fn list(&mut self, principal: &PrincipalChain) -> JanusResult<Vec<SecretDescriptor>> {
        self.audit.record(AuditEvent::new(
            AuditAction::SecretList,
            AuditOutcome::Allowed,
            "ok",
            Severity::Info,
            None,
            principal,
        ))?;
        self.store.list().await
    }

    /// Internal approved read path used by non-LLM/provider/tracer code. Agents
    /// should receive refs/permits, not call this.
    pub async fn get(
        &mut self,
        name: &SecretName,
        principal: &PrincipalChain,
    ) -> JanusResult<SecretValue> {
        let descriptor = self
            .store
            .list()
            .await?
            .into_iter()
            .find(|descriptor| &descriptor.name == name);

        let Some(descriptor) = descriptor else {
            let _ = self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Denied,
                "denied_not_in_manifest",
                Severity::Warning,
                None,
                principal,
            ));
            return Err(JanusError::NotInManifest {
                name: name.as_str().to_string(),
            });
        };

        self.audit.record(AuditEvent::new(
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            "ok",
            Severity::Notice,
            Some(descriptor.secret_ref),
            principal,
        ))?;
        self.store.get(name).await
    }

    /// Request one use permit through default-deny policy and audit.
    pub fn request_use(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> JanusResult<UsePermit> {
        let mut issuer = PermitIssuer::new(&self.policy, &mut self.audit);
        issuer.issue(req, principal, now)
    }

    /// Split the broker back into its parts for assertions or embedding.
    pub fn into_parts(self) -> (S, ProfilePolicy, A) {
        (self.store, self.policy, self.audit)
    }
}

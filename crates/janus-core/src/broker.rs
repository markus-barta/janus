//! Minimal core broker tying store, policy, and audit together.

use std::time::SystemTime;

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, Destination, ExecutorRef, JanusError,
    JanusResult, PermitIssuer, PrincipalChain, ProfilePolicy, SecretDescriptor, SecretName,
    SecretStore, SecretValue, Severity, UsePermit, UseRequest,
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
            self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Denied,
                "denied_not_in_manifest",
                Severity::Warning,
                None,
                principal,
            ))?;
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
    pub async fn request_use(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> JanusResult<UsePermit> {
        let listed = self.store.list().await?;
        if !listed
            .iter()
            .any(|descriptor| descriptor.secret_ref == req.secret_ref)
        {
            self.audit.record(AuditEvent::new(
                AuditAction::PermitDeny,
                AuditOutcome::Denied,
                "denied_not_in_manifest",
                Severity::Warning,
                Some(req.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::NotInManifest {
                name: req.secret_ref.as_str().to_string(),
            });
        }

        let mut issuer = PermitIssuer::new(&self.policy, &mut self.audit);
        issuer.issue(req, principal, now)
    }

    /// Consume a permit through the approved secret-bearing path.
    ///
    /// This is the point where copied/stale permits stay powerless: the permit
    /// must still match principal, executor, destination, expiry, and a current
    /// manifest ref before a value is read. Every denial is audited before it is
    /// returned.
    pub async fn use_permit(
        &mut self,
        permit: &UsePermit,
        principal: &PrincipalChain,
        executor: &ExecutorRef,
        destination: &Destination,
        now: SystemTime,
    ) -> JanusResult<SecretValue> {
        if let Err(err) = permit.matches(principal, executor, destination, now) {
            let reason_code = match &err {
                JanusError::PermitInvalid { reason_code, .. } => *reason_code,
                _ => "denied_permit_invalid",
            };
            self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Denied,
                reason_code,
                Severity::Warning,
                Some(permit.secret_ref().clone()),
                principal,
            ))?;
            return Err(err);
        }

        let descriptor = self
            .store
            .list()
            .await?
            .into_iter()
            .find(|descriptor| &descriptor.secret_ref == permit.secret_ref());

        let Some(descriptor) = descriptor else {
            self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Denied,
                "denied_not_in_manifest",
                Severity::Warning,
                Some(permit.secret_ref().clone()),
                principal,
            ))?;
            return Err(JanusError::NotInManifest {
                name: permit.secret_ref().as_str().to_string(),
            });
        };

        self.audit.record(AuditEvent::new(
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            "ok",
            Severity::Notice,
            Some(descriptor.secret_ref.clone()),
            principal,
        ))?;
        self.store.get(&descriptor.name).await
    }

    /// Split the broker back into its parts for assertions or embedding.
    pub fn into_parts(self) -> (S, ProfilePolicy, A) {
        (self.store, self.policy, self.audit)
    }
}

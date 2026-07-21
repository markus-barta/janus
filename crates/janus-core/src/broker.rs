//! Minimal core broker tying store, policy, and audit together.

use std::time::SystemTime;

use crate::{
    consumer::consumer_observe_event, ApprovalGrant, AuditAction, AuditEvent, AuditOutcome,
    AuditSink, ClassPermitPolicy, ConsumerDescriptor, DelegatedUseContext, DelegationGrant,
    DelegationPolicy, DelegationRevocation, Destination, ExecutorRef, JanusError, JanusResult,
    PermitIssuer, PolicyDecision, PrincipalChain, ProfilePolicy, SecretDescriptor, SecretName,
    SecretRef, SecretStore, SecretValue, Severity, UsePermit, UseRequest,
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
        let descriptors = self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|descriptor| descriptor.scope == principal.scope)
            .collect();
        self.audit.record(AuditEvent::new(
            AuditAction::SecretList,
            AuditOutcome::Allowed,
            "ok",
            Severity::Info,
            None,
            principal,
        ))?;
        Ok(descriptors)
    }

    /// Value-free describe operation by opaque ref.
    pub async fn describe(
        &mut self,
        secret_ref: &SecretRef,
        principal: &PrincipalChain,
    ) -> JanusResult<SecretDescriptor> {
        let descriptor = self
            .store
            .list()
            .await?
            .into_iter()
            .find(|descriptor| &descriptor.secret_ref == secret_ref);

        let Some(descriptor) = descriptor else {
            self.audit.record(AuditEvent::new(
                AuditAction::SecretDescribe,
                AuditOutcome::Denied,
                "denied_not_in_manifest",
                Severity::Warning,
                Some(secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::NotInManifest {
                name: secret_ref.as_str().to_string(),
            });
        };

        if descriptor.scope != principal.scope {
            self.audit.record(AuditEvent::new(
                AuditAction::SecretDescribe,
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

        self.audit.record(AuditEvent::new(
            AuditAction::SecretDescribe,
            AuditOutcome::Allowed,
            "ok",
            Severity::Info,
            Some(descriptor.secret_ref.clone()),
            principal,
        ))?;
        Ok(descriptor)
    }

    /// Value-free backend health check with audit evidence.
    pub async fn health(&mut self, principal: &PrincipalChain) -> JanusResult<crate::HealthStatus> {
        self.audit.record(AuditEvent::new(
            AuditAction::BackendHealth,
            AuditOutcome::Allowed,
            "ok",
            Severity::Info,
            None,
            principal,
        ))?;
        self.store.health().await
    }

    /// Record a value-free denial for a request rejected before a deeper core
    /// operation can be constructed.
    pub fn record_denial(
        &mut self,
        action: AuditAction,
        reason_code: &'static str,
        severity: Severity,
        secret_ref: Option<SecretRef>,
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        self.audit.record(AuditEvent::new(
            action,
            AuditOutcome::Denied,
            reason_code,
            severity,
            secret_ref,
            principal,
        ))
    }

    /// Record value-free evidence that a declared consumer used a secret.
    pub fn record_consumer_observe(
        &mut self,
        consumer: &ConsumerDescriptor,
        principal: &PrincipalChain,
    ) -> JanusResult<()> {
        if consumer.scope != principal.scope {
            self.audit.record(AuditEvent::new(
                AuditAction::ConsumerObserve,
                AuditOutcome::Denied,
                "denied_scope_mismatch",
                Severity::Warning,
                Some(consumer.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "consumer scope does not match caller scope",
            ));
        }
        self.audit
            .record(consumer_observe_event(consumer, principal)?)
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

        if descriptor.scope != principal.scope {
            self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
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

        if let Some((reason_code, detail)) = descriptor.normal_use_denial() {
            self.audit.record(AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Denied,
                reason_code,
                Severity::Warning,
                Some(descriptor.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(reason_code, detail));
        }

        self.audit.record(AuditEvent::new(
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            "ok",
            descriptor
                .classification
                .map(ClassPermitPolicy::for_class)
                .map(ClassPermitPolicy::allow_severity)
                .unwrap_or(Severity::Notice),
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
        self.request_use_with_approval(req, principal, now, None)
            .await
    }

    /// Request one use permit with an optional exact approval grant.
    ///
    /// This is for trusted/admin paths. Model-facing surfaces should continue
    /// to call `request_use` / `request_profile_use` so the model cannot mint
    /// or broaden approvals.
    pub async fn request_use_with_approval(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
        approval: Option<&ApprovalGrant>,
    ) -> JanusResult<UsePermit> {
        let listed = self.store.list().await?;
        let descriptor = listed
            .iter()
            .find(|descriptor| descriptor.secret_ref == req.secret_ref);

        let Some(descriptor) = descriptor else {
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
        };

        if descriptor.scope != principal.scope || descriptor.scope != req.scope {
            self.audit.record(AuditEvent::new(
                AuditAction::PermitDeny,
                AuditOutcome::Denied,
                "denied_scope_mismatch",
                Severity::Warning,
                Some(req.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "descriptor, request, and caller scope must match exactly",
            ));
        }

        if let Some((reason_code, detail)) = descriptor.normal_use_denial() {
            self.audit.record(AuditEvent::new(
                AuditAction::PermitDeny,
                AuditOutcome::Denied,
                reason_code,
                Severity::Warning,
                Some(req.secret_ref.clone()),
                principal,
            ))?;
            return Err(JanusError::policy_denied(reason_code, detail));
        }

        let class = descriptor
            .classification
            .expect("normal_use_denial guarantees classification is present");
        let mut issuer = PermitIssuer::new(&self.policy, &mut self.audit);
        issuer.issue_for_class_with_approval(req, principal, now, class, approval)
    }

    /// Request one permit through an exact persisted delegation grant.
    pub async fn request_use_with_delegation(
        &mut self,
        req: &UseRequest,
        principal: &PrincipalChain,
        now: SystemTime,
        grant: &DelegationGrant,
        revocation: Option<&DelegationRevocation>,
    ) -> JanusResult<UsePermit> {
        let listed = self.store.list().await?;
        let descriptor = listed
            .iter()
            .find(|descriptor| descriptor.secret_ref == req.secret_ref);
        let Some(descriptor) = descriptor else {
            let context = DelegatedUseContext::from_grant(grant);
            self.audit.record(
                AuditEvent::new(
                    AuditAction::PermitDeny,
                    AuditOutcome::Denied,
                    "denied_not_in_manifest",
                    Severity::Warning,
                    Some(req.secret_ref.clone()),
                    principal,
                )
                .with_delegation(context),
            )?;
            return Err(JanusError::NotInManifest {
                name: req.secret_ref.as_str().to_string(),
            });
        };
        DelegationPolicy::validate_persisted_use(
            grant,
            revocation,
            &self.policy,
            descriptor,
            req,
            principal,
            now,
            &mut self.audit,
        )?;
        let class = descriptor
            .classification
            .expect("delegation validation guarantees classification");
        let context = DelegatedUseContext::from_grant(grant);
        let mut issuer = PermitIssuer::new(&self.policy, &mut self.audit);
        issuer.issue_for_delegation(req, principal, now, class, &context)
    }

    /// Request use from only model-acceptable inputs.
    ///
    /// Destination, executor, TTL, egress mode, and single-use semantics come
    /// from the reviewed profile. This keeps AI-facing callers from choosing
    /// policy-critical fields.
    pub async fn request_profile_use(
        &mut self,
        secret_ref: &SecretRef,
        profile_id: &crate::ProfileId,
        purpose: crate::Purpose,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> JanusResult<UsePermit> {
        let destination = self
            .policy
            .profile_for(secret_ref, profile_id)
            .map(|profile| profile.destination.clone())
            .unwrap_or_else(|| {
                Destination::new("profile-owned-destination-unavailable")
                    .expect("static fallback destination")
            });
        let req = UseRequest {
            secret_ref: secret_ref.clone(),
            scope: principal.scope.clone(),
            profile_id: profile_id.clone(),
            destination,
            purpose,
        };
        self.request_use(&req, principal, now).await
    }

    /// Request delegated use from only model-acceptable inputs.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_delegated_profile_use(
        &mut self,
        secret_ref: &SecretRef,
        profile_id: &crate::ProfileId,
        purpose: crate::Purpose,
        principal: &PrincipalChain,
        now: SystemTime,
        grant: &DelegationGrant,
        revocation: Option<&DelegationRevocation>,
    ) -> JanusResult<UsePermit> {
        let destination = self
            .policy
            .profile_for(secret_ref, profile_id)
            .map(|profile| profile.destination.clone())
            .unwrap_or_else(|| {
                Destination::new("profile-owned-destination-unavailable")
                    .expect("static fallback destination")
            });
        let req = UseRequest {
            secret_ref: secret_ref.clone(),
            scope: principal.scope.clone(),
            profile_id: profile_id.clone(),
            destination,
            purpose,
        };
        self.request_use_with_delegation(&req, principal, now, grant, revocation)
            .await
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
        self.use_permit_with_delegation(permit, principal, executor, destination, now, None)
            .await
    }

    /// Consume a permit with optional exact current delegation evidence.
    #[allow(clippy::too_many_arguments)]
    pub async fn use_permit_with_delegation(
        &mut self,
        permit: &UsePermit,
        principal: &PrincipalChain,
        executor: &ExecutorRef,
        destination: &Destination,
        now: SystemTime,
        delegation_evidence: Option<(&DelegationGrant, Option<&DelegationRevocation>)>,
    ) -> JanusResult<SecretValue> {
        match (permit.delegation(), delegation_evidence) {
            (Some(context), None) => {
                self.audit.record(
                    AuditEvent::new(
                        AuditAction::SecretUse,
                        AuditOutcome::Denied,
                        "delegation_evidence_required",
                        Severity::Warning,
                        Some(permit.secret_ref().clone()),
                        principal,
                    )
                    .with_delegation(context.clone()),
                )?;
                return Err(JanusError::permit_invalid(
                    "delegation_evidence_required",
                    "delegated permit requires current delegation evidence",
                ));
            }
            (None, Some(_)) => {
                self.audit.record(AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    "delegation_context_unexpected",
                    Severity::Warning,
                    Some(permit.secret_ref().clone()),
                    principal,
                ))?;
                return Err(JanusError::permit_invalid(
                    "delegation_context_unexpected",
                    "non-delegated permit cannot accept delegation evidence",
                ));
            }
            _ => {}
        }
        if let Err(err) = permit.matches(principal, executor, destination, now) {
            let reason_code = match &err {
                JanusError::PermitInvalid { reason_code, .. } => *reason_code,
                _ => "denied_permit_invalid",
            };
            self.audit.record(permit_audit_event(
                permit,
                AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    reason_code,
                    Severity::Warning,
                    Some(permit.secret_ref().clone()),
                    principal,
                ),
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
            self.audit.record(permit_audit_event(
                permit,
                AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    "denied_not_in_manifest",
                    Severity::Warning,
                    Some(permit.secret_ref().clone()),
                    principal,
                ),
            ))?;
            return Err(JanusError::NotInManifest {
                name: permit.secret_ref().as_str().to_string(),
            });
        };

        if descriptor.scope != principal.scope || &descriptor.scope != permit.scope_ref() {
            self.audit.record(permit_audit_event(
                permit,
                AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    "denied_scope_mismatch",
                    Severity::Warning,
                    Some(descriptor.secret_ref.clone()),
                    principal,
                ),
            ))?;
            return Err(JanusError::policy_denied(
                "denied_scope_mismatch",
                "descriptor, permit, and caller scope must match exactly",
            ));
        }

        if let Some((reason_code, detail)) = descriptor.normal_use_denial() {
            self.audit.record(permit_audit_event(
                permit,
                AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    reason_code,
                    Severity::Warning,
                    Some(descriptor.secret_ref.clone()),
                    principal,
                ),
            ))?;
            return Err(JanusError::policy_denied(reason_code, detail));
        }

        let class = descriptor
            .classification
            .expect("normal_use_denial guarantees classification is present");
        if let (Some(context), Some((grant, revocation))) =
            (permit.delegation(), delegation_evidence)
        {
            if let Err(error) = context.validate_for(grant) {
                self.audit.record(
                    AuditEvent::new(
                        AuditAction::SecretUse,
                        AuditOutcome::Denied,
                        "delegation_context_mismatch",
                        Severity::Warning,
                        Some(descriptor.secret_ref.clone()),
                        principal,
                    )
                    .with_delegation(context.clone()),
                )?;
                return Err(error);
            }
            let request = UseRequest {
                secret_ref: permit.secret_ref().clone(),
                scope: permit.scope_ref().clone(),
                profile_id: permit.profile_id().clone(),
                destination: permit.destination().clone(),
                purpose: permit.purpose().clone(),
            };
            if let Err(error) = DelegationPolicy::validate_persisted_use(
                grant,
                revocation,
                &self.policy,
                &descriptor,
                &request,
                principal,
                now,
                &mut self.audit,
            ) {
                let reason_code = match &error {
                    JanusError::PolicyDenied { reason_code, .. } => *reason_code,
                    _ => "delegation_invalid",
                };
                self.audit.record(
                    AuditEvent::new(
                        AuditAction::SecretUse,
                        AuditOutcome::Denied,
                        reason_code,
                        Severity::Warning,
                        Some(descriptor.secret_ref.clone()),
                        principal,
                    )
                    .with_delegation(context.clone()),
                )?;
                return Err(error);
            }
        }
        let class_policy = ClassPermitPolicy::for_class(class);
        if let PolicyDecision::Deny {
            reason_code,
            detail,
        } = class_policy.decide_permit(permit, now)
        {
            self.audit.record(permit_audit_event(
                permit,
                AuditEvent::new(
                    AuditAction::SecretUse,
                    AuditOutcome::Denied,
                    reason_code,
                    class_policy.deny_severity(),
                    Some(descriptor.secret_ref.clone()),
                    principal,
                ),
            ))?;
            return Err(JanusError::policy_denied(reason_code, detail));
        }

        self.audit.record(permit_audit_event(
            permit,
            AuditEvent::new(
                AuditAction::SecretUse,
                AuditOutcome::Allowed,
                "ok",
                class_policy.allow_severity(),
                Some(descriptor.secret_ref.clone()),
                principal,
            ),
        ))?;
        self.store.get(&descriptor.name).await
    }

    /// Split the broker back into its parts for assertions or embedding.
    pub fn into_parts(self) -> (S, ProfilePolicy, A) {
        (self.store, self.policy, self.audit)
    }
}

fn permit_audit_event(permit: &UsePermit, event: AuditEvent) -> AuditEvent {
    match permit.delegation() {
        Some(delegation) => event.with_delegation(delegation.clone()),
        None => event,
    }
}

//! # janus-warden
//!
//! Reference-only Warden surface for AI-facing runtimes. This crate owns the
//! SDK-agnostic handler layer that an MCP transport can wrap: static tool
//! metadata, model-safe descriptor views, and permit requests through
//! `janus-core`. It never returns secret literals and never lets the model
//! choose destination, executor, egress mode, command, args, or TTL.

#![forbid(unsafe_code)]

use std::time::SystemTime;

use janus_core::{
    AuditSink, HealthStatus, JanusResult, PrincipalChain, ProfileId, Purpose, SecretBroker,
    SecretDescriptor, SecretRef, SecretStore, TrustLevel, UsePermit,
};
use serde::Serialize;

/// Static MCP-facing tool definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolDefinition {
    /// Tool name.
    pub name: &'static str,
    /// Static, code-reviewed description.
    pub description: &'static str,
    /// Static JSON schema for caller-supplied arguments.
    pub input_schema: &'static str,
}

/// Static Warden tool catalog. Transport shims may expose exactly these tools.
pub const TOOL_DEFINITIONS: [ToolDefinition; 4] = [
    ToolDefinition {
        name: "list_secrets",
        description: "List model-safe secret descriptors: curated labels, opaque SecretRefs, presence, trust tier, scope, and allowed use profiles. Never returns names, backend paths, or values.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    ToolDefinition {
        name: "describe_secret",
        description: "Describe one manifest-declared secret by opaque SecretRef. Returns model-safe metadata and allowed use profiles only. Unknown refs return a denial and no permit.",
        input_schema: r#"{"type":"object","properties":{"secret_ref":{"type":"string"}},"required":["secret_ref"],"additionalProperties":false}"#,
    },
    ToolDefinition {
        name: "request_use",
        description: "Request an opaque short-lived UsePermit by SecretRef, reviewed profile id, and purpose. Destination, executor, egress, command, args, and TTL come from policy, not caller input.",
        input_schema: r#"{"type":"object","properties":{"secret_ref":{"type":"string"},"profile_id":{"type":"string"},"purpose":{"type":"string"}},"required":["secret_ref","profile_id","purpose"],"additionalProperties":false}"#,
    },
    ToolDefinition {
        name: "health",
        description: "Return redacted Warden/backend health for this principal chain. No secret metadata or values are returned.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
];

/// Return the static tool catalog.
pub fn tool_definitions() -> &'static [ToolDefinition; 4] {
    &TOOL_DEFINITIONS
}

/// Model-facing descriptor. It intentionally omits raw manifest names and
/// backend paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecretDescriptorView {
    /// Opaque, non-authorizing reference.
    pub secret_ref: String,
    /// Curated model-safe label.
    pub label: String,
    /// Scope boundary.
    pub scope: String,
    /// Whether the backend says the value exists.
    pub present: bool,
    /// Trust tier as a stable string.
    pub trust_level: &'static str,
    /// Allowed profile ids.
    pub allowed_uses: Vec<String>,
    /// Invariant marker.
    pub value_returned: bool,
}

/// List response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListSecretsResponse {
    /// Model-safe descriptors.
    pub secrets: Vec<SecretDescriptorView>,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Describe response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DescribeSecretResponse {
    /// Model-safe descriptor.
    pub secret: SecretDescriptorView,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Permit response. The permit id is opaque and contains no secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestUseResponse {
    /// Opaque permit id.
    pub permit_id: String,
    /// Secret ref the permit is bound to.
    pub secret_ref: String,
    /// Profile id the permit is bound to.
    pub profile_id: String,
    /// Executor chosen by reviewed policy.
    pub executor: String,
    /// Destination chosen by reviewed policy.
    pub destination: String,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Redacted health response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthResponse {
    /// Whether backend health is ok.
    pub ok: bool,
    /// Backend label.
    pub backend: &'static str,
    /// Value-free health detail.
    pub detail: String,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Request-use arguments accepted by Warden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestUseArgs {
    /// Opaque secret ref.
    pub secret_ref: SecretRef,
    /// Reviewed profile id.
    pub profile_id: ProfileId,
    /// Caller purpose/reason.
    pub purpose: Purpose,
}

/// SDK-agnostic Warden handler over the Janus broker.
pub struct WardenRuntime<S, A> {
    broker: SecretBroker<S, A>,
}

impl<S, A> WardenRuntime<S, A>
where
    S: SecretStore,
    A: AuditSink,
{
    /// Construct a Warden runtime from the core broker.
    pub fn new(broker: SecretBroker<S, A>) -> Self {
        Self { broker }
    }

    /// List model-safe descriptors only.
    pub async fn list_secrets(
        &mut self,
        principal: &PrincipalChain,
    ) -> JanusResult<ListSecretsResponse> {
        let secrets = self
            .broker
            .list(principal)
            .await?
            .into_iter()
            .map(descriptor_view)
            .collect();
        Ok(ListSecretsResponse {
            secrets,
            value_returned: false,
        })
    }

    /// Describe one secret by opaque ref.
    pub async fn describe_secret(
        &mut self,
        secret_ref: &SecretRef,
        principal: &PrincipalChain,
    ) -> JanusResult<DescribeSecretResponse> {
        let secret = descriptor_view(self.broker.describe(secret_ref, principal).await?);
        Ok(DescribeSecretResponse {
            secret,
            value_returned: false,
        })
    }

    /// Request a use permit. The caller cannot supply policy-critical
    /// destination/executor/egress/TTL fields.
    pub async fn request_use(
        &mut self,
        args: RequestUseArgs,
        principal: &PrincipalChain,
        now: SystemTime,
    ) -> JanusResult<RequestUseResponse> {
        let permit = self
            .broker
            .request_profile_use(
                &args.secret_ref,
                &args.profile_id,
                args.purpose,
                principal,
                now,
            )
            .await?;
        Ok(permit_view(&permit))
    }

    /// Check backend health through the broker.
    pub async fn health(&mut self, principal: &PrincipalChain) -> JanusResult<HealthResponse> {
        Ok(health_view(self.broker.health(principal).await?))
    }

    /// Consume and return the underlying broker.
    pub fn into_broker(self) -> SecretBroker<S, A> {
        self.broker
    }
}

fn descriptor_view(descriptor: SecretDescriptor) -> SecretDescriptorView {
    SecretDescriptorView {
        secret_ref: descriptor.secret_ref.as_str().to_string(),
        label: descriptor.label.as_str().to_string(),
        scope: descriptor.scope.as_str().to_string(),
        present: descriptor.present,
        trust_level: trust_level_text(descriptor.trust_level),
        allowed_uses: descriptor
            .allowed_uses
            .iter()
            .map(|profile| profile.as_str().to_string())
            .collect(),
        value_returned: false,
    }
}

fn permit_view(permit: &UsePermit) -> RequestUseResponse {
    RequestUseResponse {
        permit_id: permit.id().as_str().to_string(),
        secret_ref: permit.secret_ref().as_str().to_string(),
        profile_id: permit.profile_id().as_str().to_string(),
        executor: permit.executor().as_str().to_string(),
        destination: permit.destination().as_str().to_string(),
        value_returned: false,
    }
}

fn health_view(health: HealthStatus) -> HealthResponse {
    HealthResponse {
        ok: health.ok,
        backend: health.backend,
        detail: health.detail,
        value_returned: false,
    }
}

fn trust_level_text(trust_level: TrustLevel) -> &'static str {
    match trust_level {
        TrustLevel::L0 => "l0",
        TrustLevel::L1 => "l1",
        TrustLevel::L2 => "l2",
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, Destination, EgressMode, ExecutorRef, JanusError,
        ManifestCatalog, Principal, PrincipalChain, PrincipalId, PrincipalKind, ProfileId,
        ProfilePolicy, ProjectId, Purpose, SafeLabel, ScopeRef, SecretBroker, SecretMeta,
        SecretName, SecretRef, TrustLevel, UseProfile,
    };
    use janus_mock::MockStore;

    use super::*;

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("warden-stdio").unwrap(),
            ),
            ScopeRef::new("janus/dev").unwrap(),
        )
    }

    fn runtime() -> (WardenRuntime<MockStore, AuditWrite>, SecretRef) {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }])
        .unwrap();
        let store = MockStore::new(catalog)
            .with_value(name, b"expected-canary".to_vec())
            .unwrap();
        let profile = UseProfile {
            id: ProfileId::new("profile.canary").unwrap(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("warden-stdio").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );
        (WardenRuntime::new(broker), secret_ref)
    }

    #[test]
    fn tool_catalog_is_reference_and_permit_only() {
        let tools = tool_definitions();
        let names: Vec<_> = tools.iter().map(|tool| tool.name).collect();
        assert_eq!(
            names,
            ["list_secrets", "describe_secret", "request_use", "health"]
        );

        let rendered = format!("{tools:?}");
        for forbidden in [
            "read_secret",
            "resolve",
            "reveal",
            "set_secret",
            "delete_secret",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "tool catalog exposed forbidden tool text {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn warden_outputs_are_value_free_and_omit_raw_names() {
        let (mut runtime, secret_ref) = runtime();
        let principal = principal();

        let listed = runtime.list_secrets(&principal).await.unwrap();
        assert_eq!(listed.secrets.len(), 1);
        assert_eq!(listed.secrets[0].secret_ref, secret_ref.as_str());
        assert_eq!(listed.secrets[0].label, "Canary token");
        assert!(!listed.value_returned);

        let described = runtime
            .describe_secret(&secret_ref, &principal)
            .await
            .unwrap();
        assert_eq!(described.secret.secret_ref, secret_ref.as_str());
        assert!(!described.value_returned);

        let health = runtime.health(&principal).await.unwrap();
        assert!(health.ok);
        assert!(!health.value_returned);

        let rendered = format!("{listed:?}{described:?}{health:?}");
        assert!(!rendered.contains("expected-canary"));
        assert!(!rendered.contains("CANARY"));
    }

    #[tokio::test]
    async fn request_use_returns_opaque_permit_from_profile_owned_destination() {
        let (mut runtime, secret_ref) = runtime();
        let principal = principal();

        let permit = runtime
            .request_use(
                RequestUseArgs {
                    secret_ref,
                    profile_id: ProfileId::new("profile.canary").unwrap(),
                    purpose: Purpose::new("deploy canary").unwrap(),
                },
                &principal,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap();

        assert!(permit.permit_id.starts_with("use_"));
        assert_eq!(permit.executor, "warden-stdio");
        assert_eq!(permit.destination, "deploy-api");
        assert!(!permit.value_returned);
        assert!(!format!("{permit:?}").contains("expected-canary"));
    }

    #[tokio::test]
    async fn unknown_ref_gets_no_permit_and_is_audited() {
        let (mut runtime, _secret_ref) = runtime();
        let principal = principal();

        let err = runtime
            .request_use(
                RequestUseArgs {
                    secret_ref: SecretRef::new("sec_copied_stale").unwrap(),
                    profile_id: ProfileId::new("profile.canary").unwrap(),
                    purpose: Purpose::new("deploy canary").unwrap(),
                },
                &principal,
                SystemTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JanusError::NotInManifest { .. }));

        let broker = runtime.into_broker();
        let (_store, _policy, audit) = broker.into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::PermitDeny
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_not_in_manifest"
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));
    }
}

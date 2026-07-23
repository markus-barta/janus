//! Strict, value-free contracts for managed-service secret workflows.
//!
//! These types define the shared language between reviewed nixcfg
//! declarations, Pharos orchestration, Janus custody, a host executor, and
//! fresh service-health evidence. They intentionally do not contain secret
//! values, ciphertext, filesystem paths, commands, permits, or callback URLs.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{JanusError, JanusResult};

pub const MANAGED_SERVICE_CONTRACT_VERSION: u16 = 1;
pub const MANAGED_SERVICE_DECLARATION_SCHEMA: &str = "inspr.janus.managed-service-declaration.v1";
pub const MANAGED_SERVICE_SETUP_INTENT_SCHEMA: &str = "inspr.janus.managed-service-setup-intent.v1";
pub const MANAGED_SERVICE_OPERATION_SCHEMA: &str = "inspr.janus.managed-service-operation.v1";
pub const MANAGED_SERVICE_EVIDENCE_SCHEMA: &str = "inspr.janus.managed-service-evidence.v1";
pub const MANAGED_SERVICE_FIXTURE_SCHEMA: &str =
    "inspr.janus.managed-service-secret-contract-fixture.v1";
pub const MAX_SETUP_INTENT_TTL_SECS: u64 = 300;
pub const MAX_MANAGED_SERVICE_CONTRACT_BYTES: usize = 64 * 1024;

fn invalid_contract(detail: &'static str) -> JanusError {
    JanusError::InvalidManifest {
        detail: detail.to_string(),
    }
}

fn parse_json<T: DeserializeOwned>(input: &str, error: &'static str) -> JanusResult<T> {
    if input.is_empty() || input.len() > MAX_MANAGED_SERVICE_CONTRACT_BYTES {
        return Err(invalid_contract(error));
    }
    serde_json::from_str(input).map_err(|_| invalid_contract(error))
}

fn validate_ref(kind: &'static str, prefix: &str, value: String) -> JanusResult<String> {
    if value.len() < prefix.len() + 8
        || value.len() > 96
        || !value.starts_with(prefix)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(value)
}

macro_rules! managed_ref_type {
    (
        $(#[$meta:meta])*
        $name:ident,
        $kind:literal,
        $prefix:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> JanusResult<Self> {
                Ok(Self(validate_ref($kind, $prefix, value.into())?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

managed_ref_type!(
    /// Opaque, non-authorizing enrolled-host reference.
    ManagedHostRef,
    "managed_host_ref",
    "host_"
);
managed_ref_type!(
    /// Opaque reference to one reviewed managed service.
    ManagedServiceRef,
    "managed_service_ref",
    "svc_"
);
managed_ref_type!(
    /// Opaque reference to one declared secret slot.
    ManagedSecretSlotRef,
    "managed_secret_slot_ref",
    "slot_"
);
managed_ref_type!(
    /// Opaque reference to a reviewed delivery profile.
    ManagedDeliveryProfileRef,
    "managed_delivery_profile_ref",
    "delivery_"
);
managed_ref_type!(
    /// Opaque reference to a reviewed reload profile.
    ManagedReloadProfileRef,
    "managed_reload_profile_ref",
    "reload_"
);
managed_ref_type!(
    /// Opaque reference to a reviewed health profile.
    ManagedHealthProfileRef,
    "managed_health_profile_ref",
    "health_"
);
managed_ref_type!(
    /// Opaque one-time setup intent reference.
    ManagedSetupIntentRef,
    "managed_setup_intent_ref",
    "intent_"
);
managed_ref_type!(
    /// Opaque human browser-session binding.
    ManagedHumanSessionRef,
    "managed_human_session_ref",
    "hsn_"
);
managed_ref_type!(
    /// Opaque issuer or audience system reference.
    ManagedSystemRef,
    "managed_system_ref",
    "sys_"
);
managed_ref_type!(
    /// Opaque replay-prevention nonce.
    ManagedNonceRef,
    "managed_nonce_ref",
    "nonce_"
);
managed_ref_type!(
    /// Opaque managed-secret operation reference.
    ManagedOperationRef,
    "managed_operation_ref",
    "op_"
);
managed_ref_type!(
    /// Opaque, non-authorizing reference to the declared secret.
    ManagedSecretRef,
    "managed_secret_ref",
    "sec_"
);
managed_ref_type!(
    /// Opaque delivery-generation reference.
    ManagedGenerationRef,
    "managed_generation_ref",
    "gen_"
);
managed_ref_type!(
    /// Opaque value-free evidence-event reference.
    ManagedEvidenceRef,
    "managed_evidence_ref",
    "evt_"
);
managed_ref_type!(
    /// Opaque declaration fingerprint.
    ManagedDeclarationFingerprint,
    "managed_declaration_fingerprint",
    "decl_"
);

fn validate_safe_text(
    kind: &'static str,
    value: String,
    maximum_bytes: usize,
) -> JanusResult<String> {
    let unsafe_display = |character: char| {
        character.is_control()
            || (character.is_whitespace() && character != ' ')
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}'
            )
    };
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim().len() != value.len()
        || value.chars().any(unsafe_display)
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(value)
}

/// The only consumer kind admitted by the first managed-service contract.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedConsumerKind {
    ManagedService,
}

/// The only delivery kind admitted by the MVP.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedDeliveryKind {
    PrivateEnvFile,
}

/// Reviewed ways a secret value may originate.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSecretSource {
    Generated,
    Import,
}

/// Managed secret lifecycle actions exposed to the workflow.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSecretOperationKind {
    Create,
    Replace,
    Remove,
}

/// How a failed transition became authoritative.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFailureKind {
    /// The component responsible for the attempted phase reported failure.
    Reported,
    /// Janus observed expiry of a reviewed, server-owned phase deadline.
    TimedOut,
}

/// One authoritative writer in the cross-system workflow.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedWorkflowAuthority {
    Nixcfg,
    Pharos,
    Janus,
    HostExecutor,
    HealthObserver,
}

/// Value-free phases shared by UI, orchestration, and evidence.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSecretPhase {
    Requested,
    Preflighted,
    Encrypted,
    Delivered,
    Materialized,
    Reloaded,
    Healthy,
    Active,
    RollingBack,
    RolledBack,
    DetachRequested,
    Detached,
    Revoked,
    Removing,
    Removed,
    Quarantined,
    Destroyed,
    Failed,
    Cancelled,
}

/// Closed value-free outcome vocabulary for workflow status and evidence.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedReasonCode {
    ManagedSecretRequested,
    ManagedSecretPreflighted,
    ManagedSecretEncrypted,
    ManagedSecretDelivered,
    ManagedSecretMaterialized,
    ManagedServiceReloaded,
    ManagedServiceHealthy,
    ManagedSecretActive,
    ManagedSecretRollingBack,
    ManagedSecretRolledBack,
    ManagedSecretDetachRequested,
    ManagedSecretDetached,
    ManagedSecretRevoked,
    ManagedSecretRemoving,
    ManagedSecretRemoved,
    ManagedSecretQuarantined,
    ManagedSecretDestroyed,
    ManagedSecretFailed,
    ManagedSecretCancelled,
}

impl ManagedReasonCode {
    pub fn phase(self) -> ManagedSecretPhase {
        match self {
            Self::ManagedSecretRequested => ManagedSecretPhase::Requested,
            Self::ManagedSecretPreflighted => ManagedSecretPhase::Preflighted,
            Self::ManagedSecretEncrypted => ManagedSecretPhase::Encrypted,
            Self::ManagedSecretDelivered => ManagedSecretPhase::Delivered,
            Self::ManagedSecretMaterialized => ManagedSecretPhase::Materialized,
            Self::ManagedServiceReloaded => ManagedSecretPhase::Reloaded,
            Self::ManagedServiceHealthy => ManagedSecretPhase::Healthy,
            Self::ManagedSecretActive => ManagedSecretPhase::Active,
            Self::ManagedSecretRollingBack => ManagedSecretPhase::RollingBack,
            Self::ManagedSecretRolledBack => ManagedSecretPhase::RolledBack,
            Self::ManagedSecretDetachRequested => ManagedSecretPhase::DetachRequested,
            Self::ManagedSecretDetached => ManagedSecretPhase::Detached,
            Self::ManagedSecretRevoked => ManagedSecretPhase::Revoked,
            Self::ManagedSecretRemoving => ManagedSecretPhase::Removing,
            Self::ManagedSecretRemoved => ManagedSecretPhase::Removed,
            Self::ManagedSecretQuarantined => ManagedSecretPhase::Quarantined,
            Self::ManagedSecretDestroyed => ManagedSecretPhase::Destroyed,
            Self::ManagedSecretFailed => ManagedSecretPhase::Failed,
            Self::ManagedSecretCancelled => ManagedSecretPhase::Cancelled,
        }
    }
}

impl ManagedSecretPhase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Active | Self::RolledBack | Self::Destroyed | Self::Failed | Self::Cancelled
        )
    }

    /// The sole normal authority for a phase. Failure is attributed to the
    /// component that actually failed and therefore has no single authority.
    pub fn normal_authority(self) -> Option<ManagedWorkflowAuthority> {
        match self {
            Self::Requested | Self::DetachRequested | Self::Cancelled => {
                Some(ManagedWorkflowAuthority::Pharos)
            }
            Self::Preflighted
            | Self::Encrypted
            | Self::Active
            | Self::RollingBack
            | Self::RolledBack
            | Self::Revoked
            | Self::Quarantined
            | Self::Destroyed => Some(ManagedWorkflowAuthority::Janus),
            Self::Delivered
            | Self::Materialized
            | Self::Reloaded
            | Self::Removing
            | Self::Removed => Some(ManagedWorkflowAuthority::HostExecutor),
            Self::Healthy => Some(ManagedWorkflowAuthority::HealthObserver),
            Self::Detached => Some(ManagedWorkflowAuthority::Nixcfg),
            Self::Failed => None,
        }
    }
}

/// A declared secret slot. It contains only value-free reviewed bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSecretSlotV1 {
    slot_ref: ManagedSecretSlotRef,
    safe_label: String,
    consumer_kind: ManagedConsumerKind,
    delivery_kind: ManagedDeliveryKind,
    delivery_profile_ref: ManagedDeliveryProfileRef,
    reload_profile_ref: ManagedReloadProfileRef,
    health_profile_ref: ManagedHealthProfileRef,
    allowed_sources: Vec<ManagedSecretSource>,
}

impl ManagedSecretSlotV1 {
    pub fn slot_ref(&self) -> &ManagedSecretSlotRef {
        &self.slot_ref
    }

    pub fn safe_label(&self) -> &str {
        &self.safe_label
    }

    pub fn allowed_sources(&self) -> &[ManagedSecretSource] {
        &self.allowed_sources
    }

    pub fn consumer_kind(&self) -> ManagedConsumerKind {
        self.consumer_kind
    }

    pub fn delivery_kind(&self) -> ManagedDeliveryKind {
        self.delivery_kind
    }

    pub fn delivery_profile_ref(&self) -> &ManagedDeliveryProfileRef {
        &self.delivery_profile_ref
    }

    pub fn reload_profile_ref(&self) -> &ManagedReloadProfileRef {
        &self.reload_profile_ref
    }

    pub fn health_profile_ref(&self) -> &ManagedHealthProfileRef {
        &self.health_profile_ref
    }
}

/// One reviewed managed service and all of its declared secret slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedServiceDeclarationV1 {
    host_ref: ManagedHostRef,
    service_ref: ManagedServiceRef,
    declaration_fingerprint: ManagedDeclarationFingerprint,
    slots: Vec<ManagedSecretSlotV1>,
}

impl ManagedServiceDeclarationV1 {
    pub fn parse_json(input: &str) -> JanusResult<Self> {
        let wire: DeclarationWire = parse_json(
            input,
            "managed service declaration JSON is invalid or oversized",
        )?;
        Self::from_wire(wire)
    }

    fn from_wire(wire: DeclarationWire) -> JanusResult<Self> {
        if wire.schema != MANAGED_SERVICE_DECLARATION_SCHEMA
            || wire.schema_version != MANAGED_SERVICE_CONTRACT_VERSION
        {
            return Err(invalid_contract(
                "managed service declaration schema is unsupported",
            ));
        }
        if wire.slots.is_empty() || wire.slots.len() > 64 {
            return Err(invalid_contract(
                "managed service declaration slot count is invalid",
            ));
        }
        let mut slot_refs = BTreeSet::new();
        let mut slots = Vec::with_capacity(wire.slots.len());
        for mut slot in wire.slots {
            let slot_ref = ManagedSecretSlotRef::new(slot.slot_ref)?;
            if !slot_refs.insert(slot_ref.clone()) {
                return Err(invalid_contract(
                    "managed service declaration contains a duplicate slot",
                ));
            }
            if slot.allowed_sources.is_empty() || slot.allowed_sources.len() > 2 {
                return Err(invalid_contract(
                    "managed service slot source policy is invalid",
                ));
            }
            let mut sources = BTreeSet::new();
            for source in &slot.allowed_sources {
                if !sources.insert(*source) {
                    return Err(invalid_contract(
                        "managed service slot contains a duplicate source",
                    ));
                }
            }
            slot.allowed_sources.sort_unstable();
            slots.push(ManagedSecretSlotV1 {
                slot_ref,
                safe_label: validate_safe_text("managed_slot_safe_label", slot.safe_label, 120)?,
                consumer_kind: slot.consumer_kind,
                delivery_kind: slot.delivery_kind,
                delivery_profile_ref: ManagedDeliveryProfileRef::new(slot.delivery_profile_ref)?,
                reload_profile_ref: ManagedReloadProfileRef::new(slot.reload_profile_ref)?,
                health_profile_ref: ManagedHealthProfileRef::new(slot.health_profile_ref)?,
                allowed_sources: slot.allowed_sources,
            });
        }
        Ok(Self {
            host_ref: ManagedHostRef::new(wire.host_ref)?,
            service_ref: ManagedServiceRef::new(wire.service_ref)?,
            declaration_fingerprint: ManagedDeclarationFingerprint::new(
                wire.declaration_fingerprint,
            )?,
            slots,
        })
    }

    pub fn to_json(&self) -> JanusResult<String> {
        serde_json::to_string_pretty(&DeclarationWire::from(self))
            .map_err(|_| invalid_contract("managed service declaration serialization failed"))
    }

    pub fn host_ref(&self) -> &ManagedHostRef {
        &self.host_ref
    }

    pub fn service_ref(&self) -> &ManagedServiceRef {
        &self.service_ref
    }

    pub fn declaration_fingerprint(&self) -> &ManagedDeclarationFingerprint {
        &self.declaration_fingerprint
    }

    pub fn slots(&self) -> &[ManagedSecretSlotV1] {
        &self.slots
    }
}

/// The only safe return navigation in the v1 contract.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedReturnTarget {
    PharosService,
}

/// A short-lived, single-use, value-free setup intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSetupIntentV1 {
    intent_ref: ManagedSetupIntentRef,
    operation_kind: ManagedSecretOperationKind,
    source: Option<ManagedSecretSource>,
    host_ref: ManagedHostRef,
    service_ref: ManagedServiceRef,
    slot_ref: ManagedSecretSlotRef,
    human_session_ref: ManagedHumanSessionRef,
    issuer_ref: ManagedSystemRef,
    audience_ref: ManagedSystemRef,
    nonce_ref: ManagedNonceRef,
    declaration_fingerprint: ManagedDeclarationFingerprint,
    issued_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    return_target: ManagedReturnTarget,
}

impl ManagedSetupIntentV1 {
    pub fn parse_json(input: &str) -> JanusResult<Self> {
        let wire: SetupIntentWire =
            parse_json(input, "managed setup intent JSON is invalid or oversized")?;
        Self::from_wire(wire)
    }

    fn from_wire(wire: SetupIntentWire) -> JanusResult<Self> {
        if wire.schema != MANAGED_SERVICE_SETUP_INTENT_SCHEMA
            || wire.schema_version != MANAGED_SERVICE_CONTRACT_VERSION
        {
            return Err(invalid_contract(
                "managed setup intent schema is unsupported",
            ));
        }
        let ttl = wire
            .expires_at_unix_secs
            .checked_sub(wire.issued_at_unix_secs)
            .ok_or_else(|| invalid_contract("managed setup intent time window is invalid"))?;
        if ttl == 0 || ttl > MAX_SETUP_INTENT_TTL_SECS {
            return Err(invalid_contract(
                "managed setup intent time window is invalid",
            ));
        }
        ensure_kind_source(wire.operation_kind, wire.source)?;
        Ok(Self {
            intent_ref: ManagedSetupIntentRef::new(wire.intent_ref)?,
            operation_kind: wire.operation_kind,
            source: wire.source,
            host_ref: ManagedHostRef::new(wire.host_ref)?,
            service_ref: ManagedServiceRef::new(wire.service_ref)?,
            slot_ref: ManagedSecretSlotRef::new(wire.slot_ref)?,
            human_session_ref: ManagedHumanSessionRef::new(wire.human_session_ref)?,
            issuer_ref: ManagedSystemRef::new(wire.issuer_ref)?,
            audience_ref: ManagedSystemRef::new(wire.audience_ref)?,
            nonce_ref: ManagedNonceRef::new(wire.nonce_ref)?,
            declaration_fingerprint: ManagedDeclarationFingerprint::new(
                wire.declaration_fingerprint,
            )?,
            issued_at_unix_secs: wire.issued_at_unix_secs,
            expires_at_unix_secs: wire.expires_at_unix_secs,
            return_target: wire.return_target,
        })
    }

    pub fn to_json(&self) -> JanusResult<String> {
        serde_json::to_string_pretty(&SetupIntentWire::from(self))
            .map_err(|_| invalid_contract("managed setup intent serialization failed"))
    }

    pub fn intent_ref(&self) -> &ManagedSetupIntentRef {
        &self.intent_ref
    }

    pub fn operation_kind(&self) -> ManagedSecretOperationKind {
        self.operation_kind
    }

    pub fn source(&self) -> Option<ManagedSecretSource> {
        self.source
    }

    pub fn target(&self) -> (&ManagedHostRef, &ManagedServiceRef, &ManagedSecretSlotRef) {
        (&self.host_ref, &self.service_ref, &self.slot_ref)
    }

    pub fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }

    pub fn issued_at_unix_secs(&self) -> u64 {
        self.issued_at_unix_secs
    }

    pub fn valid_at(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.issued_at_unix_secs && now_unix_secs < self.expires_at_unix_secs
    }

    pub fn human_session_ref(&self) -> &ManagedHumanSessionRef {
        &self.human_session_ref
    }

    pub fn issuer_ref(&self) -> &ManagedSystemRef {
        &self.issuer_ref
    }

    pub fn audience_ref(&self) -> &ManagedSystemRef {
        &self.audience_ref
    }

    pub fn nonce_ref(&self) -> &ManagedNonceRef {
        &self.nonce_ref
    }

    pub fn declaration_fingerprint(&self) -> &ManagedDeclarationFingerprint {
        &self.declaration_fingerprint
    }

    pub fn return_target(&self) -> ManagedReturnTarget {
        self.return_target
    }
}

/// Current value-free workflow status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSecretOperationV1 {
    operation_ref: ManagedOperationRef,
    intent_ref: ManagedSetupIntentRef,
    kind: ManagedSecretOperationKind,
    host_ref: ManagedHostRef,
    service_ref: ManagedServiceRef,
    slot_ref: ManagedSecretSlotRef,
    secret_ref: ManagedSecretRef,
    declaration_fingerprint: ManagedDeclarationFingerprint,
    source: Option<ManagedSecretSource>,
    generation_ref: Option<ManagedGenerationRef>,
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
    authority: ManagedWorkflowAuthority,
    reason_code: ManagedReasonCode,
    updated_at_unix_secs: u64,
}

impl ManagedSecretOperationV1 {
    pub fn parse_json(input: &str) -> JanusResult<Self> {
        let wire: OperationWire =
            parse_json(input, "managed operation JSON is invalid or oversized")?;
        Self::from_wire(wire)
    }

    fn from_wire(wire: OperationWire) -> JanusResult<Self> {
        if wire.schema != MANAGED_SERVICE_OPERATION_SCHEMA
            || wire.schema_version != MANAGED_SERVICE_CONTRACT_VERSION
        {
            return Err(invalid_contract("managed operation schema is unsupported"));
        }
        if wire.value_returned {
            return Err(invalid_contract("managed operation returned a value"));
        }
        ensure_phase_applies(wire.kind, wire.phase)?;
        if let Some(failed_phase) = wire.failed_phase {
            ensure_phase_applies(wire.kind, failed_phase)?;
        }
        ensure_phase_authority(
            wire.phase,
            wire.failed_phase,
            wire.failure_kind,
            wire.authority,
        )?;
        if wire.reason_code.phase() != wire.phase {
            return Err(invalid_contract(
                "managed operation reason does not match its phase",
            ));
        }
        ensure_kind_source(wire.kind, wire.source)?;
        let generation_ref = wire
            .generation_ref
            .map(ManagedGenerationRef::new)
            .transpose()?;
        let generation_required = match wire.failed_phase {
            Some(attempted_phase) => failure_requires_generation(attempted_phase),
            None => phase_requires_generation(wire.phase),
        };
        match wire.kind {
            ManagedSecretOperationKind::Remove if generation_ref.is_none() => {
                return Err(invalid_contract(
                    "managed remove operation requires a generation",
                ));
            }
            ManagedSecretOperationKind::Create | ManagedSecretOperationKind::Replace
                if generation_required && generation_ref.is_none() =>
            {
                return Err(invalid_contract(
                    "managed operation phase requires a generation",
                ));
            }
            ManagedSecretOperationKind::Create | ManagedSecretOperationKind::Replace
                if !generation_required && generation_ref.is_some() =>
            {
                return Err(invalid_contract(
                    "managed operation phase does not admit a generation",
                ));
            }
            _ => {}
        }
        if wire.updated_at_unix_secs == 0 {
            return Err(invalid_contract("managed operation timestamp is invalid"));
        }
        Ok(Self {
            operation_ref: ManagedOperationRef::new(wire.operation_ref)?,
            intent_ref: ManagedSetupIntentRef::new(wire.intent_ref)?,
            kind: wire.kind,
            host_ref: ManagedHostRef::new(wire.host_ref)?,
            service_ref: ManagedServiceRef::new(wire.service_ref)?,
            slot_ref: ManagedSecretSlotRef::new(wire.slot_ref)?,
            secret_ref: ManagedSecretRef::new(wire.secret_ref)?,
            declaration_fingerprint: ManagedDeclarationFingerprint::new(
                wire.declaration_fingerprint,
            )?,
            source: wire.source,
            generation_ref,
            phase: wire.phase,
            failed_phase: wire.failed_phase,
            failure_kind: wire.failure_kind,
            authority: wire.authority,
            reason_code: wire.reason_code,
            updated_at_unix_secs: wire.updated_at_unix_secs,
        })
    }

    pub fn to_json(&self) -> JanusResult<String> {
        serde_json::to_string_pretty(&OperationWire::from(self))
            .map_err(|_| invalid_contract("managed operation serialization failed"))
    }

    pub fn operation_ref(&self) -> &ManagedOperationRef {
        &self.operation_ref
    }

    pub fn intent_ref(&self) -> &ManagedSetupIntentRef {
        &self.intent_ref
    }

    pub fn kind(&self) -> ManagedSecretOperationKind {
        self.kind
    }

    pub fn phase(&self) -> ManagedSecretPhase {
        self.phase
    }

    pub fn authority(&self) -> ManagedWorkflowAuthority {
        self.authority
    }

    pub fn failed_phase(&self) -> Option<ManagedSecretPhase> {
        self.failed_phase
    }

    pub fn failure_kind(&self) -> Option<ManagedFailureKind> {
        self.failure_kind
    }

    pub fn updated_at_unix_secs(&self) -> u64 {
        self.updated_at_unix_secs
    }

    pub fn reason_code(&self) -> ManagedReasonCode {
        self.reason_code
    }

    pub fn generation_ref(&self) -> Option<&ManagedGenerationRef> {
        self.generation_ref.as_ref()
    }

    pub fn secret_ref(&self) -> &ManagedSecretRef {
        &self.secret_ref
    }

    pub fn declaration_fingerprint(&self) -> &ManagedDeclarationFingerprint {
        &self.declaration_fingerprint
    }

    pub fn source(&self) -> Option<ManagedSecretSource> {
        self.source
    }

    pub fn target(&self) -> (&ManagedHostRef, &ManagedServiceRef, &ManagedSecretSlotRef) {
        (&self.host_ref, &self.service_ref, &self.slot_ref)
    }
}

/// One append-only, value-free workflow observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSecretEvidenceV1 {
    evidence_ref: ManagedEvidenceRef,
    operation_ref: ManagedOperationRef,
    declaration_fingerprint: ManagedDeclarationFingerprint,
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
    authority: ManagedWorkflowAuthority,
    reason_code: ManagedReasonCode,
    observed_at_unix_secs: u64,
}

impl ManagedSecretEvidenceV1 {
    pub fn parse_json(input: &str) -> JanusResult<Self> {
        let wire: EvidenceWire =
            parse_json(input, "managed evidence JSON is invalid or oversized")?;
        Self::from_wire(wire)
    }

    fn from_wire(wire: EvidenceWire) -> JanusResult<Self> {
        if wire.schema != MANAGED_SERVICE_EVIDENCE_SCHEMA
            || wire.schema_version != MANAGED_SERVICE_CONTRACT_VERSION
        {
            return Err(invalid_contract("managed evidence schema is unsupported"));
        }
        if wire.value_returned || wire.request_body_returned {
            return Err(invalid_contract(
                "managed evidence crossed the value boundary",
            ));
        }
        ensure_phase_authority(
            wire.phase,
            wire.failed_phase,
            wire.failure_kind,
            wire.authority,
        )?;
        if wire.reason_code.phase() != wire.phase {
            return Err(invalid_contract(
                "managed evidence reason does not match its phase",
            ));
        }
        if wire.observed_at_unix_secs == 0 {
            return Err(invalid_contract("managed evidence timestamp is invalid"));
        }
        Ok(Self {
            evidence_ref: ManagedEvidenceRef::new(wire.evidence_ref)?,
            operation_ref: ManagedOperationRef::new(wire.operation_ref)?,
            declaration_fingerprint: ManagedDeclarationFingerprint::new(
                wire.declaration_fingerprint,
            )?,
            phase: wire.phase,
            failed_phase: wire.failed_phase,
            failure_kind: wire.failure_kind,
            authority: wire.authority,
            reason_code: wire.reason_code,
            observed_at_unix_secs: wire.observed_at_unix_secs,
        })
    }

    pub fn to_json(&self) -> JanusResult<String> {
        serde_json::to_string_pretty(&EvidenceWire::from(self))
            .map_err(|_| invalid_contract("managed evidence serialization failed"))
    }

    pub fn operation_ref(&self) -> &ManagedOperationRef {
        &self.operation_ref
    }

    pub fn evidence_ref(&self) -> &ManagedEvidenceRef {
        &self.evidence_ref
    }

    pub fn phase(&self) -> ManagedSecretPhase {
        self.phase
    }

    pub fn authority(&self) -> ManagedWorkflowAuthority {
        self.authority
    }

    pub fn failed_phase(&self) -> Option<ManagedSecretPhase> {
        self.failed_phase
    }

    pub fn failure_kind(&self) -> Option<ManagedFailureKind> {
        self.failure_kind
    }

    pub fn reason_code(&self) -> ManagedReasonCode {
        self.reason_code
    }

    pub fn declaration_fingerprint(&self) -> &ManagedDeclarationFingerprint {
        &self.declaration_fingerprint
    }

    pub fn observed_at_unix_secs(&self) -> u64 {
        self.observed_at_unix_secs
    }
}

/// A deterministic state machine for one exact operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedSecretStateMachine {
    kind: ManagedSecretOperationKind,
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
}

impl ManagedSecretStateMachine {
    pub fn new(kind: ManagedSecretOperationKind) -> Self {
        Self {
            kind,
            phase: ManagedSecretPhase::Requested,
            failed_phase: None,
            failure_kind: None,
        }
    }

    pub fn phase(self) -> ManagedSecretPhase {
        self.phase
    }

    pub fn advance(
        &mut self,
        next: ManagedSecretPhase,
        authority: ManagedWorkflowAuthority,
    ) -> JanusResult<()> {
        if next == ManagedSecretPhase::Failed {
            return Err(JanusError::policy_denied(
                "managed_failure_binding_required",
                "managed secret workflow failures require the exact attempted phase",
            ));
        }
        ensure_phase_authority(next, None, None, authority)?;
        if !transition_allowed(self.kind, self.phase, next) {
            return Err(JanusError::policy_denied(
                "managed_transition_denied",
                "managed secret workflow transition is not allowed",
            ));
        }
        self.phase = next;
        self.failed_phase = None;
        self.failure_kind = None;
        Ok(())
    }

    pub fn fail(
        &mut self,
        attempted_phase: ManagedSecretPhase,
        authority: ManagedWorkflowAuthority,
    ) -> JanusResult<()> {
        self.record_failure(attempted_phase, ManagedFailureKind::Reported, authority)
    }

    /// Record expiry of a reviewed server-owned deadline. Only Janus may
    /// supervise a timeout; a browser or peer cannot choose the deadline.
    pub fn time_out(&mut self, attempted_phase: ManagedSecretPhase) -> JanusResult<()> {
        self.record_failure(
            attempted_phase,
            ManagedFailureKind::TimedOut,
            ManagedWorkflowAuthority::Janus,
        )
    }

    fn record_failure(
        &mut self,
        attempted_phase: ManagedSecretPhase,
        failure_kind: ManagedFailureKind,
        authority: ManagedWorkflowAuthority,
    ) -> JanusResult<()> {
        ensure_phase_applies(self.kind, attempted_phase)?;
        ensure_phase_authority(
            ManagedSecretPhase::Failed,
            Some(attempted_phase),
            Some(failure_kind),
            authority,
        )?;
        if !transition_allowed(self.kind, self.phase, attempted_phase) {
            return Err(JanusError::policy_denied(
                "managed_failure_transition_denied",
                "managed secret workflow failure does not match the next attempted phase",
            ));
        }
        self.phase = ManagedSecretPhase::Failed;
        self.failed_phase = Some(attempted_phase);
        self.failure_kind = Some(failure_kind);
        Ok(())
    }

    pub fn failed_phase(self) -> Option<ManagedSecretPhase> {
        self.failed_phase
    }

    pub fn failure_kind(self) -> Option<ManagedFailureKind> {
        self.failure_kind
    }
}

/// The control plane accepts its own contract and exactly one predecessor.
///
/// Version zero is never a valid contract and v1 therefore accepts v1 only.
pub fn managed_contract_version_compatible(control_plane_version: u16, peer_version: u16) -> bool {
    control_plane_version > 0
        && peer_version > 0
        && (peer_version == control_plane_version
            || peer_version.checked_add(1) == Some(control_plane_version))
}

fn ensure_phase_applies(
    kind: ManagedSecretOperationKind,
    phase: ManagedSecretPhase,
) -> JanusResult<()> {
    let applies = match kind {
        ManagedSecretOperationKind::Create | ManagedSecretOperationKind::Replace => !matches!(
            phase,
            ManagedSecretPhase::DetachRequested
                | ManagedSecretPhase::Detached
                | ManagedSecretPhase::Revoked
                | ManagedSecretPhase::Removing
                | ManagedSecretPhase::Removed
                | ManagedSecretPhase::Quarantined
                | ManagedSecretPhase::Destroyed
        ),
        ManagedSecretOperationKind::Remove => !matches!(
            phase,
            ManagedSecretPhase::Encrypted
                | ManagedSecretPhase::Delivered
                | ManagedSecretPhase::Materialized
                | ManagedSecretPhase::Reloaded
                | ManagedSecretPhase::Healthy
                | ManagedSecretPhase::Active
                | ManagedSecretPhase::RollingBack
                | ManagedSecretPhase::RolledBack
        ),
    };
    applies
        .then_some(())
        .ok_or_else(|| invalid_contract("managed operation phase does not apply"))
}

fn ensure_phase_authority(
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
    authority: ManagedWorkflowAuthority,
) -> JanusResult<()> {
    if phase == ManagedSecretPhase::Failed {
        let attempted_phase = failed_phase.ok_or_else(|| {
            invalid_contract("managed failed operation is missing the attempted phase")
        })?;
        if attempted_phase == ManagedSecretPhase::Failed {
            return Err(invalid_contract(
                "managed failed operation has an invalid attempted phase",
            ));
        }
        let failure_kind = failure_kind.ok_or_else(|| {
            invalid_contract("managed failed operation is missing the failure kind")
        })?;
        let expected_authority = match failure_kind {
            ManagedFailureKind::Reported => attempted_phase.normal_authority(),
            ManagedFailureKind::TimedOut => Some(ManagedWorkflowAuthority::Janus),
        };
        if expected_authority != Some(authority) {
            return Err(invalid_contract(
                "managed failed operation has the wrong authority",
            ));
        }
        return Ok(());
    }
    if failed_phase.is_some() || failure_kind.is_some() {
        return Err(invalid_contract(
            "managed non-failed operation contains failure attribution",
        ));
    }
    if phase.normal_authority() != Some(authority) {
        return Err(invalid_contract(
            "managed operation phase has the wrong authority",
        ));
    }
    Ok(())
}

fn ensure_kind_source(
    kind: ManagedSecretOperationKind,
    source: Option<ManagedSecretSource>,
) -> JanusResult<()> {
    match (kind, source) {
        (ManagedSecretOperationKind::Create | ManagedSecretOperationKind::Replace, Some(_))
        | (ManagedSecretOperationKind::Remove, None) => Ok(()),
        _ => Err(invalid_contract("managed source does not match its action")),
    }
}

fn phase_requires_generation(phase: ManagedSecretPhase) -> bool {
    matches!(
        phase,
        ManagedSecretPhase::Encrypted
            | ManagedSecretPhase::Delivered
            | ManagedSecretPhase::Materialized
            | ManagedSecretPhase::Reloaded
            | ManagedSecretPhase::Healthy
            | ManagedSecretPhase::Active
            | ManagedSecretPhase::RollingBack
            | ManagedSecretPhase::RolledBack
    )
}

fn failure_requires_generation(attempted_phase: ManagedSecretPhase) -> bool {
    matches!(
        attempted_phase,
        ManagedSecretPhase::Delivered
            | ManagedSecretPhase::Materialized
            | ManagedSecretPhase::Reloaded
            | ManagedSecretPhase::Healthy
            | ManagedSecretPhase::Active
            | ManagedSecretPhase::RollingBack
            | ManagedSecretPhase::RolledBack
    )
}

fn transition_allowed(
    kind: ManagedSecretOperationKind,
    current: ManagedSecretPhase,
    next: ManagedSecretPhase,
) -> bool {
    if current.terminal() {
        return false;
    }
    match kind {
        ManagedSecretOperationKind::Create | ManagedSecretOperationKind::Replace => {
            matches!(
                (current, next),
                (
                    ManagedSecretPhase::Requested,
                    ManagedSecretPhase::Preflighted
                ) | (
                    ManagedSecretPhase::Preflighted,
                    ManagedSecretPhase::Encrypted
                ) | (ManagedSecretPhase::Encrypted, ManagedSecretPhase::Delivered)
                    | (
                        ManagedSecretPhase::Delivered,
                        ManagedSecretPhase::Materialized
                    )
                    | (
                        ManagedSecretPhase::Materialized,
                        ManagedSecretPhase::Reloaded
                    )
                    | (ManagedSecretPhase::Reloaded, ManagedSecretPhase::Healthy)
                    | (ManagedSecretPhase::Healthy, ManagedSecretPhase::Active)
                    | (
                        ManagedSecretPhase::Requested | ManagedSecretPhase::Preflighted,
                        ManagedSecretPhase::Cancelled
                    )
                    | (
                        ManagedSecretPhase::Encrypted
                            | ManagedSecretPhase::Delivered
                            | ManagedSecretPhase::Materialized
                            | ManagedSecretPhase::Reloaded
                            | ManagedSecretPhase::Healthy,
                        ManagedSecretPhase::RollingBack
                    )
                    | (
                        ManagedSecretPhase::RollingBack,
                        ManagedSecretPhase::RolledBack
                    )
            )
        }
        ManagedSecretOperationKind::Remove => matches!(
            (current, next),
            (
                ManagedSecretPhase::Requested,
                ManagedSecretPhase::Preflighted
            ) | (
                ManagedSecretPhase::Preflighted,
                ManagedSecretPhase::DetachRequested
            ) | (
                ManagedSecretPhase::DetachRequested,
                ManagedSecretPhase::Detached
            ) | (ManagedSecretPhase::Detached, ManagedSecretPhase::Revoked)
                | (ManagedSecretPhase::Revoked, ManagedSecretPhase::Removing)
                | (ManagedSecretPhase::Removing, ManagedSecretPhase::Removed)
                | (ManagedSecretPhase::Removed, ManagedSecretPhase::Quarantined)
                | (
                    ManagedSecretPhase::Quarantined,
                    ManagedSecretPhase::Destroyed
                )
                | (
                    ManagedSecretPhase::Requested
                        | ManagedSecretPhase::Preflighted
                        | ManagedSecretPhase::DetachRequested,
                    ManagedSecretPhase::Cancelled
                )
        ),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeclarationWire {
    schema: String,
    schema_version: u16,
    host_ref: String,
    service_ref: String,
    declaration_fingerprint: String,
    slots: Vec<SlotWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SlotWire {
    slot_ref: String,
    safe_label: String,
    consumer_kind: ManagedConsumerKind,
    delivery_kind: ManagedDeliveryKind,
    delivery_profile_ref: String,
    reload_profile_ref: String,
    health_profile_ref: String,
    allowed_sources: Vec<ManagedSecretSource>,
}

impl From<&ManagedServiceDeclarationV1> for DeclarationWire {
    fn from(value: &ManagedServiceDeclarationV1) -> Self {
        Self {
            schema: MANAGED_SERVICE_DECLARATION_SCHEMA.to_string(),
            schema_version: MANAGED_SERVICE_CONTRACT_VERSION,
            host_ref: value.host_ref.as_str().to_string(),
            service_ref: value.service_ref.as_str().to_string(),
            declaration_fingerprint: value.declaration_fingerprint.as_str().to_string(),
            slots: value
                .slots
                .iter()
                .map(|slot| SlotWire {
                    slot_ref: slot.slot_ref.as_str().to_string(),
                    safe_label: slot.safe_label.clone(),
                    consumer_kind: slot.consumer_kind,
                    delivery_kind: slot.delivery_kind,
                    delivery_profile_ref: slot.delivery_profile_ref.as_str().to_string(),
                    reload_profile_ref: slot.reload_profile_ref.as_str().to_string(),
                    health_profile_ref: slot.health_profile_ref.as_str().to_string(),
                    allowed_sources: slot.allowed_sources.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SetupIntentWire {
    schema: String,
    schema_version: u16,
    intent_ref: String,
    operation_kind: ManagedSecretOperationKind,
    source: Option<ManagedSecretSource>,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    human_session_ref: String,
    issuer_ref: String,
    audience_ref: String,
    nonce_ref: String,
    declaration_fingerprint: String,
    issued_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    return_target: ManagedReturnTarget,
}

impl From<&ManagedSetupIntentV1> for SetupIntentWire {
    fn from(value: &ManagedSetupIntentV1) -> Self {
        Self {
            schema: MANAGED_SERVICE_SETUP_INTENT_SCHEMA.to_string(),
            schema_version: MANAGED_SERVICE_CONTRACT_VERSION,
            intent_ref: value.intent_ref.as_str().to_string(),
            operation_kind: value.operation_kind,
            source: value.source,
            host_ref: value.host_ref.as_str().to_string(),
            service_ref: value.service_ref.as_str().to_string(),
            slot_ref: value.slot_ref.as_str().to_string(),
            human_session_ref: value.human_session_ref.as_str().to_string(),
            issuer_ref: value.issuer_ref.as_str().to_string(),
            audience_ref: value.audience_ref.as_str().to_string(),
            nonce_ref: value.nonce_ref.as_str().to_string(),
            declaration_fingerprint: value.declaration_fingerprint.as_str().to_string(),
            issued_at_unix_secs: value.issued_at_unix_secs,
            expires_at_unix_secs: value.expires_at_unix_secs,
            return_target: value.return_target,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationWire {
    schema: String,
    schema_version: u16,
    operation_ref: String,
    intent_ref: String,
    kind: ManagedSecretOperationKind,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    secret_ref: String,
    declaration_fingerprint: String,
    source: Option<ManagedSecretSource>,
    generation_ref: Option<String>,
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
    authority: ManagedWorkflowAuthority,
    reason_code: ManagedReasonCode,
    updated_at_unix_secs: u64,
    value_returned: bool,
}

impl From<&ManagedSecretOperationV1> for OperationWire {
    fn from(value: &ManagedSecretOperationV1) -> Self {
        Self {
            schema: MANAGED_SERVICE_OPERATION_SCHEMA.to_string(),
            schema_version: MANAGED_SERVICE_CONTRACT_VERSION,
            operation_ref: value.operation_ref.as_str().to_string(),
            intent_ref: value.intent_ref.as_str().to_string(),
            kind: value.kind,
            host_ref: value.host_ref.as_str().to_string(),
            service_ref: value.service_ref.as_str().to_string(),
            slot_ref: value.slot_ref.as_str().to_string(),
            secret_ref: value.secret_ref.as_str().to_string(),
            declaration_fingerprint: value.declaration_fingerprint.as_str().to_string(),
            source: value.source,
            generation_ref: value
                .generation_ref
                .as_ref()
                .map(|generation| generation.as_str().to_string()),
            phase: value.phase,
            failed_phase: value.failed_phase,
            failure_kind: value.failure_kind,
            authority: value.authority,
            reason_code: value.reason_code,
            updated_at_unix_secs: value.updated_at_unix_secs,
            value_returned: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    schema: String,
    schema_version: u16,
    evidence_ref: String,
    operation_ref: String,
    declaration_fingerprint: String,
    phase: ManagedSecretPhase,
    failed_phase: Option<ManagedSecretPhase>,
    failure_kind: Option<ManagedFailureKind>,
    authority: ManagedWorkflowAuthority,
    reason_code: ManagedReasonCode,
    observed_at_unix_secs: u64,
    value_returned: bool,
    request_body_returned: bool,
}

impl From<&ManagedSecretEvidenceV1> for EvidenceWire {
    fn from(value: &ManagedSecretEvidenceV1) -> Self {
        Self {
            schema: MANAGED_SERVICE_EVIDENCE_SCHEMA.to_string(),
            schema_version: MANAGED_SERVICE_CONTRACT_VERSION,
            evidence_ref: value.evidence_ref.as_str().to_string(),
            operation_ref: value.operation_ref.as_str().to_string(),
            declaration_fingerprint: value.declaration_fingerprint.as_str().to_string(),
            phase: value.phase,
            failed_phase: value.failed_phase,
            failure_kind: value.failure_kind,
            authority: value.authority,
            reason_code: value.reason_code,
            observed_at_unix_secs: value.observed_at_unix_secs,
            value_returned: false,
            request_body_returned: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureWire {
    schema: String,
    schema_version: u16,
    declaration: DeclarationWire,
    setup_intent: SetupIntentWire,
    operation: OperationWire,
    evidence: Vec<EvidenceWire>,
}

/// Parse the canonical cross-repository contract fixture.
pub fn parse_managed_service_contract_fixture(
    input: &str,
) -> JanusResult<(
    ManagedServiceDeclarationV1,
    ManagedSetupIntentV1,
    ManagedSecretOperationV1,
    Vec<ManagedSecretEvidenceV1>,
)> {
    let fixture: FixtureWire = parse_json(
        input,
        "managed service contract fixture JSON is invalid or oversized",
    )?;
    if fixture.schema != MANAGED_SERVICE_FIXTURE_SCHEMA
        || fixture.schema_version != MANAGED_SERVICE_CONTRACT_VERSION
    {
        return Err(invalid_contract(
            "managed service contract fixture schema is unsupported",
        ));
    }
    if fixture.evidence.is_empty() || fixture.evidence.len() > 64 {
        return Err(invalid_contract(
            "managed service contract fixture evidence count is invalid",
        ));
    }
    let declaration = ManagedServiceDeclarationV1::from_wire(fixture.declaration)?;
    let intent = ManagedSetupIntentV1::from_wire(fixture.setup_intent)?;
    let operation = ManagedSecretOperationV1::from_wire(fixture.operation)?;
    let declared_slot = declaration
        .slots()
        .iter()
        .find(|slot| slot.slot_ref() == intent.target().2)
        .ok_or_else(|| {
            invalid_contract("managed service contract fixture intent slot is not declared")
        })?;
    if intent.target()
        != (
            declaration.host_ref(),
            declaration.service_ref(),
            declared_slot.slot_ref(),
        )
        || operation.intent_ref() != intent.intent_ref()
        || operation.kind() != intent.operation_kind()
        || operation.source() != intent.source()
        || intent.declaration_fingerprint() != declaration.declaration_fingerprint()
        || operation.declaration_fingerprint() != declaration.declaration_fingerprint()
        || operation.host_ref != declaration.host_ref
        || operation.service_ref != declaration.service_ref
        || operation.slot_ref != *declared_slot.slot_ref()
        || operation
            .source()
            .is_some_and(|source| !declared_slot.allowed_sources().contains(&source))
    {
        return Err(invalid_contract(
            "managed service contract fixture bindings do not match",
        ));
    }
    let evidence = fixture
        .evidence
        .into_iter()
        .map(ManagedSecretEvidenceV1::from_wire)
        .collect::<JanusResult<Vec<_>>>()?;
    let mut machine = ManagedSecretStateMachine::new(operation.kind());
    let mut previous_time = 0;
    let mut evidence_refs = BTreeSet::new();
    for (index, event) in evidence.iter().enumerate() {
        if event.operation_ref() != operation.operation_ref()
            || event.declaration_fingerprint() != declaration.declaration_fingerprint()
            || event.observed_at_unix_secs() < intent.issued_at_unix_secs()
            || event.observed_at_unix_secs() < previous_time
            || !evidence_refs.insert(event.evidence_ref().clone())
        {
            return Err(invalid_contract(
                "managed service contract fixture evidence binding is invalid",
            ));
        }
        if index == 0 {
            if event.phase() != ManagedSecretPhase::Requested
                || event.authority() != ManagedWorkflowAuthority::Pharos
                || !intent.valid_at(event.observed_at_unix_secs())
            {
                return Err(invalid_contract(
                    "managed service contract fixture must begin with the request",
                ));
            }
        } else if event.phase() == ManagedSecretPhase::Failed {
            let attempted_phase = event.failed_phase().ok_or_else(|| {
                invalid_contract("managed service contract fixture failure is incomplete")
            })?;
            match event.failure_kind() {
                Some(ManagedFailureKind::Reported) => {
                    machine.fail(attempted_phase, event.authority())?;
                }
                Some(ManagedFailureKind::TimedOut) => {
                    machine.time_out(attempted_phase)?;
                }
                None => {
                    return Err(invalid_contract(
                        "managed service contract fixture failure is incomplete",
                    ));
                }
            }
        } else {
            machine.advance(event.phase(), event.authority())?;
        }
        previous_time = event.observed_at_unix_secs();
    }
    let final_event = evidence
        .last()
        .ok_or_else(|| invalid_contract("managed service contract fixture evidence is empty"))?;
    if machine.phase() != operation.phase()
        || final_event.phase() != operation.phase()
        || final_event.failed_phase() != operation.failed_phase()
        || final_event.failure_kind() != operation.failure_kind()
        || final_event.authority() != operation.authority()
        || final_event.reason_code() != operation.reason_code()
        || final_event.observed_at_unix_secs() != operation.updated_at_unix_secs()
    {
        return Err(invalid_contract(
            "managed service contract fixture final status does not match evidence",
        ));
    }
    Ok((declaration, intent, operation, evidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str =
        include_str!("../../../contracts/managed-service-secret-contract-v1.json");

    fn fixture_value() -> serde_json::Value {
        serde_json::from_str(FIXTURE).expect("checked fixture")
    }

    #[test]
    fn canonical_fixture_parses_and_round_trips_individual_documents() {
        let (declaration, intent, operation, evidence) =
            parse_managed_service_contract_fixture(FIXTURE).unwrap();

        assert_eq!(declaration.host_ref().as_str(), "host_7f94a1c8e912");
        assert_eq!(declaration.service_ref().as_str(), "svc_24b7c8f0aa19");
        assert_eq!(declaration.slots().len(), 1);
        assert_eq!(
            declaration.slots()[0].allowed_sources(),
            &[ManagedSecretSource::Generated, ManagedSecretSource::Import]
        );
        assert_eq!(intent.target().0, declaration.host_ref());
        assert_eq!(intent.target().1, declaration.service_ref());
        assert_eq!(
            intent.target().2,
            declaration.slots().first().unwrap().slot_ref()
        );
        assert_eq!(operation.kind(), ManagedSecretOperationKind::Create);
        assert_eq!(operation.phase(), ManagedSecretPhase::Active);
        assert_eq!(operation.intent_ref(), intent.intent_ref());
        assert_eq!(
            operation.declaration_fingerprint(),
            declaration.declaration_fingerprint()
        );
        assert_eq!(operation.source(), Some(ManagedSecretSource::Generated));
        assert_eq!(evidence.len(), 8);
        assert_eq!(evidence[0].phase(), ManagedSecretPhase::Requested);
        assert_eq!(evidence[0].authority(), ManagedWorkflowAuthority::Pharos);
        assert_eq!(
            evidence[6].authority(),
            ManagedWorkflowAuthority::HealthObserver
        );
        assert_eq!(evidence[7].operation_ref(), operation.operation_ref());
        assert_eq!(
            ManagedServiceDeclarationV1::parse_json(&declaration.to_json().unwrap()).unwrap(),
            declaration
        );
        assert_eq!(
            ManagedSetupIntentV1::parse_json(&intent.to_json().unwrap()).unwrap(),
            intent
        );
        assert_eq!(
            ManagedSecretOperationV1::parse_json(&operation.to_json().unwrap()).unwrap(),
            operation
        );
        for event in evidence {
            assert_eq!(
                ManagedSecretEvidenceV1::parse_json(&event.to_json().unwrap()).unwrap(),
                event
            );
        }
    }

    #[test]
    fn fixture_and_documents_reject_unknown_fields_and_versions() {
        let mut fixture = fixture_value();
        fixture["extra"] = serde_json::json!(true);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["schema_version"] = serde_json::json!(2);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["schema_version"] = serde_json::json!(0);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut declaration = fixture_value()["declaration"].clone();
        declaration["extra"] = serde_json::json!(true);
        assert!(ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["schema_version"] = serde_json::json!(2);
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["schema_version"] = serde_json::json!(2);
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut evidence = fixture_value()["evidence"][0].clone();
        evidence["schema_version"] = serde_json::json!(2);
        assert!(ManagedSecretEvidenceV1::parse_json(&evidence.to_string()).is_err());
    }

    #[test]
    fn parsers_reject_empty_and_oversized_documents() {
        assert!(ManagedServiceDeclarationV1::parse_json("").is_err());
        assert!(ManagedSetupIntentV1::parse_json("").is_err());
        assert!(ManagedSecretOperationV1::parse_json("").is_err());
        assert!(ManagedSecretEvidenceV1::parse_json("").is_err());
        assert!(parse_managed_service_contract_fixture("").is_err());

        let oversized = " ".repeat(MAX_MANAGED_SERVICE_CONTRACT_BYTES + 1);
        assert!(ManagedServiceDeclarationV1::parse_json(&oversized).is_err());
        assert!(ManagedSetupIntentV1::parse_json(&oversized).is_err());
        assert!(ManagedSecretOperationV1::parse_json(&oversized).is_err());
        assert!(ManagedSecretEvidenceV1::parse_json(&oversized).is_err());
        assert!(parse_managed_service_contract_fixture(&oversized).is_err());
    }

    #[test]
    fn declaration_rejects_duplicate_slots_sources_and_unsafe_labels() {
        let mut declaration = fixture_value()["declaration"].clone();
        let slot = declaration["slots"][0].clone();
        declaration["slots"].as_array_mut().unwrap().push(slot);
        assert!(ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).is_err());

        let mut declaration = fixture_value()["declaration"].clone();
        declaration["slots"][0]["allowed_sources"] = serde_json::json!(["generated", "generated"]);
        assert!(ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).is_err());

        let mut declaration = fixture_value()["declaration"].clone();
        declaration["slots"][0]["safe_label"] = serde_json::json!(" unsafe\nlabel ");
        assert!(ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).is_err());

        for unsafe_label in [
            "zero\u{200b}width",
            "right\u{202e}override",
            "word\u{00a0}space",
            "line\u{2028}separator",
        ] {
            let mut declaration = fixture_value()["declaration"].clone();
            declaration["slots"][0]["safe_label"] = serde_json::json!(unsafe_label);
            assert!(ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).is_err());
        }

        let mut declaration = fixture_value()["declaration"].clone();
        declaration["slots"][0]["allowed_sources"] = serde_json::json!(["import", "generated"]);
        let parsed = ManagedServiceDeclarationV1::parse_json(&declaration.to_string()).unwrap();
        assert_eq!(
            parsed.slots()[0].allowed_sources(),
            &[ManagedSecretSource::Generated, ManagedSecretSource::Import]
        );
    }

    #[test]
    fn opaque_refs_reject_paths_urls_and_cross_type_values() {
        assert!(ManagedHostRef::new("/run/secrets/service").is_err());
        assert!(ManagedServiceRef::new("https://pharos.example/service").is_err());
        assert!(ManagedSecretSlotRef::new("svc_24b7c8f0aa19").is_err());
        assert!(ManagedSetupIntentRef::new("intent_too").is_err());
        assert!(ManagedOperationRef::new("op_upperCASE123").is_err());
    }

    #[test]
    fn setup_intent_is_bounded_and_has_no_ambient_return_url() {
        let mut intent = fixture_value()["setup_intent"].clone();
        intent["expires_at_unix_secs"] =
            serde_json::json!(intent["issued_at_unix_secs"].as_u64().unwrap() + 301);
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["expires_at_unix_secs"] =
            serde_json::json!(intent["issued_at_unix_secs"].as_u64().unwrap() + 300);
        let parsed = ManagedSetupIntentV1::parse_json(&intent.to_string()).unwrap();
        assert_eq!(parsed.operation_kind(), ManagedSecretOperationKind::Create);
        assert_eq!(parsed.source(), Some(ManagedSecretSource::Generated));
        assert!(!parsed.valid_at(parsed.issued_at_unix_secs() - 1));
        assert!(parsed.valid_at(parsed.issued_at_unix_secs()));
        assert!(parsed.valid_at(parsed.expires_at_unix_secs() - 1));
        assert!(!parsed.valid_at(parsed.expires_at_unix_secs()));

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["expires_at_unix_secs"] = intent["issued_at_unix_secs"].clone();
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["return_target"] = serde_json::json!("https://attacker.example");
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["operation_kind"] = serde_json::json!("remove");
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["source"] = serde_json::Value::Null;
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_err());

        let mut intent = fixture_value()["setup_intent"].clone();
        intent["operation_kind"] = serde_json::json!("remove");
        intent["source"] = serde_json::Value::Null;
        assert!(ManagedSetupIntentV1::parse_json(&intent.to_string()).is_ok());
    }

    #[test]
    fn operation_requires_value_free_output_right_authority_and_generation() {
        let mut operation = fixture_value()["operation"].clone();
        operation["value_returned"] = serde_json::json!(true);
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["authority"] = serde_json::json!("pharos");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["generation_ref"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["source"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["secret_ref"] = serde_json::json!("/run/secret");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["reason_code"] = serde_json::json!("managed_secret_requested");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut operation = fixture_value()["operation"].clone();
        operation["updated_at_unix_secs"] = serde_json::json!(0);
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut early = fixture_value()["operation"].clone();
        early["phase"] = serde_json::json!("requested");
        early["authority"] = serde_json::json!("pharos");
        early["reason_code"] = serde_json::json!("managed_secret_requested");
        early["generation_ref"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&early.to_string()).is_ok());
        early["generation_ref"] = serde_json::json!("gen_c628b7f3e114");
        assert!(ManagedSecretOperationV1::parse_json(&early.to_string()).is_err());

        let mut remove = fixture_value()["operation"].clone();
        remove["kind"] = serde_json::json!("remove");
        remove["phase"] = serde_json::json!("requested");
        remove["authority"] = serde_json::json!("pharos");
        remove["reason_code"] = serde_json::json!("managed_secret_requested");
        remove["source"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&remove.to_string()).is_ok());
        remove["generation_ref"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&remove.to_string()).is_err());
    }

    #[test]
    fn evidence_rejects_request_or_value_return() {
        let mut evidence = fixture_value()["evidence"][0].clone();
        evidence["request_body_returned"] = serde_json::json!(true);
        assert!(ManagedSecretEvidenceV1::parse_json(&evidence.to_string()).is_err());

        let mut evidence = fixture_value()["evidence"][0].clone();
        evidence["value_returned"] = serde_json::json!(true);
        assert!(ManagedSecretEvidenceV1::parse_json(&evidence.to_string()).is_err());

        let mut evidence = fixture_value()["evidence"][0].clone();
        evidence["reason_code"] = serde_json::json!("managed_secret_active");
        assert!(ManagedSecretEvidenceV1::parse_json(&evidence.to_string()).is_err());

        let mut evidence = fixture_value()["evidence"][0].clone();
        evidence["observed_at_unix_secs"] = serde_json::json!(0);
        assert!(ManagedSecretEvidenceV1::parse_json(&evidence.to_string()).is_err());
    }

    #[test]
    fn failed_status_names_the_exact_attempted_phase_and_authority() {
        let mut operation = fixture_value()["operation"].clone();
        operation["phase"] = serde_json::json!("failed");
        operation["failed_phase"] = serde_json::json!("delivered");
        operation["failure_kind"] = serde_json::json!("reported");
        operation["authority"] = serde_json::json!("host_executor");
        operation["reason_code"] = serde_json::json!("managed_secret_failed");
        let parsed = ManagedSecretOperationV1::parse_json(&operation.to_string()).unwrap();
        assert_eq!(parsed.phase(), ManagedSecretPhase::Failed);
        assert_eq!(parsed.failed_phase(), Some(ManagedSecretPhase::Delivered));
        assert_eq!(parsed.failure_kind(), Some(ManagedFailureKind::Reported));

        operation["authority"] = serde_json::json!("janus");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        operation["failure_kind"] = serde_json::json!("timed_out");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_ok());

        operation["authority"] = serde_json::json!("host_executor");
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        operation["failed_phase"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&operation.to_string()).is_err());

        let mut non_failed = fixture_value()["operation"].clone();
        non_failed["failed_phase"] = serde_json::json!("delivered");
        non_failed["failure_kind"] = serde_json::json!("reported");
        assert!(ManagedSecretOperationV1::parse_json(&non_failed.to_string()).is_err());

        let mut encryption_failure = fixture_value()["operation"].clone();
        encryption_failure["phase"] = serde_json::json!("failed");
        encryption_failure["failed_phase"] = serde_json::json!("encrypted");
        encryption_failure["failure_kind"] = serde_json::json!("reported");
        encryption_failure["authority"] = serde_json::json!("janus");
        encryption_failure["reason_code"] = serde_json::json!("managed_secret_failed");
        encryption_failure["generation_ref"] = serde_json::Value::Null;
        assert!(ManagedSecretOperationV1::parse_json(&encryption_failure.to_string()).is_ok());
    }

    #[test]
    fn canonical_fixture_binds_every_authority_event_in_order() {
        let mut fixture = fixture_value();
        fixture["evidence"][3]["authority"] = serde_json::json!("janus");
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["evidence"][4]["evidence_ref"] = fixture["evidence"][3]["evidence_ref"].clone();
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        let early = fixture["evidence"][2]["observed_at_unix_secs"]
            .as_u64()
            .unwrap()
            - 1;
        fixture["evidence"][3]["observed_at_unix_secs"] = serde_json::json!(early);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        let mut other_slot = fixture["declaration"]["slots"][0].clone();
        other_slot["slot_ref"] = serde_json::json!("slot_018be70c42da");
        fixture["declaration"]["slots"]
            .as_array_mut()
            .unwrap()
            .insert(0, other_slot);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_ok());

        let mut fixture = fixture_value();
        fixture["setup_intent"]["declaration_fingerprint"] = serde_json::json!("decl_aaaaaaaaaaaa");
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["setup_intent"]["source"] = serde_json::json!("import");
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["operation"]["kind"] = serde_json::json!("replace");
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["declaration"]["slots"][0]["allowed_sources"] = serde_json::json!(["import"]);
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["evidence"][0]["observed_at_unix_secs"] = serde_json::json!(
            fixture["setup_intent"]["issued_at_unix_secs"]
                .as_u64()
                .unwrap()
                - 1
        );
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        fixture["evidence"][0]["observed_at_unix_secs"] =
            fixture["setup_intent"]["expires_at_unix_secs"].clone();
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());

        let mut fixture = fixture_value();
        let final_index = fixture["evidence"].as_array().unwrap().len() - 1;
        fixture["evidence"][final_index]["observed_at_unix_secs"] = serde_json::json!(
            fixture["operation"]["updated_at_unix_secs"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert!(parse_managed_service_contract_fixture(&fixture.to_string()).is_err());
    }

    #[test]
    fn create_and_replace_follow_delivery_validation_and_activation_order() {
        for kind in [
            ManagedSecretOperationKind::Create,
            ManagedSecretOperationKind::Replace,
        ] {
            let mut machine = ManagedSecretStateMachine::new(kind);
            let transitions = [
                (
                    ManagedSecretPhase::Preflighted,
                    ManagedWorkflowAuthority::Janus,
                ),
                (
                    ManagedSecretPhase::Encrypted,
                    ManagedWorkflowAuthority::Janus,
                ),
                (
                    ManagedSecretPhase::Delivered,
                    ManagedWorkflowAuthority::HostExecutor,
                ),
                (
                    ManagedSecretPhase::Materialized,
                    ManagedWorkflowAuthority::HostExecutor,
                ),
                (
                    ManagedSecretPhase::Reloaded,
                    ManagedWorkflowAuthority::HostExecutor,
                ),
                (
                    ManagedSecretPhase::Healthy,
                    ManagedWorkflowAuthority::HealthObserver,
                ),
                (ManagedSecretPhase::Active, ManagedWorkflowAuthority::Janus),
            ];
            for (phase, authority) in transitions {
                machine.advance(phase, authority).unwrap();
            }
            assert_eq!(machine.phase(), ManagedSecretPhase::Active);
            assert!(machine
                .advance(ManagedSecretPhase::Failed, ManagedWorkflowAuthority::Pharos)
                .is_err());
        }
    }

    #[test]
    fn reported_terminal_failures_and_supervised_timeouts_are_explicit() {
        let mut activation = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Create);
        for (phase, authority) in [
            (
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            ),
            (
                ManagedSecretPhase::Encrypted,
                ManagedWorkflowAuthority::Janus,
            ),
            (
                ManagedSecretPhase::Delivered,
                ManagedWorkflowAuthority::HostExecutor,
            ),
            (
                ManagedSecretPhase::Materialized,
                ManagedWorkflowAuthority::HostExecutor,
            ),
            (
                ManagedSecretPhase::Reloaded,
                ManagedWorkflowAuthority::HostExecutor,
            ),
            (
                ManagedSecretPhase::Healthy,
                ManagedWorkflowAuthority::HealthObserver,
            ),
        ] {
            activation.advance(phase, authority).unwrap();
        }
        activation
            .fail(ManagedSecretPhase::Active, ManagedWorkflowAuthority::Janus)
            .unwrap();
        assert_eq!(activation.phase(), ManagedSecretPhase::Failed);
        assert_eq!(
            activation.failure_kind(),
            Some(ManagedFailureKind::Reported)
        );

        let mut silent_host = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Create);
        silent_host
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        silent_host
            .advance(
                ManagedSecretPhase::Encrypted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        assert!(silent_host
            .fail(
                ManagedSecretPhase::Delivered,
                ManagedWorkflowAuthority::Janus
            )
            .is_err());
        silent_host.time_out(ManagedSecretPhase::Delivered).unwrap();
        assert_eq!(silent_host.phase(), ManagedSecretPhase::Failed);
        assert_eq!(
            silent_host.failure_kind(),
            Some(ManagedFailureKind::TimedOut)
        );

        let mut rollback = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Replace);
        rollback
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        rollback
            .advance(
                ManagedSecretPhase::Encrypted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        rollback
            .advance(
                ManagedSecretPhase::RollingBack,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        rollback
            .fail(
                ManagedSecretPhase::RolledBack,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        assert_eq!(rollback.phase(), ManagedSecretPhase::Failed);
    }

    #[test]
    fn rollback_and_removal_are_ordered_and_fail_closed() {
        let mut replace = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Replace);
        replace
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        replace
            .advance(
                ManagedSecretPhase::Encrypted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        replace
            .advance(
                ManagedSecretPhase::RollingBack,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        replace
            .advance(
                ManagedSecretPhase::RolledBack,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        assert_eq!(replace.phase(), ManagedSecretPhase::RolledBack);
        assert!(replace
            .advance(ManagedSecretPhase::Active, ManagedWorkflowAuthority::Janus)
            .is_err());

        let mut remove = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Remove);
        for (phase, authority) in [
            (
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            ),
            (
                ManagedSecretPhase::DetachRequested,
                ManagedWorkflowAuthority::Pharos,
            ),
            (
                ManagedSecretPhase::Detached,
                ManagedWorkflowAuthority::Nixcfg,
            ),
            (ManagedSecretPhase::Revoked, ManagedWorkflowAuthority::Janus),
            (
                ManagedSecretPhase::Removing,
                ManagedWorkflowAuthority::HostExecutor,
            ),
            (
                ManagedSecretPhase::Removed,
                ManagedWorkflowAuthority::HostExecutor,
            ),
            (
                ManagedSecretPhase::Quarantined,
                ManagedWorkflowAuthority::Janus,
            ),
            (
                ManagedSecretPhase::Destroyed,
                ManagedWorkflowAuthority::Janus,
            ),
        ] {
            remove.advance(phase, authority).unwrap();
        }
        assert_eq!(remove.phase(), ManagedSecretPhase::Destroyed);
        assert!(remove
            .advance(ManagedSecretPhase::Failed, ManagedWorkflowAuthority::Janus)
            .is_err());

        let mut invalid = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Remove);
        assert!(invalid
            .advance(
                ManagedSecretPhase::Quarantined,
                ManagedWorkflowAuthority::Janus
            )
            .is_err());

        let mut detached = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Remove);
        detached
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        detached
            .advance(
                ManagedSecretPhase::DetachRequested,
                ManagedWorkflowAuthority::Pharos,
            )
            .unwrap();
        detached
            .advance(
                ManagedSecretPhase::Detached,
                ManagedWorkflowAuthority::Nixcfg,
            )
            .unwrap();
        assert!(detached
            .advance(
                ManagedSecretPhase::Cancelled,
                ManagedWorkflowAuthority::Pharos
            )
            .is_err());

        let mut cancelled = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Remove);
        cancelled
            .advance(
                ManagedSecretPhase::Cancelled,
                ManagedWorkflowAuthority::Pharos,
            )
            .unwrap();
        assert_eq!(cancelled.phase(), ManagedSecretPhase::Cancelled);

        let mut wrong_authority =
            ManagedSecretStateMachine::new(ManagedSecretOperationKind::Create);
        assert!(wrong_authority
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Pharos
            )
            .is_err());

        let mut failed = ManagedSecretStateMachine::new(ManagedSecretOperationKind::Create);
        failed
            .advance(
                ManagedSecretPhase::Preflighted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        failed
            .advance(
                ManagedSecretPhase::Encrypted,
                ManagedWorkflowAuthority::Janus,
            )
            .unwrap();
        assert!(failed
            .fail(
                ManagedSecretPhase::Delivered,
                ManagedWorkflowAuthority::Janus
            )
            .is_err());
        failed
            .fail(
                ManagedSecretPhase::Delivered,
                ManagedWorkflowAuthority::HostExecutor,
            )
            .unwrap();
        assert_eq!(failed.phase(), ManagedSecretPhase::Failed);
        assert_eq!(failed.failed_phase(), Some(ManagedSecretPhase::Delivered));
    }

    #[test]
    fn compatibility_window_is_current_and_one_predecessor_only() {
        assert!(managed_contract_version_compatible(1, 1));
        assert!(managed_contract_version_compatible(2, 2));
        assert!(managed_contract_version_compatible(2, 1));
        assert!(!managed_contract_version_compatible(1, 0));
        assert!(!managed_contract_version_compatible(1, 2));
        assert!(!managed_contract_version_compatible(3, 1));
    }
}

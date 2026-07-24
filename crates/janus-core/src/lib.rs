//! # janus-core
//!
//! Core domain model for Janus: opaque references, principal-bound use permits,
//! policy decisions, audit-as-evidence, and backend-neutral store contracts.
//! The shipped Go envelope is an oversight surface; this crate is the engine
//! that will eventually make secret-bearing decisions.

#![forbid(unsafe_code)]

pub mod audit;
pub mod break_glass;
pub mod broker;
pub mod consumer;
pub mod delegation;
pub mod error;
pub mod managed_service;
pub mod manifest;
pub mod metadata;
pub mod migration;
pub mod minimization;
pub mod plane;
pub mod policy;
pub mod principal;
pub mod recovery;
pub mod refs;
pub mod release;
pub mod retention;
pub mod roles;
pub mod rotation;
pub mod scope;
pub mod stale;
pub mod store;
pub mod tombstone;
pub mod transfer;
pub mod value;

pub use audit::{
    audit_integrity_hash, AuditAction, AuditEvent, AuditIntegrityInput, AuditOutcome, AuditSink,
    AuditWrite, Severity,
};
pub use break_glass::{
    BreakGlassActivation, BreakGlassActivationId, BreakGlassActivationSnapshotV1,
    BreakGlassAttempt, BreakGlassAttemptId, BreakGlassAttemptSnapshotV1, BreakGlassCompletion,
    BreakGlassCompletionId, BreakGlassCompletionOutcome, BreakGlassCompletionSnapshotV1,
    BreakGlassRequest, BreakGlassRequestId, BreakGlassRequestSnapshotV1, BreakGlassReview,
    BreakGlassReviewClosure, BreakGlassReviewId, BreakGlassReviewSnapshotV1, BreakGlassRevocation,
    BreakGlassRevocationId, BreakGlassRevocationSnapshotV1, BREAK_GLASS_SNAPSHOT_VERSION,
    MAX_BREAK_GLASS_TTL,
};
pub use broker::SecretBroker;
pub use consumer::{
    BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRegistry, Environment, OwnerRef,
    ReloadMethod,
};
pub use delegation::{
    DelegatedUseContext, DelegatedUseContextSnapshotV1, DelegationAction, DelegationDecision,
    DelegationGrant, DelegationGrantSnapshotV1, DelegationId, DelegationPolicy,
    DelegationRevocation, DelegationRevocationSnapshotV1, DelegationScope, DelegationStatus,
};
pub use error::{JanusError, JanusResult};
pub use managed_service::{
    managed_contract_version_compatible, parse_managed_service_contract_fixture,
    ManagedConsumerKind, ManagedDeclarationFingerprint, ManagedDeliveryKind,
    ManagedDeliveryProfileRef, ManagedEvidenceRef, ManagedFailureKind, ManagedGenerationRef,
    ManagedHealthProfileRef, ManagedHostRef, ManagedHumanSessionRef, ManagedNonceRef,
    ManagedOperationRef, ManagedReasonCode, ManagedReloadProfileRef, ManagedReturnTarget,
    ManagedSecretEvidenceV1, ManagedSecretOperationKind, ManagedSecretOperationV1,
    ManagedSecretPhase, ManagedSecretRef, ManagedSecretSlotRef, ManagedSecretSlotV1,
    ManagedSecretSource, ManagedSecretStateMachine, ManagedServiceDeclarationV1, ManagedServiceRef,
    ManagedSetupIntentRef, ManagedSetupIntentV1, ManagedSystemRef, ManagedWorkflowAuthority,
    MANAGED_SERVICE_CONTRACT_VERSION, MANAGED_SERVICE_DECLARATION_SCHEMA,
    MANAGED_SERVICE_EVIDENCE_SCHEMA, MANAGED_SERVICE_FIXTURE_SCHEMA,
    MANAGED_SERVICE_OPERATION_SCHEMA, MANAGED_SERVICE_SETUP_INTENT_SCHEMA,
    MAX_MANAGED_SERVICE_CONTRACT_BYTES, MAX_SETUP_INTENT_TTL_SECS,
};
pub use manifest::{load_secretspec_manifest_catalog, ManifestCatalog};
pub use metadata::{SecretMetadataOverlay, SecretMetadataPatch};
pub use migration::{MigrationCompatibility, MigrationManifest, MigrationPhase, MigrationRisk};
pub use minimization::{
    enforce_value_free_json, excludes_literals, MinimizationViolation, FORBIDDEN_OUTPUT_FIELDS,
};
pub use plane::{
    authorize_runtime_action, runtime_endpoint_matrix, runtime_endpoint_policy, RuntimeAbuseBudget,
    RuntimeAction, RuntimeControlApplicability, RuntimeEndpointPolicy, RuntimeInputEncoding,
    RuntimePlane, RuntimeTimeoutPolicy, RuntimeTransport, CLI_MAX_ARGUMENT_BYTES,
    RUNTIME_ENDPOINT_POLICIES, WARDEN_CALL_TIMEOUT_MS, WARDEN_MAX_ARGUMENT_BYTES,
    WARDEN_RATE_REQUESTS, WARDEN_RATE_WINDOW_MS,
};
pub use policy::{
    ApprovalGrant, ApprovalGrantScope, ApprovalGrantSnapshot, ApprovalId, ClassPermitPolicy,
    EgressMode, PermitId, PermitIssuer, PolicyDecision, ProfileId, ProfilePolicy, Purpose,
    TrustLevel, UsePermit, UsePermitSnapshot, UseProfile, UseRequest,
};
pub use principal::{Principal, PrincipalChain, PrincipalId, PrincipalKind};
pub use recovery::{
    RecoveryComponentKind, RecoveryComponentSource, RecoveryConfigBinding,
    RecoveryDrillEvidenceInput, RecoveryDrillEvidenceV1, RecoveryDrillManifest,
};
pub use refs::{
    ConsumerRef, Destination, ExecutorRef, ProjectId, SafeLabel, SecretName, SecretRef,
};
pub use release::{
    ProductMode, ReleaseAdmission, ReleaseAdmissionDecision, ReleaseAdmissionReceipt,
    ReleaseChannelPolicy,
};
pub use retention::{
    RetentionClassRule, RetentionConfigBinding, RetentionDisposition, RetentionEvidenceClass,
    RetentionEvidenceInput, RetentionEvidenceV1, RetentionHoldRegistryV1, RetentionHoldV1,
    RetentionPolicyV1,
};
pub use roles::{
    authorization_fingerprint, authorize_role_action, Duty, DutyConflict, DutyEvidence, Permission,
    Role, RoleBinding, RoleBindingId, RoleBindingSnapshotV1, RoleBindingSource,
    RoleBindingSourceKind, RoleDecision, RoleDecisionInput, RoleDecisionSnapshotV1,
    RolePolicySnapshotV1, RolePolicyV1, SeparationPolicy, MAX_ROLE_BINDING_TTL,
    ROLE_BINDING_SNAPSHOT_VERSION, ROLE_POLICY_SNAPSHOT_VERSION,
};
pub use rotation::{
    RollbackPlan, RotationDecision, RotationOutcome, RotationPhase, RotationPlan, RotationPlanner,
    RotationSpec, RotationStrategy, ValidationProbe,
};
pub use scope::{
    EnvironmentId, NamespaceId, OrganizationId, RepositoryId, ScopePathV1, ScopeRef, WorkloadId,
};
pub use stale::{
    SecretAgeEvidence, StaleSecretPolicy, StaleSecretReportRow, StaleSecretReporter,
    StaleSecretStatus,
};
pub use store::{
    HealthStatus, LifecycleTransition, LifecycleTransitionPolicy, SecretClass, SecretDescriptor,
    SecretLifecycle, SecretMeta, SecretStore, StoreCapabilities,
};
pub use tombstone::{SecretTombstone, SecretTombstoneRequest, TombstonePolicy};
pub use transfer::{ScopeTransferManifest, ScopeTransferMode};
pub use value::SecretValue;

#[cfg(test)]
pub(crate) fn test_scope(environment: &str) -> ScopeRef {
    ScopePathV1::new(
        OrganizationId::new("fixture-org").expect("static organization"),
        ProjectId::new("janus").expect("static project"),
        RepositoryId::new("janus").expect("static repository"),
        EnvironmentId::new(environment).expect("valid test environment"),
    )
    .scope_ref()
}

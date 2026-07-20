//! # janus-core
//!
//! Core domain model for Janus: opaque references, principal-bound use permits,
//! policy decisions, audit-as-evidence, and backend-neutral store contracts.
//! The shipped Go envelope is an oversight surface; this crate is the engine
//! that will eventually make secret-bearing decisions.

#![forbid(unsafe_code)]

pub mod audit;
pub mod broker;
pub mod consumer;
pub mod error;
pub mod manifest;
pub mod metadata;
pub mod migration;
pub mod plane;
pub mod policy;
pub mod principal;
pub mod refs;
pub mod release;
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
pub use broker::SecretBroker;
pub use consumer::{
    BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRegistry, Environment, OwnerRef,
    ReloadMethod,
};
pub use error::{JanusError, JanusResult};
pub use manifest::ManifestCatalog;
pub use metadata::{SecretMetadataOverlay, SecretMetadataPatch};
pub use migration::{MigrationCompatibility, MigrationManifest, MigrationPhase, MigrationRisk};
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
pub use refs::{
    ConsumerRef, Destination, ExecutorRef, ProjectId, SafeLabel, SecretName, SecretRef,
};
pub use release::{
    ProductMode, ReleaseAdmission, ReleaseAdmissionDecision, ReleaseAdmissionReceipt,
    ReleaseChannelPolicy,
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

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
pub mod policy;
pub mod principal;
pub mod refs;
pub mod rotation;
pub mod store;
pub mod value;

pub use audit::{AuditAction, AuditEvent, AuditOutcome, AuditSink, AuditWrite, Severity};
pub use broker::SecretBroker;
pub use consumer::{
    BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRegistry, Environment, OwnerRef,
    ReloadMethod,
};
pub use error::{JanusError, JanusResult};
pub use manifest::ManifestCatalog;
pub use policy::{
    EgressMode, PermitId, PermitIssuer, PolicyDecision, ProfileId, ProfilePolicy, Purpose,
    TrustLevel, UsePermit, UseProfile, UseRequest,
};
pub use principal::{Principal, PrincipalChain, PrincipalId, PrincipalKind, ScopeRef};
pub use refs::{
    ConsumerRef, Destination, ExecutorRef, ProjectId, SafeLabel, SecretName, SecretRef,
};
pub use rotation::{
    RollbackPlan, RotationDecision, RotationOutcome, RotationPhase, RotationPlan, RotationPlanner,
    RotationSpec, RotationStrategy, ValidationProbe,
};
pub use store::{HealthStatus, SecretDescriptor, SecretMeta, SecretStore, StoreCapabilities};
pub use value::SecretValue;

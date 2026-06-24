//! Error types shared by Janus core contracts.

use std::fmt;

/// Convenience result alias for Janus core operations.
pub type JanusResult<T> = Result<T, JanusError>;

/// Core decision and contract errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JanusError {
    /// A caller supplied an empty or malformed identifier.
    InvalidIdentifier { kind: &'static str },
    /// A manifest/catalog contains duplicate or inconsistent metadata.
    InvalidManifest { detail: String },
    /// A requested secret is outside the manifest/catalog allowlist.
    NotInManifest { name: String },
    /// A manifest-declared secret is not present in the backend.
    NotFound { name: String },
    /// A backend or profile does not support a requested capability.
    Unsupported { capability: &'static str },
    /// Policy denied the request with a stable reason code.
    PolicyDenied {
        reason_code: &'static str,
        detail: String,
    },
    /// A presented permit is malformed, stale, expired, or not bound to the caller.
    PermitInvalid {
        reason_code: &'static str,
        detail: String,
    },
    /// Required audit evidence could not be written; secret-bearing work fails closed.
    AuditUnavailable { detail: String },
    /// The backend store failed without exposing secret material.
    StoreUnavailable { detail: String },
}

impl JanusError {
    /// Build a policy-denial error with a stable machine-readable reason code.
    pub fn policy_denied(reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self::PolicyDenied {
            reason_code,
            detail: detail.into(),
        }
    }

    /// Build a permit validation error with a stable reason code.
    pub fn permit_invalid(reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self::PermitInvalid {
            reason_code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for JanusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { kind } => write!(f, "invalid {kind}"),
            Self::InvalidManifest { detail } => write!(f, "invalid manifest: {detail}"),
            Self::NotInManifest { name } => {
                write!(f, "secret is not in manifest: {name}")
            }
            Self::NotFound { name } => write!(f, "manifest secret is not present: {name}"),
            Self::Unsupported { capability } => write!(f, "unsupported capability: {capability}"),
            Self::PolicyDenied {
                reason_code,
                detail,
            } => write!(f, "policy denied ({reason_code}): {detail}"),
            Self::PermitInvalid {
                reason_code,
                detail,
            } => write!(f, "permit invalid ({reason_code}): {detail}"),
            Self::AuditUnavailable { detail } => write!(f, "audit unavailable: {detail}"),
            Self::StoreUnavailable { detail } => write!(f, "store unavailable: {detail}"),
        }
    }
}

impl std::error::Error for JanusError {}

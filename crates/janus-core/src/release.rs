//! Trusted release-channel admission contracts.
//!
//! Cryptographic verification happens outside the artifact being admitted.
//! Runtime consumes the resulting policy-bound receipt and refuses to reuse it
//! across channels, artifacts, policy revisions, or product modes.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::{
    AuditAction, AuditEvent, AuditOutcome, JanusError, JanusResult, PrincipalChain, SafeLabel,
    Severity,
};

const POLICY_SCHEMA_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_SAFE_FIELD_BYTES: usize = 512;

/// Runtime product mode relevant to release-channel enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductMode {
    /// Explicit development mode; cannot claim production evidence.
    Dev,
    /// Secure local/self-hosted mode.
    SelfHosted,
    /// Production mode with trusted-release admission.
    Production,
    /// Enterprise mode with trusted-release admission.
    Enterprise,
}

impl ProductMode {
    /// Parse stable configuration text.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "dev" => Ok(Self::Dev),
            "self_hosted" => Ok(Self::SelfHosted),
            "production" => Ok(Self::Production),
            "enterprise" => Ok(Self::Enterprise),
            _ => Err(JanusError::InvalidIdentifier {
                kind: "product_mode",
            }),
        }
    }

    /// Stable configuration and evidence text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::SelfHosted => "self_hosted",
            Self::Production => "production",
            Self::Enterprise => "enterprise",
        }
    }

    /// Whether this mode must never start secret-bearing work without a
    /// trusted release admission receipt.
    pub fn requires_trusted_release(self) -> bool {
        matches!(self, Self::Production | Self::Enterprise)
    }
}

/// Reviewable release-channel admission policy.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseChannelPolicy {
    schema_version: u8,
    policy_id: String,
    policy_version: u64,
    required_modes: Vec<ProductMode>,
    deny_mode_downgrade: bool,
    channels: Vec<ReleaseChannel>,
    revoked_digests: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseChannel {
    name: String,
    image: String,
    tag_prefix: String,
    repository: String,
    signer_workflow: String,
    certificate_identity_prefix: String,
    oidc_issuer: String,
    provenance_predicate_type: String,
    sbom_predicate_type: String,
}

impl ReleaseChannelPolicy {
    /// Parse and structurally validate one versioned JSON policy.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let policy: Self =
            serde_json::from_str(contents).map_err(|_| JanusError::InvalidIdentifier {
                kind: "release_channel_policy",
            })?;
        policy.validate()?;
        Ok(policy)
    }

    /// Stable policy id.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Monotonic review version.
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Whether this mode requires a trusted release receipt.
    pub fn requires_admission(&self, mode: ProductMode) -> bool {
        self.required_modes.contains(&mode)
    }

    fn validate(&self) -> JanusResult<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION
            || self.policy_version == 0
            || !safe_field(&self.policy_id)
            || self.channels.is_empty()
        {
            return invalid_policy();
        }
        let mut modes = BTreeSet::new();
        if self.required_modes.iter().any(|mode| !modes.insert(*mode)) {
            return invalid_policy();
        }
        let mut channel_names = BTreeSet::new();
        for channel in &self.channels {
            if !channel_names.insert(channel.name.as_str())
                || !safe_field(&channel.name)
                || !safe_field(&channel.image)
                || !safe_field(&channel.tag_prefix)
                || !safe_field(&channel.repository)
                || !safe_field(&channel.signer_workflow)
                || !safe_field(&channel.certificate_identity_prefix)
                || !safe_field(&channel.oidc_issuer)
                || !safe_field(&channel.provenance_predicate_type)
                || !safe_field(&channel.sbom_predicate_type)
            {
                return invalid_policy();
            }
        }
        let mut revoked = BTreeSet::new();
        if self
            .revoked_digests
            .iter()
            .any(|digest| !valid_digest(digest) || !revoked.insert(digest.as_str()))
        {
            return invalid_policy();
        }
        Ok(())
    }
}

/// Value-free receipt emitted after external cryptographic verification.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAdmissionReceipt {
    schema_version: u8,
    policy_id: String,
    policy_version: u64,
    channel: String,
    mode: ProductMode,
    previous_mode: ProductMode,
    artifact: AdmittedArtifact,
    signature: SignatureEvidence,
    provenance: ProvenanceEvidence,
    sbom: SbomEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedArtifact {
    image: String,
    tag: String,
    digest: String,
    development: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureEvidence {
    verified: bool,
    identity: String,
    oidc_issuer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceEvidence {
    verified: bool,
    repository: String,
    signer_workflow: String,
    source_ref: String,
    predicate_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SbomEvidence {
    verified: bool,
    predicate_type: String,
}

impl ReleaseAdmissionReceipt {
    /// Parse and structurally validate one JSON admission receipt.
    pub fn parse_json(contents: &str) -> JanusResult<Self> {
        let receipt: Self =
            serde_json::from_str(contents).map_err(|_| JanusError::InvalidIdentifier {
                kind: "release_admission_receipt",
            })?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> JanusResult<()> {
        let fields = [
            self.policy_id.as_str(),
            self.channel.as_str(),
            self.artifact.image.as_str(),
            self.artifact.tag.as_str(),
            self.signature.identity.as_str(),
            self.signature.oidc_issuer.as_str(),
            self.provenance.repository.as_str(),
            self.provenance.signer_workflow.as_str(),
            self.provenance.source_ref.as_str(),
            self.provenance.predicate_type.as_str(),
            self.sbom.predicate_type.as_str(),
        ];
        if self.schema_version != RECEIPT_SCHEMA_VERSION
            || self.policy_version == 0
            || !valid_digest(&self.artifact.digest)
            || fields.iter().any(|field| !safe_field(field))
        {
            return Err(JanusError::InvalidIdentifier {
                kind: "release_admission_receipt",
            });
        }
        Ok(())
    }
}

/// Runtime release-admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseAdmissionDecision {
    /// The configured mode does not require release admission.
    NotRequired,
    /// Artifact matches policy and externally verified evidence.
    Trusted,
    /// Missing, mismatched, revoked, or untrusted evidence.
    Denied,
}

impl ReleaseAdmissionDecision {
    /// Stable health and diagnostics text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Trusted => "trusted",
            Self::Denied => "denied",
        }
    }
}

/// Value-free runtime release posture suitable for health and audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAdmission {
    decision: ReleaseAdmissionDecision,
    reason_code: &'static str,
    mode: ProductMode,
    policy_id: Option<String>,
    policy_version: Option<u64>,
    channel: Option<String>,
    artifact_id: Option<String>,
}

impl ReleaseAdmission {
    /// Evaluate an externally produced receipt against the current policy and mode.
    pub fn evaluate(
        policy: &ReleaseChannelPolicy,
        receipt: &ReleaseAdmissionReceipt,
        runtime_mode: ProductMode,
        configured_digest: Option<&str>,
    ) -> Self {
        if runtime_mode.requires_trusted_release() && !policy.requires_admission(runtime_mode) {
            return Self::base(policy, receipt, runtime_mode).deny("release_policy_mode_missing");
        }
        if !policy.requires_admission(runtime_mode) {
            return Self::not_required(runtime_mode);
        }
        let base = Self::base(policy, receipt, runtime_mode);
        if receipt.policy_id != policy.policy_id || receipt.policy_version != policy.policy_version
        {
            return base.deny("release_policy_mismatch");
        }
        if receipt.mode != runtime_mode {
            return base.deny("release_mode_mismatch");
        }
        if policy.deny_mode_downgrade && receipt.previous_mode > runtime_mode {
            return base.deny("release_mode_downgrade");
        }
        let Some(channel) = policy
            .channels
            .iter()
            .find(|channel| channel.name == receipt.channel)
        else {
            return base.deny("release_channel_denied");
        };
        if channel.image != receipt.artifact.image
            || !receipt.artifact.tag.starts_with(&channel.tag_prefix)
        {
            return base.deny("release_channel_denied");
        }
        if receipt.artifact.development || development_tag(&receipt.artifact.tag) {
            return base.deny("release_development_artifact");
        }
        if configured_digest != Some(receipt.artifact.digest.as_str()) {
            return base.deny("release_digest_mismatch");
        }
        if policy
            .revoked_digests
            .iter()
            .any(|digest| digest == &receipt.artifact.digest)
        {
            return base.deny("release_digest_revoked");
        }
        let expected_identity = format!(
            "{}{}",
            channel.certificate_identity_prefix, receipt.artifact.tag
        );
        if !receipt.signature.verified
            || receipt.signature.identity != expected_identity
            || receipt.signature.oidc_issuer != channel.oidc_issuer
        {
            return base.deny("release_signature_untrusted");
        }
        if !receipt.provenance.verified
            || receipt.provenance.repository != channel.repository
            || receipt.provenance.signer_workflow != channel.signer_workflow
            || receipt.provenance.source_ref != format!("refs/tags/{}", receipt.artifact.tag)
            || receipt.provenance.predicate_type != channel.provenance_predicate_type
        {
            return base.deny("release_provenance_untrusted");
        }
        if !receipt.sbom.verified || receipt.sbom.predicate_type != channel.sbom_predicate_type {
            return base.deny("release_sbom_untrusted");
        }
        Self {
            decision: ReleaseAdmissionDecision::Trusted,
            reason_code: "release_trust_ok",
            ..base
        }
    }

    /// Construct a posture for a mode that does not require admission.
    pub fn not_required(mode: ProductMode) -> Self {
        Self {
            decision: ReleaseAdmissionDecision::NotRequired,
            reason_code: "release_trust_not_required",
            mode,
            policy_id: None,
            policy_version: None,
            channel: None,
            artifact_id: None,
        }
    }

    /// Construct a value-free denial when policy or receipt loading failed.
    pub fn denied(mode: ProductMode, reason_code: &'static str) -> Self {
        Self {
            decision: ReleaseAdmissionDecision::Denied,
            reason_code,
            mode,
            policy_id: None,
            policy_version: None,
            channel: None,
            artifact_id: None,
        }
    }

    /// Whether secret-bearing runtime startup may continue.
    pub fn allows_secret_use(&self) -> bool {
        self.decision != ReleaseAdmissionDecision::Denied
    }

    /// Admission decision.
    pub fn decision(&self) -> ReleaseAdmissionDecision {
        self.decision
    }

    /// Stable value-free reason code.
    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    /// Runtime mode evaluated by admission.
    pub fn mode(&self) -> ProductMode {
        self.mode
    }

    /// Policy id, when safely available.
    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    /// Policy version, when safely available.
    pub fn policy_version(&self) -> Option<u64> {
        self.policy_version
    }

    /// Release channel, when safely available.
    pub fn channel(&self) -> Option<&str> {
        self.channel.as_deref()
    }

    /// Digest-pinned safe artifact id, when safely available.
    pub fn artifact_id(&self) -> Option<&str> {
        self.artifact_id.as_deref()
    }

    /// Create a value-free release admission audit event.
    pub fn audit_event(&self, principal: &PrincipalChain) -> AuditEvent {
        let outcome = if self.allows_secret_use() {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Denied
        };
        let severity = if self.allows_secret_use() {
            Severity::Info
        } else {
            Severity::Critical
        };
        let mut event = AuditEvent::new(
            AuditAction::ReleaseAdmission,
            outcome,
            self.reason_code,
            severity,
            None,
            principal,
        );
        if let Some(evidence) = self.evidence_label() {
            event = event.with_evidence(evidence);
        }
        event
    }

    fn base(
        policy: &ReleaseChannelPolicy,
        receipt: &ReleaseAdmissionReceipt,
        mode: ProductMode,
    ) -> Self {
        Self {
            decision: ReleaseAdmissionDecision::Denied,
            reason_code: "release_trust_denied",
            mode,
            policy_id: Some(policy.policy_id.clone()),
            policy_version: Some(policy.policy_version),
            channel: Some(receipt.channel.clone()),
            artifact_id: Some(format!(
                "{}@{}",
                receipt.artifact.image, receipt.artifact.digest
            )),
        }
    }

    fn deny(mut self, reason_code: &'static str) -> Self {
        self.reason_code = reason_code;
        self
    }

    fn evidence_label(&self) -> Option<SafeLabel> {
        let policy = self.policy_id.as_deref()?;
        let channel = self.channel.as_deref()?;
        let artifact = self.artifact_id.as_deref()?;
        SafeLabel::new(format!("{policy}:{channel}:{artifact}")).ok()
    }
}

fn safe_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SAFE_FIELD_BYTES
        && value.trim().len() == value.len()
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == "sha256:".len() + 64
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn development_tag(tag: &str) -> bool {
    let tag = tag.to_ascii_lowercase();
    ["-dev", ".dev", "snapshot", "dirty"]
        .iter()
        .any(|marker| tag.contains(marker))
}

fn invalid_policy<T>() -> JanusResult<T> {
    Err(JanusError::InvalidIdentifier {
        kind: "release_channel_policy",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Principal, PrincipalId, PrincipalKind};

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn policy_json(revoked: bool) -> String {
        format!(
            r#"{{
  "schema_version": 1,
  "policy_id": "janus-engine-release-v1",
  "policy_version": 1,
  "required_modes": ["production", "enterprise"],
  "deny_mode_downgrade": true,
  "channels": [{{
    "name": "stable",
    "image": "ghcr.io/markus-barta/janus/janus-engine",
    "tag_prefix": "rust-engine-v",
    "repository": "markus-barta/janus",
    "signer_workflow": "markus-barta/janus/.github/workflows/rust.yml",
    "certificate_identity_prefix": "https://github.com/markus-barta/janus/.github/workflows/rust.yml@refs/tags/",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "provenance_predicate_type": "https://slsa.dev/provenance/v1",
    "sbom_predicate_type": "https://spdx.dev/Document/v2.3"
  }}],
  "revoked_digests": [{}]
}}"#,
            if revoked {
                format!(r#""{DIGEST}""#)
            } else {
                String::new()
            }
        )
    }

    fn receipt_json(overrides: &[(&str, &str)]) -> String {
        let mut value = serde_json::json!({
            "schema_version": 1,
            "policy_id": "janus-engine-release-v1",
            "policy_version": 1,
            "channel": "stable",
            "mode": "enterprise",
            "previous_mode": "enterprise",
            "artifact": {
                "image": "ghcr.io/markus-barta/janus/janus-engine",
                "tag": "rust-engine-v0.1.6",
                "digest": DIGEST,
                "development": false
            },
            "signature": {
                "verified": true,
                "identity": "https://github.com/markus-barta/janus/.github/workflows/rust.yml@refs/tags/rust-engine-v0.1.6",
                "oidc_issuer": "https://token.actions.githubusercontent.com"
            },
            "provenance": {
                "verified": true,
                "repository": "markus-barta/janus",
                "signer_workflow": "markus-barta/janus/.github/workflows/rust.yml",
                "source_ref": "refs/tags/rust-engine-v0.1.6",
                "predicate_type": "https://slsa.dev/provenance/v1"
            },
            "sbom": {
                "verified": true,
                "predicate_type": "https://spdx.dev/Document/v2.3"
            }
        });
        for (pointer, replacement) in overrides {
            *value.pointer_mut(pointer).unwrap() = serde_json::from_str(replacement).unwrap();
        }
        serde_json::to_string(&value).unwrap()
    }

    fn admission(overrides: &[(&str, &str)], revoked: bool) -> ReleaseAdmission {
        let policy = ReleaseChannelPolicy::parse_json(&policy_json(revoked)).unwrap();
        let receipt = ReleaseAdmissionReceipt::parse_json(&receipt_json(overrides)).unwrap();
        ReleaseAdmission::evaluate(&policy, &receipt, ProductMode::Enterprise, Some(DIGEST))
    }

    #[test]
    fn trusted_receipt_is_policy_mode_channel_and_digest_bound() {
        let admission = admission(&[], false);
        assert_eq!(admission.decision(), ReleaseAdmissionDecision::Trusted);
        assert_eq!(admission.reason_code(), "release_trust_ok");
        assert_eq!(admission.policy_id(), Some("janus-engine-release-v1"));
        assert_eq!(admission.channel(), Some("stable"));
        assert!(admission.artifact_id().unwrap().ends_with(DIGEST));
    }

    #[test]
    fn unsigned_mismatched_revoked_and_development_artifacts_fail_closed() {
        let cases = [
            (
                vec![("/signature/verified", "false")],
                false,
                "release_signature_untrusted",
            ),
            (
                vec![("/signature/identity", r#""attacker""#)],
                false,
                "release_signature_untrusted",
            ),
            (
                vec![("/provenance/verified", "false")],
                false,
                "release_provenance_untrusted",
            ),
            (
                vec![("/provenance/source_ref", r#""refs/heads/main""#)],
                false,
                "release_provenance_untrusted",
            ),
            (
                vec![("/sbom/verified", "false")],
                false,
                "release_sbom_untrusted",
            ),
            (
                vec![("/artifact/development", "true")],
                false,
                "release_development_artifact",
            ),
            (
                vec![("/artifact/tag", r#""rust-engine-v0.1.6-dev""#)],
                false,
                "release_development_artifact",
            ),
            (Vec::new(), true, "release_digest_revoked"),
        ];
        for (overrides, revoked, expected) in cases {
            let admission = admission(&overrides, revoked);
            assert_eq!(admission.decision(), ReleaseAdmissionDecision::Denied);
            assert_eq!(admission.reason_code(), expected);
        }
    }

    #[test]
    fn policy_revision_channel_and_mode_changes_require_readmission() {
        let cases = [
            (vec![("/policy_version", "2")], "release_policy_mismatch"),
            (
                vec![("/channel", r#""candidate""#)],
                "release_channel_denied",
            ),
            (vec![("/mode", r#""production""#)], "release_mode_mismatch"),
            (
                vec![
                    ("/previous_mode", r#""enterprise""#),
                    ("/mode", r#""production""#),
                ],
                "release_mode_mismatch",
            ),
        ];
        for (overrides, expected) in cases {
            let admission = admission(&overrides, false);
            assert_eq!(admission.reason_code(), expected);
            assert!(!admission.allows_secret_use());
        }

        let policy = ReleaseChannelPolicy::parse_json(&policy_json(false)).unwrap();
        let receipt = ReleaseAdmissionReceipt::parse_json(&receipt_json(&[
            ("/mode", r#""production""#),
            ("/previous_mode", r#""enterprise""#),
        ]))
        .unwrap();
        let downgrade =
            ReleaseAdmission::evaluate(&policy, &receipt, ProductMode::Production, Some(DIGEST));
        assert_eq!(downgrade.reason_code(), "release_mode_downgrade");

        let digest_mismatch = ReleaseAdmission::evaluate(
            &policy,
            &ReleaseAdmissionReceipt::parse_json(&receipt_json(&[])).unwrap(),
            ProductMode::Enterprise,
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );
        assert_eq!(digest_mismatch.reason_code(), "release_digest_mismatch");

        let mut missing_mode_policy: serde_json::Value =
            serde_json::from_str(&policy_json(false)).unwrap();
        missing_mode_policy["required_modes"] = serde_json::json!(["production"]);
        let missing_mode_policy =
            ReleaseChannelPolicy::parse_json(&serde_json::to_string(&missing_mode_policy).unwrap())
                .unwrap();
        let receipt = ReleaseAdmissionReceipt::parse_json(&receipt_json(&[])).unwrap();
        let missing_mode = ReleaseAdmission::evaluate(
            &missing_mode_policy,
            &receipt,
            ProductMode::Enterprise,
            Some(DIGEST),
        );
        assert_eq!(missing_mode.reason_code(), "release_policy_mode_missing");
        assert!(!missing_mode.allows_secret_use());
    }

    #[test]
    fn non_required_modes_are_explicit_and_cannot_claim_trusted_release() {
        let policy = ReleaseChannelPolicy::parse_json(&policy_json(false)).unwrap();
        let receipt = ReleaseAdmissionReceipt::parse_json(&receipt_json(&[])).unwrap();
        let admission =
            ReleaseAdmission::evaluate(&policy, &receipt, ProductMode::SelfHosted, None);
        assert_eq!(admission.decision(), ReleaseAdmissionDecision::NotRequired);
        assert_eq!(admission.reason_code(), "release_trust_not_required");
        assert!(admission.artifact_id().is_none());
    }

    #[test]
    fn release_audit_is_value_free_and_critical_on_denial() {
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("release-admission").unwrap(),
            ),
            crate::test_scope("release"),
        );
        let trusted = admission(&[], false).audit_event(&principal);
        assert_eq!(trusted.action, AuditAction::ReleaseAdmission);
        assert_eq!(trusted.outcome, AuditOutcome::Allowed);
        let evidence = trusted.evidence.as_ref().unwrap().as_str();
        assert!(evidence.contains("janus-engine-release-v1:stable:"));
        assert!(evidence.ends_with(DIGEST));
        assert!(!trusted.value_returned);

        let denied = admission(&[("/signature/verified", "false")], false).audit_event(&principal);
        assert_eq!(denied.outcome, AuditOutcome::Denied);
        assert_eq!(denied.severity, Severity::Critical);
        assert!(!denied.value_returned);
    }

    #[test]
    fn malformed_or_ambiguous_policy_and_receipt_are_rejected() {
        assert!(ReleaseChannelPolicy::parse_json("{}").is_err());
        assert!(ReleaseAdmissionReceipt::parse_json("{}").is_err());
        let duplicate = policy_json(false).replace(
            r#""required_modes": ["production", "enterprise"]"#,
            r#""required_modes": ["enterprise", "enterprise"]"#,
        );
        assert!(ReleaseChannelPolicy::parse_json(&duplicate).is_err());
        let uppercase_digest = receipt_json(&[(
            "/artifact/digest",
            r#""sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#,
        )]);
        assert!(ReleaseAdmissionReceipt::parse_json(&uppercase_digest).is_err());
    }

    #[test]
    fn repository_release_fixtures_cover_trusted_and_rejected_artifacts() {
        let policy = ReleaseChannelPolicy::parse_json(include_str!(
            "../../../config/release-channels/v1.json"
        ))
        .unwrap();
        let trusted = ReleaseAdmissionReceipt::parse_json(include_str!(
            "../../../fixtures/release-admission/trusted.json"
        ))
        .unwrap();
        assert_eq!(
            ReleaseAdmission::evaluate(&policy, &trusted, ProductMode::Enterprise, Some(DIGEST))
                .decision(),
            ReleaseAdmissionDecision::Trusted
        );

        let unsigned = ReleaseAdmissionReceipt::parse_json(include_str!(
            "../../../fixtures/release-admission/unsigned.json"
        ))
        .unwrap();
        assert_eq!(
            ReleaseAdmission::evaluate(&policy, &unsigned, ProductMode::Enterprise, Some(DIGEST))
                .reason_code(),
            "release_signature_untrusted"
        );

        let development = ReleaseAdmissionReceipt::parse_json(include_str!(
            "../../../fixtures/release-admission/development.json"
        ))
        .unwrap();
        assert_eq!(
            ReleaseAdmission::evaluate(
                &policy,
                &development,
                ProductMode::Enterprise,
                Some(DIGEST)
            )
            .reason_code(),
            "release_development_artifact"
        );
    }
}

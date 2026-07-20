use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use janus_core::{
    AuditSink, JanusError, JanusResult, PrincipalChain, ProductMode, ReleaseAdmission,
    ReleaseAdmissionReceipt, ReleaseChannelPolicy,
};

use crate::JsonlAuditSink;

const MAX_RELEASE_EVIDENCE_BYTES: u64 = 1024 * 1024;

/// Load and evaluate a versioned release policy and external admission receipt.
///
/// Production and enterprise modes fail closed when either path is absent,
/// unreadable, mutable by group/world, malformed, or mismatched. Development
/// and self-hosted modes remain explicit `not_required` unless both artifacts
/// are supplied for posture reporting.
pub fn load_release_admission(
    mode: ProductMode,
    policy_path: Option<&Path>,
    receipt_path: Option<&Path>,
    configured_digest: Option<&str>,
) -> ReleaseAdmission {
    let (Some(policy_path), Some(receipt_path)) = (policy_path, receipt_path) else {
        return if mode.requires_trusted_release() {
            ReleaseAdmission::denied(mode, "release_evidence_missing")
        } else {
            ReleaseAdmission::not_required(mode)
        };
    };

    let policy_text = match read_reviewed_file(policy_path) {
        Ok(contents) => contents,
        Err(()) => return ReleaseAdmission::denied(mode, "release_policy_unavailable"),
    };
    let policy = match ReleaseChannelPolicy::parse_json(&policy_text) {
        Ok(policy) => policy,
        Err(_) => return ReleaseAdmission::denied(mode, "release_policy_invalid"),
    };
    let receipt_text = match read_reviewed_file(receipt_path) {
        Ok(contents) => contents,
        Err(()) => return ReleaseAdmission::denied(mode, "release_receipt_unavailable"),
    };
    let receipt = match ReleaseAdmissionReceipt::parse_json(&receipt_text) {
        Ok(receipt) => receipt,
        Err(_) => return ReleaseAdmission::denied(mode, "release_receipt_invalid"),
    };
    ReleaseAdmission::evaluate(&policy, &receipt, mode, configured_digest)
}

/// Persist release posture and fail closed if required admission was denied.
pub fn audit_release_admission(
    admission: &ReleaseAdmission,
    audit_path: &Path,
    principal: &PrincipalChain,
) -> JanusResult<()> {
    let mut audit = JsonlAuditSink::open(audit_path)?;
    audit.record(admission.audit_event(principal))?;
    if admission.allows_secret_use() {
        Ok(())
    } else {
        Err(JanusError::policy_denied(
            admission.reason_code(),
            "running release is not admitted for secret-bearing work",
        ))
    }
}

/// Load, persist, and enforce the common runtime release environment.
///
/// `JANUS_PRODUCT_MODE` defaults to `self_hosted`. Production and enterprise
/// require `JANUS_RELEASE_CHANNEL_POLICY`, `JANUS_RELEASE_ADMISSION_RECEIPT`,
/// `JANUS_RELEASE_ARTIFACT_DIGEST`, and `JANUS_RELEASE_AUDIT_FILE`.
pub fn enforce_release_admission_from_env(
    principal: &PrincipalChain,
) -> JanusResult<ReleaseAdmission> {
    let mode = env::var("JANUS_PRODUCT_MODE")
        .ok()
        .map(|value| ProductMode::parse(&value))
        .transpose()?
        .unwrap_or(ProductMode::SelfHosted);
    let policy_path = env_path("JANUS_RELEASE_CHANNEL_POLICY");
    let receipt_path = env_path("JANUS_RELEASE_ADMISSION_RECEIPT");
    let configured_digest = env::var("JANUS_RELEASE_ARTIFACT_DIGEST").ok();
    let audit_path = env_path("JANUS_RELEASE_AUDIT_FILE");
    let admission = load_release_admission(
        mode,
        policy_path.as_deref(),
        receipt_path.as_deref(),
        configured_digest.as_deref(),
    );

    if let Some(audit_path) = audit_path {
        audit_release_admission(&admission, &audit_path, principal)?;
    } else if !admission.allows_secret_use() {
        return Err(JanusError::policy_denied(
            admission.reason_code(),
            "running release is not admitted for secret-bearing work",
        ));
    } else if mode.requires_trusted_release() {
        return Err(JanusError::policy_denied(
            "release_audit_missing",
            "trusted release admission requires a durable audit path",
        ));
    }

    Ok(admission)
}

fn env_path(key: &'static str) -> Option<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn read_reviewed_file(path: &Path) -> Result<String, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_RELEASE_EVIDENCE_BYTES
    {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(());
        }
    }
    fs::read_to_string(path).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use janus_core::{
        Principal, PrincipalId, PrincipalKind, ReleaseAdmissionDecision, ScopePathV1,
    };
    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const RELEASE_ENV_KEYS: &[&str] = &[
        "JANUS_PRODUCT_MODE",
        "JANUS_RELEASE_CHANNEL_POLICY",
        "JANUS_RELEASE_ADMISSION_RECEIPT",
        "JANUS_RELEASE_ARTIFACT_DIGEST",
        "JANUS_RELEASE_AUDIT_FILE",
    ];

    struct ReleaseEnvGuard(Vec<(&'static str, Option<String>)>);

    impl ReleaseEnvGuard {
        fn clear() -> Self {
            let saved = RELEASE_ENV_KEYS
                .iter()
                .map(|key| (*key, env::var(key).ok()))
                .collect();
            for key in RELEASE_ENV_KEYS {
                env::remove_var(key);
            }
            Self(saved)
        }
    }

    impl Drop for ReleaseEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn policy() -> String {
        r#"{
  "schema_version": 1,
  "policy_id": "janus-engine-release-v1",
  "policy_version": 1,
  "required_modes": ["production", "enterprise"],
  "deny_mode_downgrade": true,
  "channels": [{
    "name": "stable",
    "image": "ghcr.io/markus-barta/janus/janus-engine",
    "tag_prefix": "rust-engine-v",
    "repository": "markus-barta/janus",
    "signer_workflow": "markus-barta/janus/.github/workflows/rust.yml",
    "certificate_identity_prefix": "https://github.com/markus-barta/janus/.github/workflows/rust.yml@refs/tags/",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "provenance_predicate_type": "https://slsa.dev/provenance/v1",
    "sbom_predicate_type": "https://spdx.dev/Document/v2.3"
  }],
  "revoked_digests": []
}"#
        .to_string()
    }

    fn receipt() -> String {
        format!(
            r#"{{
  "schema_version": 1,
  "policy_id": "janus-engine-release-v1",
  "policy_version": 1,
  "channel": "stable",
  "mode": "enterprise",
  "previous_mode": "enterprise",
  "artifact": {{
    "image": "ghcr.io/markus-barta/janus/janus-engine",
    "tag": "rust-engine-v0.1.6",
    "digest": "{DIGEST}",
    "development": false
  }},
  "signature": {{
    "verified": true,
    "identity": "https://github.com/markus-barta/janus/.github/workflows/rust.yml@refs/tags/rust-engine-v0.1.6",
    "oidc_issuer": "https://token.actions.githubusercontent.com"
  }},
  "provenance": {{
    "verified": true,
    "repository": "markus-barta/janus",
    "signer_workflow": "markus-barta/janus/.github/workflows/rust.yml",
    "source_ref": "refs/tags/rust-engine-v0.1.6",
    "predicate_type": "https://slsa.dev/provenance/v1"
  }},
  "sbom": {{
    "verified": true,
    "predicate_type": "https://spdx.dev/Document/v2.3"
  }}
}}"#
        )
    }

    fn write(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("release-admission").unwrap(),
            ),
            ScopePathV1::for_repository("fixture-org", "janus", "janus", "release")
                .unwrap()
                .scope_ref(),
        )
    }

    #[test]
    fn production_and_enterprise_require_both_reviewed_files() {
        assert_eq!(
            load_release_admission(ProductMode::Enterprise, None, None, None).decision(),
            ReleaseAdmissionDecision::Denied
        );
        assert_eq!(
            load_release_admission(ProductMode::SelfHosted, None, None, None).decision(),
            ReleaseAdmissionDecision::NotRequired
        );
    }

    #[test]
    fn runtime_environment_fails_closed_and_audits_trusted_startup() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = ReleaseEnvGuard::clear();
        env::set_var("JANUS_PRODUCT_MODE", "enterprise");
        let missing = enforce_release_admission_from_env(&principal()).unwrap_err();
        assert!(matches!(
            missing,
            JanusError::PolicyDenied {
                reason_code: "release_evidence_missing",
                ..
            }
        ));

        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        let receipt_path = dir.path().join("receipt.json");
        let audit_path = dir.path().join("audit/events.jsonl");
        write(&policy_path, &policy());
        write(&receipt_path, &receipt());
        env::set_var("JANUS_RELEASE_CHANNEL_POLICY", &policy_path);
        env::set_var("JANUS_RELEASE_ADMISSION_RECEIPT", &receipt_path);
        env::set_var("JANUS_RELEASE_ARTIFACT_DIGEST", DIGEST);
        let missing_audit = enforce_release_admission_from_env(&principal()).unwrap_err();
        assert!(matches!(
            missing_audit,
            JanusError::PolicyDenied {
                reason_code: "release_audit_missing",
                ..
            }
        ));
        env::set_var("JANUS_RELEASE_AUDIT_FILE", &audit_path);

        let trusted = enforce_release_admission_from_env(&principal()).unwrap();

        assert_eq!(trusted.decision(), ReleaseAdmissionDecision::Trusted);
        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("release_trust_ok"));
        assert!(audit.contains("\"value_returned\":false"));
    }

    #[test]
    fn loader_accepts_matching_receipt_and_rejects_tampering() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        let receipt_path = dir.path().join("receipt.json");
        write(&policy_path, &policy());
        write(&receipt_path, &receipt());

        let trusted = load_release_admission(
            ProductMode::Enterprise,
            Some(&policy_path),
            Some(&receipt_path),
            Some(DIGEST),
        );
        assert_eq!(trusted.decision(), ReleaseAdmissionDecision::Trusted);

        let mut tampered: Value = serde_json::from_str(&receipt()).unwrap();
        tampered["artifact"]["digest"] = Value::String(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );
        write(&receipt_path, &serde_json::to_string(&tampered).unwrap());
        let denied = load_release_admission(
            ProductMode::Enterprise,
            Some(&policy_path),
            Some(&receipt_path),
            Some(DIGEST),
        );
        assert_eq!(denied.decision(), ReleaseAdmissionDecision::Denied);
        assert_eq!(denied.reason_code(), "release_digest_mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn mutable_or_symlinked_evidence_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        let receipt_path = dir.path().join("receipt.json");
        write(&policy_path, &policy());
        write(&receipt_path, &receipt());
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o622)).unwrap();
        assert_eq!(
            load_release_admission(
                ProductMode::Enterprise,
                Some(&policy_path),
                Some(&receipt_path),
                Some(DIGEST)
            )
            .reason_code(),
            "release_receipt_unavailable"
        );

        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("receipt-link.json");
        symlink(&receipt_path, &link).unwrap();
        assert_eq!(
            load_release_admission(
                ProductMode::Enterprise,
                Some(&policy_path),
                Some(&link),
                Some(DIGEST)
            )
            .reason_code(),
            "release_receipt_unavailable"
        );
    }

    #[test]
    fn audited_denial_is_durable_and_value_free() {
        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit/events.jsonl");
        let denied = ReleaseAdmission::denied(ProductMode::Enterprise, "release_receipt_invalid");
        assert!(audit_release_admission(&denied, &audit_path, &principal()).is_err());
        let rendered = fs::read_to_string(audit_path).unwrap();
        assert!(rendered.contains("release.admission"));
        assert!(rendered.contains("release_receipt_invalid"));
        assert!(rendered.contains("\"value_returned\":false"));
    }

    #[test]
    fn oversized_evidence_fails_without_reading_content() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        let receipt_path = dir.path().join("receipt.json");
        write(&policy_path, &policy());
        let mut file = fs::File::create(&receipt_path).unwrap();
        file.write_all(&vec![b'x'; MAX_RELEASE_EVIDENCE_BYTES as usize + 1])
            .unwrap();
        let denied = load_release_admission(
            ProductMode::Enterprise,
            Some(&policy_path),
            Some(&receipt_path),
            Some(DIGEST),
        );
        assert_eq!(denied.reason_code(), "release_receipt_unavailable");
    }
}

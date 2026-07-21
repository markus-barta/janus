use std::env;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use janus_core::{
    Principal, PrincipalChain, PrincipalId, PrincipalKind, ReleaseAdmission, SecretMetadataOverlay,
    SecretStore,
};
use janus_local::{
    enforce_retention_ready_from_env, JsonlAuditSink, RecoveryDrillRunner, RecoveryDrillStatus,
};
use janus_provider_age::AgeSecretStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryOperation {
    Snapshot,
    Preflight,
    Restore,
    Postflight,
    Rollback,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoveryCommand {
    operation: RecoveryOperation,
    manifest: PathBuf,
}

pub(super) fn is_recovery_drill_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "recovery-drill")
}

pub(super) async fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let command = parse(args)?;
    let principal = recovery_principal_from_env()?;
    let runner = RecoveryDrillRunner::load(&command.manifest, release.clone(), principal.clone())
        .context("failed to load reviewed recovery drill")?;
    let status = match command.operation {
        RecoveryOperation::Snapshot => runner.snapshot(SystemTime::now()),
        RecoveryOperation::Preflight => {
            let target = runner
                .prepare_preflight_provider_check()
                .context("recovery provider preflight preparation failed closed")?;
            verify_provider_recoverability(&runner, &target, &principal).await?;
            runner.preflight(SystemTime::now())
        }
        RecoveryOperation::Restore => runner.restore(SystemTime::now()),
        RecoveryOperation::Postflight => {
            let target = runner
                .prepare_postflight()
                .context("recovery postflight preparation failed closed")?;
            let checked = verify_provider_recoverability(&runner, &target, &principal).await?;
            enforce_retention_ready_from_env(&release, &principal.scope)
                .context("recovered retention evidence is not current")?;
            runner.postflight(SystemTime::now(), checked)
        }
        RecoveryOperation::Rollback => runner.rollback(),
        RecoveryOperation::Status => runner.status(),
    }
    .context("recovery drill command failed closed")?;
    emit_status(command.operation, &status);
    Ok(())
}

async fn verify_provider_recoverability(
    runner: &RecoveryDrillRunner,
    target: &janus_local::RecoveryPostflightTarget,
    principal: &PrincipalChain,
) -> Result<u64> {
    let metadata = SecretMetadataOverlay::load_toml_file(target.metadata_path())
        .context("failed to load recovered lifecycle metadata overlay")?;
    let manifest = PathBuf::from(
        recovery_env_first(&[
            "JANUS_RECOVERY_AGE_MANIFEST_FILE",
            "JANUS_AGE_MANIFEST_FILE",
            "JANUS_WARDEN_AGE_MANIFEST_FILE",
            "JANUS_WARDEN_SECRETSPEC_FILE",
        ])
        .context("JANUS_RECOVERY_AGE_MANIFEST_FILE is required for provider verification")?,
    );
    runner
        .validate_bound_config_path(&manifest)
        .context("recovery Age manifest is not an exact reviewed config binding")?;
    let profile_manifest = PathBuf::from(
        recovery_env_first(&[
            "JANUS_RECOVERY_PROFILE_MANIFEST",
            "JANUS_RUN_PROFILE_MANIFEST",
            "JANUS_MANAGED_PROFILE_MANIFEST",
        ])
        .context("JANUS_RECOVERY_PROFILE_MANIFEST is required for policy verification")?,
    );
    runner
        .validate_bound_config_path(&profile_manifest)
        .context("recovery profile manifest is not an exact reviewed config binding")?;
    let profile = recovery_env_first(&[
        "JANUS_RECOVERY_AGE_PROFILE",
        "JANUS_AGE_PROFILE",
        "JANUS_WARDEN_AGE_PROFILE",
    ])
    .unwrap_or_else(|| "default".to_string());
    let identity_files = recovery_identity_files_from_env()?;
    let store = AgeSecretStore::load_from_secretspec_manifest_with_metadata(
        &manifest,
        profile,
        target.age_root(),
        identity_files.clone(),
        recovery_recipients_from_env()?,
        runner.manifest().scope_ref(),
        Some(&metadata),
    )
    .context("failed to load recovered Age state")?;
    let descriptors = store
        .list()
        .await
        .context("failed to load recovered descriptors")?;
    let profiles = super::ManagedCommandProfileCatalog::load(&profile_manifest)
        .context("failed to load current approved-use profile policy")?;
    let _policy = profiles
        .use_policy(&descriptors)
        .context("current descriptor/profile policy is inconsistent")?;
    let mut audit = JsonlAuditSink::open(runner.manifest().operation_audit_path())
        .context("failed to open recovery drill audit")?;
    let report = store
        .verify_recoverability_with_audit(identity_files, &mut audit, principal)
        .await
        .context("recovered Age payloads are not decryptable")?;
    drop(audit);
    if !report.recoverable
        || report.value_returned
        || report.checked as u64 != target.expected_ciphertext_files()
    {
        anyhow::bail!("recovery provider verification did not cover the sealed payload set");
    }
    Ok(report.checked as u64)
}

fn parse(args: &[String]) -> Result<RecoveryCommand> {
    let [command, operation, manifest_flag, manifest] = args else {
        anyhow::bail!(
            "usage: janusd-admin recovery-drill snapshot|preflight|restore|postflight|rollback|status --manifest PATH"
        );
    };
    if command != "recovery-drill" || manifest_flag != "--manifest" || manifest.is_empty() {
        anyhow::bail!(
            "usage: janusd-admin recovery-drill snapshot|preflight|restore|postflight|rollback|status --manifest PATH"
        );
    }
    let operation = match operation.as_str() {
        "snapshot" => RecoveryOperation::Snapshot,
        "preflight" => RecoveryOperation::Preflight,
        "restore" => RecoveryOperation::Restore,
        "postflight" => RecoveryOperation::Postflight,
        "rollback" => RecoveryOperation::Rollback,
        "status" => RecoveryOperation::Status,
        _ => anyhow::bail!("unsupported recovery drill operation"),
    };
    Ok(RecoveryCommand {
        operation,
        manifest: PathBuf::from(manifest),
    })
}

fn recovery_principal_from_env() -> Result<PrincipalChain> {
    let executor =
        env::var("JANUS_RECOVERY_EXECUTOR").unwrap_or_else(|_| "janusd-recovery-drill".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

fn recovery_env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env::var(key).ok())
}

fn recovery_identity_files_from_env() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if let Ok(value) = env::var("JANUS_RECOVERY_AGE_IDENTITY_FILE") {
        files.push(PathBuf::from(value));
    }
    if let Ok(value) = env::var("JANUS_RECOVERY_AGE_IDENTITY_FILES") {
        files.extend(
            value
                .split(':')
                .filter(|part| !part.trim().is_empty())
                .map(PathBuf::from),
        );
    }
    if files.is_empty() {
        super::age_identity_files_from_env()
    } else {
        Ok(files)
    }
}

fn recovery_recipients_from_env() -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    if let Ok(value) = env::var("JANUS_RECOVERY_AGE_RECIPIENT") {
        recipients.push(value);
    }
    if let Ok(path) = env::var("JANUS_RECOVERY_AGE_RECIPIENTS_FILE") {
        recipients.extend(super::read_recipient_file(Path::new(&path))?);
    }
    if recipients.is_empty() {
        super::age_recipients_from_env()
    } else {
        Ok(recipients)
    }
}

fn emit_status(operation: RecoveryOperation, status: &RecoveryDrillStatus) {
    let operation = match operation {
        RecoveryOperation::Snapshot => "snapshot",
        RecoveryOperation::Preflight => "preflight",
        RecoveryOperation::Restore => "restore",
        RecoveryOperation::Postflight => "postflight",
        RecoveryOperation::Rollback => "rollback",
        RecoveryOperation::Status => "status",
    };
    println!(
        "janusd-admin recovery-drill {operation} ok operation_id={} phase={} scope_ref={} bundle_fingerprint={} config_fingerprint={} target_fingerprint={} component_count={} file_count={} total_bytes={} excluded_permit_count={} audit_sequence={} reason_code={} value_returned={}",
        status.operation_id,
        status.phase,
        status.scope_ref,
        status.bundle_fingerprint,
        status.config_fingerprint,
        status.target_fingerprint,
        status.component_count,
        status.file_count,
        status.total_bytes,
        status.excluded_permit_count,
        status.audit_sequence,
        status.reason_code,
        status.value_returned,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_only_the_narrow_reviewed_recovery_surface() {
        for (name, expected) in [
            ("snapshot", RecoveryOperation::Snapshot),
            ("preflight", RecoveryOperation::Preflight),
            ("restore", RecoveryOperation::Restore),
            ("postflight", RecoveryOperation::Postflight),
            ("rollback", RecoveryOperation::Rollback),
            ("status", RecoveryOperation::Status),
        ] {
            let parsed = parse(&args(&[
                "recovery-drill",
                name,
                "--manifest",
                "/etc/janus/recovery-drill.json",
            ]))
            .unwrap();
            assert_eq!(parsed.operation, expected);
        }
    }

    #[test]
    fn rejects_pathless_unknown_and_target_override_arguments() {
        for invalid in [
            args(&["recovery-drill", "restore"]),
            args(&["recovery-drill", "unknown", "--manifest", "/tmp/plan"]),
            args(&["recovery-drill", "restore", "--target", "/tmp/state"]),
            args(&[
                "recovery-drill",
                "restore",
                "--manifest",
                "/tmp/plan",
                "--identity",
                "/tmp/key",
            ]),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}

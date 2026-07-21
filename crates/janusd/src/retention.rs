use std::env;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use janus_core::{
    Principal, PrincipalChain, PrincipalId, PrincipalKind, ReleaseAdmission, SecretStore,
};
use janus_local::{RetentionRunner, RetentionStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetentionOperation {
    Preflight,
    Quarantine,
    Purge,
    Rollback,
    Status,
}

impl RetentionOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Quarantine => "quarantine",
            Self::Purge => "purge",
            Self::Rollback => "rollback",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetentionCommand {
    operation: RetentionOperation,
    policy: PathBuf,
}

pub(super) fn is_retention_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "retention")
}

pub(super) async fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let command = parse(args)?;
    let principal = retention_principal_from_env()?;
    let runner = RetentionRunner::load(&command.policy, release, principal)
        .context("failed to load reviewed retention policy")?;
    let status = match command.operation {
        RetentionOperation::Preflight | RetentionOperation::Quarantine => {
            let manifest = super::env_first(&[
                "JANUS_AGE_MANIFEST_FILE",
                "JANUS_WARDEN_AGE_MANIFEST_FILE",
                "JANUS_WARDEN_SECRETSPEC_FILE",
            ])
            .map(PathBuf::from)
            .context("JANUS_AGE_MANIFEST_FILE is required for retention planning")?;
            runner
                .validate_bound_config_path(&manifest)
                .context("retention Age manifest is not an exact reviewed config binding")?;
            let store = super::load_age_store_from_env_with_metadata_path(Some(
                runner.policy().metadata_overlay_path(),
            ))?;
            let descriptors = store
                .list()
                .await
                .context("failed to load current retention descriptors")?;
            match command.operation {
                RetentionOperation::Preflight => runner.preflight(SystemTime::now(), &descriptors),
                RetentionOperation::Quarantine => {
                    runner.quarantine(SystemTime::now(), &descriptors)
                }
                _ => unreachable!("closed retention descriptor operations"),
            }
        }
        RetentionOperation::Purge => runner.purge(SystemTime::now()),
        RetentionOperation::Rollback => runner.rollback(),
        RetentionOperation::Status => runner.status(),
    }
    .context("retention command failed closed")?;
    emit_status(command.operation, &status);
    Ok(())
}

fn parse(args: &[String]) -> Result<RetentionCommand> {
    let [command, operation, policy_flag, policy] = args else {
        anyhow::bail!(
            "usage: janusd-admin retention preflight|quarantine|purge|rollback|status --policy PATH"
        );
    };
    if command != "retention" || policy_flag != "--policy" || policy.is_empty() {
        anyhow::bail!(
            "usage: janusd-admin retention preflight|quarantine|purge|rollback|status --policy PATH"
        );
    }
    let operation = match operation.as_str() {
        "preflight" => RetentionOperation::Preflight,
        "quarantine" => RetentionOperation::Quarantine,
        "purge" => RetentionOperation::Purge,
        "rollback" => RetentionOperation::Rollback,
        "status" => RetentionOperation::Status,
        _ => anyhow::bail!("unsupported retention operation"),
    };
    Ok(RetentionCommand {
        operation,
        policy: PathBuf::from(policy),
    })
}

fn retention_principal_from_env() -> Result<PrincipalChain> {
    let executor =
        env::var("JANUS_RETENTION_EXECUTOR").unwrap_or_else(|_| "janusd-retention".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

fn emit_status(operation: RetentionOperation, status: &RetentionStatus) {
    println!(
        "janusd-admin retention {} ok operation_id={} phase={} scope_ref={} policy_fingerprint={} config_fingerprint={} hold_fingerprint={} source_fingerprint={} quarantine_fingerprint={} eligible_count={} held_count={} protected_count={} next_due_at_unix_secs={} reason_code={} value_returned={}",
        operation.as_str(),
        status.operation_id,
        status.phase,
        status.scope_ref,
        status.policy_fingerprint,
        status.config_fingerprint,
        status.hold_fingerprint,
        status.source_fingerprint,
        status.quarantine_fingerprint,
        status.eligible_count,
        status.held_count,
        status.protected_count,
        status.next_due_at_unix_secs,
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
    fn parses_only_the_narrow_reviewed_retention_surface() {
        for (name, expected) in [
            ("preflight", RetentionOperation::Preflight),
            ("quarantine", RetentionOperation::Quarantine),
            ("purge", RetentionOperation::Purge),
            ("rollback", RetentionOperation::Rollback),
            ("status", RetentionOperation::Status),
        ] {
            let parsed = parse(&args(&[
                "retention",
                name,
                "--policy",
                "/etc/janus/retention.json",
            ]))
            .unwrap();
            assert_eq!(parsed.operation, expected);
        }
    }

    #[test]
    fn rejects_pathless_unknown_and_override_arguments() {
        for invalid in [
            args(&["retention", "preflight"]),
            args(&["retention", "unknown", "--policy", "/tmp/policy"]),
            args(&["retention", "purge", "--root", "/tmp/state"]),
            args(&["retention", "purge", "--policy", "/tmp/policy", "--force"]),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}

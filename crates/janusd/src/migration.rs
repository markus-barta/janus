use std::env;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use janus_core::{Principal, PrincipalChain, PrincipalId, PrincipalKind, ReleaseAdmission};
use janus_local::{enforce_retention_ready_from_env, ApprovalMigrationRunner, MigrationStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationOperation {
    Preflight,
    Apply,
    Postflight,
    Rollback,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MigrationCommand {
    operation: MigrationOperation,
    manifest: PathBuf,
}

pub(super) fn is_migration_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "migrate")
}

pub(super) fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let command = parse(args)?;
    let principal = migration_principal_from_env()?;
    let runner =
        ApprovalMigrationRunner::load(&command.manifest, release.clone(), principal.clone())
            .context("failed to load reviewed migration")?;
    let status = match command.operation {
        MigrationOperation::Preflight => runner.preflight(SystemTime::now()),
        MigrationOperation::Apply => runner.apply(SystemTime::now()),
        MigrationOperation::Postflight => {
            enforce_retention_ready_from_env(&release, &principal.scope)
                .context("migrated retention evidence is not current")?;
            runner.postflight()
        }
        MigrationOperation::Rollback => runner.rollback(),
        MigrationOperation::Status => runner.status(),
    }
    .context("migration command failed closed")?;
    emit_status(command.operation, &status);
    Ok(())
}

fn parse(args: &[String]) -> Result<MigrationCommand> {
    let [migrate, operation, manifest_flag, manifest] = args else {
        anyhow::bail!(
            "usage: janusd-admin migrate preflight|apply|postflight|rollback|status --manifest PATH"
        );
    };
    if migrate != "migrate" || manifest_flag != "--manifest" || manifest.is_empty() {
        anyhow::bail!(
            "usage: janusd-admin migrate preflight|apply|postflight|rollback|status --manifest PATH"
        );
    }
    let operation = match operation.as_str() {
        "preflight" => MigrationOperation::Preflight,
        "apply" => MigrationOperation::Apply,
        "postflight" => MigrationOperation::Postflight,
        "rollback" => MigrationOperation::Rollback,
        "status" => MigrationOperation::Status,
        _ => anyhow::bail!("unsupported migration operation"),
    };
    Ok(MigrationCommand {
        operation,
        manifest: PathBuf::from(manifest),
    })
}

fn migration_principal_from_env() -> Result<PrincipalChain> {
    let executor =
        env::var("JANUS_MIGRATION_EXECUTOR").unwrap_or_else(|_| "janusd-migrate".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

fn emit_status(operation: MigrationOperation, status: &MigrationStatus) {
    let operation = match operation {
        MigrationOperation::Preflight => "preflight",
        MigrationOperation::Apply => "apply",
        MigrationOperation::Postflight => "postflight",
        MigrationOperation::Rollback => "rollback",
        MigrationOperation::Status => "status",
    };
    println!(
        "janusd-admin migrate {operation} ok migration_id={} schema_id={} phase={} current_version={} target_version={} record_count={} target_fingerprint={} reason_code={} value_returned={}",
        status.migration_id,
        status.schema_id,
        status.phase,
        status.current_version,
        status.target_version,
        status.record_count,
        status.target_fingerprint,
        status.reason_code,
        status.value_returned
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_only_the_narrow_reviewed_migration_surface() {
        for (name, expected) in [
            ("preflight", MigrationOperation::Preflight),
            ("apply", MigrationOperation::Apply),
            ("postflight", MigrationOperation::Postflight),
            ("rollback", MigrationOperation::Rollback),
            ("status", MigrationOperation::Status),
        ] {
            let parsed = parse(&args(&[
                "migrate",
                name,
                "--manifest",
                "/etc/janus/migration.json",
            ]))
            .unwrap();
            assert_eq!(parsed.operation, expected);
        }
    }

    #[test]
    fn rejects_pathless_unknown_and_policy_override_arguments() {
        for invalid in [
            args(&["migrate", "apply"]),
            args(&["migrate", "unknown", "--manifest", "/tmp/plan"]),
            args(&["migrate", "apply", "--target", "/tmp/approvals"]),
            args(&[
                "migrate",
                "apply",
                "--manifest",
                "/tmp/plan",
                "--from-version",
                "0",
            ]),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}

use std::env;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use janus_core::{Principal, PrincipalChain, PrincipalId, PrincipalKind, ReleaseAdmission};
use janus_local::{ScopeTransferRunner, ScopeTransferStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeTransferOperation {
    Preflight,
    Apply,
    Postflight,
    Rollback,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScopeTransferCommand {
    operation: ScopeTransferOperation,
    manifest: PathBuf,
}

pub(super) fn is_scope_transfer_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "scope-transfer")
}

pub(super) fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let command = parse(args)?;
    let runner = ScopeTransferRunner::load(
        &command.manifest,
        release,
        scope_transfer_principal_from_env()?,
    )
    .context("failed to load reviewed scope transfer")?;
    let status = match command.operation {
        ScopeTransferOperation::Preflight => runner.preflight(SystemTime::now()),
        ScopeTransferOperation::Apply => runner.apply(SystemTime::now()),
        ScopeTransferOperation::Postflight => runner.postflight(),
        ScopeTransferOperation::Rollback => runner.rollback(),
        ScopeTransferOperation::Status => runner.status(),
    }
    .context("scope transfer command failed closed")?;
    emit_status(command.operation, &status);
    Ok(())
}

fn parse(args: &[String]) -> Result<ScopeTransferCommand> {
    let [command, operation, manifest_flag, manifest] = args else {
        anyhow::bail!(
            "usage: janusd scope-transfer preflight|apply|postflight|rollback|status --manifest PATH"
        );
    };
    if command != "scope-transfer" || manifest_flag != "--manifest" || manifest.is_empty() {
        anyhow::bail!(
            "usage: janusd scope-transfer preflight|apply|postflight|rollback|status --manifest PATH"
        );
    }
    let operation = match operation.as_str() {
        "preflight" => ScopeTransferOperation::Preflight,
        "apply" => ScopeTransferOperation::Apply,
        "postflight" => ScopeTransferOperation::Postflight,
        "rollback" => ScopeTransferOperation::Rollback,
        "status" => ScopeTransferOperation::Status,
        _ => anyhow::bail!("unsupported scope transfer operation"),
    };
    Ok(ScopeTransferCommand {
        operation,
        manifest: PathBuf::from(manifest),
    })
}

fn scope_transfer_principal_from_env() -> Result<PrincipalChain> {
    let executor = env::var("JANUS_SCOPE_TRANSFER_EXECUTOR")
        .unwrap_or_else(|_| "janusd-scope-transfer".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

fn emit_status(operation: ScopeTransferOperation, status: &ScopeTransferStatus) {
    let operation = match operation {
        ScopeTransferOperation::Preflight => "preflight",
        ScopeTransferOperation::Apply => "apply",
        ScopeTransferOperation::Postflight => "postflight",
        ScopeTransferOperation::Rollback => "rollback",
        ScopeTransferOperation::Status => "status",
    };
    println!(
        "janusd scope-transfer {operation} ok operation_id={} mode={} phase={} source_scope_ref={} destination_scope_ref={} record_count={} approval_count={} excluded_approval_count={} excluded_permit_count={} source_inventory_fingerprint={} target_fingerprint={} planned_target_fingerprint={} manifest_fingerprint={} mapping_fingerprint={} reason_code={} value_returned={}",
        status.operation_id,
        status.mode,
        status.phase,
        status.source_scope_ref,
        status.destination_scope_ref,
        status.record_count,
        status.approval_count,
        status.excluded_approval_count,
        status.excluded_permit_count,
        status.source_inventory_fingerprint,
        status.target_fingerprint,
        status.planned_target_fingerprint,
        status.manifest_fingerprint,
        status.mapping_fingerprint,
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
    fn parses_only_the_narrow_reviewed_scope_transfer_surface() {
        for (name, expected) in [
            ("preflight", ScopeTransferOperation::Preflight),
            ("apply", ScopeTransferOperation::Apply),
            ("postflight", ScopeTransferOperation::Postflight),
            ("rollback", ScopeTransferOperation::Rollback),
            ("status", ScopeTransferOperation::Status),
        ] {
            let parsed = parse(&args(&[
                "scope-transfer",
                name,
                "--manifest",
                "/etc/janus/scope-transfer.json",
            ]))
            .unwrap();
            assert_eq!(parsed.operation, expected);
        }
    }

    #[test]
    fn rejects_pathless_unknown_and_mapping_override_arguments() {
        for invalid in [
            args(&["scope-transfer", "apply"]),
            args(&["scope-transfer", "unknown", "--manifest", "/tmp/plan"]),
            args(&["scope-transfer", "apply", "--target", "/tmp/state"]),
            args(&[
                "scope-transfer",
                "apply",
                "--manifest",
                "/tmp/plan",
                "--destination-scope",
                "prod",
            ]),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}

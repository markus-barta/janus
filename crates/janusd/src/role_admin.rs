//! Closed local administration surface for durable role bindings.

use std::env;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, PrincipalChain, Role, RoleBinding,
    RoleBindingId, RoleBindingSource, RoleBindingSourceKind, SafeLabel, Severity,
    MAX_ROLE_BINDING_TTL,
};
use janus_local::{
    FileRoleBindingRegistry, JsonlAuditSink, LoadedRoleAuthorization, RoleBindingRegistry,
};
use serde_json::json;

pub fn is_role_admin_command(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("role-binding" | "authorization-policy")
    )
}

pub fn run(
    args: &[String],
    principal: &PrincipalChain,
    authorization: Option<&LoadedRoleAuthorization>,
) -> Result<()> {
    let authorization = authorization.context(
        "role administration is unavailable while role authorization is explicitly disabled",
    )?;
    match args {
        [role_binding, issue, rest @ ..]
            if role_binding == "role-binding" && issue == "issue" =>
        {
            issue_binding(rest, principal)
        }
        [role_binding, list] if role_binding == "role-binding" && list == "list" => {
            list_bindings()
        }
        [role_binding, status, rest @ ..]
            if role_binding == "role-binding" && status == "status" =>
        {
            binding_status(rest)
        }
        [role_binding, revoke, rest @ ..]
            if role_binding == "role-binding" && revoke == "revoke" =>
        {
            revoke_binding(rest, principal)
        }
        [policy, status] if policy == "authorization-policy" && status == "status" => {
            let snapshot = authorization.policy.snapshot();
            println!(
                "{}",
                json!({
                    "schema_version": snapshot.schema_version,
                    "policy_id": snapshot.policy_id,
                    "role_count": snapshot.roles.len(),
                    "status": "checked",
                    "value_returned": false
                })
            );
            Ok(())
        }
        _ => anyhow::bail!(
            "unsupported role administration command reason_code=role_admin_args_invalid value_returned=false"
        ),
    }
}

struct IssueConfig {
    principal_binding: String,
    role: Role,
    target_binding: Option<String>,
    ttl: Duration,
    source_reference: String,
    reason: SafeLabel,
}

fn issue_binding(args: &[String], actor: &PrincipalChain) -> Result<()> {
    let config = parse_issue(args)?;
    if config.principal_binding == actor.binding_key() {
        anyhow::bail!(
            "role binding denied reason_code=separation_self_role_grant value_returned=false"
        );
    }
    let now = SystemTime::now();
    let binding = RoleBinding::issue(
        config.principal_binding,
        actor.scope.clone(),
        config.role,
        config.target_binding,
        now,
        now.checked_add(config.ttl)
            .context("role binding expiry overflow")?,
        RoleBindingSource::new(
            RoleBindingSourceKind::LocalReviewed,
            &config.source_reference,
        )?,
    )?;
    let mut audit = role_audit()?;
    audit.record(
        AuditEvent::new(
            AuditAction::RoleAssign,
            AuditOutcome::Allowed,
            "role_assignment_authorized",
            Severity::High,
            None,
            actor,
        )
        .with_evidence(SafeLabel::new(format!(
            "{} {} {}",
            binding.id().as_str(),
            binding.role().as_str(),
            config.reason.as_str()
        ))?),
    )?;
    registry()?.store(&binding)?;
    println!(
        "{}",
        json!({
            "binding_id": binding.id().as_str(),
            "role": binding.role().as_str(),
            "scope_ref": binding.scope().as_str(),
            "targeted": binding.target_binding().is_some(),
            "expires_at_unix_secs": unix_secs(binding.expires_at()),
            "status": "active",
            "value_returned": false
        })
    );
    Ok(())
}

fn list_bindings() -> Result<()> {
    let rows = registry()?
        .list(SystemTime::now())?
        .into_iter()
        .map(|row| {
            json!({
                "binding_id": row.binding_id.as_str(),
                "role": row.role.as_str(),
                "scope_ref": row.scope.as_str(),
                "targeted": row.targeted,
                "valid_from_unix_secs": unix_secs(row.valid_from),
                "expires_at_unix_secs": unix_secs(row.expires_at),
                "source_kind": row.source_kind.as_str(),
                "status": row.status.as_str(),
                "value_returned": false
            })
        })
        .collect::<Vec<_>>();
    println!("{}", json!({"bindings": rows, "value_returned": false}));
    Ok(())
}

fn binding_status(args: &[String]) -> Result<()> {
    let binding_id = parse_binding_only(args)?;
    let record = registry()?.get(binding_id.as_str())?;
    println!(
        "{}",
        json!({
            "binding_id": record.binding.id().as_str(),
            "role": record.binding.role().as_str(),
            "scope_ref": record.binding.scope().as_str(),
            "targeted": record.binding.target_binding().is_some(),
            "status": record.status_at(SystemTime::now()).as_str(),
            "value_returned": false
        })
    );
    Ok(())
}

fn revoke_binding(args: &[String], actor: &PrincipalChain) -> Result<()> {
    let (binding_id, reason) = parse_revoke(args)?;
    let registry = registry()?;
    let record = registry.get(binding_id.as_str())?;
    role_audit()?.record(
        AuditEvent::new(
            AuditAction::RoleRevoke,
            AuditOutcome::Allowed,
            "role_revocation_authorized",
            Severity::High,
            None,
            actor,
        )
        .with_evidence(SafeLabel::new(format!(
            "{} {} {}",
            record.binding.id().as_str(),
            record.binding.role().as_str(),
            reason.as_str()
        ))?),
    )?;
    registry.revoke(
        binding_id.as_str(),
        &actor.binding_key(),
        &reason,
        SystemTime::now(),
    )?;
    println!(
        "{}",
        json!({
            "binding_id": binding_id.as_str(),
            "status": "revoked",
            "value_returned": false
        })
    );
    Ok(())
}

fn parse_issue(args: &[String]) -> Result<IssueConfig> {
    let mut principal_binding = None;
    let mut role = None;
    let mut target_binding = None;
    let mut expires_in_seconds = None;
    let mut source_reference = None;
    let mut reason = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--principal-binding" => replace_once(
                &mut principal_binding,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--target-binding" => replace_once(
                &mut target_binding,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--source-reference" => replace_once(
                &mut source_reference,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--role" => replace_once(
                &mut role,
                Role::parse(required(arg, args.next())?)?,
                arg,
            )?,
            "--expires-in-seconds" => replace_once(
                &mut expires_in_seconds,
                required(arg, args.next())?
                    .parse::<u64>()
                    .context("invalid --expires-in-seconds")?,
                arg,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(arg, args.next())?)?,
                arg,
            )?,
            _ => anyhow::bail!(
                "role binding issue arguments invalid reason_code=role_admin_args_invalid value_returned=false"
            ),
        }
    }
    let ttl = Duration::from_secs(expires_in_seconds.context("--expires-in-seconds is required")?);
    if ttl.is_zero() || ttl > MAX_ROLE_BINDING_TTL {
        anyhow::bail!(
            "role binding validity denied reason_code=role_binding_validity_invalid value_returned=false"
        );
    }
    Ok(IssueConfig {
        principal_binding: principal_binding.context("--principal-binding is required")?,
        role: role.context("--role is required")?,
        target_binding,
        ttl,
        source_reference: source_reference.context("--source-reference is required")?,
        reason: reason.context("--reason is required")?,
    })
}

fn parse_binding_only(args: &[String]) -> Result<RoleBindingId> {
    match args {
        [flag, binding_id] if flag == "--binding" => {
            Ok(RoleBindingId::from_opaque(binding_id.clone())?)
        }
        _ => anyhow::bail!(
            "role binding status arguments invalid reason_code=role_admin_args_invalid value_returned=false"
        ),
    }
}

fn parse_revoke(args: &[String]) -> Result<(RoleBindingId, SafeLabel)> {
    let mut binding = None;
    let mut reason = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--binding" => replace_once(
                &mut binding,
                RoleBindingId::from_opaque(required(arg, args.next())?.to_string())?,
                arg,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(arg, args.next())?)?,
                arg,
            )?,
            _ => anyhow::bail!(
                "role binding revoke arguments invalid reason_code=role_admin_args_invalid value_returned=false"
            ),
        }
    }
    Ok((
        binding.context("--binding is required")?,
        reason.context("--reason is required")?,
    ))
}

fn required<'a>(flag: &str, value: Option<&'a String>) -> Result<&'a str> {
    value
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{flag} requires a value"))
}

fn replace_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        anyhow::bail!("{flag} may only be provided once");
    }
    Ok(())
}

fn registry() -> Result<FileRoleBindingRegistry> {
    Ok(FileRoleBindingRegistry::new(required_env_path(
        "JANUS_ROLE_BINDINGS_ROOT",
    )?))
}

fn role_audit() -> Result<JsonlAuditSink> {
    Ok(JsonlAuditSink::open(required_env_path(
        "JANUS_ROLE_AUDIT_FILE",
    )?)?)
}

fn required_env_path(key: &'static str) -> Result<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("{key} is required"))
}

fn unix_secs(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_parser_is_closed_and_bounded() {
        let args = vec![
            "--principal-binding".to_string(),
            "executor:other|scope:scp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--role".to_string(),
            "viewer".to_string(),
            "--expires-in-seconds".to_string(),
            "60".to_string(),
            "--source-reference".to_string(),
            "review-1".to_string(),
            "--reason".to_string(),
            "on call".to_string(),
        ];
        assert_eq!(parse_issue(&args).unwrap().role, Role::Viewer);
        let mut attacked = args;
        attacked.extend(["--claim-role".to_string(), "owner".to_string()]);
        assert!(parse_issue(&attacked).is_err());
    }
}

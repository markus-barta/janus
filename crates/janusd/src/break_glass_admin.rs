//! Closed local administration surface for break-glass lifecycle records.

use std::env;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use janus_core::{
    BreakGlassActivation, BreakGlassActivationId, BreakGlassRequest, BreakGlassRequestId,
    BreakGlassReview, BreakGlassReviewClosure, BreakGlassRevocation, Permission, PrincipalChain,
    Role, RoleBindingId, SafeLabel, SecretRef, MAX_BREAK_GLASS_TTL,
};
use janus_local::{
    BreakGlassRegistry, FileBreakGlassRegistry, FileRoleBindingRegistry, JsonlAuditSink,
    RoleBindingRegistry, RoleBindingStatus,
};
use serde_json::json;

pub fn is_break_glass_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "break-glass")
}

pub fn run(args: &[String], principal: &PrincipalChain) -> Result<()> {
    match args {
        [root, request, rest @ ..] if root == "break-glass" && request == "request" => {
            request_activation(rest, principal)
        }
        [root, approve, rest @ ..] if root == "break-glass" && approve == "approve" => {
            approve_activation(rest, principal)
        }
        [root, list] if root == "break-glass" && list == "list" => list_activations(),
        [root, status, rest @ ..] if root == "break-glass" && status == "status" => {
            activation_status(rest)
        }
        [root, revoke, rest @ ..] if root == "break-glass" && revoke == "revoke" => {
            revoke_activation(rest, principal)
        }
        [root, review, rest @ ..] if root == "break-glass" && review == "review" => {
            review_activation(rest, principal)
        }
        _ => anyhow::bail!(
            "unsupported break-glass command reason_code=break_glass_args_invalid value_returned=false"
        ),
    }
}

struct RequestConfig {
    eligibility_binding: RoleBindingId,
    permission: Permission,
    target: SecretRef,
    reason: SafeLabel,
    ttl: Duration,
}

fn request_activation(args: &[String], principal: &PrincipalChain) -> Result<()> {
    let config = parse_request(args)?;
    let now = SystemTime::now();
    let role_registry =
        FileRoleBindingRegistry::new(required_env_path("JANUS_ROLE_BINDINGS_ROOT")?);
    let eligibility = role_registry.get(config.eligibility_binding.as_str())?;
    if eligibility.revocation.is_some()
        || eligibility.status_at(now) != RoleBindingStatus::Active
        || eligibility.binding.role() != Role::BreakGlassAdmin
    {
        anyhow::bail!(
            "break-glass request denied reason_code=break_glass_eligibility_inactive value_returned=false"
        );
    }
    let mut audit = break_glass_audit()?;
    let request = BreakGlassRequest::request(
        &eligibility.binding,
        principal,
        config.permission,
        config.target,
        config.reason,
        now,
        config.ttl,
        &mut audit,
    )?;
    registry()?.store_request(&request)?;
    println!(
        "{}",
        json!({
            "request_id": request.id().as_str(),
            "scope_ref": request.scope().as_str(),
            "permission": request.permission().as_str(),
            "target_ref": request.target().as_str(),
            "expires_at_unix_secs": unix_secs(request.expires_at()),
            "status": "pending_approval",
            "value_returned": false
        })
    );
    Ok(())
}

fn approve_activation(args: &[String], principal: &PrincipalChain) -> Result<()> {
    let request_id = parse_request_only(args)?;
    let registry = registry()?;
    let request = registry.get_request(request_id.as_str())?;
    let mut audit = break_glass_audit()?;
    let activation =
        BreakGlassActivation::approve(request, principal, SystemTime::now(), &mut audit)?;
    registry.store_activation(&activation)?;
    println!(
        "{}",
        json!({
            "activation_id": activation.id().as_str(),
            "request_id": activation.request().id().as_str(),
            "scope_ref": activation.request().scope().as_str(),
            "permission": activation.request().permission().as_str(),
            "target_ref": activation.request().target().as_str(),
            "expires_at_unix_secs": unix_secs(activation.request().expires_at()),
            "status": "active",
            "value_returned": false
        })
    );
    Ok(())
}

fn list_activations() -> Result<()> {
    let rows = registry()?
        .list(SystemTime::now())?
        .into_iter()
        .map(|row| {
            json!({
                "request_id": row.request_id.as_str(),
                "activation_id": row.activation_id.map(|id| id.as_str().to_string()),
                "scope_ref": row.scope.as_str(),
                "permission": row.permission.as_str(),
                "target_ref": row.target.as_str(),
                "expires_at_unix_secs": unix_secs(row.expires_at),
                "status": row.status.as_str(),
                "attempt_count": row.attempt_count,
                "review_required": row.review_required,
                "value_returned": false
            })
        })
        .collect::<Vec<_>>();
    println!("{}", json!({"activations": rows, "value_returned": false}));
    Ok(())
}

fn activation_status(args: &[String]) -> Result<()> {
    let activation_id = parse_activation_only(args)?;
    let record = registry()?.get(activation_id.as_str())?;
    let status = record.status_at(SystemTime::now());
    println!(
        "{}",
        json!({
            "activation_id": record.activation.id().as_str(),
            "request_id": record.request.id().as_str(),
            "scope_ref": record.request.scope().as_str(),
            "permission": record.request.permission().as_str(),
            "target_ref": record.request.target().as_str(),
            "expires_at_unix_secs": unix_secs(record.request.expires_at()),
            "status": status.as_str(),
            "attempt_count": record.attempts.len(),
            "completion_recorded": record.completion.is_some(),
            "review_required": record.completion.is_some() && record.review.is_none(),
            "review_closed": record.review.is_some(),
            "value_returned": false
        })
    );
    Ok(())
}

fn revoke_activation(args: &[String], principal: &PrincipalChain) -> Result<()> {
    let (activation_id, reason) = parse_revoke(args)?;
    let registry = registry()?;
    let record = registry.get(activation_id.as_str())?;
    let mut audit = break_glass_audit()?;
    let revocation = BreakGlassRevocation::revoke(
        &record.activation,
        principal,
        reason,
        SystemTime::now(),
        &mut audit,
    )?;
    registry.record_revocation(&revocation)?;
    println!(
        "{}",
        json!({
            "activation_id": activation_id.as_str(),
            "status": "revoked",
            "value_returned": false
        })
    );
    Ok(())
}

struct ReviewConfig {
    activation: BreakGlassActivationId,
    findings: SafeLabel,
    remediation: SafeLabel,
    closure: BreakGlassReviewClosure,
}

fn review_activation(args: &[String], principal: &PrincipalChain) -> Result<()> {
    let config = parse_review(args)?;
    let registry = registry()?;
    let record = registry.get(config.activation.as_str())?;
    let completion = record
        .completion
        .as_ref()
        .context("break-glass activation has no completed action to review")?;
    let mut audit = break_glass_audit()?;
    let review = BreakGlassReview::review(
        &record.activation,
        completion,
        principal,
        config.findings,
        config.remediation,
        config.closure,
        SystemTime::now(),
        &mut audit,
    )?;
    registry.record_review(&review)?;
    println!(
        "{}",
        json!({
            "activation_id": config.activation.as_str(),
            "review_id": review.id().as_str(),
            "closure": review.closure().as_str(),
            "status": "review_closed",
            "value_returned": false
        })
    );
    Ok(())
}

fn parse_request(args: &[String]) -> Result<RequestConfig> {
    let mut eligibility_binding = None;
    let mut permission = None;
    let mut target = None;
    let mut reason = None;
    let mut ttl = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--eligibility-binding" => replace_once(
                &mut eligibility_binding,
                RoleBindingId::from_opaque(required(flag, args.next())?.to_string())?,
                flag,
            )?,
            "--permission" => replace_once(
                &mut permission,
                Permission::parse(required(flag, args.next())?)?,
                flag,
            )?,
            "--target-ref" => replace_once(
                &mut target,
                SecretRef::new(required(flag, args.next())?)?,
                flag,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(flag, args.next())?)?,
                flag,
            )?,
            "--expires-in-seconds" => replace_once(
                &mut ttl,
                Duration::from_secs(
                    required(flag, args.next())?
                        .parse::<u64>()
                        .context("invalid --expires-in-seconds")?,
                ),
                flag,
            )?,
            _ => anyhow::bail!(
                "break-glass request arguments invalid reason_code=break_glass_args_invalid value_returned=false"
            ),
        }
    }
    let permission = permission.context("--permission is required")?;
    if !matches!(permission, Permission::ManagedRun | Permission::EnvFile) {
        anyhow::bail!(
            "break-glass request denied reason_code=break_glass_action_unavailable value_returned=false"
        );
    }
    let ttl = ttl.context("--expires-in-seconds is required")?;
    if ttl.is_zero() || ttl > MAX_BREAK_GLASS_TTL {
        anyhow::bail!(
            "break-glass request denied reason_code=break_glass_ttl_invalid value_returned=false"
        );
    }
    Ok(RequestConfig {
        eligibility_binding: eligibility_binding.context("--eligibility-binding is required")?,
        permission,
        target: target.context("--target-ref is required")?,
        reason: reason.context("--reason is required")?,
        ttl,
    })
}

fn parse_request_only(args: &[String]) -> Result<BreakGlassRequestId> {
    match args {
        [flag, id] if flag == "--request" => {
            Ok(BreakGlassRequestId::from_opaque(id.clone())?)
        }
        _ => anyhow::bail!(
            "break-glass approve arguments invalid reason_code=break_glass_args_invalid value_returned=false"
        ),
    }
}

fn parse_activation_only(args: &[String]) -> Result<BreakGlassActivationId> {
    match args {
        [flag, id] if flag == "--activation" => {
            Ok(BreakGlassActivationId::from_opaque(id.clone())?)
        }
        _ => anyhow::bail!(
            "break-glass status arguments invalid reason_code=break_glass_args_invalid value_returned=false"
        ),
    }
}

fn parse_revoke(args: &[String]) -> Result<(BreakGlassActivationId, SafeLabel)> {
    let mut activation = None;
    let mut reason = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--activation" => replace_once(
                &mut activation,
                BreakGlassActivationId::from_opaque(required(flag, args.next())?.to_string())?,
                flag,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(flag, args.next())?)?,
                flag,
            )?,
            _ => anyhow::bail!(
                "break-glass revoke arguments invalid reason_code=break_glass_args_invalid value_returned=false"
            ),
        }
    }
    Ok((
        activation.context("--activation is required")?,
        reason.context("--reason is required")?,
    ))
}

fn parse_review(args: &[String]) -> Result<ReviewConfig> {
    let mut activation = None;
    let mut findings = None;
    let mut remediation = None;
    let mut closure = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--activation" => replace_once(
                &mut activation,
                BreakGlassActivationId::from_opaque(required(flag, args.next())?.to_string())?,
                flag,
            )?,
            "--findings" => replace_once(
                &mut findings,
                SafeLabel::new(required(flag, args.next())?)?,
                flag,
            )?,
            "--remediation" => replace_once(
                &mut remediation,
                SafeLabel::new(required(flag, args.next())?)?,
                flag,
            )?,
            "--closure" => replace_once(
                &mut closure,
                BreakGlassReviewClosure::parse(required(flag, args.next())?)?,
                flag,
            )?,
            _ => anyhow::bail!(
                "break-glass review arguments invalid reason_code=break_glass_args_invalid value_returned=false"
            ),
        }
    }
    Ok(ReviewConfig {
        activation: activation.context("--activation is required")?,
        findings: findings.context("--findings is required")?,
        remediation: remediation.context("--remediation is required")?,
        closure: closure.context("--closure is required")?,
    })
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

fn registry() -> Result<FileBreakGlassRegistry> {
    Ok(FileBreakGlassRegistry::new(required_env_path(
        "JANUS_BREAK_GLASS_ROOT",
    )?))
}

fn break_glass_audit() -> Result<JsonlAuditSink> {
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
    fn request_parser_is_closed_short_and_use_only() {
        let args = vec![
            "--eligibility-binding".to_string(),
            "rbd_aaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--permission".to_string(),
            "managed_run.use".to_string(),
            "--target-ref".to_string(),
            "sec_emergency".to_string(),
            "--reason".to_string(),
            "incident response".to_string(),
            "--expires-in-seconds".to_string(),
            "300".to_string(),
        ];
        assert_eq!(
            parse_request(&args).unwrap().permission,
            Permission::ManagedRun
        );

        let mut broad = args.clone();
        broad[3] = "role_binding.issue".to_string();
        assert!(parse_request(&broad).is_err());
        let mut long = args.clone();
        long[9] = "901".to_string();
        assert!(parse_request(&long).is_err());
        let mut injected = args;
        injected.extend(["--reveal".to_string(), "true".to_string()]);
        assert!(parse_request(&injected).is_err());
    }
}

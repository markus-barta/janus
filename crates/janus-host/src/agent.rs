//! Host-ref-bound managed-service orchestration.
//!
//! The agent can select only a declaratively configured profile. It carries
//! the encrypted Janus packet directly to the host executor and sends Pharos
//! value-free phase results only.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    read_private_regular, valid_ref, HostEnvelopeControlV1, HostEnvelopeQuarantineControlV1,
    HostExecutor, HostExecutorOutcome,
};

const CONFIG_SCHEMA: &str = "inspr.janus.managed-host-agent-config.v1";
const CLAIM_SCHEMA: &str = "inspr.pharos.managed-service-operation-claim.v1";
const LEASE_SCHEMA: &str = "inspr.pharos.managed-service-operation-lease.v1";
const RESULT_SCHEMA: &str = "inspr.pharos.managed-service-operation-result.v1";
const STATUS_SCHEMA: &str = "inspr.pharos.managed-service-operation-status.v1";
const RECONCILE_SCHEMA: &str = "inspr.janus.managed-host-reconcile-request.v1";
const SCHEMA_VERSION: u16 = 1;
const SYSTEM_CONFIG_PATH: &str = "/run/janus-managed-agent/config.json";
const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_JSON_BYTES: usize = 32 * 1024;
const MAX_PACKET_BYTES: usize = 256 * 1024;
const MAX_PROFILES: usize = 128;
const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024;

/// Stable, value-free agent failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedHostAgentError {
    reason_code: &'static str,
}

impl ManagedHostAgentError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    /// Stable value-free reason code.
    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for ManagedHostAgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ManagedHostAgentError {}

type AgentResult<T> = Result<T, ManagedHostAgentError>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedHostAgentConfigV1 {
    schema: String,
    schema_version: u16,
    host_ref: String,
    pharos_origin: String,
    janus_origin: String,
    token_file: String,
    docker_executable: String,
    compose_project: String,
    poll_interval_seconds: u64,
    profiles: Vec<ManagedHostProfileV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedHostProfileV1 {
    service_ref: String,
    slot_ref: String,
    delivery_profile_ref: String,
    reload_profile_ref: String,
    health_profile_ref: String,
    detach_profile_ref: String,
    compose_file: String,
    compose_service: String,
    container_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AgentPhase {
    Install,
    Reload,
    Verify,
    Remove,
}

impl AgentPhase {
    fn expected_profile_prefix(self) -> &'static str {
        match self {
            Self::Install => "delivery_",
            Self::Reload => "reload_",
            Self::Verify => "health_",
            Self::Remove => "detach_",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedOperationLeaseV1 {
    schema: String,
    schema_version: u16,
    lease_ref: String,
    operation_ref: String,
    #[serde(default = "default_create_operation_kind")]
    operation_kind: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    generation: u64,
    #[serde(default)]
    purge_not_before_unix_secs: Option<i64>,
    phase: AgentPhase,
    profile_ref: String,
    leased_at_unix_secs: i64,
    expires_at_unix_secs: i64,
    value_returned: bool,
}

#[derive(Serialize)]
struct ManagedOperationClaimV1<'a> {
    schema: &'static str,
    schema_version: u16,
    host_ref: &'a str,
}

#[derive(Serialize)]
struct ManagedOperationResultV1<'a> {
    schema: &'static str,
    schema_version: u16,
    lease_ref: &'a str,
    operation_ref: &'a str,
    host_ref: &'a str,
    phase: AgentPhase,
    outcome: &'static str,
    reason_code: &'static str,
    generation: u64,
    health_evidence: Option<ManagedHealthEvidenceV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_evidence: Option<ManagedRollbackEvidenceV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    removal_evidence: Option<ManagedRemovalEvidenceV1>,
    value_returned: bool,
}

#[derive(Clone, Copy, Serialize)]
struct ManagedHealthEvidenceV1 {
    generation: u64,
    materialized: bool,
    process_state: &'static str,
    probe_state: &'static str,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    probe_observed_at_unix_secs: i64,
}

#[derive(Clone, Copy, Serialize)]
struct ManagedRollbackEvidenceV1 {
    restored_generation: u64,
    materialized: bool,
    process_state: &'static str,
    probe_state: &'static str,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    probe_observed_at_unix_secs: i64,
}

#[derive(Clone, Copy, Serialize)]
struct ManagedRemovalEvidenceV1 {
    generation: u64,
    runtime_absent: bool,
    process_state: &'static str,
    cache_state: &'static str,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    cache_observed_at_unix_secs: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedOperationStatusV1 {
    schema: String,
    schema_version: u16,
    operation: ManagedOperationSummaryV1,
    value_returned: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedOperationSummaryV1 {
    operation_ref: String,
    operation_kind: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    generation: u64,
    #[serde(default)]
    purge_not_before_unix_secs: Option<i64>,
    phase: String,
    reason_code: Option<String>,
    created_at_unix_secs: i64,
    updated_at_unix_secs: i64,
    health: Option<ManagedHealthSummaryV1>,
    #[serde(default)]
    rollback: Option<ManagedRollbackSummaryV1>,
    #[serde(default)]
    removal: Option<ManagedRemovalSummaryV1>,
    value_returned: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedHealthSummaryV1 {
    generation: u64,
    outcome: String,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    probe_observed_at_unix_secs: i64,
    accepted_at_unix_secs: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRollbackSummaryV1 {
    restored_generation: u64,
    outcome: String,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    probe_observed_at_unix_secs: i64,
    accepted_at_unix_secs: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRemovalSummaryV1 {
    generation: u64,
    outcome: String,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    cache_observed_at_unix_secs: i64,
    accepted_at_unix_secs: i64,
}

#[derive(Serialize)]
struct ManagedHostReconcileRequestV1<'a> {
    schema: &'static str,
    schema_version: u16,
    operation_ref: &'a str,
    host_ref: &'a str,
    generation: u64,
}

#[derive(Deserialize)]
struct DockerState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Health")]
    health: Option<DockerHealth>,
}

#[derive(Deserialize)]
struct DockerHealth {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "FailingStreak")]
    failing_streak: u64,
    #[serde(rename = "Log")]
    log: Vec<serde_json::Value>,
}

struct ManagedHostAgent {
    config: ManagedHostAgentConfigV1,
    token: String,
    http: ureq::Agent,
}

/// Load the root-owned configuration and continuously process exact leases.
pub fn run_from_system() -> AgentResult<()> {
    let config_raw = read_private_regular(
        Path::new(SYSTEM_CONFIG_PATH),
        MAX_CONFIG_BYTES,
        Some(0),
        "managed_host_agent_config_unavailable",
    )
    .map_err(|_| ManagedHostAgentError::new("managed_host_agent_config_unavailable"))?;
    let config: ManagedHostAgentConfigV1 = decode_strict(&config_raw)
        .map_err(|_| ManagedHostAgentError::new("managed_host_agent_config_invalid"))?;
    let agent = ManagedHostAgent::new(config)?;
    let executor = HostExecutor::from_system()
        .map_err(|_| ManagedHostAgentError::new("managed_host_executor_unavailable"))?;
    loop {
        if let Err(error) = agent.run_once(&executor) {
            eprintln!(
                "janus-managed-host-agent cycle reason_code={} value_returned=false",
                error.reason_code()
            );
        }
        thread::sleep(Duration::from_secs(agent.config.poll_interval_seconds));
    }
}

impl ManagedHostAgent {
    fn new(config: ManagedHostAgentConfigV1) -> AgentResult<Self> {
        validate_config(&config)?;
        let token = read_private_regular(
            Path::new(&config.token_file),
            MAX_TOKEN_BYTES,
            Some(0),
            "managed_host_agent_token_unavailable",
        )
        .map_err(|_| ManagedHostAgentError::new("managed_host_agent_token_unavailable"))?;
        let token = String::from_utf8(token)
            .map_err(|_| ManagedHostAgentError::new("managed_host_agent_token_invalid"))?;
        let token = token.trim_end_matches('\n').to_string();
        if token.len() < 32
            || token.len() > MAX_TOKEN_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ManagedHostAgentError::new(
                "managed_host_agent_token_invalid",
            ));
        }
        let http = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout_read(Duration::from_secs(8))
            .timeout_write(Duration::from_secs(8))
            .redirects(0)
            .build();
        Ok(Self {
            config,
            token,
            http,
        })
    }

    fn run_once(&self, executor: &HostExecutor) -> AgentResult<()> {
        match self.claim()? {
            Some(lease) => self.execute_lease(executor, &lease),
            None => self.recover_staged(executor),
        }
    }

    fn claim(&self) -> AgentResult<Option<ManagedOperationLeaseV1>> {
        let body = serde_json::to_vec(&ManagedOperationClaimV1 {
            schema: CLAIM_SCHEMA,
            schema_version: SCHEMA_VERSION,
            host_ref: &self.config.host_ref,
        })
        .map_err(|_| ManagedHostAgentError::new("managed_host_claim_invalid"))?;
        let response = self.post_json(
            &self.config.pharos_origin,
            "/agent/managed-services/claim",
            &body,
            MAX_JSON_BYTES,
        )?;
        if response.status == 204 {
            return Ok(None);
        }
        if response.status != 200 {
            return Err(ManagedHostAgentError::new("managed_host_claim_unavailable"));
        }
        let lease: ManagedOperationLeaseV1 = decode_strict(&response.body)
            .map_err(|_| ManagedHostAgentError::new("managed_host_lease_invalid"))?;
        validate_lease(&lease, &self.config.host_ref)?;
        self.profile_for_lease(&lease)?;
        Ok(Some(lease))
    }

    fn execute_lease(
        &self,
        executor: &HostExecutor,
        lease: &ManagedOperationLeaseV1,
    ) -> AgentResult<()> {
        let profile = self.profile_for_lease(lease)?;
        match lease.phase {
            AgentPhase::Install => {
                let packet = match self.fetch_packet(lease) {
                    Ok(packet) => packet,
                    Err(_) => {
                        let rollback = if lease.operation_kind == "replace" {
                            self.recover_replacement(executor, lease, profile).ok()
                        } else {
                            None
                        };
                        let outcome = if lease.operation_kind == "replace" && rollback.is_none() {
                            "uncertain"
                        } else {
                            "failed"
                        };
                        self.report_failure_and_reconcile(
                            lease,
                            outcome,
                            "delivery_failed",
                            rollback,
                        )?;
                        return Ok(());
                    }
                };
                if executor.install(&packet, SystemTime::now()).is_err() {
                    let rollback = if lease.operation_kind == "replace" {
                        self.recover_replacement(executor, lease, profile).ok()
                    } else {
                        None
                    };
                    let (outcome, reason) =
                        if lease.operation_kind == "replace" && rollback.is_none() {
                            ("uncertain", "executor_failed")
                        } else {
                            ("failed", "delivery_failed")
                        };
                    self.report_failure_and_reconcile(lease, outcome, reason, rollback)?;
                    return Ok(());
                }
                self.report(lease, "succeeded", "phase_succeeded", None, None, None)?;
            }
            AgentPhase::Reload => {
                if !staged_exact(executor, lease)? {
                    let rollback = if lease.operation_kind == "replace" {
                        self.recover_replacement(executor, lease, profile).ok()
                    } else {
                        None
                    };
                    let (outcome, reason) =
                        if lease.operation_kind == "replace" && rollback.is_none() {
                            ("uncertain", "reload_uncertain")
                        } else {
                            ("failed", "reload_failed")
                        };
                    self.report_failure_and_reconcile(lease, outcome, reason, rollback)?;
                    return Ok(());
                }
                if self.compose_up(profile).is_err() {
                    let (rollback, recovered) = if lease.operation_kind == "replace" {
                        let rollback = self.recover_replacement(executor, lease, profile).ok();
                        let recovered = rollback.is_some();
                        (rollback, recovered)
                    } else {
                        (
                            None,
                            self.rollback_and_recover(executor, lease, profile).is_ok(),
                        )
                    };
                    let (outcome, reason) = if recovered {
                        ("failed", "reload_failed")
                    } else {
                        ("uncertain", "reload_uncertain")
                    };
                    self.report_failure_and_reconcile(lease, outcome, reason, rollback)?;
                    return Ok(());
                }
                self.report(lease, "succeeded", "phase_succeeded", None, None, None)?;
            }
            AgentPhase::Verify => {
                if !staged_exact(executor, lease)? {
                    let rollback = if lease.operation_kind == "replace" {
                        self.recover_replacement(executor, lease, profile).ok()
                    } else {
                        None
                    };
                    let (outcome, reason) =
                        if lease.operation_kind == "replace" && rollback.is_none() {
                            ("uncertain", "executor_failed")
                        } else {
                            ("failed", "verification_failed")
                        };
                    self.report_failure_and_reconcile(lease, outcome, reason, rollback)?;
                    return Ok(());
                }
                let evidence = match self.verify(profile, lease.generation) {
                    Ok(evidence) => evidence,
                    Err(_) => {
                        let (rollback, recovered) = if lease.operation_kind == "replace" {
                            let rollback = self.recover_replacement(executor, lease, profile).ok();
                            let recovered = rollback.is_some();
                            (rollback, recovered)
                        } else {
                            (
                                None,
                                self.rollback_and_recover(executor, lease, profile).is_ok(),
                            )
                        };
                        let (outcome, reason) = if recovered {
                            ("failed", "verification_failed")
                        } else {
                            ("uncertain", "executor_failed")
                        };
                        self.report_failure_and_reconcile(lease, outcome, reason, rollback)?;
                        return Ok(());
                    }
                };
                let status = self.report(
                    lease,
                    "succeeded",
                    "phase_succeeded",
                    Some(evidence),
                    None,
                    None,
                )?;
                if status.operation.phase != "active" {
                    return Err(ManagedHostAgentError::new(
                        "managed_host_activation_unconfirmed",
                    ));
                }
                // Janus must commit the central transaction while the host's
                // previous generation is still recoverable. A lost response is
                // retry-safe; only the acknowledged central commit permits the
                // host rollback generation to be discarded.
                self.reconcile(lease)?;
                executor
                    .commit(&control_for_lease(lease))
                    .map_err(|_| ManagedHostAgentError::new("managed_host_commit_failed"))?;
            }
            AgentPhase::Remove => {
                let purge_not_before = lease
                    .purge_not_before_unix_secs
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or_else(|| ManagedHostAgentError::new("managed_host_lease_invalid"))?;
                if self.compose_stop_for_removal(profile).is_err()
                    || self.verify_stopped(profile).is_err()
                {
                    self.report_failure_and_reconcile(
                        lease,
                        "uncertain",
                        "removal_uncertain",
                        None,
                    )?;
                    return Ok(());
                }
                let control = quarantine_control_for_lease(lease, purge_not_before);
                let quarantined = match executor.quarantine(&control) {
                    Ok(outcome)
                        if outcome.phase == "quarantined"
                            && outcome.operation_ref.as_deref()
                                == Some(lease.operation_ref.as_str())
                            && outcome.generation == Some(lease.generation) =>
                    {
                        outcome
                    }
                    _ => {
                        self.report_failure_and_reconcile(
                            lease,
                            "uncertain",
                            "removal_uncertain",
                            None,
                        )?;
                        return Ok(());
                    }
                };
                let missing = executor
                    .status()
                    .map_err(|_| ManagedHostAgentError::new("managed_host_status_unavailable"))?
                    .into_iter()
                    .any(|outcome| {
                        outcome.service_ref.as_deref() == Some(lease.service_ref.as_str())
                            && outcome.slot_ref.as_deref() == Some(lease.slot_ref.as_str())
                            && outcome.phase == "quarantined"
                            && outcome.operation_ref.as_deref()
                                == quarantined.operation_ref.as_deref()
                            && outcome.generation == Some(lease.generation)
                    });
                if !missing {
                    self.report_failure_and_reconcile(
                        lease,
                        "uncertain",
                        "removal_uncertain",
                        None,
                    )?;
                    return Ok(());
                }
                let observed_at = unix_seconds()?;
                let status = self.report(
                    lease,
                    "succeeded",
                    "phase_succeeded",
                    None,
                    None,
                    Some(ManagedRemovalEvidenceV1 {
                        generation: lease.generation,
                        runtime_absent: true,
                        process_state: "stopped",
                        cache_state: "quarantined",
                        heartbeat_observed_at_unix_secs: observed_at,
                        process_observed_at_unix_secs: observed_at,
                        cache_observed_at_unix_secs: observed_at,
                    }),
                )?;
                if status.operation.phase != "removed" {
                    return Err(ManagedHostAgentError::new(
                        "managed_host_removal_unconfirmed",
                    ));
                }
                self.reconcile(lease)?;
            }
        }
        Ok(())
    }

    fn recover_staged(&self, executor: &HostExecutor) -> AgentResult<()> {
        let outcomes = executor
            .status()
            .map_err(|_| ManagedHostAgentError::new("managed_host_status_unavailable"))?;
        for outcome in outcomes
            .iter()
            .filter(|outcome| matches!(outcome.phase.as_str(), "staged" | "quarantined"))
        {
            let (Some(operation_ref), Some(generation), Some(service_ref), Some(slot_ref)) = (
                outcome.operation_ref.as_deref(),
                outcome.generation,
                outcome.service_ref.as_deref(),
                outcome.slot_ref.as_deref(),
            ) else {
                return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
            };
            let status = self.status(operation_ref)?;
            if status.operation.host_ref != self.config.host_ref
                || status.operation.service_ref != service_ref
                || status.operation.slot_ref != slot_ref
                || status.operation.generation != generation
            {
                return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
            }
            if outcome.phase == "quarantined" {
                match status.operation.phase.as_str() {
                    "removed" => {
                        self.reconcile_parts(operation_ref, generation)?;
                        if status
                            .operation
                            .purge_not_before_unix_secs
                            .is_some_and(|deadline| unix_seconds().is_ok_and(|now| now >= deadline))
                        {
                            let deadline =
                                u64::try_from(status.operation.purge_not_before_unix_secs.unwrap())
                                    .map_err(|_| {
                                        ManagedHostAgentError::new("managed_host_status_invalid")
                                    })?;
                            executor
                                .purge_quarantine(
                                    &HostEnvelopeQuarantineControlV1 {
                                        schema: "inspr.janus.host-envelope-quarantine-control.v1"
                                            .to_string(),
                                        schema_version: 1,
                                        operation_ref: operation_ref.to_string(),
                                        host_ref: self.config.host_ref.clone(),
                                        service_ref: service_ref.to_string(),
                                        slot_ref: slot_ref.to_string(),
                                        generation,
                                        purge_not_before_unix_secs: deadline,
                                    },
                                    SystemTime::now(),
                                )
                                .map_err(|_| {
                                    ManagedHostAgentError::new(
                                        "managed_host_quarantine_purge_failed",
                                    )
                                })?;
                        }
                    }
                    "failed" | "superseded" => {
                        return Err(ManagedHostAgentError::new(
                            "managed_host_quarantine_review_required",
                        ))
                    }
                    _ => {}
                }
                continue;
            }
            let control = HostEnvelopeControlV1 {
                schema: "inspr.janus.host-envelope-control.v1".to_string(),
                schema_version: 1,
                operation_ref: operation_ref.to_string(),
                host_ref: self.config.host_ref.clone(),
                service_ref: service_ref.to_string(),
                slot_ref: slot_ref.to_string(),
                generation,
            };
            match status.operation.phase.as_str() {
                "active" => {
                    self.reconcile_parts(operation_ref, generation)?;
                    executor
                        .commit(&control)
                        .map_err(|_| ManagedHostAgentError::new("managed_host_commit_failed"))?;
                }
                "failed" | "rolled_back" | "superseded" => {
                    let profile = self.profile_for_slot(service_ref, slot_ref)?;
                    let rollback = executor
                        .rollback(&control, SystemTime::now())
                        .map_err(|_| ManagedHostAgentError::new("managed_host_rollback_failed"))?;
                    self.recover_runtime(profile, &rollback)?;
                    self.reconcile_parts(operation_ref, generation)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn fetch_packet(&self, lease: &ManagedOperationLeaseV1) -> AgentResult<Vec<u8>> {
        let path = format!(
            "/internal/managed-service-host-envelopes/{}/{}",
            lease.host_ref, lease.operation_ref
        );
        let response = self.get(
            &self.config.janus_origin,
            &path,
            MAX_PACKET_BYTES,
            Some("application/octet-stream"),
        )?;
        if response.status != 200 || response.body.is_empty() {
            return Err(ManagedHostAgentError::new(
                "managed_host_envelope_unavailable",
            ));
        }
        Ok(response.body)
    }

    fn report(
        &self,
        lease: &ManagedOperationLeaseV1,
        outcome: &'static str,
        reason_code: &'static str,
        health_evidence: Option<ManagedHealthEvidenceV1>,
        rollback_evidence: Option<ManagedRollbackEvidenceV1>,
        removal_evidence: Option<ManagedRemovalEvidenceV1>,
    ) -> AgentResult<ManagedOperationStatusV1> {
        let result = ManagedOperationResultV1 {
            schema: RESULT_SCHEMA,
            schema_version: SCHEMA_VERSION,
            lease_ref: &lease.lease_ref,
            operation_ref: &lease.operation_ref,
            host_ref: &lease.host_ref,
            phase: lease.phase,
            outcome,
            reason_code,
            generation: lease.generation,
            health_evidence,
            rollback_evidence,
            removal_evidence,
            value_returned: false,
        };
        let body = serde_json::to_vec(&result)
            .map_err(|_| ManagedHostAgentError::new("managed_host_result_invalid"))?;
        let path = format!("/agent/managed-services/{}/result", lease.operation_ref);
        let response = self.post_json(&self.config.pharos_origin, &path, &body, MAX_JSON_BYTES)?;
        if response.status != 200 {
            return Err(ManagedHostAgentError::new(
                "managed_host_result_unavailable",
            ));
        }
        let status: ManagedOperationStatusV1 = decode_strict(&response.body)
            .map_err(|_| ManagedHostAgentError::new("managed_host_status_invalid"))?;
        validate_status(&status, &self.config.host_ref, &lease.operation_ref)?;
        Ok(status)
    }

    fn report_failure_and_reconcile(
        &self,
        lease: &ManagedOperationLeaseV1,
        outcome: &'static str,
        reason_code: &'static str,
        rollback_evidence: Option<ManagedRollbackEvidenceV1>,
    ) -> AgentResult<()> {
        let status = self.report(lease, outcome, reason_code, None, rollback_evidence, None)?;
        if matches!(
            status.operation.phase.as_str(),
            "failed" | "rolled_back" | "superseded"
        ) {
            self.reconcile(lease)?;
        }
        Ok(())
    }

    fn status(&self, operation_ref: &str) -> AgentResult<ManagedOperationStatusV1> {
        let path = format!(
            "/agent/managed-services/{operation_ref}?host_ref={}",
            self.config.host_ref
        );
        let response = self.get(
            &self.config.pharos_origin,
            &path,
            MAX_JSON_BYTES,
            Some("application/json"),
        )?;
        if response.status != 200 {
            return Err(ManagedHostAgentError::new(
                "managed_host_status_unavailable",
            ));
        }
        let status: ManagedOperationStatusV1 = decode_strict(&response.body)
            .map_err(|_| ManagedHostAgentError::new("managed_host_status_invalid"))?;
        validate_status(&status, &self.config.host_ref, operation_ref)?;
        Ok(status)
    }

    fn reconcile(&self, lease: &ManagedOperationLeaseV1) -> AgentResult<()> {
        self.reconcile_parts(&lease.operation_ref, lease.generation)
    }

    fn reconcile_parts(&self, operation_ref: &str, generation: u64) -> AgentResult<()> {
        let body = serde_json::to_vec(&ManagedHostReconcileRequestV1 {
            schema: RECONCILE_SCHEMA,
            schema_version: SCHEMA_VERSION,
            operation_ref,
            host_ref: &self.config.host_ref,
            generation,
        })
        .map_err(|_| ManagedHostAgentError::new("managed_host_reconcile_invalid"))?;
        let path = format!("/internal/managed-service-operations/{operation_ref}/reconcile");
        let response = self.post_json(&self.config.janus_origin, &path, &body, MAX_JSON_BYTES)?;
        if response.status != 204 {
            return Err(ManagedHostAgentError::new(
                "managed_host_reconcile_unavailable",
            ));
        }
        Ok(())
    }

    fn rollback_and_recover(
        &self,
        executor: &HostExecutor,
        lease: &ManagedOperationLeaseV1,
        profile: &ManagedHostProfileV1,
    ) -> AgentResult<()> {
        let outcome = executor
            .rollback(&control_for_lease(lease), SystemTime::now())
            .map_err(|_| ManagedHostAgentError::new("managed_host_rollback_failed"))?;
        self.recover_runtime(profile, &outcome)
    }

    fn recover_replacement(
        &self,
        executor: &HostExecutor,
        lease: &ManagedOperationLeaseV1,
        profile: &ManagedHostProfileV1,
    ) -> AgentResult<ManagedRollbackEvidenceV1> {
        let status = executor
            .status()
            .map_err(|_| ManagedHostAgentError::new("managed_host_status_unavailable"))?;
        let current = status
            .into_iter()
            .find(|outcome| {
                outcome.service_ref.as_deref() == Some(lease.service_ref.as_str())
                    && outcome.slot_ref.as_deref() == Some(lease.slot_ref.as_str())
            })
            .ok_or_else(|| ManagedHostAgentError::new("managed_host_status_invalid"))?;
        let restored = if current.phase == "staged"
            && current.generation == Some(lease.generation)
            && current.operation_ref.as_deref() == Some(lease.operation_ref.as_str())
        {
            let outcome = executor
                .rollback(&control_for_lease(lease), SystemTime::now())
                .map_err(|_| ManagedHostAgentError::new("managed_host_rollback_failed"))?;
            self.recover_runtime(profile, &outcome)?;
            outcome
        } else if current.phase == "active"
            && current
                .generation
                .is_some_and(|generation| generation < lease.generation)
        {
            current
        } else {
            return Err(ManagedHostAgentError::new("managed_host_recovery_unproven"));
        };
        let restored_generation = restored
            .generation
            .filter(|generation| *generation > 0 && *generation < lease.generation)
            .ok_or_else(|| ManagedHostAgentError::new("managed_host_recovery_unproven"))?;
        let health = self.verify(profile, restored_generation)?;
        Ok(ManagedRollbackEvidenceV1 {
            restored_generation,
            materialized: health.materialized,
            process_state: health.process_state,
            probe_state: health.probe_state,
            heartbeat_observed_at_unix_secs: health.heartbeat_observed_at_unix_secs,
            process_observed_at_unix_secs: health.process_observed_at_unix_secs,
            probe_observed_at_unix_secs: health.probe_observed_at_unix_secs,
        })
    }

    fn recover_runtime(
        &self,
        profile: &ManagedHostProfileV1,
        outcome: &HostExecutorOutcome,
    ) -> AgentResult<()> {
        if outcome.reason_code == "host_envelope_create_rolled_back" {
            self.compose_stop(profile)
        } else {
            self.compose_up(profile)
        }
    }

    fn compose_up(&self, profile: &ManagedHostProfileV1) -> AgentResult<()> {
        let status = self
            .compose_command(profile)
            .args(["up", "--detach", "--no-deps", &profile.compose_service])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ManagedHostAgentError::new("managed_host_reload_failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(ManagedHostAgentError::new("managed_host_reload_failed"))
        }
    }

    fn compose_stop(&self, profile: &ManagedHostProfileV1) -> AgentResult<()> {
        let status = self
            .compose_command(profile)
            .args(["stop", &profile.compose_service])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ManagedHostAgentError::new("managed_host_recovery_failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(ManagedHostAgentError::new("managed_host_recovery_failed"))
        }
    }

    fn compose_stop_for_removal(&self, profile: &ManagedHostProfileV1) -> AgentResult<()> {
        let status = self
            .compose_command(profile)
            .args(["stop", &profile.compose_service])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ManagedHostAgentError::new("managed_host_removal_uncertain"))?;
        if status.success() {
            Ok(())
        } else {
            Err(ManagedHostAgentError::new("managed_host_removal_uncertain"))
        }
    }

    fn verify_stopped(&self, profile: &ManagedHostProfileV1) -> AgentResult<()> {
        let compose = self
            .compose_command(profile)
            .args([
                "ps",
                "--status",
                "running",
                "--quiet",
                &profile.compose_service,
            ])
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ManagedHostAgentError::new("managed_host_removal_uncertain"))?;
        if !compose.status.success()
            || compose.stdout.len() > MAX_COMMAND_OUTPUT_BYTES
            || !compose.stdout.iter().all(u8::is_ascii_whitespace)
        {
            return Err(ManagedHostAgentError::new("managed_host_removal_uncertain"));
        }
        let exact = Command::new(&self.config.docker_executable)
            .args([
                "inspect",
                "--format",
                "{{json .State}}",
                &profile.container_name,
            ])
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ManagedHostAgentError::new("managed_host_removal_uncertain"))?;
        if exact.status.success()
            && !exact.stdout.is_empty()
            && exact.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES
            && docker_state_is_stopped(&exact.stdout)
        {
            Ok(())
        } else {
            Err(ManagedHostAgentError::new("managed_host_removal_uncertain"))
        }
    }

    fn compose_command(&self, profile: &ManagedHostProfileV1) -> Command {
        let mut command = Command::new(&self.config.docker_executable);
        command.args([
            "compose",
            "--project-name",
            &self.config.compose_project,
            "--file",
            &profile.compose_file,
        ]);
        command
    }

    fn verify(
        &self,
        profile: &ManagedHostProfileV1,
        generation: u64,
    ) -> AgentResult<ManagedHealthEvidenceV1> {
        let output = Command::new(&self.config.docker_executable)
            .args([
                "inspect",
                "--format",
                "{{json .State}}",
                &profile.container_name,
            ])
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ManagedHostAgentError::new("managed_host_verification_failed"))?;
        if !output.status.success()
            || output.stdout.is_empty()
            || output.stdout.len() > MAX_COMMAND_OUTPUT_BYTES
        {
            return Err(ManagedHostAgentError::new(
                "managed_host_verification_failed",
            ));
        }
        let state: DockerState = decode_strict(&output.stdout)
            .map_err(|_| ManagedHostAgentError::new("managed_host_verification_failed"))?;
        let health = state
            .health
            .ok_or_else(|| ManagedHostAgentError::new("managed_host_verification_failed"))?;
        if !state.running
            || state.status != "running"
            || health.status != "healthy"
            || health.failing_streak != 0
        {
            return Err(ManagedHostAgentError::new(
                "managed_host_verification_failed",
            ));
        }
        let _ = health.log;
        let now = unix_seconds()?;
        Ok(ManagedHealthEvidenceV1 {
            generation,
            materialized: true,
            process_state: "running",
            probe_state: "healthy",
            heartbeat_observed_at_unix_secs: now,
            process_observed_at_unix_secs: now,
            probe_observed_at_unix_secs: now,
        })
    }

    fn profile_for_lease(
        &self,
        lease: &ManagedOperationLeaseV1,
    ) -> AgentResult<&ManagedHostProfileV1> {
        let profile = self.profile_for_slot(&lease.service_ref, &lease.slot_ref)?;
        let expected = match lease.phase {
            AgentPhase::Install => &profile.delivery_profile_ref,
            AgentPhase::Reload => &profile.reload_profile_ref,
            AgentPhase::Verify => &profile.health_profile_ref,
            AgentPhase::Remove => &profile.detach_profile_ref,
        };
        if expected != &lease.profile_ref {
            return Err(ManagedHostAgentError::new("managed_host_profile_mismatch"));
        }
        Ok(profile)
    }

    fn profile_for_slot(
        &self,
        service_ref: &str,
        slot_ref: &str,
    ) -> AgentResult<&ManagedHostProfileV1> {
        let mut matches =
            self.config.profiles.iter().filter(|profile| {
                profile.service_ref == service_ref && profile.slot_ref == slot_ref
            });
        let profile = matches
            .next()
            .ok_or_else(|| ManagedHostAgentError::new("managed_host_profile_unknown"))?;
        if matches.next().is_some() {
            return Err(ManagedHostAgentError::new("managed_host_profile_ambiguous"));
        }
        Ok(profile)
    }

    fn post_json(
        &self,
        origin: &str,
        path: &str,
        body: &[u8],
        maximum: usize,
    ) -> AgentResult<HttpResponse> {
        let target = endpoint(origin, path)?;
        let response = match self
            .http
            .post(target.as_str())
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/json")
            .set("Content-Type", "application/json")
            .send_bytes(body)
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(_)) => {
                return Err(ManagedHostAgentError::new(
                    "managed_host_transport_unavailable",
                ))
            }
        };
        read_http_response(response, maximum, Some("application/json"))
    }

    fn get(
        &self,
        origin: &str,
        path: &str,
        maximum: usize,
        content_type: Option<&str>,
    ) -> AgentResult<HttpResponse> {
        let target = endpoint(origin, path)?;
        let response = match self
            .http
            .get(target.as_str())
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", content_type.unwrap_or("application/json"))
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(_)) => {
                return Err(ManagedHostAgentError::new(
                    "managed_host_transport_unavailable",
                ))
            }
        };
        read_http_response(response, maximum, content_type)
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_http_response(
    response: ureq::Response,
    maximum: usize,
    expected_content_type: Option<&str>,
) -> AgentResult<HttpResponse> {
    let status = response.status();
    if status != 204 {
        if let Some(expected) = expected_content_type {
            let actual = response
                .header("Content-Type")
                .and_then(|value| value.split(';').next())
                .unwrap_or_default();
            if actual != expected {
                return Err(ManagedHostAgentError::new("managed_host_response_invalid"));
            }
        }
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take((maximum + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| ManagedHostAgentError::new("managed_host_response_unavailable"))?;
    if body.len() > maximum || (status == 204 && !body.is_empty()) {
        return Err(ManagedHostAgentError::new("managed_host_response_invalid"));
    }
    Ok(HttpResponse { status, body })
}

fn endpoint(origin: &str, path: &str) -> AgentResult<Url> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(ManagedHostAgentError::new("managed_host_target_invalid"));
    }
    let origin = Url::parse(origin)
        .map_err(|_| ManagedHostAgentError::new("managed_host_target_invalid"))?;
    origin
        .join(path)
        .map_err(|_| ManagedHostAgentError::new("managed_host_target_invalid"))
}

fn validate_config(config: &ManagedHostAgentConfigV1) -> AgentResult<()> {
    if config.schema != CONFIG_SCHEMA
        || config.schema_version != SCHEMA_VERSION
        || !valid_ref("host_", &config.host_ref)
        || validate_origin(&config.pharos_origin).is_err()
        || validate_origin(&config.janus_origin).is_err()
        || !absolute_clean(&config.token_file)
        || !absolute_clean(&config.docker_executable)
        || !safe_runtime_name(&config.compose_project)
        || !(2..=300).contains(&config.poll_interval_seconds)
        || config.profiles.is_empty()
        || config.profiles.len() > MAX_PROFILES
    {
        return Err(ManagedHostAgentError::new(
            "managed_host_agent_config_invalid",
        ));
    }
    for (index, profile) in config.profiles.iter().enumerate() {
        if !valid_profile(profile)
            || config.profiles[..index].iter().any(|previous| {
                previous.service_ref == profile.service_ref && previous.slot_ref == profile.slot_ref
            })
        {
            return Err(ManagedHostAgentError::new(
                "managed_host_agent_config_invalid",
            ));
        }
    }
    Ok(())
}

fn valid_profile(profile: &ManagedHostProfileV1) -> bool {
    valid_ref("svc_", &profile.service_ref)
        && valid_ref("slot_", &profile.slot_ref)
        && valid_ref("delivery_", &profile.delivery_profile_ref)
        && valid_ref("reload_", &profile.reload_profile_ref)
        && valid_ref("health_", &profile.health_profile_ref)
        && valid_ref("detach_", &profile.detach_profile_ref)
        && absolute_clean(&profile.compose_file)
        && safe_runtime_name(&profile.compose_service)
        && safe_runtime_name(&profile.container_name)
}

fn validate_origin(raw: &str) -> AgentResult<()> {
    let parsed =
        Url::parse(raw).map_err(|_| ManagedHostAgentError::new("managed_host_target_invalid"))?;
    let local_http = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if (parsed.scheme() != "https" && !local_http)
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(ManagedHostAgentError::new("managed_host_target_invalid"));
    }
    Ok(())
}

fn absolute_clean(raw: &str) -> bool {
    let path = PathBuf::from(raw);
    path.is_absolute() && path.as_os_str() == path.components().collect::<PathBuf>().as_os_str()
}

fn safe_runtime_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn default_create_operation_kind() -> String {
    "create".to_string()
}

fn validate_lease(lease: &ManagedOperationLeaseV1, host_ref: &str) -> AgentResult<()> {
    if lease.schema != LEASE_SCHEMA
        || lease.schema_version != SCHEMA_VERSION
        || !valid_ref("lease_", &lease.lease_ref)
        || !valid_ref("op_", &lease.operation_ref)
        || !matches!(
            lease.operation_kind.as_str(),
            "create" | "replace" | "remove"
        )
        || lease.host_ref != host_ref
        || !valid_ref("svc_", &lease.service_ref)
        || !valid_ref("slot_", &lease.slot_ref)
        || !valid_ref("decl_", &lease.declaration_fingerprint)
        || !valid_ref(lease.phase.expected_profile_prefix(), &lease.profile_ref)
        || lease.generation == 0
        || match lease.operation_kind.as_str() {
            "remove" => {
                lease.phase != AgentPhase::Remove
                    || lease
                        .purge_not_before_unix_secs
                        .map_or(true, |deadline| deadline <= lease.expires_at_unix_secs)
            }
            "create" | "replace" => {
                lease.phase == AgentPhase::Remove || lease.purge_not_before_unix_secs.is_some()
            }
            _ => true,
        }
        || lease.leased_at_unix_secs <= 0
        || lease.expires_at_unix_secs <= lease.leased_at_unix_secs
        || lease.value_returned
    {
        return Err(ManagedHostAgentError::new("managed_host_lease_invalid"));
    }
    Ok(())
}

fn validate_status(
    status: &ManagedOperationStatusV1,
    host_ref: &str,
    operation_ref: &str,
) -> AgentResult<()> {
    let operation = &status.operation;
    if status.schema != STATUS_SCHEMA
        || status.schema_version != SCHEMA_VERSION
        || status.value_returned
        || operation.value_returned
        || operation.operation_ref != operation_ref
        || operation.host_ref != host_ref
        || !matches!(
            operation.operation_kind.as_str(),
            "create" | "replace" | "remove"
        )
        || !valid_ref("svc_", &operation.service_ref)
        || !valid_ref("slot_", &operation.slot_ref)
        || !valid_ref("decl_", &operation.declaration_fingerprint)
        || operation.generation == 0
        || match operation.operation_kind.as_str() {
            "remove" => operation
                .purge_not_before_unix_secs
                .map_or(true, |deadline| deadline <= operation.created_at_unix_secs),
            "create" | "replace" => operation.purge_not_before_unix_secs.is_some(),
            _ => true,
        }
        || operation.created_at_unix_secs <= 0
        || operation.updated_at_unix_secs < operation.created_at_unix_secs
        || match operation.operation_kind.as_str() {
            "remove" => !matches!(
                operation.phase.as_str(),
                "removal_pending" | "removing" | "removed" | "failed" | "superseded"
            ),
            "create" | "replace" => matches!(
                operation.phase.as_str(),
                "removal_pending" | "removing" | "removed"
            ),
            _ => true,
        }
        || !matches!(
            operation.phase.as_str(),
            "install_pending"
                | "installing"
                | "reload_pending"
                | "reloading"
                | "verify_pending"
                | "verifying"
                | "removal_pending"
                | "removing"
                | "active"
                | "removed"
                | "rolled_back"
                | "failed"
                | "superseded"
        )
    {
        return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
    }
    if operation.phase == "active" {
        let Some(health) = &operation.health else {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        };
        if health.generation != operation.generation
            || health.outcome != "healthy"
            || health.heartbeat_observed_at_unix_secs <= 0
            || health.process_observed_at_unix_secs <= 0
            || health.probe_observed_at_unix_secs <= 0
            || health.accepted_at_unix_secs <= 0
        {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        }
    } else if operation.health.is_some() {
        return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
    }
    if operation.phase == "rolled_back" {
        let Some(rollback) = &operation.rollback else {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        };
        if operation.operation_kind != "replace"
            || rollback.restored_generation == 0
            || rollback.restored_generation >= operation.generation
            || rollback.outcome != "healthy"
            || rollback.heartbeat_observed_at_unix_secs <= 0
            || rollback.process_observed_at_unix_secs <= 0
            || rollback.probe_observed_at_unix_secs <= 0
            || rollback.accepted_at_unix_secs <= 0
        {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        }
    } else if operation.rollback.is_some() {
        return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
    }
    if operation.phase == "removed" {
        let Some(removal) = &operation.removal else {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        };
        if operation.operation_kind != "remove"
            || removal.generation != operation.generation
            || removal.outcome != "healthy"
            || removal.heartbeat_observed_at_unix_secs <= 0
            || removal.process_observed_at_unix_secs <= 0
            || removal.cache_observed_at_unix_secs <= 0
            || removal.accepted_at_unix_secs <= 0
            || removal.accepted_at_unix_secs != operation.updated_at_unix_secs
            || operation
                .purge_not_before_unix_secs
                .map_or(true, |deadline| deadline <= removal.accepted_at_unix_secs)
            || [
                removal.heartbeat_observed_at_unix_secs,
                removal.process_observed_at_unix_secs,
                removal.cache_observed_at_unix_secs,
            ]
            .iter()
            .any(|observed| {
                *observed < operation.created_at_unix_secs
                    || *observed > removal.accepted_at_unix_secs
            })
        {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        }
    } else if operation.removal.is_some() {
        return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
    }
    if let Some(reason) = &operation.reason_code {
        if !safe_runtime_name(reason) {
            return Err(ManagedHostAgentError::new("managed_host_status_invalid"));
        }
    }
    Ok(())
}

fn docker_state_is_stopped(raw: &[u8]) -> bool {
    decode_strict::<DockerState>(raw).is_ok_and(|state| !state.running && state.status == "exited")
}

fn staged_exact(executor: &HostExecutor, lease: &ManagedOperationLeaseV1) -> AgentResult<bool> {
    let outcomes = executor
        .status()
        .map_err(|_| ManagedHostAgentError::new("managed_host_status_unavailable"))?;
    Ok(outcomes.iter().any(|outcome| {
        outcome.host_ref == lease.host_ref
            && outcome.service_ref.as_deref() == Some(&lease.service_ref)
            && outcome.slot_ref.as_deref() == Some(&lease.slot_ref)
            && outcome.operation_ref.as_deref() == Some(&lease.operation_ref)
            && outcome.generation == Some(lease.generation)
            && outcome.phase == "staged"
    }))
}

fn control_for_lease(lease: &ManagedOperationLeaseV1) -> HostEnvelopeControlV1 {
    HostEnvelopeControlV1 {
        schema: "inspr.janus.host-envelope-control.v1".to_string(),
        schema_version: 1,
        operation_ref: lease.operation_ref.clone(),
        host_ref: lease.host_ref.clone(),
        service_ref: lease.service_ref.clone(),
        slot_ref: lease.slot_ref.clone(),
        generation: lease.generation,
    }
}

fn quarantine_control_for_lease(
    lease: &ManagedOperationLeaseV1,
    purge_not_before_unix_secs: u64,
) -> HostEnvelopeQuarantineControlV1 {
    HostEnvelopeQuarantineControlV1 {
        schema: "inspr.janus.host-envelope-quarantine-control.v1".to_string(),
        schema_version: 1,
        operation_ref: lease.operation_ref.clone(),
        host_ref: lease.host_ref.clone(),
        service_ref: lease.service_ref.clone(),
        slot_ref: lease.slot_ref.clone(),
        generation: lease.generation,
        purge_not_before_unix_secs,
    }
}

fn decode_strict<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Result<T, ()> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let decoded = T::deserialize(&mut deserializer).map_err(|_| ())?;
    deserializer.end().map_err(|_| ())?;
    Ok(decoded)
}

fn unix_seconds() -> AgentResult<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ManagedHostAgentError::new("managed_host_clock_invalid"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ManagedHostAgentError::new("managed_host_clock_invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ManagedHostAgentConfigV1 {
        ManagedHostAgentConfigV1 {
            schema: CONFIG_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            host_ref: "host_58f36c72a91e".to_string(),
            pharos_origin: "https://pharos.example.test".to_string(),
            janus_origin: "https://vault.example.test".to_string(),
            token_file: "/run/credentials/janus-managed-host-agent/token".to_string(),
            docker_executable: "/nix/store/0123456789abcdef-docker/bin/docker".to_string(),
            compose_project: "janus-managed-canary".to_string(),
            poll_interval_seconds: 5,
            profiles: vec![ManagedHostProfileV1 {
                service_ref: "svc_0bca8d31f7e2".to_string(),
                slot_ref: "slot_49c0e8a17d63".to_string(),
                delivery_profile_ref: "delivery_2d7a0f63c951".to_string(),
                reload_profile_ref: "reload_094df2f6c8b1".to_string(),
                health_profile_ref: "health_2a02f96c33d4".to_string(),
                detach_profile_ref: "detach_8a0f4e271c93".to_string(),
                compose_file: "/etc/janus-managed/canary.compose.yaml".to_string(),
                compose_service: "secret-canary".to_string(),
                container_name: "janus-managed-secret-canary".to_string(),
            }],
        }
    }

    #[test]
    fn config_is_closed_and_profile_bound() {
        let mut fixture = config();
        validate_config(&fixture).expect("valid config");
        fixture.profiles[0].compose_file = "../dynamic.yaml".to_string();
        assert_eq!(
            validate_config(&fixture).expect_err("relative path denied"),
            ManagedHostAgentError::new("managed_host_agent_config_invalid")
        );
    }

    #[test]
    fn lease_cannot_choose_a_different_profile() {
        let fixture = config();
        let agent = ManagedHostAgent {
            config: fixture,
            token: "t".repeat(32),
            http: ureq::AgentBuilder::new().build(),
        };
        let mut lease = ManagedOperationLeaseV1 {
            schema: LEASE_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            lease_ref: "lease_49c0e8a17d63".to_string(),
            operation_ref: "op_58f36c72a91e".to_string(),
            operation_kind: "create".to_string(),
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint: "decl_a84f209c4b32".to_string(),
            generation: 1,
            purge_not_before_unix_secs: None,
            phase: AgentPhase::Reload,
            profile_ref: "reload_094df2f6c8b1".to_string(),
            leased_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_000_060,
            value_returned: false,
        };
        validate_lease(&lease, &agent.config.host_ref).expect("valid lease");
        agent.profile_for_lease(&lease).expect("bound profile");
        lease.profile_ref = "reload_attacker0001".to_string();
        assert_eq!(
            agent.profile_for_lease(&lease).expect_err("profile denied"),
            ManagedHostAgentError::new("managed_host_profile_mismatch")
        );
    }

    #[test]
    fn strict_contracts_reject_value_and_output_fields() {
        let lease = br#"{
          "schema":"inspr.pharos.managed-service-operation-lease.v1",
          "schema_version":1,
          "lease_ref":"lease_49c0e8a17d63",
          "operation_ref":"op_58f36c72a91e",
          "operation_kind":"create",
          "host_ref":"host_58f36c72a91e",
          "service_ref":"svc_0bca8d31f7e2",
          "slot_ref":"slot_49c0e8a17d63",
          "declaration_fingerprint":"decl_a84f209c4b32",
          "generation":1,
          "phase":"install",
          "profile_ref":"delivery_2d7a0f63c951",
          "leased_at_unix_secs":1800000000,
          "expires_at_unix_secs":1800000060,
          "value_returned":false,
          "secret_value":"SENSITIVE_AGENT_CANARY"
        }"#;
        assert!(decode_strict::<ManagedOperationLeaseV1>(lease).is_err());

        let previous_create_lease = br#"{
          "schema":"inspr.pharos.managed-service-operation-lease.v1",
          "schema_version":1,
          "lease_ref":"lease_49c0e8a17d63",
          "operation_ref":"op_58f36c72a91e",
          "host_ref":"host_58f36c72a91e",
          "service_ref":"svc_0bca8d31f7e2",
          "slot_ref":"slot_49c0e8a17d63",
          "declaration_fingerprint":"decl_a84f209c4b32",
          "generation":1,
          "phase":"install",
          "profile_ref":"delivery_2d7a0f63c951",
          "leased_at_unix_secs":1800000000,
          "expires_at_unix_secs":1800000060,
          "value_returned":false
        }"#;
        assert_eq!(
            decode_strict::<ManagedOperationLeaseV1>(previous_create_lease)
                .unwrap()
                .operation_kind,
            "create"
        );
    }

    #[test]
    fn removal_lease_status_and_exact_container_absence_are_closed() {
        let mut lease = ManagedOperationLeaseV1 {
            schema: LEASE_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            lease_ref: "lease_remove000001".to_string(),
            operation_ref: "op_remove00000001".to_string(),
            operation_kind: "remove".to_string(),
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint: "decl_a84f209c4b32".to_string(),
            generation: 1,
            purge_not_before_unix_secs: Some(1_800_086_400),
            phase: AgentPhase::Remove,
            profile_ref: "detach_8a0f4e271c93".to_string(),
            leased_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_000_060,
            value_returned: false,
        };
        validate_lease(&lease, "host_58f36c72a91e").expect("bound removal lease");
        lease.profile_ref = "health_2a02f96c33d4".to_string();
        assert_eq!(
            validate_lease(&lease, "host_58f36c72a91e").unwrap_err(),
            ManagedHostAgentError::new("managed_host_lease_invalid")
        );

        assert!(docker_state_is_stopped(
            br#"{"Running":false,"Status":"exited","Health":null}"#
        ));
        assert!(!docker_state_is_stopped(
            br#"{"Running":true,"Status":"running","Health":null}"#
        ));
        assert!(!docker_state_is_stopped(
            br#"{"Running":false,"Status":"dead","Health":null}"#
        ));

        let raw = br#"{
          "schema":"inspr.pharos.managed-service-operation-status.v1",
          "schema_version":1,
          "operation":{
            "operation_ref":"op_remove00000001",
            "operation_kind":"remove",
            "host_ref":"host_58f36c72a91e",
            "service_ref":"svc_0bca8d31f7e2",
            "slot_ref":"slot_49c0e8a17d63",
            "declaration_fingerprint":"decl_a84f209c4b32",
            "generation":1,
            "purge_not_before_unix_secs":1800086400,
            "phase":"removed",
            "reason_code":"phase_succeeded",
            "created_at_unix_secs":1800000000,
            "updated_at_unix_secs":1800000010,
            "health":null,
            "rollback":null,
            "removal":{
              "generation":1,
              "outcome":"healthy",
              "heartbeat_observed_at_unix_secs":1800000009,
              "process_observed_at_unix_secs":1800000009,
              "cache_observed_at_unix_secs":1800000009,
              "accepted_at_unix_secs":1800000010
            },
            "value_returned":false
          },
          "value_returned":false
        }"#;
        let mut status: ManagedOperationStatusV1 = decode_strict(raw).unwrap();
        validate_status(&status, "host_58f36c72a91e", "op_remove00000001")
            .expect("exact removal status");
        status.operation.removal.as_mut().unwrap().generation = 2;
        assert_eq!(
            validate_status(&status, "host_58f36c72a91e", "op_remove00000001").unwrap_err(),
            ManagedHostAgentError::new("managed_host_status_invalid")
        );
    }

    #[test]
    fn rolled_back_status_requires_a_bound_healthy_previous_generation() {
        let raw = br#"{
          "schema":"inspr.pharos.managed-service-operation-status.v1",
          "schema_version":1,
          "operation":{
            "operation_ref":"op_58f36c72a91e",
            "operation_kind":"replace",
            "host_ref":"host_58f36c72a91e",
            "service_ref":"svc_0bca8d31f7e2",
            "slot_ref":"slot_49c0e8a17d63",
            "declaration_fingerprint":"decl_a84f209c4b32",
            "generation":2,
            "phase":"rolled_back",
            "reason_code":"verification_failed",
            "created_at_unix_secs":1800000000,
            "updated_at_unix_secs":1800000010,
            "health":null,
            "rollback":{
              "restored_generation":1,
              "outcome":"healthy",
              "heartbeat_observed_at_unix_secs":1800000009,
              "process_observed_at_unix_secs":1800000009,
              "probe_observed_at_unix_secs":1800000009,
              "accepted_at_unix_secs":1800000010
            },
            "value_returned":false
          },
          "value_returned":false
        }"#;
        let mut status: ManagedOperationStatusV1 = decode_strict(raw).unwrap();
        validate_status(&status, "host_58f36c72a91e", "op_58f36c72a91e")
            .expect("healthy previous generation accepted");
        status
            .operation
            .rollback
            .as_mut()
            .unwrap()
            .restored_generation = 2;
        assert_eq!(
            validate_status(&status, "host_58f36c72a91e", "op_58f36c72a91e",)
                .expect_err("current generation cannot be rollback proof"),
            ManagedHostAgentError::new("managed_host_status_invalid")
        );
    }
}

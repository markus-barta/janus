//! Approved-use execution layer.
//!
//! This crate consumes an opaque [`janus_core::UsePermit`] through the broker,
//! re-checks principal,
//! executor, destination, expiry, manifest membership, and required audit, then
//! hands the secret value only to managed-command internals. Public outcomes are
//! value-free.

#![forbid(unsafe_code)]

mod pharos_generation;

pub use pharos_generation::{
    publish_host as publish_pharos_beacon_token_generation_host,
    retire_host as retire_pharos_beacon_token_generation_host,
};

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use janus_core::{
    AuditSink, ConsumerDescriptor, ConsumerKind, ConsumerRef, DelegationGrant,
    DelegationRevocation, Destination, ExecutorRef, JanusError, JanusResult, PrincipalChain,
    ProfileId, SafeLabel, SecretBroker, SecretRef, SecretStore, SecretValue, UsePermit,
};
#[cfg(test)]
use sha2::{Digest, Sha256};

/// Request to consume one approved-use permit.
pub struct ApprovedUseInvocation<'a> {
    /// Opaque permit issued by Warden/broker policy.
    pub permit: &'a UsePermit,
    /// Principal chain attempting execution.
    pub principal: &'a PrincipalChain,
    /// Executor identity for this execution path.
    pub executor: ExecutorRef,
    /// Destination this execution path is allowed to reach.
    pub destination: Destination,
    /// Environment variable used by the reviewed managed command profile.
    pub env_name: SafeLabel,
    /// Time used for permit expiry checks.
    pub now: SystemTime,
}

/// Secret-bearing binding visible only inside the managed execution callback.
pub struct SecretEnvBinding<'a> {
    env_name: SafeLabel,
    value: &'a SecretValue,
}

impl SecretEnvBinding<'_> {
    /// Reviewed environment variable name.
    pub fn env_name(&self) -> &SafeLabel {
        &self.env_name
    }

    /// Borrow the secret bytes for immediate child-process environment setup.
    ///
    /// This is intentionally available only inside the executor callback. The
    /// returned [`ApprovedUseOutcome`] is value-free.
    pub fn expose_value_bytes(&self) -> &[u8] {
        self.value.expose_bytes()
    }
}

/// Value-free result of an approved execution attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedUseOutcome {
    /// Secret used by opaque reference only.
    pub secret_ref: SecretRef,
    /// Reviewed profile bound to the permit.
    pub profile_id: ProfileId,
    /// Executor that successfully consumed the permit.
    pub executor: ExecutorRef,
    /// Destination bound to the execution.
    pub destination: Destination,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Minimal approved-use executor over a Janus broker.
pub struct ApprovedUseExecutor<S, A> {
    broker: SecretBroker<S, A>,
}

/// Reviewable managed-command profile config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandProfileSpec {
    /// Profile id also used by Warden permit requests.
    pub profile_id: ProfileId,
    /// Secret consumed by this profile.
    pub secret_ref: SecretRef,
    /// Executor allowed to run the profile.
    pub executor: ExecutorRef,
    /// Destination owned by the profile.
    pub destination: Destination,
    /// Environment variable that receives the secret inside the child process.
    pub env_name: SafeLabel,
    /// Reviewed executable path. Must be absolute.
    pub binary: PathBuf,
    /// Exact reviewed argv for this execution profile.
    pub allowed_args: Vec<String>,
    /// Reviewed process limits for timeout and model-facing output.
    pub runtime_limits: ManagedCommandRuntimeLimits,
    /// Declared consumer metadata used by rotation evidence.
    pub consumer: ConsumerDescriptor,
}

/// Reviewed process limits for a managed command profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedCommandRuntimeLimits {
    /// Maximum wall-clock runtime before Janus kills the child.
    pub timeout: Duration,
    /// Maximum stdout bytes captured before the stream is suppressed.
    pub max_stdout_bytes: usize,
    /// Maximum stderr bytes captured before the stream is suppressed.
    pub max_stderr_bytes: usize,
}

impl Default for ManagedCommandRuntimeLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        }
    }
}

/// Reviewable service env-file profile config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileProfileSpec {
    /// Profile id also used by Warden permit requests.
    pub profile_id: ProfileId,
    /// Secret consumed by this profile.
    pub secret_ref: SecretRef,
    /// Executor allowed to render this env file.
    pub executor: ExecutorRef,
    /// Destination owned by the profile.
    pub destination: Destination,
    /// Environment variable written to the reviewed file.
    pub env_name: SafeLabel,
    /// Reviewed absolute output path for the env file.
    pub output_path: PathBuf,
    /// Optional reviewed SHA-256 sidecar artifact derived from the same secret.
    pub hash_sidecar: Option<EnvFileHashSidecarSpec>,
    /// Declared service/host consumer metadata used by rotation evidence.
    pub consumer: ConsumerDescriptor,
}

/// Supported value-free hash sidecar formats for service handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvFileHashSidecarFormat {
    /// Pharos immutable `inspr.pharos.beacon-token-generation.v2` contract.
    PharosBeaconTokenGenerationV2,
}

impl EnvFileHashSidecarFormat {
    /// Stable value-free format label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PharosBeaconTokenGenerationV2 => "pharos-beacon-token-generation-v2",
        }
    }
}

/// Optional reviewed hash sidecar for env-file handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileHashSidecarSpec {
    /// Sidecar format.
    pub format: EnvFileHashSidecarFormat,
    /// Subject key inside the sidecar, for example a Pharos host name.
    pub subject: SafeLabel,
    /// Reviewed absolute output path for the sidecar.
    pub output_path: PathBuf,
}

/// Reviewed hash sidecar for env-file handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileHashSidecar {
    format: EnvFileHashSidecarFormat,
    subject: SafeLabel,
    output_path: PathBuf,
}

/// A reviewed service env-file profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileProfile {
    profile_id: ProfileId,
    secret_ref: SecretRef,
    executor: ExecutorRef,
    destination: Destination,
    env_name: SafeLabel,
    output_path: PathBuf,
    hash_sidecar: Option<EnvFileHashSidecar>,
    consumer: ConsumerDescriptor,
}

impl EnvFileProfile {
    /// Build a profile from reviewed typed config.
    pub fn new(spec: EnvFileProfileSpec) -> JanusResult<Self> {
        validate_env_file_name(&spec.env_name)?;
        if !spec.output_path.is_absolute() {
            return Err(JanusError::InvalidManifest {
                detail: "env-file output path must be absolute".to_string(),
            });
        }
        let hash_sidecar = spec
            .hash_sidecar
            .map(|sidecar| {
                if !sidecar.output_path.is_absolute() {
                    return Err(JanusError::InvalidManifest {
                        detail: "env-file hash sidecar output path must be absolute".to_string(),
                    });
                }
                if sidecar.output_path == spec.output_path {
                    return Err(JanusError::InvalidManifest {
                        detail: "env-file hash sidecar output path must differ from env file"
                            .to_string(),
                    });
                }
                if sidecar.format == EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2
                    && !pharos_generation::valid_token_subject(sidecar.subject.as_str())
                {
                    return Err(JanusError::InvalidManifest {
                        detail: "Pharos hash sidecar subject must be a canonical host name"
                            .to_string(),
                    });
                }
                Ok(EnvFileHashSidecar {
                    format: sidecar.format,
                    subject: sidecar.subject,
                    output_path: sidecar.output_path,
                })
            })
            .transpose()?;
        if spec.consumer.kind == ConsumerKind::ManagedCommand {
            return Err(JanusError::InvalidManifest {
                detail: "env-file profile consumer must not be managed_command".to_string(),
            });
        }
        if spec.consumer.secret_ref != spec.secret_ref {
            return Err(JanusError::InvalidManifest {
                detail: "env-file consumer must reference the profile secret".to_string(),
            });
        }
        Ok(Self {
            profile_id: spec.profile_id,
            secret_ref: spec.secret_ref,
            executor: spec.executor,
            destination: spec.destination,
            env_name: spec.env_name,
            output_path: spec.output_path,
            hash_sidecar,
            consumer: spec.consumer,
        })
    }

    /// Profile id bound to this env-file handoff.
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Secret ref bound to this env-file handoff.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Executor bound to this env-file handoff.
    pub fn executor(&self) -> &ExecutorRef {
        &self.executor
    }

    /// Destination bound to this env-file handoff.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Environment variable written to the env file.
    pub fn env_name(&self) -> &SafeLabel {
        &self.env_name
    }

    /// Reviewed output path.
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Optional reviewed hash sidecar.
    pub fn hash_sidecar(&self) -> Option<&EnvFileHashSidecar> {
        self.hash_sidecar.as_ref()
    }

    /// Declared consumer ref for observation/rotation evidence.
    pub fn consumer_ref(&self) -> &ConsumerRef {
        &self.consumer.consumer_ref
    }

    /// Declared consumer metadata used for observation evidence.
    pub fn consumer(&self) -> &ConsumerDescriptor {
        &self.consumer
    }

    /// Validate the reviewed env-file target without reading a secret.
    pub fn preflight_target(&self) -> JanusResult<EnvFilePlan> {
        let plan = self.plan();
        preflight_env_file_target(&plan.output_path, &plan.env_name)?;
        if let Some(sidecar) = &plan.hash_sidecar {
            preflight_hash_sidecar_target(&sidecar.output_path)?;
        }
        Ok(plan)
    }

    fn plan(&self) -> EnvFilePlan {
        EnvFilePlan {
            profile_id: self.profile_id.clone(),
            secret_ref: self.secret_ref.clone(),
            executor: self.executor.clone(),
            destination: self.destination.clone(),
            env_name: self.env_name.clone(),
            output_path: self.output_path.clone(),
            hash_sidecar: self.hash_sidecar.clone().map(EnvFileHashSidecarPlan::from),
            consumer_ref: self.consumer.consumer_ref.clone(),
            value_returned: false,
        }
    }
}

impl EnvFileHashSidecar {
    /// Sidecar format.
    pub fn format(&self) -> EnvFileHashSidecarFormat {
        self.format
    }

    /// Reviewed subject key.
    pub fn subject(&self) -> &SafeLabel {
        &self.subject
    }

    /// Reviewed output path.
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }
}

/// A reviewed managed command profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandProfile {
    profile_id: ProfileId,
    secret_ref: SecretRef,
    executor: ExecutorRef,
    destination: Destination,
    env_name: SafeLabel,
    binary: PathBuf,
    allowed_args: Vec<String>,
    runtime_limits: ManagedCommandRuntimeLimits,
    consumer: ConsumerDescriptor,
}

impl ManagedCommandProfile {
    /// Build a profile from reviewed typed config.
    pub fn new(spec: ManagedCommandProfileSpec) -> JanusResult<Self> {
        if !spec.binary.is_absolute() {
            return Err(JanusError::InvalidManifest {
                detail: "managed command binary must be an absolute path".to_string(),
            });
        }
        for arg in &spec.allowed_args {
            if arg.trim().is_empty() || arg.trim().len() != arg.len() {
                return Err(JanusError::InvalidIdentifier {
                    kind: "managed_command_arg",
                });
            }
        }
        if spec.runtime_limits.timeout.is_zero() {
            return Err(JanusError::InvalidManifest {
                detail: "managed command timeout must be greater than zero".to_string(),
            });
        }
        if spec.runtime_limits.max_stdout_bytes == 0 || spec.runtime_limits.max_stderr_bytes == 0 {
            return Err(JanusError::InvalidManifest {
                detail: "managed command output limits must be greater than zero".to_string(),
            });
        }
        if spec.consumer.kind != ConsumerKind::ManagedCommand {
            return Err(JanusError::InvalidManifest {
                detail: "managed command profile requires a managed-command consumer".to_string(),
            });
        }
        if spec.consumer.secret_ref != spec.secret_ref {
            return Err(JanusError::InvalidManifest {
                detail: "managed command consumer must reference the profile secret".to_string(),
            });
        }
        Ok(Self {
            profile_id: spec.profile_id,
            secret_ref: spec.secret_ref,
            executor: spec.executor,
            destination: spec.destination,
            env_name: spec.env_name,
            binary: spec.binary,
            allowed_args: spec.allowed_args,
            runtime_limits: spec.runtime_limits,
            consumer: spec.consumer,
        })
    }

    /// Profile id bound to this managed command.
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Secret ref bound to this managed command.
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// Executor bound to this managed command.
    pub fn executor(&self) -> &ExecutorRef {
        &self.executor
    }

    /// Destination bound to this managed command.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Environment variable that receives the secret.
    pub fn env_name(&self) -> &SafeLabel {
        &self.env_name
    }

    /// Reviewed executable path.
    pub fn binary(&self) -> &PathBuf {
        &self.binary
    }

    /// Exact reviewed argv for this execution profile.
    pub fn allowed_args(&self) -> &[String] {
        &self.allowed_args
    }

    /// Reviewed process limits for timeout and model-facing output.
    pub fn runtime_limits(&self) -> ManagedCommandRuntimeLimits {
        self.runtime_limits
    }

    /// Declared consumer ref for observation/rotation evidence.
    pub fn consumer_ref(&self) -> &ConsumerRef {
        &self.consumer.consumer_ref
    }

    /// Declared consumer metadata used for observation evidence.
    pub fn consumer(&self) -> &ConsumerDescriptor {
        &self.consumer
    }

    /// Validate the reviewed command and exact argv without reading a secret,
    /// resolving a permit, or spawning the process.
    pub fn preflight_command(&self, requested_args: &[String]) -> JanusResult<ManagedCommandPlan> {
        let mut plan = self.plan_for_args(requested_args)?;
        plan.binary = preflight_managed_command_binary(&plan.binary)?;
        Ok(plan)
    }

    fn plan_for_args(&self, requested_args: &[String]) -> JanusResult<ManagedCommandPlan> {
        if requested_args != self.allowed_args.as_slice() {
            return Err(JanusError::policy_denied(
                "denied_unreviewed_command_args",
                "managed command arguments are not exactly reviewed by the profile",
            ));
        }
        Ok(ManagedCommandPlan {
            profile_id: self.profile_id.clone(),
            secret_ref: self.secret_ref.clone(),
            executor: self.executor.clone(),
            destination: self.destination.clone(),
            env_name: self.env_name.clone(),
            binary: self.binary.clone(),
            args: self.allowed_args.clone(),
            consumer_ref: self.consumer.consumer_ref.clone(),
            runtime_limits: self.runtime_limits,
            value_returned: false,
        })
    }
}

/// Caller request for a reviewed managed command.
pub struct ManagedCommandRequest<'a> {
    /// Reviewed profile.
    pub profile: &'a ManagedCommandProfile,
    /// Opaque permit to consume.
    pub permit: &'a UsePermit,
    /// Principal chain attempting execution.
    pub principal: &'a PrincipalChain,
    /// Caller-supplied argv candidate. Must exactly match the profile.
    pub requested_args: Vec<String>,
    /// Time used for permit expiry checks.
    pub now: SystemTime,
}

/// Caller request for a reviewed env-file handoff.
pub struct EnvFileRequest<'a> {
    /// Reviewed profile.
    pub profile: &'a EnvFileProfile,
    /// Opaque permit to consume.
    pub permit: &'a UsePermit,
    /// Principal chain attempting execution.
    pub principal: &'a PrincipalChain,
    /// Time used for permit expiry checks.
    pub now: SystemTime,
}

/// Value-free execution plan for a managed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandPlan {
    /// Reviewed profile id.
    pub profile_id: ProfileId,
    /// Opaque secret ref.
    pub secret_ref: SecretRef,
    /// Reviewed executor.
    pub executor: ExecutorRef,
    /// Reviewed destination.
    pub destination: Destination,
    /// Reviewed env var name.
    pub env_name: SafeLabel,
    /// Reviewed binary.
    pub binary: PathBuf,
    /// Reviewed argv.
    pub args: Vec<String>,
    /// Declared consumer.
    pub consumer_ref: ConsumerRef,
    /// Reviewed runtime limits.
    pub runtime_limits: ManagedCommandRuntimeLimits,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Value-free execution plan for an env-file handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFilePlan {
    /// Reviewed profile id.
    pub profile_id: ProfileId,
    /// Opaque secret ref.
    pub secret_ref: SecretRef,
    /// Reviewed executor.
    pub executor: ExecutorRef,
    /// Reviewed destination.
    pub destination: Destination,
    /// Reviewed env var name.
    pub env_name: SafeLabel,
    /// Reviewed output path.
    pub output_path: PathBuf,
    /// Optional reviewed hash sidecar plan.
    pub hash_sidecar: Option<EnvFileHashSidecarPlan>,
    /// Declared consumer.
    pub consumer_ref: ConsumerRef,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Value-free hash sidecar execution plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileHashSidecarPlan {
    /// Reviewed sidecar format.
    pub format: EnvFileHashSidecarFormat,
    /// Reviewed subject key.
    pub subject: SafeLabel,
    /// Reviewed output path.
    pub output_path: PathBuf,
    /// Invariant marker.
    pub value_returned: bool,
}

impl From<EnvFileHashSidecar> for EnvFileHashSidecarPlan {
    fn from(sidecar: EnvFileHashSidecar) -> Self {
        Self {
            format: sidecar.format,
            subject: sidecar.subject,
            output_path: sidecar.output_path,
            value_returned: false,
        }
    }
}

/// Secret-bearing execution context available only inside the executor callback.
pub struct ManagedCommandExecution<'a> {
    plan: &'a ManagedCommandPlan,
    binding: SecretEnvBinding<'a>,
}

impl ManagedCommandExecution<'_> {
    /// Value-free command plan.
    pub fn plan(&self) -> &ManagedCommandPlan {
        self.plan
    }

    /// Secret env binding for immediate child-process setup.
    pub fn binding(&self) -> &SecretEnvBinding<'_> {
        &self.binding
    }

    /// Spawn the reviewed absolute binary with the reviewed argv and inject the
    /// secret only as the profile's reviewed environment variable.
    pub fn run_process(&self) -> JanusResult<ManagedCommandOutput> {
        let env_value = secret_env_value(self.binding.value.expose_bytes())?;
        let mut child = ProcessCommand::new(&self.plan.binary)
            .args(&self.plan.args)
            .env_clear()
            .env(self.binding.env_name.as_str(), env_value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| JanusError::StoreUnavailable {
                detail: "managed command failed to start".to_string(),
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| JanusError::StoreUnavailable {
                detail: "managed command stdout capture unavailable".to_string(),
            })?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| JanusError::StoreUnavailable {
                detail: "managed command stderr capture unavailable".to_string(),
            })?;
        let stdout_handle = thread::spawn({
            let limit = self.plan.runtime_limits.max_stdout_bytes;
            move || capture_stream(stdout, limit)
        });
        let stderr_handle = thread::spawn({
            let limit = self.plan.runtime_limits.max_stderr_bytes;
            move || capture_stream(stderr, limit)
        });

        let (status, timed_out) = wait_with_timeout(&mut child, self.plan.runtime_limits.timeout)?;
        let stdout = join_capture(stdout_handle)?;
        let stderr = join_capture(stderr_handle)?;

        Ok(ManagedCommandOutput::from_captured_process(
            status, timed_out, stdout, stderr,
        ))
    }
}

/// Managed command output after Janus redaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandOutput {
    /// Redacted stdout.
    pub stdout: String,
    /// Redacted stderr.
    pub stderr: String,
    /// Child process exit success marker.
    pub exit_success: bool,
    /// Child process exit code where the platform exposes one.
    pub exit_code: Option<i32>,
    /// Stable value-free process outcome reason.
    pub reason_code: &'static str,
    /// Whether Janus killed the child after the reviewed timeout.
    pub timed_out: bool,
    /// Whether stdout exceeded the reviewed capture limit.
    pub stdout_truncated: bool,
    /// Whether stderr exceeded the reviewed capture limit.
    pub stderr_truncated: bool,
    /// Invariant marker.
    pub value_returned: bool,
}

impl ManagedCommandOutput {
    /// Construct output from raw process text. The executor applies known-value
    /// redaction before returning it.
    pub fn from_raw(stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_success: true,
            exit_code: Some(0),
            reason_code: "ok",
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
            value_returned: false,
        }
    }

    fn from_captured_process(
        status: ExitStatus,
        timed_out: bool,
        stdout: CapturedStream,
        stderr: CapturedStream,
    ) -> Self {
        let stdout_truncated = stdout.truncated;
        let stderr_truncated = stderr.truncated;
        let exit_success = status.success() && !timed_out;
        let reason_code = if timed_out {
            "managed_command_timeout"
        } else if !status.success() {
            "managed_command_exit_nonzero"
        } else if stdout_truncated || stderr_truncated {
            "managed_command_output_truncated"
        } else {
            "ok"
        };
        Self {
            stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
            exit_success,
            exit_code: status.code(),
            reason_code,
            timed_out,
            stdout_truncated,
            stderr_truncated,
            value_returned: false,
        }
    }

    fn redact_known_value(mut self, value: &SecretValue) -> Self {
        if let Ok(secret) = std::str::from_utf8(value.expose_bytes()) {
            if !secret.is_empty() {
                self.stdout = self.stdout.replace(secret, "[REDACTED]");
                self.stderr = self.stderr.replace(secret, "[REDACTED]");
            }
        }
        if self.stdout_truncated {
            self.stdout = "[TRUNCATED]".to_string();
        }
        if self.stderr_truncated {
            self.stderr = "[TRUNCATED]".to_string();
        }
        self.value_returned = false;
        self
    }
}

struct CapturedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

fn capture_stream(mut reader: impl Read, limit: usize) -> JanusResult<CapturedStream> {
    let mut bytes = Vec::with_capacity(limit);
    let mut scratch = [0_u8; 4096];
    let mut truncated = false;

    loop {
        let read = reader
            .read(&mut scratch)
            .map_err(|_| JanusError::StoreUnavailable {
                detail: "managed command output capture failed".to_string(),
            })?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let to_store = remaining.min(read);
        if to_store > 0 {
            bytes.extend_from_slice(&scratch[..to_store]);
        }
        if to_store < read {
            truncated = true;
        }
    }

    Ok(CapturedStream { bytes, truncated })
}

fn join_capture(
    handle: thread::JoinHandle<JanusResult<CapturedStream>>,
) -> JanusResult<CapturedStream> {
    handle.join().map_err(|_| JanusError::StoreUnavailable {
        detail: "managed command output capture failed".to_string(),
    })?
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> JanusResult<(ExitStatus, bool)> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| JanusError::StoreUnavailable {
            detail: "managed command wait failed".to_string(),
        })? {
            return Ok((status, false));
        }

        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let status = child.wait().map_err(|_| JanusError::StoreUnavailable {
                detail: "managed command kill wait failed".to_string(),
            })?;
            return Ok((status, true));
        }

        thread::sleep((deadline - now).min(Duration::from_millis(10)));
    }
}

#[cfg(unix)]
fn secret_env_value(value: &[u8]) -> JanusResult<OsString> {
    use std::os::unix::ffi::OsStringExt;

    Ok(OsString::from_vec(value.to_vec()))
}

#[cfg(not(unix))]
fn secret_env_value(value: &[u8]) -> JanusResult<OsString> {
    String::from_utf8(value.to_vec())
        .map(OsString::from)
        .map_err(|_| JanusError::Unsupported {
            capability: "non_utf8_managed_command_env",
        })
}

/// Value-free managed command execution outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCommandOutcome {
    /// Value-free reviewed plan.
    pub plan: ManagedCommandPlan,
    /// Redacted command output.
    pub output: ManagedCommandOutput,
    /// Invariant marker.
    pub value_returned: bool,
}

/// Value-free env-file handoff outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileOutcome {
    /// Value-free reviewed plan.
    pub plan: EnvFilePlan,
    /// Stable value-free outcome reason.
    pub reason_code: &'static str,
    /// Invariant marker.
    pub value_returned: bool,
}

impl<S, A> ApprovedUseExecutor<S, A>
where
    S: SecretStore,
    A: AuditSink,
{
    /// Construct from the policy/audit broker.
    pub fn new(broker: SecretBroker<S, A>) -> Self {
        Self { broker }
    }

    /// Consume a permit and run secret-bearing internals without returning a
    /// literal to the caller.
    pub async fn execute_with_secret<F>(
        &mut self,
        invocation: ApprovedUseInvocation<'_>,
        execute: F,
    ) -> JanusResult<ApprovedUseOutcome>
    where
        F: FnOnce(SecretEnvBinding<'_>) -> JanusResult<()>,
    {
        self.execute_with_secret_and_delegation(invocation, None, execute)
            .await
    }

    /// Consume a permit with exact current delegation evidence when acting as
    /// a grantor, without exposing a literal to the caller.
    pub async fn execute_with_secret_and_delegation<F>(
        &mut self,
        invocation: ApprovedUseInvocation<'_>,
        delegation: Option<(&DelegationGrant, Option<&DelegationRevocation>)>,
        execute: F,
    ) -> JanusResult<ApprovedUseOutcome>
    where
        F: FnOnce(SecretEnvBinding<'_>) -> JanusResult<()>,
    {
        let value = self
            .broker
            .use_permit_with_delegation(
                invocation.permit,
                invocation.principal,
                &invocation.executor,
                &invocation.destination,
                invocation.now,
                delegation,
            )
            .await?;
        let outcome = ApprovedUseOutcome {
            secret_ref: invocation.permit.secret_ref().clone(),
            profile_id: invocation.permit.profile_id().clone(),
            executor: invocation.executor,
            destination: invocation.destination,
            value_returned: false,
        };
        execute(SecretEnvBinding {
            env_name: invocation.env_name,
            value: &value,
        })?;
        Ok(outcome)
    }

    /// Execute a reviewed managed-command profile with a caller-supplied
    /// secret-bearing callback. This is the shared policy boundary used by the
    /// real process runner and narrow connector adapters.
    pub async fn execute_managed_command<F>(
        &mut self,
        request: ManagedCommandRequest<'_>,
        execute: F,
    ) -> JanusResult<ManagedCommandOutcome>
    where
        F: FnOnce(ManagedCommandExecution<'_>) -> JanusResult<ManagedCommandOutput>,
    {
        self.execute_managed_command_with_delegation(request, None, execute)
            .await
    }

    /// Execute a reviewed managed command using exact current delegation
    /// evidence for a delegated permit.
    pub async fn execute_managed_command_with_delegation<F>(
        &mut self,
        request: ManagedCommandRequest<'_>,
        delegation: Option<(&DelegationGrant, Option<&DelegationRevocation>)>,
        execute: F,
    ) -> JanusResult<ManagedCommandOutcome>
    where
        F: FnOnce(ManagedCommandExecution<'_>) -> JanusResult<ManagedCommandOutput>,
    {
        if request.permit.profile_id() != request.profile.profile_id() {
            return Err(JanusError::permit_invalid(
                "denied_profile_mismatch",
                "permit profile does not match managed command profile",
            ));
        }
        if request.permit.secret_ref() != request.profile.secret_ref() {
            return Err(JanusError::permit_invalid(
                "denied_secret_mismatch",
                "permit secret does not match managed command profile",
            ));
        }
        let plan = request.profile.preflight_command(&request.requested_args)?;
        let value = self
            .broker
            .use_permit_with_delegation(
                request.permit,
                request.principal,
                request.profile.executor(),
                request.profile.destination(),
                request.now,
                delegation,
            )
            .await?;
        let output = execute(ManagedCommandExecution {
            plan: &plan,
            binding: SecretEnvBinding {
                env_name: request.profile.env_name().clone(),
                value: &value,
            },
        })?
        .redact_known_value(&value);
        self.broker
            .record_consumer_observe(request.profile.consumer(), request.principal)?;
        Ok(ManagedCommandOutcome {
            plan,
            output,
            value_returned: false,
        })
    }

    /// Execute a reviewed managed-command profile by spawning its reviewed
    /// absolute binary and exact argv, injecting the secret as the reviewed env
    /// binding, and returning only redacted output.
    pub async fn run_managed_command(
        &mut self,
        request: ManagedCommandRequest<'_>,
    ) -> JanusResult<ManagedCommandOutcome> {
        self.run_managed_command_with_delegation(request, None)
            .await
    }

    /// Spawn a reviewed managed command with exact current delegation
    /// evidence for a delegated permit.
    pub async fn run_managed_command_with_delegation(
        &mut self,
        request: ManagedCommandRequest<'_>,
        delegation: Option<(&DelegationGrant, Option<&DelegationRevocation>)>,
    ) -> JanusResult<ManagedCommandOutcome> {
        self.execute_managed_command_with_delegation(request, delegation, |execution| {
            execution.run_process()
        })
        .await
    }

    /// Render a reviewed service env file from a permit-bound secret.
    ///
    /// The caller cannot choose the env var name or output path; both come from
    /// the reviewed profile. The literal is written only to the private file
    /// and is never included in the returned outcome.
    pub async fn render_env_file(
        &mut self,
        request: EnvFileRequest<'_>,
    ) -> JanusResult<EnvFileOutcome> {
        self.render_env_file_with_delegation(request, None).await
    }

    /// Render a reviewed private env file with exact current delegation
    /// evidence for a delegated permit.
    pub async fn render_env_file_with_delegation(
        &mut self,
        request: EnvFileRequest<'_>,
        delegation: Option<(&DelegationGrant, Option<&DelegationRevocation>)>,
    ) -> JanusResult<EnvFileOutcome> {
        if request.permit.profile_id() != request.profile.profile_id() {
            return Err(JanusError::permit_invalid(
                "denied_profile_mismatch",
                "permit profile does not match env-file profile",
            ));
        }
        if request.permit.secret_ref() != request.profile.secret_ref() {
            return Err(JanusError::permit_invalid(
                "denied_secret_mismatch",
                "permit secret does not match env-file profile",
            ));
        }
        let plan = request.profile.plan();
        preflight_env_file_target(&plan.output_path, &plan.env_name)?;
        if let Some(sidecar) = request.profile.hash_sidecar() {
            preflight_hash_sidecar_target(sidecar.output_path())?;
        }
        let value = self
            .broker
            .use_permit_with_delegation(
                request.permit,
                request.principal,
                request.profile.executor(),
                request.profile.destination(),
                request.now,
                delegation,
            )
            .await?;
        write_env_file_atomic(&plan.output_path, &plan.env_name, &value)?;
        if let Some(sidecar) = request.profile.hash_sidecar() {
            write_hash_sidecar_atomic(sidecar, &value)?;
        }
        self.broker
            .record_consumer_observe(request.profile.consumer(), request.principal)?;
        Ok(EnvFileOutcome {
            plan,
            reason_code: "ok",
            value_returned: false,
        })
    }

    /// Consume and return the underlying broker for inspection or embedding.
    pub fn into_broker(self) -> SecretBroker<S, A> {
        self.broker
    }
}

fn validate_env_file_name(name: &SafeLabel) -> JanusResult<()> {
    let value = name.as_str();
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(JanusError::InvalidIdentifier { kind: "env_name" });
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(JanusError::InvalidIdentifier { kind: "env_name" });
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err(JanusError::InvalidIdentifier { kind: "env_name" });
    }
    Ok(())
}

fn write_env_file_atomic(
    path: &Path,
    env_name: &SafeLabel,
    value: &SecretValue,
) -> JanusResult<()> {
    preflight_env_file_target(path, env_name)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .expect("preflight validates parent");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("preflight validates file name");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut created_temp = false;
    let result = (|| -> JanusResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|_| JanusError::StoreUnavailable {
                detail: "failed to create temporary env file".to_string(),
            })?;
        created_temp = true;
        write_env_assignment(&mut file, env_name, value)?;
        file.flush().map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to flush temporary env file".to_string(),
        })?;
        file.sync_all().map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to sync temporary env file".to_string(),
        })?;
        fs::rename(&temp_path, path).map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to replace env file atomically".to_string(),
        })?;
        created_temp = false;
        Ok(())
    })();
    if result.is_err() && created_temp {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_hash_sidecar_atomic(sidecar: &EnvFileHashSidecar, value: &SecretValue) -> JanusResult<()> {
    let path = sidecar.output_path();
    preflight_hash_sidecar_target(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .expect("preflight validates parent");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("preflight validates file name");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut created_temp = false;
    let result = (|| -> JanusResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|_| JanusError::StoreUnavailable {
                detail: "failed to create temporary hash sidecar".to_string(),
            })?;
        created_temp = true;
        let token_sha256 = write_hash_sidecar(&mut file, sidecar, value)?;
        file.flush().map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to flush temporary hash sidecar".to_string(),
        })?;
        file.sync_all().map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to sync temporary hash sidecar".to_string(),
        })?;
        fs::rename(&temp_path, path).map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to replace hash sidecar atomically".to_string(),
        })?;
        created_temp = false;
        pharos_generation::publish_entry(parent, sidecar.subject(), &token_sha256)?;
        Ok(())
    })();
    if created_temp {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn preflight_env_file_target(path: &Path, env_name: &SafeLabel) -> JanusResult<()> {
    validate_env_file_name(env_name)?;
    preflight_private_output_path(path, "env-file output")
}

fn preflight_managed_command_binary(path: &Path) -> JanusResult<PathBuf> {
    let resolved = fs::canonicalize(path).map_err(|_| JanusError::InvalidManifest {
        detail: "managed command binary is unavailable".to_string(),
    })?;
    let metadata = fs::metadata(&resolved).map_err(|_| JanusError::InvalidManifest {
        detail: "managed command binary is unavailable".to_string(),
    })?;
    if !metadata.is_file() {
        return Err(JanusError::InvalidManifest {
            detail: "managed command binary must resolve to a regular file".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(JanusError::InvalidManifest {
                detail: "managed command binary must be executable".to_string(),
            });
        }
        if mode & 0o022 != 0 {
            return Err(JanusError::InvalidManifest {
                detail: "managed command binary must not be group or world writable".to_string(),
            });
        }
    }
    Ok(resolved)
}

fn preflight_hash_sidecar_target(path: &Path) -> JanusResult<()> {
    preflight_private_output_path(path, "env-file hash sidecar output")
}

fn preflight_private_output_path(path: &Path, label: &'static str) -> JanusResult<()> {
    if !path.is_absolute() {
        return Err(JanusError::InvalidManifest {
            detail: format!("{label} path must be absolute"),
        });
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let Some(parent) = parent else {
        return Err(JanusError::InvalidManifest {
            detail: format!("{label} path must have a parent directory"),
        });
    };
    ensure_private_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JanusError::StoreUnavailable {
                detail: format!("{label} path is not a regular file"),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(JanusError::StoreUnavailable {
                    detail: format!("{label} path must be private"),
                });
            }
        }
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| JanusError::InvalidManifest {
            detail: format!("{label} path must include a file name"),
        })?;
    if file_name.contains('/') || file_name.is_empty() {
        return Err(JanusError::InvalidManifest {
            detail: format!("{label} path must include a safe file name"),
        });
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| JanusError::StoreUnavailable {
        detail: "env-file parent directory unavailable".to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JanusError::StoreUnavailable {
            detail: "env-file parent path is not a directory".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JanusError::StoreUnavailable {
                detail: "env-file parent directory must be private".to_string(),
            });
        }
    }
    Ok(())
}

fn write_env_assignment(
    mut writer: impl Write,
    env_name: &SafeLabel,
    value: &SecretValue,
) -> JanusResult<()> {
    let value = std::str::from_utf8(value.expose_bytes()).map_err(|_| JanusError::Unsupported {
        capability: "non_utf8_env_file_secret",
    })?;
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(JanusError::Unsupported {
            capability: "multiline_env_file_secret",
        });
    }
    writer
        .write_all(env_name.as_str().as_bytes())
        .and_then(|_| writer.write_all(b"="))
        .and_then(|_| writer.write_all(value.as_bytes()))
        .and_then(|_| writer.write_all(b"\n"))
        .map_err(|_| JanusError::StoreUnavailable {
            detail: "failed to write env file".to_string(),
        })
}

fn write_hash_sidecar(
    mut writer: impl Write,
    sidecar: &EnvFileHashSidecar,
    value: &SecretValue,
) -> JanusResult<String> {
    match sidecar.format() {
        EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2 => {
            pharos_generation::write_entry(&mut writer, sidecar.subject(), value.expose_bytes())
        }
    }
}

#[cfg(test)]
fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex(&digest)
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    #[cfg(unix)]
    use std::{fs, process};

    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, BlastRadius, ConsumerDescriptor, ConsumerKind,
        ConsumerRef, DelegationPolicy, EgressMode, Environment, JanusError, ManifestCatalog,
        OwnerRef, Principal, PrincipalId, PrincipalKind, ProfilePolicy, Purpose, ReloadMethod,
        SafeLabel, ScopePathV1, ScopeRef, SecretClass, SecretLifecycle, SecretMeta, SecretName,
        TrustLevel, UseProfile, UseRequest, ValidationProbe,
    };
    use janus_mock::MockStore;

    use super::*;

    const START: SystemTime = SystemTime::UNIX_EPOCH;

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    fn run_at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1)
    }

    fn principal(executor: &str, scope_label: &str) -> PrincipalChain {
        let environment = scope_label.rsplit('/').next().unwrap_or("dev");
        let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", environment)
            .unwrap()
            .scope_ref();
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            scope,
        )
    }

    async fn executor_fixture() -> (
        ApprovedUseExecutor<MockStore, AuditWrite>,
        janus_core::UsePermit,
        PrincipalChain,
        ExecutorRef,
        Destination,
        ManagedCommandProfile,
    ) {
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: scope(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![profile_id.clone()],
        }])
        .unwrap();
        let store = MockStore::new(catalog)
            .with_value(name, b"expected-canary".to_vec())
            .unwrap();
        let executor = ExecutorRef::new("janus-run@m5").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let managed_profile = managed_command_profile(
            profile_id.clone(),
            secret_ref.clone(),
            executor.clone(),
            destination.clone(),
        );
        let profile = UseProfile {
            id: profile_id.clone(),
            scope: scope(),
            secret_ref: secret_ref.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            egress: EgressMode::Connector,
            trust_level: TrustLevel::L2,
            ttl: Duration::from_secs(60),
            single_use: true,
            enabled: true,
        };
        let principal = principal("janus-run@m5", "janus/dev");
        let mut broker = SecretBroker::new(
            store,
            ProfilePolicy::new(vec![profile]),
            AuditWrite::accepting(),
        );
        let permit = broker
            .request_use(
                &UseRequest {
                    scope: scope(),
                    secret_ref,
                    profile_id,
                    destination: destination.clone(),
                    purpose: Purpose::new("deploy canary").unwrap(),
                },
                &principal,
                START,
            )
            .await
            .unwrap();
        (
            ApprovedUseExecutor::new(broker),
            permit,
            principal,
            executor,
            destination,
            managed_profile,
        )
    }

    fn managed_command_profile(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
    ) -> ManagedCommandProfile {
        managed_command_profile_with_command(
            profile_id,
            secret_ref,
            executor,
            destination,
            std::env::current_exe().expect("test binary path is available"),
            vec!["release".to_string(), "upload".to_string()],
        )
    }

    fn managed_command_profile_with_command(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
        binary: PathBuf,
        allowed_args: Vec<String>,
    ) -> ManagedCommandProfile {
        managed_command_profile_with_command_and_limits(
            profile_id,
            secret_ref,
            executor,
            destination,
            binary,
            allowed_args,
            ManagedCommandRuntimeLimits::default(),
        )
    }

    fn managed_command_profile_with_command_and_limits(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
        binary: PathBuf,
        allowed_args: Vec<String>,
        runtime_limits: ManagedCommandRuntimeLimits,
    ) -> ManagedCommandProfile {
        ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id,
            secret_ref: secret_ref.clone(),
            executor,
            destination,
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary,
            allowed_args,
            runtime_limits,
            consumer: ConsumerDescriptor {
                scope: scope(),
                consumer_ref: ConsumerRef::new("consumer.github_release_publish").unwrap(),
                secret_ref,
                kind: ConsumerKind::ManagedCommand,
                owner: OwnerRef::new("infra").unwrap(),
                environment: Environment::new("prod").unwrap(),
                reload: ReloadMethod::None,
                validation: vec![ValidationProbe::new("gh-auth-status").unwrap()],
                supports_dual_value: false,
                blast_radius: BlastRadius::new("release-publishing").unwrap(),
                declared: true,
            },
        })
        .unwrap()
    }

    #[cfg(unix)]
    fn env_file_profile(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
        output_path: PathBuf,
    ) -> EnvFileProfile {
        EnvFileProfile::new(EnvFileProfileSpec {
            profile_id,
            secret_ref: secret_ref.clone(),
            executor,
            destination,
            env_name: SafeLabel::new("SERVICE_TOKEN").unwrap(),
            output_path,
            hash_sidecar: None,
            consumer: ConsumerDescriptor {
                scope: scope(),
                consumer_ref: ConsumerRef::new("consumer.fixture_service").unwrap(),
                secret_ref,
                kind: ConsumerKind::Service,
                owner: OwnerRef::new("infra").unwrap(),
                environment: Environment::new("prod").unwrap(),
                reload: ReloadMethod::Manual,
                validation: vec![ValidationProbe::new("service-health").unwrap()],
                supports_dual_value: false,
                blast_radius: BlastRadius::new("fixture-service").unwrap(),
                declared: true,
            },
        })
        .unwrap()
    }

    fn env_file_profile_with_hash_sidecar(
        profile_id: ProfileId,
        secret_ref: SecretRef,
        executor: ExecutorRef,
        destination: Destination,
        output_path: PathBuf,
        hash_output_path: PathBuf,
    ) -> EnvFileProfile {
        EnvFileProfile::new(EnvFileProfileSpec {
            profile_id,
            secret_ref: secret_ref.clone(),
            executor,
            destination,
            env_name: SafeLabel::new("SERVICE_TOKEN").unwrap(),
            output_path,
            hash_sidecar: Some(EnvFileHashSidecarSpec {
                format: EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2,
                subject: SafeLabel::new("ares").unwrap(),
                output_path: hash_output_path,
            }),
            consumer: ConsumerDescriptor {
                scope: scope(),
                consumer_ref: ConsumerRef::new("consumer.fixture_service").unwrap(),
                secret_ref,
                kind: ConsumerKind::Service,
                owner: janus_core::OwnerRef::new("janusd-test").unwrap(),
                environment: janus_core::Environment::new("test").unwrap(),
                reload: janus_core::ReloadMethod::None,
                validation: vec![],
                supports_dual_value: false,
                blast_radius: janus_core::BlastRadius::new("fixture-service").unwrap(),
                declared: true,
            },
        })
        .unwrap()
    }

    #[cfg(unix)]
    fn marker_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "janus-executor-{test_name}-{}-{nanos}",
            process::id()
        ))
    }

    fn invocation<'a>(
        permit: &'a UsePermit,
        principal: &'a PrincipalChain,
        executor: ExecutorRef,
        destination: Destination,
    ) -> ApprovedUseInvocation<'a> {
        ApprovedUseInvocation {
            permit,
            principal,
            executor,
            destination,
            env_name: SafeLabel::new("CANARY_TOKEN").unwrap(),
            now: run_at(),
        }
    }

    #[tokio::test]
    async fn approved_execution_consumes_permit_without_returning_literal() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let mut callback_saw_value = false;

        let outcome = executor
            .execute_with_secret(
                invocation(&permit, &principal, executor_ref, destination),
                |binding| {
                    assert_eq!(binding.env_name().as_str(), "CANARY_TOKEN");
                    assert_eq!(binding.expose_value_bytes(), b"expected-canary");
                    callback_saw_value = true;
                    Ok(())
                },
            )
            .await
            .unwrap();

        assert!(callback_saw_value);
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));
    }

    #[tokio::test]
    async fn revocation_after_delegated_permit_issue_blocks_secret_exposure() {
        let (executor, _plain_permit, mut grantor, executor_ref, destination, profile) =
            executor_fixture().await;
        grantor.human = Some(Principal::new(
            PrincipalKind::Human,
            PrincipalId::new("human-grantor").unwrap(),
        ));
        let mut delegate = principal("janus-run@m5", "janus/dev");
        delegate.agent = Some(Principal::new(
            PrincipalKind::AgentSession,
            PrincipalId::new("session:delegate,model:codex").unwrap(),
        ));
        let (store, policy, mut audit) = executor.into_broker().into_parts();
        let descriptor = store
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|descriptor| descriptor.secret_ref == *profile.secret_ref())
            .unwrap();
        let request = UseRequest {
            scope: scope(),
            secret_ref: profile.secret_ref().clone(),
            profile_id: profile.profile_id().clone(),
            destination: destination.clone(),
            purpose: Purpose::new("deploy canary").unwrap(),
        };
        let grant = DelegationPolicy::issue_use(
            &policy,
            &descriptor,
            &request,
            &grantor,
            &delegate,
            None,
            START,
            START + Duration::from_secs(30),
            SafeLabel::new("coverage").unwrap(),
            &mut audit,
        )
        .unwrap();
        let mut broker = SecretBroker::new(store, policy, audit);
        let permit = broker
            .request_use_with_delegation(&request, &delegate, START, &grant, None)
            .await
            .unwrap();
        let (_store, _policy, mut audit) = broker.into_parts();
        let revocation = DelegationPolicy::authorize_revocation(
            &grant,
            &delegate,
            START + Duration::from_millis(500),
            SafeLabel::new("coverage ended").unwrap(),
            &mut audit,
        )
        .unwrap();
        let mut executor = ApprovedUseExecutor::new(SecretBroker::new(_store, _policy, audit));
        let mut callback_called = false;
        let error = executor
            .execute_with_secret_and_delegation(
                invocation(&permit, &delegate, executor_ref, destination),
                Some((&grant, Some(&revocation))),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert!(!callback_called);
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "delegation_revoked",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "delegation_revoked"
                && event.delegation.is_some()
        }));
    }

    #[tokio::test]
    async fn wrong_destination_fails_before_secret_exposure() {
        let (mut executor, permit, principal, executor_ref, _destination, _profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(
                    &permit,
                    &principal,
                    executor_ref,
                    Destination::new("attacker-api").unwrap(),
                ),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_unapproved_destination",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_unapproved_destination"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn wrong_executor_fails_before_secret_exposure() {
        let (mut executor, permit, principal, _executor_ref, destination, _profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(
                    &permit,
                    &principal,
                    ExecutorRef::new("janus-run@other-host").unwrap(),
                    destination,
                ),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_wrong_executor",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_wrong_executor"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn wrong_principal_fails_before_secret_exposure() {
        let (mut executor, permit, _principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let wrong_principal = principal("janus-run@m5", "janus/prod");
        let mut callback_called = false;

        let err = executor
            .execute_with_secret(
                invocation(&permit, &wrong_principal, executor_ref, destination),
                |_binding| {
                    callback_called = true;
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PermitInvalid {
                reason_code: "denied_scope_mismatch",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_scope_mismatch"
                && !event.value_returned
        }));
    }

    #[tokio::test]
    async fn managed_command_profile_builds_reviewed_plan_and_redacts_output() {
        let (mut executor, permit, principal, _executor_ref, _destination, profile) =
            executor_fixture().await;
        let mut callback_saw_value = false;

        let outcome = executor
            .execute_managed_command(
                ManagedCommandRequest {
                    profile: &profile,
                    permit: &permit,
                    principal: &principal,
                    requested_args: vec!["release".to_string(), "upload".to_string()],
                    now: run_at(),
                },
                |execution| {
                    assert_eq!(&execution.plan().binary, profile.binary());
                    assert_eq!(
                        execution.plan().args,
                        vec!["release".to_string(), "upload".to_string()]
                    );
                    assert_eq!(&execution.plan().consumer_ref, profile.consumer_ref());
                    assert_eq!(execution.binding().env_name().as_str(), "GITHUB_TOKEN");
                    assert_eq!(execution.binding().expose_value_bytes(), b"expected-canary");
                    callback_saw_value = true;
                    Ok(ManagedCommandOutput::from_raw(
                        "uploaded with expected-canary",
                        "debug expected-canary",
                    ))
                },
            )
            .await
            .unwrap();

        assert!(callback_saw_value);
        assert!(!outcome.value_returned);
        assert!(!outcome.plan.value_returned);
        assert_eq!(outcome.output.stdout, "uploaded with [REDACTED]");
        assert_eq!(outcome.output.stderr, "debug [REDACTED]");
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::ConsumerObserve
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && event.secret_ref.as_ref() == Some(profile.secret_ref())
                && event
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.as_str() == profile.consumer_ref().as_str())
                && !event.value_returned
                && event
                    .event_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64)
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_runner_spawns_reviewed_process_and_redacts_output() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "printf 'stdout:%s' \"$GITHUB_TOKEN\"; printf 'stderr:%s' \"$GITHUB_TOKEN\" >&2"
                    .to_string(),
            ],
        );

        let outcome = executor
            .run_managed_command(ManagedCommandRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                requested_args: profile.allowed_args().to_vec(),
                now: run_at(),
            })
            .await
            .unwrap();

        assert!(!outcome.value_returned);
        assert!(!outcome.plan.value_returned);
        assert_eq!(outcome.plan.binary, fs::canonicalize("/bin/sh").unwrap());
        assert_eq!(outcome.output.stdout, "stdout:[REDACTED]");
        assert_eq!(outcome.output.stderr, "stderr:[REDACTED]");
        assert!(outcome.output.exit_success);
        assert_eq!(outcome.output.exit_code, Some(0));
        assert_eq!(outcome.output.reason_code, "ok");
        assert!(!outcome.output.timed_out);
        assert!(!outcome.output.stdout_truncated);
        assert!(!outcome.output.stderr_truncated);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::ConsumerObserve
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && event.secret_ref.as_ref() == Some(profile.secret_ref())
                && event
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.as_str() == profile.consumer_ref().as_str())
                && !event.value_returned
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_runner_maps_nonzero_exit_without_leaking_output() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "printf 'bad:%s' \"$GITHUB_TOKEN\"; printf 'err:%s' \"$GITHUB_TOKEN\" >&2; exit 7"
                    .to_string(),
            ],
        );

        let outcome = executor
            .run_managed_command(ManagedCommandRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                requested_args: profile.allowed_args().to_vec(),
                now: run_at(),
            })
            .await
            .unwrap();

        assert!(!outcome.output.exit_success);
        assert_eq!(outcome.output.exit_code, Some(7));
        assert_eq!(outcome.output.reason_code, "managed_command_exit_nonzero");
        assert!(!outcome.output.timed_out);
        assert_eq!(outcome.output.stdout, "bad:[REDACTED]");
        assert_eq!(outcome.output.stderr, "err:[REDACTED]");
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_runner_caps_output_without_partial_secret_leaks() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let profile = managed_command_profile_with_command_and_limits(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "printf 'stdout:%s:tail' \"$GITHUB_TOKEN\"; printf 'stderr:%s:tail' \"$GITHUB_TOKEN\" >&2"
                    .to_string(),
            ],
            ManagedCommandRuntimeLimits {
                timeout: Duration::from_secs(5),
                max_stdout_bytes: 8,
                max_stderr_bytes: 8,
            },
        );

        let outcome = executor
            .run_managed_command(ManagedCommandRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                requested_args: profile.allowed_args().to_vec(),
                now: run_at(),
            })
            .await
            .unwrap();

        assert!(!outcome.output.timed_out);
        assert!(outcome.output.exit_success);
        assert_eq!(
            outcome.output.reason_code,
            "managed_command_output_truncated"
        );
        assert!(outcome.output.stdout_truncated);
        assert!(outcome.output.stderr_truncated);
        assert_eq!(outcome.output.stdout, "[TRUNCATED]");
        assert_eq!(outcome.output.stderr, "[TRUNCATED]");
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_runner_times_out_reviewed_process() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let profile = managed_command_profile_with_command_and_limits(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            PathBuf::from("/bin/sh"),
            vec!["-c".to_string(), "while :; do :; done".to_string()],
            ManagedCommandRuntimeLimits {
                timeout: Duration::from_millis(20),
                max_stdout_bytes: 1024,
                max_stderr_bytes: 1024,
            },
        );

        let outcome = executor
            .run_managed_command(ManagedCommandRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                requested_args: profile.allowed_args().to_vec(),
                now: run_at(),
            })
            .await
            .unwrap();

        assert!(!outcome.output.exit_success);
        assert!(outcome.output.timed_out);
        assert_eq!(outcome.output.reason_code, "managed_command_timeout");
        assert_eq!(outcome.output.stdout, "");
        assert_eq!(outcome.output.stderr, "");
        assert!(!format!("{outcome:?}").contains("expected-canary"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_preflight_validates_exact_executable_without_secret_use() {
        use std::os::unix::fs::PermissionsExt;

        let (_executor, permit, _principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let binary = marker_path("managed-command-preflight-ok");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).unwrap();
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            binary.clone(),
            vec!["deploy".to_string(), "hsb0".to_string()],
        );

        let plan = profile.preflight_command(profile.allowed_args()).unwrap();

        assert_eq!(plan.binary, fs::canonicalize(&binary).unwrap());
        assert_eq!(plan.args, ["deploy", "hsb0"]);
        assert_eq!(plan.secret_ref, permit.secret_ref().clone());
        assert!(!plan.value_returned);
        assert!(!format!("{plan:?}").contains("expected-canary"));

        fs::set_permissions(&binary, fs::Permissions::from_mode(0o520)).unwrap();
        let err = profile
            .preflight_command(profile.allowed_args())
            .unwrap_err();
        assert!(matches!(err, JanusError::InvalidManifest { .. }));
        assert!(err
            .to_string()
            .contains("must not be group or world writable"));

        let _ = fs::remove_file(binary);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_preflight_resolves_symlink_and_rejects_unreviewed_args() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_executor, permit, _principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let target = marker_path("managed-command-preflight-target");
        let binary = marker_path("managed-command-preflight-link");
        fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).unwrap();
        symlink(&target, &binary).unwrap();
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            binary.clone(),
            vec!["deploy".to_string(), "hsb0".to_string()],
        );

        let plan = profile.preflight_command(profile.allowed_args()).unwrap();
        assert_eq!(plan.binary, fs::canonicalize(&target).unwrap());

        let err = profile
            .preflight_command(&["deploy".to_string(), "csb0".to_string()])
            .unwrap_err();
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_unreviewed_command_args",
                ..
            }
        ));

        let _ = fs::remove_file(binary);
        let _ = fs::remove_file(target);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_execution_rejects_tampered_binary_before_secret_use() {
        use std::os::unix::fs::PermissionsExt;

        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let binary = marker_path("managed-command-execution-tampered");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o520)).unwrap();
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            binary.clone(),
            vec!["deploy".to_string(), "hsb0".to_string()],
        );
        let mut callback_called = false;

        let err = executor
            .execute_managed_command(
                ManagedCommandRequest {
                    profile: &profile,
                    permit: &permit,
                    principal: &principal,
                    requested_args: profile.allowed_args().to_vec(),
                    now: run_at(),
                },
                |_execution| {
                    callback_called = true;
                    Ok(ManagedCommandOutput::from_raw("", ""))
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(err
            .to_string()
            .contains("must not be group or world writable"));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(!audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse && event.outcome == AuditOutcome::Allowed
        }));

        let _ = fs::remove_file(binary);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_command_runner_rejects_unreviewed_args_before_spawn() {
        let (mut executor, permit, principal, executor_ref, destination, _profile) =
            executor_fixture().await;
        let marker = marker_path("unreviewed-args");
        let profile = managed_command_profile_with_command(
            permit.profile_id().clone(),
            permit.secret_ref().clone(),
            executor_ref,
            destination,
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "printf spawned > \"$1\"".to_string(),
                "janus-fixture".to_string(),
                marker.to_string_lossy().into_owned(),
            ],
        );
        let mut requested_args = profile.allowed_args().to_vec();
        requested_args.push("--attacker-controlled".to_string());

        let err = executor
            .run_managed_command(ManagedCommandRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                requested_args,
                now: run_at(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_unreviewed_command_args",
                ..
            }
        ));
        assert!(!marker.exists());
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse));
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::ConsumerObserve));
        let _ = fs::remove_file(marker);
    }

    #[tokio::test]
    async fn managed_command_rejects_unreviewed_args_before_secret_exposure() {
        let (mut executor, permit, principal, _executor_ref, _destination, profile) =
            executor_fixture().await;
        let mut callback_called = false;

        let err = executor
            .execute_managed_command(
                ManagedCommandRequest {
                    profile: &profile,
                    permit: &permit,
                    principal: &principal,
                    requested_args: vec![
                        "release".to_string(),
                        "upload".to_string(),
                        "--repo".to_string(),
                        "attacker/repo".to_string(),
                    ],
                    now: run_at(),
                },
                |_execution| {
                    callback_called = true;
                    Ok(ManagedCommandOutput::from_raw("expected-canary", ""))
                },
            )
            .await
            .unwrap_err();

        assert!(!callback_called);
        assert!(matches!(
            err,
            JanusError::PolicyDenied {
                reason_code: "denied_unreviewed_command_args",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse));
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::ConsumerObserve));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_handoff_writes_private_file_without_returning_literal() {
        use std::os::unix::fs::PermissionsExt;

        let (mut executor, permit, principal, executor_ref, destination, managed_profile) =
            executor_fixture().await;
        let dir = marker_path("env-file-ok");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let output_path = dir.join("service.env");
        let profile = env_file_profile(
            managed_profile.profile_id().clone(),
            managed_profile.secret_ref().clone(),
            executor_ref,
            destination,
            output_path.clone(),
        );

        let outcome = executor
            .render_env_file(EnvFileRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                now: run_at(),
            })
            .await
            .unwrap();

        assert_eq!(
            fs::read_to_string(&output_path).unwrap(),
            "SERVICE_TOKEN=expected-canary\n"
        );
        assert_eq!(
            fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(outcome.plan.output_path, output_path);
        assert_eq!(outcome.reason_code, "ok");
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && !event.value_returned
        }));
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::ConsumerObserve
                && event.outcome == AuditOutcome::Allowed
                && event.reason_code == "ok"
                && event.secret_ref.as_ref() == Some(profile.secret_ref())
                && event
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.as_str() == profile.consumer_ref().as_str())
                && !event.value_returned
        }));
        assert!(!format!("{:?}", audit.events()).contains("expected-canary"));

        let _ = fs::remove_file(output_path);
        let _ = fs::remove_dir(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_handoff_writes_private_hash_sidecar_without_returning_literal() {
        use std::os::unix::fs::PermissionsExt;

        let (mut executor, permit, principal, executor_ref, destination, managed_profile) =
            executor_fixture().await;
        let dir = marker_path("env-file-hash-sidecar-ok");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let output_path = dir.join("service.env");
        let hash_output_path = dir.join("service-token-hash.json");
        let profile = env_file_profile_with_hash_sidecar(
            managed_profile.profile_id().clone(),
            managed_profile.secret_ref().clone(),
            executor_ref,
            destination,
            output_path.clone(),
            hash_output_path.clone(),
        );

        let outcome = executor
            .render_env_file(EnvFileRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                now: run_at(),
            })
            .await
            .unwrap();

        let sidecar = fs::read_to_string(&hash_output_path).unwrap();
        assert!(sidecar.contains("\"schema\":\"inspr.pharos.beacon-token-entry.v2\""));
        assert!(sidecar.contains("\"name\":\"ares\""));
        assert!(sidecar.contains(&sha256_hex(b"expected-canary")));
        assert!(!sidecar.contains("expected-canary"));
        let generation = fs::read_to_string(dir.join("current"))
            .expect("generation pointer exists")
            .trim()
            .to_string();
        let generation_payload =
            fs::read_to_string(dir.join(format!("generation-{generation}.json")))
                .expect("immutable generation exists");
        assert!(
            generation_payload.contains("\"schema\":\"inspr.pharos.beacon-token-generation.v2\"")
        );
        assert!(!generation_payload.contains("expected-canary"));
        assert_eq!(
            fs::metadata(&hash_output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            outcome
                .plan
                .hash_sidecar
                .as_ref()
                .map(|sidecar| sidecar.output_path.as_path()),
            Some(hash_output_path.as_path())
        );
        assert!(!outcome.value_returned);
        assert!(!format!("{outcome:?}").contains("expected-canary"));

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_preflight_checks_private_target_without_secret_use() {
        use std::os::unix::fs::PermissionsExt;

        let (_executor, _permit, _principal, executor_ref, destination, managed_profile) =
            executor_fixture().await;
        let dir = marker_path("env-file-preflight-ok");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let output_path = dir.join("service.env");
        let profile = env_file_profile(
            managed_profile.profile_id().clone(),
            managed_profile.secret_ref().clone(),
            executor_ref,
            destination,
            output_path.clone(),
        );

        let plan = profile.preflight_target().unwrap();

        assert_eq!(plan.output_path, output_path);
        assert_eq!(plan.secret_ref, managed_profile.secret_ref().clone());
        assert_eq!(plan.consumer_ref, profile.consumer_ref().clone());
        assert!(!plan.value_returned);
        assert!(!plan.output_path.exists());
        assert!(!format!("{plan:?}").contains("expected-canary"));

        let _ = fs::remove_dir(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_file_handoff_rejects_insecure_parent_before_secret_use() {
        use std::os::unix::fs::PermissionsExt;

        let (mut executor, permit, principal, executor_ref, destination, managed_profile) =
            executor_fixture().await;
        let dir = marker_path("env-file-insecure-parent");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let output_path = dir.join("service.env");
        let profile = env_file_profile(
            managed_profile.profile_id().clone(),
            managed_profile.secret_ref().clone(),
            executor_ref,
            destination,
            output_path.clone(),
        );

        let err = executor
            .render_env_file(EnvFileRequest {
                profile: &profile,
                permit: &permit,
                principal: &principal,
                now: run_at(),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, JanusError::StoreUnavailable { .. }));
        assert!(!output_path.exists());
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(!audit
            .events()
            .iter()
            .any(|event| event.action == AuditAction::SecretUse));

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir(dir);
    }

    #[test]
    fn managed_command_profile_requires_absolute_binary_and_matching_consumer() {
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let executor = ExecutorRef::new("janus-run@m5").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let wrong_consumer_secret = SecretRef::new("sec_other").unwrap();
        let consumer = ConsumerDescriptor {
            scope: scope(),
            consumer_ref: ConsumerRef::new("consumer.github_release_publish").unwrap(),
            secret_ref: secret_ref.clone(),
            kind: ConsumerKind::ManagedCommand,
            owner: OwnerRef::new("infra").unwrap(),
            environment: Environment::new("prod").unwrap(),
            reload: ReloadMethod::None,
            validation: vec![ValidationProbe::new("gh-auth-status").unwrap()],
            supports_dual_value: false,
            blast_radius: BlastRadius::new("release-publishing").unwrap(),
            declared: true,
        };

        let relative_binary = ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id: profile_id.clone(),
            secret_ref: secret_ref.clone(),
            executor: executor.clone(),
            destination: destination.clone(),
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            runtime_limits: ManagedCommandRuntimeLimits::default(),
            consumer: consumer.clone(),
        });
        assert!(matches!(
            relative_binary,
            Err(JanusError::InvalidManifest { .. })
        ));

        let wrong_consumer = ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id,
            secret_ref: secret_ref.clone(),
            executor,
            destination,
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("/usr/bin/gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            runtime_limits: ManagedCommandRuntimeLimits::default(),
            consumer: ConsumerDescriptor {
                secret_ref: wrong_consumer_secret,
                ..consumer.clone()
            },
        });
        assert!(matches!(
            wrong_consumer,
            Err(JanusError::InvalidManifest { .. })
        ));

        let zero_timeout = ManagedCommandProfile::new(ManagedCommandProfileSpec {
            profile_id: ProfileId::new("profile.canary").unwrap(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("janus-run@m5").unwrap(),
            destination: Destination::new("deploy-api").unwrap(),
            env_name: SafeLabel::new("GITHUB_TOKEN").unwrap(),
            binary: PathBuf::from("/usr/bin/gh"),
            allowed_args: vec!["release".to_string(), "upload".to_string()],
            runtime_limits: ManagedCommandRuntimeLimits {
                timeout: Duration::ZERO,
                max_stdout_bytes: 1024,
                max_stderr_bytes: 1024,
            },
            consumer,
        });
        assert!(matches!(
            zero_timeout,
            Err(JanusError::InvalidManifest { .. })
        ));
    }
}

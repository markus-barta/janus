//! Approved-use execution skeleton.
//!
//! This crate is the first JANUS-28 execution-layer shape: it consumes an
//! opaque [`janus_core::UsePermit`] through the broker, re-checks principal,
//! executor, destination, expiry, manifest membership, and required audit, then
//! hands the secret value only to managed-command internals. Public outcomes are
//! value-free.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use janus_core::{
    AuditSink, ConsumerDescriptor, ConsumerKind, ConsumerRef, Destination, ExecutorRef, JanusError,
    JanusResult, PrincipalChain, ProfileId, SafeLabel, SecretBroker, SecretRef, SecretStore,
    SecretValue, UsePermit,
};

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
    /// Exact reviewed argv for this first skeleton.
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

    /// Exact reviewed argv for this first skeleton.
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
        let value = self
            .broker
            .use_permit(
                invocation.permit,
                invocation.principal,
                &invocation.executor,
                &invocation.destination,
                invocation.now,
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
        let plan = request.profile.plan_for_args(&request.requested_args)?;
        let value = self
            .broker
            .use_permit(
                request.permit,
                request.principal,
                request.profile.executor(),
                request.profile.destination(),
                request.now,
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
        self.execute_managed_command(request, |execution| execution.run_process())
            .await
    }

    /// Consume and return the underlying broker for inspection or embedding.
    pub fn into_broker(self) -> SecretBroker<S, A> {
        self.broker
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    #[cfg(unix)]
    use std::{fs, process};

    use janus_core::{
        AuditAction, AuditOutcome, AuditWrite, BlastRadius, ConsumerDescriptor, ConsumerKind,
        ConsumerRef, EgressMode, Environment, JanusError, ManifestCatalog, OwnerRef, Principal,
        PrincipalId, PrincipalKind, ProfilePolicy, ProjectId, Purpose, ReloadMethod, SafeLabel,
        ScopeRef, SecretMeta, SecretName, TrustLevel, UseProfile, UseRequest, ValidationProbe,
    };
    use janus_mock::MockStore;

    use super::*;

    const START: SystemTime = SystemTime::UNIX_EPOCH;

    fn run_at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1)
    }

    fn principal(executor: &str, scope: &str) -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(PrincipalKind::Executor, PrincipalId::new(executor).unwrap()),
            ScopeRef::new(scope).unwrap(),
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
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let catalog = ManifestCatalog::new(vec![SecretMeta {
            secret_ref: secret_ref.clone(),
            name: name.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/dev").unwrap(),
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
            PathBuf::from("/usr/bin/gh"),
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
                reason_code: "denied_wrong_principal",
                ..
            }
        ));
        let (_store, _policy, audit) = executor.into_broker().into_parts();
        assert!(audit.events().iter().any(|event| {
            event.action == AuditAction::SecretUse
                && event.outcome == AuditOutcome::Denied
                && event.reason_code == "denied_wrong_principal"
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
                    assert_eq!(execution.plan().binary, PathBuf::from("/usr/bin/gh"));
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
        assert_eq!(outcome.plan.binary, PathBuf::from("/bin/sh"));
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

    #[test]
    fn managed_command_profile_requires_absolute_binary_and_matching_consumer() {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("CANARY").unwrap();
        let secret_ref = SecretRef::for_manifest_entry(&project, &name);
        let profile_id = ProfileId::new("profile.canary").unwrap();
        let executor = ExecutorRef::new("janus-run@m5").unwrap();
        let destination = Destination::new("deploy-api").unwrap();
        let wrong_consumer_secret = SecretRef::new("sec_other").unwrap();
        let consumer = ConsumerDescriptor {
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

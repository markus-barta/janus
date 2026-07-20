use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use janus_core::SecretLifecycle;
use janus_executor::{EnvFileHashSidecarFormat, EnvFileProfile};
use serde::{Deserialize, Serialize};

const INTENT_SCHEMA: &str = "inspr.pharos.janus-retirements.v1";
const STATE_SCHEMA: &str = "inspr.janus.pharos-beacon-retirement.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PharosRetirementRequest {
    pub(crate) host: String,
    pub(crate) disposition: String,
    pub(crate) successor: Option<String>,
    pub(crate) intent_file: PathBuf,
    pub(crate) metadata_file: PathBuf,
    pub(crate) profile_manifest: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) retain_for_days: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PharosRetirementBinding {
    host: String,
    disposition: String,
    successor: Option<String>,
    profile_id: String,
    secret_ref: String,
    output: OutputRetirement,
}

impl PharosRetirementBinding {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn secret_ref(&self) -> &str {
        &self.secret_ref
    }

    pub(crate) fn expected_secret_name(&self) -> String {
        format!("PHAROS_BEACON_{}_TOKEN", self.host.to_ascii_uppercase())
    }

    pub(crate) fn outputs(&self) -> &OutputRetirement {
        &self.output
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PharosRetirementPhase {
    Requested,
    Disabled,
    OutputsRemoved,
    PendingDelete,
    TombstoneRecorded,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PharosRetirementRecord {
    schema: String,
    version: u8,
    host: String,
    disposition: String,
    successor: Option<String>,
    profile_id: String,
    secret_ref: String,
    phase: PharosRetirementPhase,
    value_returned: bool,
    provider_deleted: bool,
}

impl PharosRetirementRecord {
    fn from_binding(binding: &PharosRetirementBinding, phase: PharosRetirementPhase) -> Self {
        Self {
            schema: STATE_SCHEMA.to_string(),
            version: 1,
            host: binding.host.clone(),
            disposition: binding.disposition.clone(),
            successor: binding.successor.clone(),
            profile_id: binding.profile_id.clone(),
            secret_ref: binding.secret_ref.clone(),
            phase,
            value_returned: false,
            provider_deleted: false,
        }
    }

    pub(crate) fn phase(&self) -> PharosRetirementPhase {
        self.phase
    }

    fn validate(&self, binding: &PharosRetirementBinding) -> PharosRetirementResult<()> {
        if self.schema != STATE_SCHEMA
            || self.version != 1
            || self.value_returned
            || self.provider_deleted
        {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_state_invalid",
            ));
        }
        if self.host != binding.host
            || self.disposition != binding.disposition
            || self.successor != binding.successor
            || self.profile_id != binding.profile_id
            || self.secret_ref != binding.secret_ref
        {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_request_mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilePharosRetirementRegistry {
    root: PathBuf,
}

impl FilePharosRetirementRegistry {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(crate) fn load(
        &self,
        binding: &PharosRetirementBinding,
    ) -> PharosRetirementResult<Option<PharosRetirementRecord>> {
        self.ensure_root()?;
        let path = self.path_for(binding.host())?;
        let file = match OpenOptions::new().read(true).open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_state_unavailable",
                ))
            }
        };
        check_private_regular_file(&path)?;
        let record: PharosRetirementRecord = serde_json::from_reader(BufReader::new(file))
            .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_state_invalid"))?;
        record.validate(binding)?;
        Ok(Some(record))
    }

    pub(crate) fn store(
        &self,
        binding: &PharosRetirementBinding,
        phase: PharosRetirementPhase,
    ) -> PharosRetirementResult<PharosRetirementRecord> {
        self.ensure_root()?;
        let path = self.path_for(binding.host())?;
        if let Some(existing) = self.load(binding)? {
            if phase_rank(phase) < phase_rank(existing.phase) {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_state_regression",
                ));
            }
        }
        let record = PharosRetirementRecord::from_binding(binding, phase);
        write_record_atomic(&path, &record)?;
        Ok(record)
    }

    fn ensure_root(&self) -> PharosRetirementResult<()> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_state_unavailable",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.root).map_err(|_| {
                    PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
                })?;
            }
            Err(_) => {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_state_unavailable",
                ));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).map_err(|_| {
                PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
            })?;
        }
        let metadata = fs::symlink_metadata(&self.root).map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_state_unavailable",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_state_not_private",
                ));
            }
        }
        Ok(())
    }

    fn path_for(&self, host: &str) -> PharosRetirementResult<PathBuf> {
        if !valid_host(host) {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_host_invalid",
            ));
        }
        Ok(self.root.join(format!("{host}.json")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutputRetirement {
    env_file: PathBuf,
    env_staged: PathBuf,
    hash_file: PathBuf,
    hash_staged: PathBuf,
}

impl OutputRetirement {
    pub(crate) fn inspect(&self) -> PharosRetirementResult<OutputPosture> {
        let env = inspect_output_path(&self.env_file, &self.env_staged)?;
        let hash = inspect_output_path(&self.hash_file, &self.hash_staged)?;
        Ok(OutputPosture { env, hash })
    }

    pub(crate) fn stage(&self) -> PharosRetirementResult<()> {
        let env_moved = stage_one(&self.env_file, &self.env_staged)?;
        if let Err(error) = stage_one(&self.hash_file, &self.hash_staged) {
            if env_moved {
                let _ = fs::rename(&self.env_staged, &self.env_file);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn purge_staged(&self) -> PharosRetirementResult<()> {
        purge_one(&self.env_staged)?;
        purge_one(&self.hash_staged)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputPathPosture {
    Present,
    Absent,
    Staged,
    Drift,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputPosture {
    env: OutputPathPosture,
    hash: OutputPathPosture,
}

impl OutputPosture {
    pub(crate) fn has_original(self) -> bool {
        matches!(
            self.env,
            OutputPathPosture::Present | OutputPathPosture::Drift
        ) || matches!(
            self.hash,
            OutputPathPosture::Present | OutputPathPosture::Drift
        )
    }

    pub(crate) fn has_staged(self) -> bool {
        matches!(
            self.env,
            OutputPathPosture::Staged | OutputPathPosture::Drift
        ) || matches!(
            self.hash,
            OutputPathPosture::Staged | OutputPathPosture::Drift
        )
    }

    pub(crate) fn is_drift(self) -> bool {
        matches!(self.env, OutputPathPosture::Drift)
            || matches!(self.hash, OutputPathPosture::Drift)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PharosReconcileState {
    Complete,
    NeedsFinalize,
    Drift,
    ActionRequired,
}

impl PharosReconcileState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::NeedsFinalize => "needs_finalize",
            Self::Drift => "drift",
            Self::ActionRequired => "action_required",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PharosReconcileOutcome {
    pub(crate) host: String,
    pub(crate) state: PharosReconcileState,
    pub(crate) reason_code: &'static str,
    pub(crate) value_returned: bool,
    pub(crate) provider_deleted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PharosCredentialEvidence {
    pub(crate) lifecycle: SecretLifecycle,
    pub(crate) tombstone_present: bool,
}

#[async_trait]
pub(crate) trait PharosRetirementLifecycle {
    async fn evidence(
        &mut self,
        binding: &PharosRetirementBinding,
    ) -> PharosRetirementResult<PharosCredentialEvidence>;

    async fn transition(
        &mut self,
        binding: &PharosRetirementBinding,
        to: SecretLifecycle,
    ) -> PharosRetirementResult<()>;

    async fn record_tombstone(
        &mut self,
        binding: &PharosRetirementBinding,
        retain_for_days: u64,
    ) -> PharosRetirementResult<()>;

    async fn finalize(&mut self, binding: &PharosRetirementBinding) -> PharosRetirementResult<()>;
}

pub(crate) async fn execute_retirement<B>(
    request: &PharosRetirementRequest,
    binding: &PharosRetirementBinding,
    registry: &FilePharosRetirementRegistry,
    backend: &mut B,
    stop_after_phase: Option<PharosRetirementPhase>,
) -> PharosRetirementResult<PharosReconcileOutcome>
where
    B: PharosRetirementLifecycle + Send,
{
    let mut record = registry.load(binding)?;
    if record.is_none() {
        record = Some(registry.store(binding, PharosRetirementPhase::Requested)?);
        stop_after(stop_after_phase, PharosRetirementPhase::Requested)?;
    }

    for _ in 0..8 {
        let evidence = backend.evidence(binding).await?;
        validate_phase_lifecycle(record.as_ref(), evidence.lifecycle)?;
        let outputs = binding.outputs().inspect()?;
        match evidence.lifecycle {
            SecretLifecycle::Active => {
                if evidence.tombstone_present || outputs.has_staged() || outputs.is_drift() {
                    return Err(PharosRetirementFailure::new(
                        "pharos_beacon_retirement_active_state_drift",
                    ));
                }
                backend
                    .transition(binding, SecretLifecycle::Disabled)
                    .await?;
                record = Some(registry.store(binding, PharosRetirementPhase::Disabled)?);
                stop_after(stop_after_phase, PharosRetirementPhase::Disabled)?;
            }
            SecretLifecycle::Disabled => {
                if evidence.tombstone_present || outputs.is_drift() {
                    return Err(PharosRetirementFailure::new(
                        "pharos_beacon_retirement_disabled_state_drift",
                    ));
                }
                binding.outputs().stage()?;
                registry.store(binding, PharosRetirementPhase::OutputsRemoved)?;
                stop_after(stop_after_phase, PharosRetirementPhase::OutputsRemoved)?;
                backend
                    .transition(binding, SecretLifecycle::PendingDelete)
                    .await?;
                record = Some(registry.store(binding, PharosRetirementPhase::PendingDelete)?);
                stop_after(stop_after_phase, PharosRetirementPhase::PendingDelete)?;
                binding.outputs().purge_staged()?;
            }
            SecretLifecycle::PendingDelete => {
                if outputs.has_original() || outputs.is_drift() {
                    return Err(PharosRetirementFailure::new(
                        "pharos_beacon_retirement_pending_output_present",
                    ));
                }
                binding.outputs().purge_staged()?;
                if !evidence.tombstone_present {
                    backend
                        .record_tombstone(binding, request.retain_for_days)
                        .await?;
                }
                record = Some(registry.store(binding, PharosRetirementPhase::TombstoneRecorded)?);
                stop_after(stop_after_phase, PharosRetirementPhase::TombstoneRecorded)?;
                backend.finalize(binding).await?;
            }
            SecretLifecycle::Destroyed => {
                if !evidence.tombstone_present {
                    return Err(PharosRetirementFailure::new(
                        "pharos_beacon_retirement_tombstone_missing",
                    ));
                }
                if outputs.has_original() || outputs.is_drift() {
                    return Err(PharosRetirementFailure::new(
                        "pharos_beacon_retirement_destroyed_output_present",
                    ));
                }
                binding.outputs().purge_staged()?;
                let record = registry.store(binding, PharosRetirementPhase::Complete)?;
                stop_after(stop_after_phase, PharosRetirementPhase::Complete)?;
                return Ok(reconcile(
                    binding,
                    evidence.lifecycle,
                    evidence.tombstone_present,
                    Some(&record),
                    binding.outputs().inspect()?,
                ));
            }
            SecretLifecycle::Draft | SecretLifecycle::Rotating | SecretLifecycle::Deprecated => {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_lifecycle_not_ready",
                ));
            }
        }
    }

    Err(PharosRetirementFailure::new(
        "pharos_beacon_retirement_did_not_converge",
    ))
}

fn validate_phase_lifecycle(
    record: Option<&PharosRetirementRecord>,
    lifecycle: SecretLifecycle,
) -> PharosRetirementResult<()> {
    let Some(record) = record else {
        return Ok(());
    };
    let consistent = match record.phase() {
        PharosRetirementPhase::Requested => true,
        PharosRetirementPhase::Disabled | PharosRetirementPhase::OutputsRemoved => matches!(
            lifecycle,
            SecretLifecycle::Disabled | SecretLifecycle::PendingDelete | SecretLifecycle::Destroyed
        ),
        PharosRetirementPhase::PendingDelete | PharosRetirementPhase::TombstoneRecorded => {
            matches!(
                lifecycle,
                SecretLifecycle::PendingDelete | SecretLifecycle::Destroyed
            )
        }
        PharosRetirementPhase::Complete => lifecycle == SecretLifecycle::Destroyed,
    };
    if !consistent {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_state_lifecycle_drift",
        ));
    }
    Ok(())
}

fn stop_after(
    configured: Option<PharosRetirementPhase>,
    current: PharosRetirementPhase,
) -> PharosRetirementResult<()> {
    if configured == Some(current) {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_interrupted",
        ));
    }
    Ok(())
}

pub(crate) fn reconcile(
    binding: &PharosRetirementBinding,
    lifecycle: SecretLifecycle,
    tombstone_present: bool,
    record: Option<&PharosRetirementRecord>,
    outputs: OutputPosture,
) -> PharosReconcileOutcome {
    let (state, reason_code) = if outputs.is_drift() {
        (
            PharosReconcileState::Drift,
            "pharos_beacon_retirement_output_drift",
        )
    } else if lifecycle == SecretLifecycle::PendingDelete && outputs.has_original() {
        (
            PharosReconcileState::Drift,
            "pharos_beacon_retirement_pending_output_present",
        )
    } else if lifecycle == SecretLifecycle::Destroyed && outputs.has_original() {
        (
            PharosReconcileState::Drift,
            "pharos_beacon_retirement_destroyed_output_present",
        )
    } else {
        match (lifecycle, tombstone_present) {
            (SecretLifecycle::Active, false) => (
                PharosReconcileState::ActionRequired,
                "pharos_beacon_retirement_ready",
            ),
            (SecretLifecycle::Disabled, false) => (
                PharosReconcileState::ActionRequired,
                "pharos_beacon_retirement_disabled",
            ),
            (SecretLifecycle::PendingDelete, false) => (
                PharosReconcileState::ActionRequired,
                "pharos_beacon_retirement_tombstone_required",
            ),
            (SecretLifecycle::PendingDelete, true) => (
                PharosReconcileState::NeedsFinalize,
                "pharos_beacon_retirement_needs_finalize",
            ),
            (SecretLifecycle::Destroyed, true)
                if !outputs.has_original()
                    && !outputs.has_staged()
                    && record.is_some_and(|record| {
                        record.phase() == PharosRetirementPhase::Complete
                    }) =>
            {
                (
                    PharosReconcileState::Complete,
                    "pharos_beacon_retirement_complete",
                )
            }
            (SecretLifecycle::Destroyed, true) => (
                PharosReconcileState::ActionRequired,
                "pharos_beacon_retirement_record_reconcile_required",
            ),
            (SecretLifecycle::Destroyed, false) => (
                PharosReconcileState::Drift,
                "pharos_beacon_retirement_tombstone_missing",
            ),
            (_, true) => (
                PharosReconcileState::Drift,
                "pharos_beacon_retirement_lifecycle_mismatch",
            ),
            _ => (
                PharosReconcileState::ActionRequired,
                "pharos_beacon_retirement_lifecycle_not_ready",
            ),
        }
    };
    PharosReconcileOutcome {
        host: binding.host.clone(),
        state,
        reason_code,
        value_returned: false,
        provider_deleted: false,
    }
}

pub(crate) fn prepare_binding(
    request: &PharosRetirementRequest,
    profile: &EnvFileProfile,
) -> PharosRetirementResult<PharosRetirementBinding> {
    validate_request(request)?;
    validate_intent(request)?;

    let expected_profile_id = format!(
        "profile.PHAROS_BEACON_{}_TOKEN",
        request.host.to_ascii_uppercase()
    );
    let expected_destination = format!("pharos-beacon-{}", request.host);
    let expected_consumer = format!("consumer.pharos_beacon_{}", request.host);
    if profile.profile_id().as_str() != expected_profile_id
        || profile.destination().as_str() != expected_destination
        || profile.env_name().as_str() != "PHAROS_TOKEN"
        || profile.consumer_ref().as_str() != expected_consumer
    {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_profile_mismatch",
        ));
    }
    let sidecar = profile
        .hash_sidecar()
        .ok_or_else(|| PharosRetirementFailure::new("pharos_beacon_retirement_profile_mismatch"))?;
    if sidecar.format() != EnvFileHashSidecarFormat::PharosBeaconTokenHashesV1
        || sidecar.subject().as_str() != request.host
    {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_profile_mismatch",
        ));
    }
    validate_output_binding(profile.output_path(), &request.host, "env", "beacons")?;
    validate_output_binding(
        sidecar.output_path(),
        &request.host,
        "json",
        "beacon-token-hashes",
    )?;

    let env_staged = staged_path(profile.output_path())?;
    let hash_staged = staged_path(sidecar.output_path())?;
    Ok(PharosRetirementBinding {
        host: request.host.clone(),
        disposition: request.disposition.clone(),
        successor: request.successor.clone(),
        profile_id: profile.profile_id().as_str().to_string(),
        secret_ref: profile.secret_ref().as_str().to_string(),
        output: OutputRetirement {
            env_file: profile.output_path().to_path_buf(),
            env_staged,
            hash_file: sidecar.output_path().to_path_buf(),
            hash_staged,
        },
    })
}

pub(crate) fn expected_profile_id(
    request: &PharosRetirementRequest,
) -> PharosRetirementResult<String> {
    validate_request(request)?;
    Ok(format!(
        "profile.PHAROS_BEACON_{}_TOKEN",
        request.host.to_ascii_uppercase()
    ))
}

fn validate_request(request: &PharosRetirementRequest) -> PharosRetirementResult<()> {
    if !valid_host(&request.host) {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_host_invalid",
        ));
    }
    match request.disposition.as_str() {
        "rebuilt" => {
            let successor = request.successor.as_deref().ok_or_else(|| {
                PharosRetirementFailure::new("pharos_beacon_retirement_successor_invalid")
            })?;
            if !valid_host(successor) || successor == request.host {
                return Err(PharosRetirementFailure::new(
                    "pharos_beacon_retirement_successor_invalid",
                ));
            }
        }
        "destroyed" | "unmanaged" if request.successor.is_none() => {}
        "destroyed" | "unmanaged" => {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_successor_unexpected",
            ))
        }
        _ => {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_disposition_invalid",
            ))
        }
    }
    if request.retain_for_days == 0 {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_retention_invalid",
        ));
    }
    Ok(())
}

fn validate_intent(request: &PharosRetirementRequest) -> PharosRetirementResult<()> {
    let metadata = fs::symlink_metadata(&request.intent_file)
        .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_intent_unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_intent_unsafe",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(&request.intent_file)
        .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_intent_unavailable"))?;
    let intent: RetirementIntent = serde_json::from_reader(BufReader::new(file))
        .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_intent_invalid"))?;
    if intent.schema != INTENT_SCHEMA || intent.version != 1 {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_intent_invalid",
        ));
    }
    let matches = intent
        .retirements
        .iter()
        .filter(|entry| entry.host == request.host)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_consumer_active",
        ));
    }
    if matches.len() != 1 {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_intent_invalid",
        ));
    }
    let entry = matches[0];
    if entry.disposition != request.disposition
        || entry.successor != request.successor
        || !entry.credential_retirement_required
        || entry.server_deletion
    {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_request_mismatch",
        ));
    }
    Ok(())
}

fn validate_output_binding(
    path: &Path,
    host: &str,
    extension: &str,
    parent_name: &str,
) -> PharosRetirementResult<()> {
    let expected = format!("{host}.{extension}");
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some(expected.as_str())
        || path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(parent_name)
    {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_profile_mismatch",
        ));
    }
    Ok(())
}

fn staged_path(path: &Path) -> PharosRetirementResult<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| PharosRetirementFailure::new("pharos_beacon_retirement_profile_mismatch"))?;
    Ok(path.with_file_name(format!(".{file_name}.janus-retired")))
}

fn inspect_output_path(
    original: &Path,
    staged: &Path,
) -> PharosRetirementResult<OutputPathPosture> {
    let original_present = inspect_regular_file(original)?;
    let staged_present = inspect_regular_file(staged)?;
    Ok(match (original_present, staged_present) {
        (true, false) => OutputPathPosture::Present,
        (false, false) => OutputPathPosture::Absent,
        (false, true) => OutputPathPosture::Staged,
        (true, true) => OutputPathPosture::Drift,
    })
}

fn inspect_regular_file(path: &Path) -> PharosRetirementResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            PharosRetirementFailure::new("pharos_beacon_retirement_output_unsafe"),
        ),
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_output_unavailable",
        )),
    }
}

fn stage_one(original: &Path, staged: &Path) -> PharosRetirementResult<bool> {
    match inspect_output_path(original, staged)? {
        OutputPathPosture::Present => {
            fs::rename(original, staged).map_err(|_| {
                PharosRetirementFailure::new("pharos_beacon_retirement_output_stage_failed")
            })?;
            Ok(true)
        }
        OutputPathPosture::Absent | OutputPathPosture::Staged => Ok(false),
        OutputPathPosture::Drift => Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_output_drift",
        )),
    }
}

fn purge_one(path: &Path) -> PharosRetirementResult<()> {
    if !inspect_regular_file(path)? {
        return Ok(());
    }
    fs::remove_file(path)
        .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_output_purge_failed"))
}

fn write_record_atomic(path: &Path, record: &PharosRetirementRecord) -> PharosRetirementResult<()> {
    let parent = path.parent().ok_or_else(|| {
        PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| -> PharosRetirementResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temp_path).map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, record).map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        writer.write_all(b"\n").map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        writer.flush().map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        writer.get_ref().sync_all().map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        fs::rename(&temp_path, path).map_err(|_| {
            PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| {
                PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable")
            })?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn check_private_regular_file(path: &Path) -> PharosRetirementResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| PharosRetirementFailure::new("pharos_beacon_retirement_state_unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PharosRetirementFailure::new(
            "pharos_beacon_retirement_state_unavailable",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PharosRetirementFailure::new(
                "pharos_beacon_retirement_state_not_private",
            ));
        }
    }
    Ok(())
}

fn phase_rank(phase: PharosRetirementPhase) -> u8 {
    match phase {
        PharosRetirementPhase::Requested => 0,
        PharosRetirementPhase::Disabled => 1,
        PharosRetirementPhase::OutputsRemoved => 2,
        PharosRetirementPhase::PendingDelete => 3,
        PharosRetirementPhase::TombstoneRecorded => 4,
        PharosRetirementPhase::Complete => 5,
    }
}

fn valid_host(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementIntent {
    schema: String,
    version: u8,
    retirements: Vec<RetirementIntentEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementIntentEntry {
    host: String,
    disposition: String,
    successor: Option<String>,
    credential_retirement_required: bool,
    server_deletion: bool,
}

pub(crate) type PharosRetirementResult<T> = Result<T, PharosRetirementFailure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PharosRetirementFailure {
    reason_code: &'static str,
}

impl PharosRetirementFailure {
    pub(crate) const fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub(crate) fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for PharosRetirementFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl Error for PharosRetirementFailure {}

#[cfg(test)]
mod tests {
    use std::fs;

    use async_trait::async_trait;
    use janus_core::{
        BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRef, Destination, Environment,
        ExecutorRef, OwnerRef, ProfileId, ReloadMethod, SafeLabel, ScopePathV1, ScopeRef,
        SecretLifecycle, SecretRef,
    };
    use janus_executor::{EnvFileHashSidecarSpec, EnvFileProfileSpec};
    use tempfile::TempDir;

    use super::*;

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }

    struct Fixture {
        _temp: TempDir,
        request: PharosRetirementRequest,
        profile: EnvFileProfile,
        binding: PharosRetirementBinding,
        registry: FilePharosRetirementRegistry,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let beacons = temp.path().join("beacons");
            let hashes = temp.path().join("beacon-token-hashes");
            fs::create_dir_all(&beacons).unwrap();
            fs::create_dir_all(&hashes).unwrap();
            let env_file = beacons.join("ares.env");
            let hash_file = hashes.join("ares.json");
            fs::write(&env_file, "rendered\n").unwrap();
            fs::write(&hash_file, "{}\n").unwrap();
            let intent_file = temp.path().join("retired-hosts.json");
            write_intent(&intent_file, "destroyed", None);

            let secret_ref = SecretRef::new("sec_fixture").unwrap();
            let profile = EnvFileProfile::new(EnvFileProfileSpec {
                profile_id: ProfileId::new("profile.PHAROS_BEACON_ARES_TOKEN").unwrap(),
                secret_ref: secret_ref.clone(),
                executor: ExecutorRef::new("janus-run@test").unwrap(),
                destination: Destination::new("pharos-beacon-ares").unwrap(),
                env_name: SafeLabel::new("PHAROS_TOKEN").unwrap(),
                output_path: env_file,
                hash_sidecar: Some(EnvFileHashSidecarSpec {
                    format: EnvFileHashSidecarFormat::PharosBeaconTokenHashesV1,
                    subject: SafeLabel::new("ares").unwrap(),
                    output_path: hash_file,
                }),
                consumer: ConsumerDescriptor {
                    scope: scope(),
                    consumer_ref: ConsumerRef::new("consumer.pharos_beacon_ares").unwrap(),
                    secret_ref,
                    kind: ConsumerKind::Service,
                    owner: OwnerRef::new("pharos").unwrap(),
                    environment: Environment::new("test").unwrap(),
                    reload: ReloadMethod::None,
                    validation: vec![],
                    supports_dual_value: false,
                    blast_radius: BlastRadius::new("pharos-fixture").unwrap(),
                    declared: true,
                },
            })
            .unwrap();
            let request = PharosRetirementRequest {
                host: "ares".to_string(),
                disposition: "destroyed".to_string(),
                successor: None,
                intent_file,
                metadata_file: temp.path().join("metadata.toml"),
                profile_manifest: temp.path().join("profiles.toml"),
                state_dir: temp.path().join("state"),
                retain_for_days: 365,
            };
            let binding = prepare_binding(&request, &profile).unwrap();
            let registry = FilePharosRetirementRegistry::new(&request.state_dir);
            Self {
                _temp: temp,
                request,
                profile,
                binding,
                registry,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBackend {
        lifecycle: SecretLifecycle,
        tombstone_present: bool,
        transitions: Vec<SecretLifecycle>,
        tombstone_records: usize,
        finalizations: usize,
        fail_next_transition_to: Option<SecretLifecycle>,
        fail_next_finalize: bool,
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            Self {
                lifecycle: SecretLifecycle::Active,
                tombstone_present: false,
                transitions: Vec::new(),
                tombstone_records: 0,
                finalizations: 0,
                fail_next_transition_to: None,
                fail_next_finalize: false,
            }
        }
    }

    #[async_trait]
    impl PharosRetirementLifecycle for FakeBackend {
        async fn evidence(
            &mut self,
            _binding: &PharosRetirementBinding,
        ) -> PharosRetirementResult<PharosCredentialEvidence> {
            Ok(PharosCredentialEvidence {
                lifecycle: self.lifecycle,
                tombstone_present: self.tombstone_present,
            })
        }

        async fn transition(
            &mut self,
            _binding: &PharosRetirementBinding,
            to: SecretLifecycle,
        ) -> PharosRetirementResult<()> {
            if self.fail_next_transition_to == Some(to) {
                self.fail_next_transition_to = None;
                return Err(PharosRetirementFailure::new("fixture_transition_denied"));
            }
            let allowed = matches!(
                (self.lifecycle, to),
                (SecretLifecycle::Active, SecretLifecycle::Disabled)
                    | (SecretLifecycle::Disabled, SecretLifecycle::PendingDelete)
            );
            if !allowed {
                return Err(PharosRetirementFailure::new("fixture_transition_denied"));
            }
            self.lifecycle = to;
            self.transitions.push(to);
            Ok(())
        }

        async fn record_tombstone(
            &mut self,
            _binding: &PharosRetirementBinding,
            retain_for_days: u64,
        ) -> PharosRetirementResult<()> {
            if self.lifecycle != SecretLifecycle::PendingDelete
                || self.tombstone_present
                || retain_for_days == 0
            {
                return Err(PharosRetirementFailure::new("fixture_tombstone_denied"));
            }
            self.tombstone_present = true;
            self.tombstone_records += 1;
            Ok(())
        }

        async fn finalize(
            &mut self,
            _binding: &PharosRetirementBinding,
        ) -> PharosRetirementResult<()> {
            if self.fail_next_finalize {
                self.fail_next_finalize = false;
                return Err(PharosRetirementFailure::new("fixture_finalize_denied"));
            }
            if self.lifecycle != SecretLifecycle::PendingDelete || !self.tombstone_present {
                return Err(PharosRetirementFailure::new("fixture_finalize_denied"));
            }
            self.lifecycle = SecretLifecycle::Destroyed;
            self.finalizations += 1;
            Ok(())
        }
    }

    fn write_intent(path: &Path, disposition: &str, successor: Option<&str>) {
        let intent = serde_json::json!({
            "schema": INTENT_SCHEMA,
            "version": 1,
            "retirements": [{
                "host": "ares",
                "disposition": disposition,
                "successor": successor,
                "credential_retirement_required": true,
                "server_deletion": false
            }]
        });
        fs::write(path, serde_json::to_vec_pretty(&intent).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn retirement_converges_without_provider_delete_or_value_return() {
        let fixture = Fixture::new();
        let mut backend = FakeBackend::default();

        let outcome = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();

        assert_eq!(outcome.state, PharosReconcileState::Complete);
        assert!(!outcome.value_returned);
        assert!(!outcome.provider_deleted);
        assert_eq!(backend.lifecycle, SecretLifecycle::Destroyed);
        assert!(backend.tombstone_present);
        assert_eq!(backend.tombstone_records, 1);
        assert_eq!(backend.finalizations, 1);
        assert_eq!(
            backend.transitions,
            vec![SecretLifecycle::Disabled, SecretLifecycle::PendingDelete]
        );
        let outputs = fixture.binding.outputs().inspect().unwrap();
        assert!(!outputs.has_original());
        assert!(!outputs.has_staged());
        assert_eq!(
            fixture
                .registry
                .load(&fixture.binding)
                .unwrap()
                .unwrap()
                .phase(),
            PharosRetirementPhase::Complete
        );
    }

    #[tokio::test]
    async fn completed_retirement_is_idempotent() {
        let fixture = Fixture::new();
        let mut backend = FakeBackend::default();
        execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();
        let calls = (
            backend.transitions.len(),
            backend.tombstone_records,
            backend.finalizations,
        );

        let replay = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();

        assert_eq!(replay.state, PharosReconcileState::Complete);
        assert_eq!(
            calls,
            (
                backend.transitions.len(),
                backend.tombstone_records,
                backend.finalizations
            )
        );
    }

    #[tokio::test]
    async fn completed_retirement_blocks_reactivation_without_mutation() {
        let fixture = Fixture::new();
        let mut backend = FakeBackend::default();
        execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();
        backend.lifecycle = SecretLifecycle::Active;
        let calls = backend.transitions.len();

        let failure = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_state_lifecycle_drift"
        );
        assert_eq!(backend.lifecycle, SecretLifecycle::Active);
        assert_eq!(backend.transitions.len(), calls);
    }

    #[tokio::test]
    async fn retirement_resumes_from_every_persisted_phase() {
        for phase in [
            PharosRetirementPhase::Requested,
            PharosRetirementPhase::Disabled,
            PharosRetirementPhase::OutputsRemoved,
            PharosRetirementPhase::PendingDelete,
            PharosRetirementPhase::TombstoneRecorded,
        ] {
            let fixture = Fixture::new();
            let mut backend = FakeBackend::default();
            let interrupted = execute_retirement(
                &fixture.request,
                &fixture.binding,
                &fixture.registry,
                &mut backend,
                Some(phase),
            )
            .await
            .unwrap_err();
            assert_eq!(
                interrupted.reason_code(),
                "pharos_beacon_retirement_interrupted"
            );

            let mut restarted = backend.clone();
            let outcome = execute_retirement(
                &fixture.request,
                &fixture.binding,
                &fixture.registry,
                &mut restarted,
                None,
            )
            .await
            .unwrap();
            assert_eq!(outcome.state, PharosReconcileState::Complete);
            assert_eq!(restarted.lifecycle, SecretLifecycle::Destroyed);
            assert!(restarted.tombstone_present);
        }
    }

    #[tokio::test]
    async fn failed_pending_delete_transition_keeps_outputs_quarantined_for_retry() {
        let fixture = Fixture::new();
        let mut backend = FakeBackend {
            fail_next_transition_to: Some(SecretLifecycle::PendingDelete),
            ..FakeBackend::default()
        };

        let failure = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.reason_code(), "fixture_transition_denied");
        let quarantined = fixture.binding.outputs().inspect().unwrap();
        assert!(!quarantined.has_original());
        assert!(quarantined.has_staged());

        let outcome = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.state, PharosReconcileState::Complete);
    }

    #[tokio::test]
    async fn failed_finalization_resumes_without_a_second_tombstone() {
        let fixture = Fixture::new();
        let mut backend = FakeBackend {
            fail_next_finalize: true,
            ..FakeBackend::default()
        };

        let failure = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.reason_code(), "fixture_finalize_denied");
        assert_eq!(backend.lifecycle, SecretLifecycle::PendingDelete);
        assert!(backend.tombstone_present);
        assert_eq!(backend.tombstone_records, 1);

        let outcome = execute_retirement(
            &fixture.request,
            &fixture.binding,
            &fixture.registry,
            &mut backend,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.state, PharosReconcileState::Complete);
        assert_eq!(backend.tombstone_records, 1);
        assert_eq!(backend.finalizations, 1);
    }

    #[test]
    fn missing_intent_rejects_an_existing_profile() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.request.intent_file,
            format!("{{\"schema\":\"{INTENT_SCHEMA}\",\"version\":1,\"retirements\":[]}}"),
        )
        .unwrap();

        let failure = prepare_binding(&fixture.request, &fixture.profile).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_consumer_active"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_intent_is_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let linked = fixture._temp.path().join("retired-hosts-linked.json");
        symlink(&fixture.request.intent_file, &linked).unwrap();
        let mut request = fixture.request.clone();
        request.intent_file = linked;

        let failure = prepare_binding(&request, &fixture.profile).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_intent_unsafe"
        );
    }

    #[test]
    fn request_mismatch_is_rejected_before_output_mutation() {
        let fixture = Fixture::new();
        let mut request = fixture.request.clone();
        request.disposition = "unmanaged".to_string();

        let failure = prepare_binding(&request, &fixture.profile).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_request_mismatch"
        );
        assert!(fixture.binding.outputs().inspect().unwrap().has_original());
    }

    #[test]
    fn server_deletion_intent_is_rejected() {
        let fixture = Fixture::new();
        let intent = serde_json::json!({
            "schema": INTENT_SCHEMA,
            "version": 1,
            "retirements": [{
                "host": "ares",
                "disposition": "destroyed",
                "successor": null,
                "credential_retirement_required": true,
                "server_deletion": true
            }]
        });
        fs::write(
            &fixture.request.intent_file,
            serde_json::to_vec_pretty(&intent).unwrap(),
        )
        .unwrap();

        let failure = prepare_binding(&fixture.request, &fixture.profile).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_request_mismatch"
        );
    }

    #[test]
    fn rebuilt_retirement_requires_the_exact_successor() {
        let fixture = Fixture::new();
        write_intent(&fixture.request.intent_file, "rebuilt", Some("hera"));
        let mut request = fixture.request.clone();
        request.disposition = "rebuilt".to_string();
        request.successor = Some("hera".to_string());
        prepare_binding(&request, &fixture.profile).unwrap();

        request.successor = None;
        let failure = prepare_binding(&request, &fixture.profile).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_successor_invalid"
        );
    }

    #[test]
    fn profile_mismatch_is_rejected() {
        let fixture = Fixture::new();
        let secret_ref = SecretRef::new("sec_fixture").unwrap();
        let mismatched = EnvFileProfile::new(EnvFileProfileSpec {
            profile_id: ProfileId::new("profile.PHAROS_BEACON_ARES_TOKEN").unwrap(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("janus-run@test").unwrap(),
            destination: Destination::new("pharos-beacon-other").unwrap(),
            env_name: SafeLabel::new("PHAROS_TOKEN").unwrap(),
            output_path: fixture.binding.outputs().env_file.clone(),
            hash_sidecar: Some(EnvFileHashSidecarSpec {
                format: EnvFileHashSidecarFormat::PharosBeaconTokenHashesV1,
                subject: SafeLabel::new("ares").unwrap(),
                output_path: fixture.binding.outputs().hash_file.clone(),
            }),
            consumer: ConsumerDescriptor {
                scope: scope(),
                consumer_ref: ConsumerRef::new("consumer.pharos_beacon_ares").unwrap(),
                secret_ref,
                kind: ConsumerKind::Service,
                owner: OwnerRef::new("pharos").unwrap(),
                environment: Environment::new("test").unwrap(),
                reload: ReloadMethod::None,
                validation: vec![],
                supports_dual_value: false,
                blast_radius: BlastRadius::new("pharos-fixture").unwrap(),
                declared: true,
            },
        })
        .unwrap();

        let failure = prepare_binding(&fixture.request, &mismatched).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_profile_mismatch"
        );
    }

    #[test]
    fn second_output_stage_failure_rolls_back_the_first_output() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.binding.outputs().hash_staged.clone()).unwrap();

        let failure = fixture.binding.outputs().stage().unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_output_unsafe"
        );
        assert!(fixture.binding.outputs().env_file.is_file());
        assert!(!fixture.binding.outputs().env_staged.exists());
    }

    #[test]
    fn reconcile_distinguishes_finalize_drift_and_completion() {
        let fixture = Fixture::new();
        fixture.binding.outputs().stage().unwrap();
        fixture.binding.outputs().purge_staged().unwrap();
        let pending = reconcile(
            &fixture.binding,
            SecretLifecycle::PendingDelete,
            true,
            None,
            fixture.binding.outputs().inspect().unwrap(),
        );
        assert_eq!(pending.state, PharosReconcileState::NeedsFinalize);

        fs::write(&fixture.binding.outputs().env_file, "rendered\n").unwrap();
        fs::write(&fixture.binding.outputs().hash_file, "{}\n").unwrap();
        let pending_with_generated_output = reconcile(
            &fixture.binding,
            SecretLifecycle::PendingDelete,
            true,
            None,
            fixture.binding.outputs().inspect().unwrap(),
        );
        assert_eq!(
            pending_with_generated_output.state,
            PharosReconcileState::Drift
        );

        let destroyed_without_tombstone = reconcile(
            &fixture.binding,
            SecretLifecycle::Destroyed,
            false,
            None,
            fixture.binding.outputs().inspect().unwrap(),
        );
        assert_eq!(
            destroyed_without_tombstone.state,
            PharosReconcileState::Drift
        );
    }

    #[test]
    fn persisted_request_cannot_be_reused_for_a_different_disposition() {
        let fixture = Fixture::new();
        fixture
            .registry
            .store(&fixture.binding, PharosRetirementPhase::Requested)
            .unwrap();
        let mut request = fixture.request.clone();
        request.disposition = "unmanaged".to_string();
        write_intent(&request.intent_file, "unmanaged", None);
        let different_binding = prepare_binding(&request, &fixture.profile).unwrap();

        let failure = fixture.registry.load(&different_binding).unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_request_mismatch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retirement_state_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        fixture
            .registry
            .store(&fixture.binding, PharosRetirementPhase::Requested)
            .unwrap();
        let dir_mode = fs::metadata(&fixture.request.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(fixture.request.state_dir.join("ares.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn retirement_state_rejects_a_symlinked_registry_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let target = fixture._temp.path().join("state-target");
        let linked = fixture._temp.path().join("state-linked");
        fs::create_dir(&target).unwrap();
        symlink(&target, &linked).unwrap();
        let registry = FilePharosRetirementRegistry::new(linked);

        let failure = registry
            .store(&fixture.binding, PharosRetirementPhase::Requested)
            .unwrap_err();
        assert_eq!(
            failure.reason_code(),
            "pharos_beacon_retirement_state_unavailable"
        );
    }
}

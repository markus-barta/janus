//! Host-bound encrypted envelope cache and private runtime materializer.
//!
//! The transport carries a Janus-signed Age packet directly to one enrolled
//! host. Only ciphertext is persisted. Plaintext exists in bounded memory and
//! the fixed `/run/janus-managed/<service>/<slot>.env` target.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::{Decryptor, Encryptor};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use janus_core::{ScopeRef, SecretValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const CONFIG_SCHEMA: &str = "inspr.janus.host-executor-config.v1";
const ENVELOPE_SCHEMA: &str = "inspr.janus.host-envelope.v1";
const PAYLOAD_SCHEMA: &str = "inspr.janus.host-envelope-payload.v1";
const STATE_SCHEMA: &str = "inspr.janus.host-envelope-state.v1";
const CONTROL_SCHEMA: &str = "inspr.janus.host-envelope-control.v1";
const SIGNATURE_DOMAIN: &[u8] = b"inspr.janus.host-envelope.signature.v1\0";
const SCHEMA_VERSION: u8 = 1;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_PACKET_BYTES: usize = 256 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 192 * 1024;
const MAX_PAYLOAD_METADATA_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_SLOTS: usize = 128;
const MAX_KEYS: usize = 8;
const CLOCK_SKEW: Duration = Duration::from_secs(30);
const SYSTEM_CONFIG_PATH: &str = "/run/janus-host-executor/config.json";
const SYSTEM_IDENTITY_PATH: &str = "/etc/ssh/ssh_host_ed25519_key";
const SYSTEM_CACHE_ROOT: &str = "/var/lib/janus-host-executor";
const SYSTEM_RUNTIME_ROOT: &str = "/run/janus-managed";

/// Stable fail-closed error boundary. It never includes values, paths, or
/// dependency error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostEnvelopeError {
    reason_code: &'static str,
}

impl HostEnvelopeError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    /// Stable value-free reason code.
    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for HostEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for HostEnvelopeError {}

type HostResult<T> = Result<T, HostEnvelopeError>;

/// Exact binding encrypted into one host envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostEnvelopeBindingV1 {
    pub schema: String,
    pub schema_version: u8,
    pub envelope_ref: String,
    pub operation_ref: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub secret_ref: String,
    pub scope_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

/// Input to the central, value-bearing seal boundary.
pub struct HostEnvelopeSealRequest<'a> {
    pub binding: HostEnvelopeBindingV1,
    pub host_recipient: &'a str,
    pub signing_key_id: &'a str,
    pub signing_key: &'a SigningKey,
    pub value: SecretValue,
}

/// Signed packet delivered directly to the exact enrolled host.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedHostEnvelopeV1 {
    pub schema: String,
    pub schema_version: u8,
    pub key_id: String,
    pub ciphertext: String,
    pub signature: String,
}

/// Host-side immutable verification key.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostProducerKeyV1 {
    pub key_id: String,
    pub public_key: String,
}

/// One exact declared host slot.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostSecretSlotV1 {
    pub service_ref: String,
    pub slot_ref: String,
    pub secret_ref: String,
    pub declaration_fingerprint: String,
    pub minimum_generation: u64,
    pub rollback_window_seconds: u64,
}

/// Value-free, root-owned executor configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostExecutorConfigV1 {
    pub schema: String,
    pub schema_version: u8,
    pub host_ref: String,
    pub scope_ref: String,
    pub owner_uid: u32,
    pub minimum_revocation_epoch: u64,
    pub retired: bool,
    pub producer_keys: Vec<HostProducerKeyV1>,
    pub revoked_envelope_refs: Vec<String>,
    pub slots: Vec<HostSecretSlotV1>,
}

/// Strict value-free request for commit or rollback.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostEnvelopeControlV1 {
    pub schema: String,
    pub schema_version: u8,
    pub operation_ref: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub generation: u64,
}

/// Value-free result suitable for Pharos status forwarding.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostExecutorOutcome {
    pub action: String,
    pub host_ref: String,
    pub service_ref: Option<String>,
    pub slot_ref: Option<String>,
    pub operation_ref: Option<String>,
    pub generation: Option<u64>,
    pub phase: String,
    pub reason_code: String,
    pub value_returned: bool,
}

#[derive(Clone, Debug)]
struct ExecutorPaths {
    identity: PathBuf,
    cache_root: PathBuf,
    runtime_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CachedGenerationV1 {
    envelope_ref: String,
    operation_ref: String,
    generation: u64,
    revocation_epoch: u64,
    expires_at_unix_secs: u64,
    packet_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostSlotStateV1 {
    schema: String,
    schema_version: u8,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    current: CachedGenerationV1,
    previous: Option<CachedGenerationV1>,
    rollback_deadline_unix_secs: Option<u64>,
    committed: bool,
    integrity_hash: String,
}

struct DecryptedHostEnvelope {
    binding: HostEnvelopeBindingV1,
    value: SecretValue,
    packet_sha256: String,
}

struct SlotLock {
    file: File,
}

impl Drop for SlotLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Seal one bounded value for exactly one host and sign the ciphertext as
/// Janus. The returned bytes are safe to cache but must bypass Pharos.
pub fn seal_host_envelope(request: HostEnvelopeSealRequest<'_>) -> HostResult<Vec<u8>> {
    validate_binding(&request.binding)?;
    let value = request.value.expose_bytes();
    if value.is_empty() || value.len() > MAX_SECRET_BYTES {
        return Err(HostEnvelopeError::new("host_envelope_value_invalid"));
    }
    if !valid_ref("key_", request.signing_key_id) {
        return Err(HostEnvelopeError::new("host_envelope_signing_key_invalid"));
    }
    let metadata = serde_json::to_vec(&request.binding)
        .map_err(|_| HostEnvelopeError::new("host_envelope_metadata_invalid"))?;
    if metadata.len() > MAX_PAYLOAD_METADATA_BYTES {
        return Err(HostEnvelopeError::new("host_envelope_metadata_oversized"));
    }
    let mut plaintext = Vec::with_capacity(4 + metadata.len() + value.len());
    plaintext.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(&metadata);
    plaintext.extend_from_slice(value);
    let ciphertext = encrypt_for_recipient(request.host_recipient, &plaintext);
    plaintext.zeroize();
    let ciphertext = ciphertext?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(HostEnvelopeError::new("host_envelope_ciphertext_oversized"));
    }
    let signature = request
        .signing_key
        .sign(&signature_message(request.signing_key_id, &ciphertext));
    let packet = SignedHostEnvelopeV1 {
        schema: ENVELOPE_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        key_id: request.signing_key_id.to_string(),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
        signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
    };
    let encoded = serde_json::to_vec(&packet)
        .map_err(|_| HostEnvelopeError::new("host_envelope_packet_invalid"))?;
    if encoded.len() > MAX_PACKET_BYTES {
        return Err(HostEnvelopeError::new("host_envelope_packet_oversized"));
    }
    Ok(encoded)
}

/// Host-side cache and materialization boundary.
pub struct HostExecutor {
    config: HostExecutorConfigV1,
    keys: BTreeMap<String, VerifyingKey>,
    paths: ExecutorPaths,
}

impl HostExecutor {
    /// Load the root-owned system configuration and fixed host paths.
    pub fn from_system() -> HostResult<Self> {
        let raw = read_private_regular(
            Path::new(SYSTEM_CONFIG_PATH),
            MAX_CONFIG_BYTES,
            Some(0),
            "host_executor_config_unavailable",
        )?;
        let config: HostExecutorConfigV1 =
            decode_strict_json(&raw, "host_executor_config_invalid")?;
        Self::new(
            config,
            ExecutorPaths {
                identity: PathBuf::from(SYSTEM_IDENTITY_PATH),
                cache_root: PathBuf::from(SYSTEM_CACHE_ROOT),
                runtime_root: PathBuf::from(SYSTEM_RUNTIME_ROOT),
            },
        )
    }

    fn new(config: HostExecutorConfigV1, paths: ExecutorPaths) -> HostResult<Self> {
        let keys = validate_config(&config)?;
        Ok(Self {
            config,
            keys,
            paths,
        })
    }

    /// Verify, decrypt, persist ciphertext, and atomically materialize one
    /// newer generation.
    pub fn install(&self, packet: &[u8], now: SystemTime) -> HostResult<HostExecutorOutcome> {
        if self.config.retired {
            return Err(HostEnvelopeError::new("host_executor_retired"));
        }
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(HostEnvelopeError::new("host_envelope_packet_oversized"));
        }
        let decrypted = self.open_packet(packet, now)?;
        let slot = self.resolve_slot(&decrypted.binding)?;
        let slot_dir = self.slot_cache_dir(&slot.slot_ref);
        ensure_private_dir(&self.paths.cache_root, self.config.owner_uid)?;
        ensure_private_dir(&slot_dir, self.config.owner_uid)?;
        let _lock = lock_slot(&slot_dir, self.config.owner_uid)?;
        self.reconcile_interrupted_install(slot, now)?;
        reject_partial_files(&slot_dir, self.config.owner_uid)?;

        let current_path = slot_dir.join("current.envelope");
        let previous_path = slot_dir.join("previous.envelope");
        let state_path = slot_dir.join("state.json");
        let current_state = load_optional_state(&state_path, self.config.owner_uid)?;
        if let Some(state) = &current_state {
            validate_state_binding(state, &self.config.host_ref, slot)?;
            if state.current.packet_sha256 == decrypted.packet_sha256 {
                self.materialize(slot, &decrypted.value)?;
                return Ok(outcome(
                    "install",
                    &decrypted.binding,
                    "materialized",
                    "host_envelope_idempotent",
                ));
            }
            if decrypted.binding.generation <= state.current.generation {
                return Err(HostEnvelopeError::new("host_envelope_generation_downgrade"));
            }
            if state.previous.is_some() && !state.committed {
                return Err(HostEnvelopeError::new("host_envelope_conflicting_stage"));
            }
        } else if entry_exists(&current_path, "host_cache_current_unavailable")? {
            return Err(HostEnvelopeError::new("host_cache_state_missing"));
        }

        let cached = cached_generation(&decrypted.binding, &decrypted.packet_sha256);
        let previous = current_state.as_ref().map(|state| state.current.clone());
        if entry_exists(&previous_path, "host_cache_previous_unavailable")? {
            validate_private_regular_metadata(
                &previous_path,
                self.config.owner_uid,
                "host_cache_previous_unsafe",
            )?;
            fs::remove_file(&previous_path)
                .map_err(|_| HostEnvelopeError::new("host_cache_previous_unavailable"))?;
        }
        let preserved_current = if entry_exists(&current_path, "host_cache_current_unavailable")? {
            let current_packet = read_private_regular(
                &current_path,
                MAX_PACKET_BYTES,
                Some(self.config.owner_uid),
                "host_cache_current_unavailable",
            )?;
            atomic_write(
                &previous_path,
                &current_packet,
                0o600,
                self.config.owner_uid,
                "host_cache_rotation_failed",
            )?;
            true
        } else {
            false
        };
        if let Err(error) = atomic_write(
            &current_path,
            packet,
            0o600,
            self.config.owner_uid,
            "host_cache_write_failed",
        ) {
            if preserved_current {
                let _ = fs::remove_file(&previous_path);
            }
            return Err(error);
        }
        self.materialize(slot, &decrypted.value)?;
        let now_secs = unix_seconds(now)?;
        let rollback_deadline = previous
            .as_ref()
            .map(|_| now_secs.saturating_add(slot.rollback_window_seconds));
        let state = HostSlotStateV1 {
            schema: STATE_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            host_ref: self.config.host_ref.clone(),
            service_ref: slot.service_ref.clone(),
            slot_ref: slot.slot_ref.clone(),
            current: cached,
            previous,
            rollback_deadline_unix_secs: rollback_deadline,
            committed: rollback_deadline.is_none(),
            integrity_hash: String::new(),
        };
        write_state(&state_path, state, self.config.owner_uid)?;
        sync_dir(&slot_dir, "host_cache_sync_failed")?;
        Ok(outcome(
            "install",
            &decrypted.binding,
            "materialized",
            "host_envelope_materialized",
        ))
    }

    /// Restore every committed slot from ciphertext without contacting Janus.
    pub fn restore_all(&self, now: SystemTime) -> HostResult<Vec<HostExecutorOutcome>> {
        if self.config.retired {
            self.remove_runtime_files()?;
            return Err(HostEnvelopeError::new("host_executor_retired"));
        }
        let mut results = Vec::with_capacity(self.config.slots.len());
        for slot in &self.config.slots {
            results.push(self.restore_slot(slot, now)?);
        }
        Ok(results)
    }

    /// Permanently accept a staged generation and discard rollback material.
    pub fn commit(&self, request: &HostEnvelopeControlV1) -> HostResult<HostExecutorOutcome> {
        validate_control(request, &self.config.host_ref)?;
        let slot = self.control_slot(request)?;
        let slot_dir = self.slot_cache_dir(&slot.slot_ref);
        let _lock = lock_slot(&slot_dir, self.config.owner_uid)?;
        self.reconcile_interrupted_install(slot, SystemTime::now())?;
        reject_partial_files(&slot_dir, self.config.owner_uid)?;
        let state_path = slot_dir.join("state.json");
        let mut state = load_required_state(&state_path, self.config.owner_uid)?;
        validate_control_state(request, &state)?;
        if state.committed {
            return Ok(outcome_from_control(
                "commit",
                request,
                "active",
                "host_envelope_commit_idempotent",
            ));
        }
        let previous_path = slot_dir.join("previous.envelope");
        if state.previous.is_some() {
            validate_private_regular_metadata(
                &previous_path,
                self.config.owner_uid,
                "host_cache_previous_unsafe",
            )?;
            fs::remove_file(&previous_path)
                .map_err(|_| HostEnvelopeError::new("host_cache_previous_unavailable"))?;
        }
        state.previous = None;
        state.rollback_deadline_unix_secs = None;
        state.committed = true;
        write_state(&state_path, state, self.config.owner_uid)?;
        sync_dir(&slot_dir, "host_cache_sync_failed")?;
        Ok(outcome_from_control(
            "commit",
            request,
            "active",
            "host_envelope_committed",
        ))
    }

    /// Restore the previous signed generation before the bounded deadline.
    pub fn rollback(
        &self,
        request: &HostEnvelopeControlV1,
        now: SystemTime,
    ) -> HostResult<HostExecutorOutcome> {
        validate_control(request, &self.config.host_ref)?;
        let slot = self.control_slot(request)?;
        let slot_dir = self.slot_cache_dir(&slot.slot_ref);
        let _lock = lock_slot(&slot_dir, self.config.owner_uid)?;
        self.reconcile_interrupted_install(slot, now)?;
        reject_partial_files(&slot_dir, self.config.owner_uid)?;
        let state_path = slot_dir.join("state.json");
        let mut state = load_required_state(&state_path, self.config.owner_uid)?;
        validate_control_state(request, &state)?;
        if state.committed {
            return Err(HostEnvelopeError::new(
                "host_envelope_rollback_not_available",
            ));
        }
        let deadline = state
            .rollback_deadline_unix_secs
            .ok_or_else(|| HostEnvelopeError::new("host_envelope_rollback_not_available"))?;
        if unix_seconds(now)? >= deadline {
            return Err(HostEnvelopeError::new("host_envelope_rollback_expired"));
        }
        let previous_record = state
            .previous
            .clone()
            .ok_or_else(|| HostEnvelopeError::new("host_envelope_rollback_not_available"))?;
        let previous_path = slot_dir.join("previous.envelope");
        let previous_packet = read_private_regular(
            &previous_path,
            MAX_PACKET_BYTES,
            Some(self.config.owner_uid),
            "host_cache_previous_unavailable",
        )?;
        let previous = self.open_packet(&previous_packet, now)?;
        self.resolve_slot(&previous.binding)?;
        if previous.packet_sha256 != previous_record.packet_sha256
            || previous.binding.generation != previous_record.generation
        {
            return Err(HostEnvelopeError::new("host_cache_previous_mismatch"));
        }
        self.materialize(slot, &previous.value)?;
        let current_path = slot_dir.join("current.envelope");
        atomic_write(
            &current_path,
            &previous_packet,
            0o600,
            self.config.owner_uid,
            "host_cache_write_failed",
        )?;
        fs::remove_file(&previous_path)
            .map_err(|_| HostEnvelopeError::new("host_cache_previous_unavailable"))?;
        state.current = previous_record;
        state.previous = None;
        state.rollback_deadline_unix_secs = None;
        state.committed = true;
        write_state(&state_path, state, self.config.owner_uid)?;
        sync_dir(&slot_dir, "host_cache_sync_failed")?;
        Ok(outcome(
            "rollback",
            &previous.binding,
            "rolled_back",
            "host_envelope_rolled_back",
        ))
    }

    /// Value-free cache status. It does not decrypt or read runtime files.
    pub fn status(&self) -> HostResult<Vec<HostExecutorOutcome>> {
        let mut results = Vec::with_capacity(self.config.slots.len());
        for slot in &self.config.slots {
            let slot_dir = self.slot_cache_dir(&slot.slot_ref);
            let state_path = slot_dir.join("state.json");
            match load_optional_state(&state_path, self.config.owner_uid)? {
                Some(state) => {
                    validate_state_binding(&state, &self.config.host_ref, slot)?;
                    validate_cached_packet(
                        &slot_dir.join("current.envelope"),
                        &state.current,
                        self.config.owner_uid,
                        "host_cache_current_unavailable",
                    )?;
                    if let Some(previous) = &state.previous {
                        validate_cached_packet(
                            &slot_dir.join("previous.envelope"),
                            previous,
                            self.config.owner_uid,
                            "host_cache_previous_unavailable",
                        )?;
                    }
                    results.push(HostExecutorOutcome {
                        action: "status".to_string(),
                        host_ref: self.config.host_ref.clone(),
                        service_ref: Some(slot.service_ref.clone()),
                        slot_ref: Some(slot.slot_ref.clone()),
                        operation_ref: Some(state.current.operation_ref),
                        generation: Some(state.current.generation),
                        phase: if state.committed {
                            "active".to_string()
                        } else {
                            "staged".to_string()
                        },
                        reason_code: "host_envelope_status_ok".to_string(),
                        value_returned: false,
                    });
                }
                None => results.push(HostExecutorOutcome {
                    action: "status".to_string(),
                    host_ref: self.config.host_ref.clone(),
                    service_ref: Some(slot.service_ref.clone()),
                    slot_ref: Some(slot.slot_ref.clone()),
                    operation_ref: None,
                    generation: None,
                    phase: "missing".to_string(),
                    reason_code: "host_envelope_missing".to_string(),
                    value_returned: false,
                }),
            }
        }
        Ok(results)
    }

    fn restore_slot(
        &self,
        slot: &HostSecretSlotV1,
        now: SystemTime,
    ) -> HostResult<HostExecutorOutcome> {
        let slot_dir = self.slot_cache_dir(&slot.slot_ref);
        let _lock = lock_slot(&slot_dir, self.config.owner_uid)?;
        self.reconcile_interrupted_install(slot, now)?;
        reject_partial_files(&slot_dir, self.config.owner_uid)?;
        let state = load_required_state(&slot_dir.join("state.json"), self.config.owner_uid)?;
        validate_state_binding(&state, &self.config.host_ref, slot)?;
        if !state.committed
            && state
                .rollback_deadline_unix_secs
                .is_some_and(|deadline| unix_seconds(now).is_ok_and(|current| current >= deadline))
        {
            return Err(HostEnvelopeError::new("host_envelope_rollback_expired"));
        }
        let packet = read_private_regular(
            &slot_dir.join("current.envelope"),
            MAX_PACKET_BYTES,
            Some(self.config.owner_uid),
            "host_cache_current_unavailable",
        )?;
        let opened = self.open_packet(&packet, now)?;
        self.resolve_slot(&opened.binding)?;
        if opened.packet_sha256 != state.current.packet_sha256
            || opened.binding.generation != state.current.generation
        {
            return Err(HostEnvelopeError::new("host_cache_current_mismatch"));
        }
        self.materialize(slot, &opened.value)?;
        Ok(outcome(
            "restore",
            &opened.binding,
            "materialized",
            "host_envelope_restored_offline",
        ))
    }

    fn open_packet(&self, raw_packet: &[u8], now: SystemTime) -> HostResult<DecryptedHostEnvelope> {
        let packet: SignedHostEnvelopeV1 =
            decode_strict_json(raw_packet, "host_envelope_packet_invalid")?;
        if packet.schema != ENVELOPE_SCHEMA
            || packet.schema_version != SCHEMA_VERSION
            || !valid_ref("key_", &packet.key_id)
        {
            return Err(HostEnvelopeError::new("host_envelope_packet_invalid"));
        }
        let ciphertext = STANDARD_NO_PAD
            .decode(packet.ciphertext.as_bytes())
            .map_err(|_| HostEnvelopeError::new("host_envelope_ciphertext_invalid"))?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(HostEnvelopeError::new("host_envelope_ciphertext_oversized"));
        }
        let signature_bytes = STANDARD_NO_PAD
            .decode(packet.signature.as_bytes())
            .map_err(|_| HostEnvelopeError::new("host_envelope_signature_invalid"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| HostEnvelopeError::new("host_envelope_signature_invalid"))?;
        let key = self
            .keys
            .get(&packet.key_id)
            .ok_or_else(|| HostEnvelopeError::new("host_envelope_signing_key_unknown"))?;
        key.verify(&signature_message(&packet.key_id, &ciphertext), &signature)
            .map_err(|_| HostEnvelopeError::new("host_envelope_signature_invalid"))?;
        let mut plaintext =
            decrypt_with_identity(&ciphertext, &self.paths.identity, self.config.owner_uid)?;
        let parsed = parse_plaintext(&plaintext);
        plaintext.zeroize();
        let (binding, value) = parsed?;
        self.validate_host_binding(&binding, now)?;
        Ok(DecryptedHostEnvelope {
            binding,
            value,
            packet_sha256: sha256_hex(raw_packet),
        })
    }

    fn validate_host_binding(
        &self,
        binding: &HostEnvelopeBindingV1,
        now: SystemTime,
    ) -> HostResult<()> {
        validate_binding(binding)?;
        if binding.host_ref != self.config.host_ref
            || binding.scope_ref != self.config.scope_ref
            || binding.revocation_epoch < self.config.minimum_revocation_epoch
            || self
                .config
                .revoked_envelope_refs
                .iter()
                .any(|reference| reference == &binding.envelope_ref)
        {
            return Err(HostEnvelopeError::new("host_envelope_binding_denied"));
        }
        let now = unix_seconds(now)?;
        if binding.issued_at_unix_secs > now.saturating_add(CLOCK_SKEW.as_secs())
            || now >= binding.expires_at_unix_secs
        {
            return Err(HostEnvelopeError::new("host_envelope_expired"));
        }
        Ok(())
    }

    fn resolve_slot(&self, binding: &HostEnvelopeBindingV1) -> HostResult<&HostSecretSlotV1> {
        let slot = self
            .config
            .slots
            .iter()
            .find(|slot| {
                slot.service_ref == binding.service_ref
                    && slot.slot_ref == binding.slot_ref
                    && slot.secret_ref == binding.secret_ref
            })
            .ok_or_else(|| HostEnvelopeError::new("host_envelope_slot_denied"))?;
        if slot.declaration_fingerprint != binding.declaration_fingerprint
            || binding.generation < slot.minimum_generation
        {
            return Err(HostEnvelopeError::new("host_envelope_declaration_drift"));
        }
        Ok(slot)
    }

    fn control_slot(&self, request: &HostEnvelopeControlV1) -> HostResult<&HostSecretSlotV1> {
        self.config
            .slots
            .iter()
            .find(|slot| {
                slot.service_ref == request.service_ref && slot.slot_ref == request.slot_ref
            })
            .ok_or_else(|| HostEnvelopeError::new("host_envelope_slot_denied"))
    }

    fn slot_cache_dir(&self, slot_ref: &str) -> PathBuf {
        self.paths.cache_root.join(slot_ref)
    }

    fn materialize(&self, slot: &HostSecretSlotV1, value: &SecretValue) -> HostResult<()> {
        ensure_private_dir(&self.paths.runtime_root, self.config.owner_uid)?;
        let service_dir = self.paths.runtime_root.join(&slot.service_ref);
        ensure_private_dir(&service_dir, self.config.owner_uid)?;
        let target = service_dir.join(format!("{}.env", slot.slot_ref));
        atomic_write(
            &target,
            value.expose_bytes(),
            0o400,
            self.config.owner_uid,
            "host_runtime_write_failed",
        )?;
        sync_dir(&service_dir, "host_runtime_sync_failed")
    }

    fn remove_runtime_files(&self) -> HostResult<()> {
        for slot in &self.config.slots {
            let target = self
                .paths
                .runtime_root
                .join(&slot.service_ref)
                .join(format!("{}.env", slot.slot_ref));
            if entry_exists(&target, "host_runtime_target_unsafe")? {
                validate_private_regular_metadata(
                    &target,
                    self.config.owner_uid,
                    "host_runtime_target_unsafe",
                )?;
                fs::remove_file(&target)
                    .map_err(|_| HostEnvelopeError::new("host_runtime_remove_failed"))?;
            }
        }
        Ok(())
    }

    fn reconcile_interrupted_install(
        &self,
        slot: &HostSecretSlotV1,
        now: SystemTime,
    ) -> HostResult<()> {
        let slot_dir = self.slot_cache_dir(&slot.slot_ref);
        reject_partial_names(&slot_dir)?;
        let current_path = slot_dir.join("current.envelope");
        let previous_path = slot_dir.join("previous.envelope");
        let state_path = slot_dir.join("state.json");
        let state = load_optional_state(&state_path, self.config.owner_uid)?;

        let current_exists = entry_exists(&current_path, "host_cache_current_unavailable")?;
        let previous_exists = entry_exists(&previous_path, "host_cache_previous_unavailable")?;
        if state.is_none() && current_exists && !previous_exists {
            let packet = read_private_regular(
                &current_path,
                MAX_PACKET_BYTES,
                Some(self.config.owner_uid),
                "host_cache_current_unavailable",
            )?;
            let opened = self.open_packet(&packet, now)?;
            let resolved = self.resolve_slot(&opened.binding)?;
            if resolved.slot_ref != slot.slot_ref {
                return Err(HostEnvelopeError::new("host_cache_current_mismatch"));
            }
            write_state(
                &state_path,
                HostSlotStateV1 {
                    schema: STATE_SCHEMA.to_string(),
                    schema_version: SCHEMA_VERSION,
                    host_ref: self.config.host_ref.clone(),
                    service_ref: slot.service_ref.clone(),
                    slot_ref: slot.slot_ref.clone(),
                    current: cached_generation(&opened.binding, &opened.packet_sha256),
                    previous: None,
                    rollback_deadline_unix_secs: None,
                    committed: true,
                    integrity_hash: String::new(),
                },
                self.config.owner_uid,
            )?;
            return Ok(());
        }

        let Some(state) = state else {
            return Ok(());
        };
        validate_state_binding(&state, &self.config.host_ref, slot)?;
        if !(current_exists && previous_exists) {
            return Ok(());
        }
        let current_packet = read_private_regular(
            &current_path,
            MAX_PACKET_BYTES,
            Some(self.config.owner_uid),
            "host_cache_current_unavailable",
        )?;
        let previous_packet = read_private_regular(
            &previous_path,
            MAX_PACKET_BYTES,
            Some(self.config.owner_uid),
            "host_cache_previous_unavailable",
        )?;
        let current_hash = sha256_hex(&current_packet);
        let previous_hash = sha256_hex(&previous_packet);
        if current_hash == state.current.packet_sha256
            && previous_hash == state.current.packet_sha256
            && state.committed
            && state.previous.is_none()
        {
            fs::remove_file(&previous_path)
                .map_err(|_| HostEnvelopeError::new("host_cache_recovery_failed"))?;
            return Ok(());
        }
        if previous_hash == state.current.packet_sha256
            && current_hash != state.current.packet_sha256
            && state.committed
            && state.previous.is_none()
        {
            let opened = self.open_packet(&current_packet, now)?;
            let resolved = self.resolve_slot(&opened.binding)?;
            if resolved.slot_ref != slot.slot_ref
                || opened.binding.generation <= state.current.generation
            {
                return Err(HostEnvelopeError::new("host_cache_recovery_failed"));
            }
            let deadline = unix_seconds(now)?.saturating_add(slot.rollback_window_seconds);
            write_state(
                &state_path,
                HostSlotStateV1 {
                    schema: STATE_SCHEMA.to_string(),
                    schema_version: SCHEMA_VERSION,
                    host_ref: self.config.host_ref.clone(),
                    service_ref: slot.service_ref.clone(),
                    slot_ref: slot.slot_ref.clone(),
                    current: cached_generation(&opened.binding, &opened.packet_sha256),
                    previous: Some(state.current),
                    rollback_deadline_unix_secs: Some(deadline),
                    committed: false,
                    integrity_hash: String::new(),
                },
                self.config.owner_uid,
            )?;
        }
        Ok(())
    }
}

fn validate_config(config: &HostExecutorConfigV1) -> HostResult<BTreeMap<String, VerifyingKey>> {
    if config.schema != CONFIG_SCHEMA
        || config.schema_version != SCHEMA_VERSION
        || !valid_ref("host_", &config.host_ref)
        || ScopeRef::from_opaque(config.scope_ref.clone()).is_err()
        || config.producer_keys.is_empty()
        || config.producer_keys.len() > MAX_KEYS
        || config.slots.is_empty()
        || config.slots.len() > MAX_SLOTS
        || config.revoked_envelope_refs.len() > 1024
    {
        return Err(HostEnvelopeError::new("host_executor_config_invalid"));
    }
    let mut keys = BTreeMap::new();
    for entry in &config.producer_keys {
        if !valid_ref("key_", &entry.key_id) || keys.contains_key(&entry.key_id) {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
        let raw = STANDARD_NO_PAD
            .decode(entry.public_key.as_bytes())
            .map_err(|_| HostEnvelopeError::new("host_executor_config_invalid"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| HostEnvelopeError::new("host_executor_config_invalid"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| HostEnvelopeError::new("host_executor_config_invalid"))?;
        keys.insert(entry.key_id.clone(), key);
    }
    let mut slots = BTreeSet::new();
    for slot in &config.slots {
        if !valid_ref("svc_", &slot.service_ref)
            || !valid_ref("slot_", &slot.slot_ref)
            || !valid_ref("sec_", &slot.secret_ref)
            || !valid_ref("decl_", &slot.declaration_fingerprint)
            || slot.minimum_generation == 0
            || !(60..=86_400).contains(&slot.rollback_window_seconds)
            || !slots.insert((slot.service_ref.clone(), slot.slot_ref.clone()))
        {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
    }
    let mut revoked = BTreeSet::new();
    for reference in &config.revoked_envelope_refs {
        if !valid_ref("env_", reference) || !revoked.insert(reference) {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
    }
    Ok(keys)
}

fn validate_binding(binding: &HostEnvelopeBindingV1) -> HostResult<()> {
    let ttl = binding
        .expires_at_unix_secs
        .checked_sub(binding.issued_at_unix_secs)
        .ok_or_else(|| HostEnvelopeError::new("host_envelope_binding_invalid"))?;
    if binding.schema != PAYLOAD_SCHEMA
        || binding.schema_version != SCHEMA_VERSION
        || !valid_ref("env_", &binding.envelope_ref)
        || !valid_ref("op_", &binding.operation_ref)
        || !valid_ref("host_", &binding.host_ref)
        || !valid_ref("svc_", &binding.service_ref)
        || !valid_ref("slot_", &binding.slot_ref)
        || !valid_ref("sec_", &binding.secret_ref)
        || ScopeRef::from_opaque(binding.scope_ref.clone()).is_err()
        || !valid_ref("decl_", &binding.declaration_fingerprint)
        || binding.generation == 0
        || binding.revocation_epoch == 0
        || binding.issued_at_unix_secs == 0
        || !(60..=31 * 24 * 60 * 60).contains(&ttl)
    {
        return Err(HostEnvelopeError::new("host_envelope_binding_invalid"));
    }
    Ok(())
}

fn validate_control(request: &HostEnvelopeControlV1, host_ref: &str) -> HostResult<()> {
    if request.schema != CONTROL_SCHEMA
        || request.schema_version != SCHEMA_VERSION
        || request.host_ref != host_ref
        || !valid_ref("op_", &request.operation_ref)
        || !valid_ref("svc_", &request.service_ref)
        || !valid_ref("slot_", &request.slot_ref)
        || request.generation == 0
    {
        return Err(HostEnvelopeError::new("host_envelope_control_invalid"));
    }
    Ok(())
}

fn validate_control_state(
    request: &HostEnvelopeControlV1,
    state: &HostSlotStateV1,
) -> HostResult<()> {
    if state.host_ref != request.host_ref
        || state.service_ref != request.service_ref
        || state.slot_ref != request.slot_ref
        || state.current.operation_ref != request.operation_ref
        || state.current.generation != request.generation
    {
        return Err(HostEnvelopeError::new("host_envelope_control_mismatch"));
    }
    Ok(())
}

fn validate_state_binding(
    state: &HostSlotStateV1,
    host_ref: &str,
    slot: &HostSecretSlotV1,
) -> HostResult<()> {
    if state.schema != STATE_SCHEMA
        || state.schema_version != SCHEMA_VERSION
        || state.host_ref != host_ref
        || state.service_ref != slot.service_ref
        || state.slot_ref != slot.slot_ref
        || state.current.generation < slot.minimum_generation
        || !validate_cached_generation(&state.current)
        || state.previous.as_ref().is_some_and(|previous| {
            !validate_cached_generation(previous)
                || previous.generation >= state.current.generation
                || previous.revocation_epoch > state.current.revocation_epoch
        })
        || !state.committed
            && (state.previous.is_none() || state.rollback_deadline_unix_secs.is_none())
        || state.committed
            && (state.previous.is_some() || state.rollback_deadline_unix_secs.is_some())
    {
        return Err(HostEnvelopeError::new("host_cache_state_invalid"));
    }
    Ok(())
}

fn validate_cached_generation(generation: &CachedGenerationV1) -> bool {
    valid_ref("env_", &generation.envelope_ref)
        && valid_ref("op_", &generation.operation_ref)
        && generation.generation > 0
        && generation.revocation_epoch > 0
        && generation.expires_at_unix_secs > 0
        && validate_state_hash(&generation.packet_sha256)
}

fn validate_cached_packet(
    path: &Path,
    generation: &CachedGenerationV1,
    owner_uid: u32,
    reason: &'static str,
) -> HostResult<()> {
    let packet = read_private_regular(path, MAX_PACKET_BYTES, Some(owner_uid), reason)?;
    if sha256_hex(&packet) != generation.packet_sha256 {
        return Err(HostEnvelopeError::new(reason));
    }
    Ok(())
}

fn encrypt_for_recipient(recipient: &str, plaintext: &[u8]) -> HostResult<Vec<u8>> {
    let recipient = parse_recipient(recipient)?;
    let encryptor =
        Encryptor::with_recipients(std::iter::once(recipient.as_ref() as &dyn age::Recipient))
            .map_err(|_| HostEnvelopeError::new("host_envelope_recipient_invalid"))?;
    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|_| HostEnvelopeError::new("host_envelope_encrypt_failed"))?;
        writer
            .write_all(plaintext)
            .map_err(|_| HostEnvelopeError::new("host_envelope_encrypt_failed"))?;
        writer
            .finish()
            .map_err(|_| HostEnvelopeError::new("host_envelope_encrypt_failed"))?;
    }
    Ok(ciphertext)
}

fn parse_recipient(value: &str) -> HostResult<Box<dyn age::Recipient + Send>> {
    let value = value.trim();
    if let Ok(recipient) = value.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(recipient));
    }
    if !value.starts_with("ssh-ed25519 ") {
        return Err(HostEnvelopeError::new("host_envelope_recipient_invalid"));
    }
    match value.parse::<age::ssh::Recipient>() {
        Ok(recipient @ age::ssh::Recipient::SshEd25519(_, _)) => Ok(Box::new(recipient)),
        _ => Err(HostEnvelopeError::new("host_envelope_recipient_invalid")),
    }
}

fn decrypt_with_identity(
    ciphertext: &[u8],
    identity_path: &Path,
    owner_uid: u32,
) -> HostResult<Vec<u8>> {
    let raw = read_private_regular(
        identity_path,
        64 * 1024,
        Some(owner_uid),
        "host_identity_unavailable",
    )?;
    let identity = parse_identity(&raw)?;
    let decryptor = Decryptor::new_buffered(ciphertext)
        .map_err(|_| HostEnvelopeError::new("host_envelope_decrypt_denied"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_ref() as &dyn age::Identity))
        .map_err(|_| HostEnvelopeError::new("host_envelope_decrypt_denied"))?;
    let mut plaintext = Vec::new();
    reader
        .by_ref()
        .take((MAX_SECRET_BYTES + MAX_PAYLOAD_METADATA_BYTES + 5) as u64)
        .read_to_end(&mut plaintext)
        .map_err(|_| HostEnvelopeError::new("host_envelope_decrypt_denied"))?;
    if plaintext.len() > MAX_SECRET_BYTES + MAX_PAYLOAD_METADATA_BYTES + 4 {
        plaintext.zeroize();
        return Err(HostEnvelopeError::new("host_envelope_plaintext_oversized"));
    }
    Ok(plaintext)
}

fn parse_identity(raw: &[u8]) -> HostResult<Box<dyn age::Identity + Send>> {
    let text =
        std::str::from_utf8(raw).map_err(|_| HostEnvelopeError::new("host_identity_invalid"))?;
    let trimmed = text.trim();
    if let Ok(identity) = trimmed.parse::<age::x25519::Identity>() {
        return Ok(Box::new(identity));
    }
    if trimmed.contains("BEGIN RSA PRIVATE KEY") {
        return Err(HostEnvelopeError::new("host_identity_invalid"));
    }
    let private = ssh_key::PrivateKey::from_openssh(raw)
        .map_err(|_| HostEnvelopeError::new("host_identity_invalid"))?;
    if private.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(HostEnvelopeError::new("host_identity_invalid"));
    }
    let reader = BufReader::new(raw);
    let identity = age::ssh::Identity::from_buffer(reader, None)
        .map_err(|_| HostEnvelopeError::new("host_identity_invalid"))?;
    Ok(Box::new(identity))
}

fn parse_plaintext(raw: &[u8]) -> HostResult<(HostEnvelopeBindingV1, SecretValue)> {
    if raw.len() < 5 {
        return Err(HostEnvelopeError::new("host_envelope_plaintext_invalid"));
    }
    let metadata_len = u32::from_be_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| HostEnvelopeError::new("host_envelope_plaintext_invalid"))?,
    ) as usize;
    if metadata_len == 0
        || metadata_len > MAX_PAYLOAD_METADATA_BYTES
        || 4 + metadata_len >= raw.len()
    {
        return Err(HostEnvelopeError::new("host_envelope_plaintext_invalid"));
    }
    let binding = decode_strict_json(&raw[4..4 + metadata_len], "host_envelope_metadata_invalid")?;
    let value = &raw[4 + metadata_len..];
    if value.is_empty() || value.len() > MAX_SECRET_BYTES {
        return Err(HostEnvelopeError::new("host_envelope_value_invalid"));
    }
    Ok((binding, SecretValue::new(value.to_vec())))
}

fn signature_message(key_id: &str, ciphertext: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + key_id.len() + 1 + ciphertext.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(ciphertext);
    message
}

fn read_private_regular(
    path: &Path,
    maximum: usize,
    owner_uid: Option<u32>,
    reason: &'static str,
) -> HostResult<Vec<u8>> {
    let metadata = validate_private_regular_metadata(path, owner_uid.unwrap_or(u32::MAX), reason)?;
    if owner_uid.is_none() && metadata.mode() & 0o077 != 0 {
        return Err(HostEnvelopeError::new(reason));
    }
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(HostEnvelopeError::new(reason));
    }
    let mut file = File::open(path).map_err(|_| HostEnvelopeError::new(reason))?;
    let opened = file
        .metadata()
        .map_err(|_| HostEnvelopeError::new(reason))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(HostEnvelopeError::new(reason));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| HostEnvelopeError::new(reason))?;
    if raw.len() > maximum {
        raw.zeroize();
        return Err(HostEnvelopeError::new(reason));
    }
    Ok(raw)
}

fn validate_private_regular_metadata(
    path: &Path,
    owner_uid: u32,
    reason: &'static str,
) -> HostResult<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HostEnvelopeError::new(reason))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || owner_uid != u32::MAX && metadata.uid() != owner_uid
    {
        return Err(HostEnvelopeError::new(reason));
    }
    Ok(metadata)
}

fn ensure_private_dir(path: &Path, owner_uid: u32) -> HostResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    if !path.is_absolute() {
        return Err(HostEnvelopeError::new("host_directory_invalid"));
    }
    if !entry_exists(path, "host_directory_unavailable")? {
        let parent = path
            .parent()
            .ok_or_else(|| HostEnvelopeError::new("host_directory_invalid"))?;
        if !parent.is_dir() {
            return Err(HostEnvelopeError::new("host_directory_unavailable"));
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|_| HostEnvelopeError::new("host_directory_unavailable"))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HostEnvelopeError::new("host_directory_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(HostEnvelopeError::new("host_directory_unsafe"));
    }
    Ok(())
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner_uid: u32,
    reason: &'static str,
) -> HostResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| HostEnvelopeError::new(reason))?;
    ensure_private_dir(parent, owner_uid)?;
    if entry_exists(path, reason)? {
        validate_private_regular_metadata(path, owner_uid, reason)?;
    }
    let tmp = parent.join(format!(
        ".janus-host-{}.{}.tmp",
        std::process::id(),
        monotonic_nonce()?
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| HostEnvelopeError::new(reason))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| HostEnvelopeError::new(reason))?;
        file.write_all(bytes)
            .map_err(|_| HostEnvelopeError::new(reason))?;
        file.sync_all()
            .map_err(|_| HostEnvelopeError::new(reason))?;
        drop(file);
        let metadata = validate_private_regular_metadata(&tmp, owner_uid, reason)?;
        if metadata.mode() & 0o777 != mode {
            return Err(HostEnvelopeError::new(reason));
        }
        fs::rename(&tmp, path).map_err(|_| HostEnvelopeError::new(reason))?;
        sync_dir(parent, reason)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn lock_slot(slot_dir: &Path, owner_uid: u32) -> HostResult<SlotLock> {
    ensure_private_dir(slot_dir, owner_uid)?;
    let path = slot_dir.join(".lock");
    if entry_exists(&path, "host_cache_lock_unsafe")? {
        validate_private_regular_metadata(&path, owner_uid, "host_cache_lock_unsafe")?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| HostEnvelopeError::new("host_cache_lock_unavailable"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| HostEnvelopeError::new("host_cache_lock_unavailable"))?;
    file.try_lock_exclusive()
        .map_err(|_| HostEnvelopeError::new("host_cache_busy"))?;
    Ok(SlotLock { file })
}

fn reject_partial_files(slot_dir: &Path, owner_uid: u32) -> HostResult<()> {
    reject_partial_names(slot_dir)?;
    for entry in
        fs::read_dir(slot_dir).map_err(|_| HostEnvelopeError::new("host_cache_unavailable"))?
    {
        let entry = entry.map_err(|_| HostEnvelopeError::new("host_cache_unavailable"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| HostEnvelopeError::new("host_cache_unsafe_entry"))?;
        if !matches!(
            name,
            ".lock" | "current.envelope" | "previous.envelope" | "state.json"
        ) {
            return Err(HostEnvelopeError::new("host_cache_unsafe_entry"));
        }
        validate_private_regular_metadata(&entry.path(), owner_uid, "host_cache_unsafe_entry")?;
    }
    Ok(())
}

fn reject_partial_names(slot_dir: &Path) -> HostResult<()> {
    for entry in
        fs::read_dir(slot_dir).map_err(|_| HostEnvelopeError::new("host_cache_unavailable"))?
    {
        let entry = entry.map_err(|_| HostEnvelopeError::new("host_cache_unavailable"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| HostEnvelopeError::new("host_cache_unsafe_entry"))?;
        if name.ends_with(".tmp") {
            return Err(HostEnvelopeError::new("host_cache_partial_file"));
        }
    }
    Ok(())
}

fn write_state(path: &Path, mut state: HostSlotStateV1, owner_uid: u32) -> HostResult<()> {
    state.integrity_hash.clear();
    state.integrity_hash = state_integrity(&state)?;
    let raw = serde_json::to_vec(&state)
        .map_err(|_| HostEnvelopeError::new("host_cache_state_invalid"))?;
    atomic_write(
        path,
        &raw,
        0o600,
        owner_uid,
        "host_cache_state_write_failed",
    )
}

fn load_optional_state(path: &Path, owner_uid: u32) -> HostResult<Option<HostSlotStateV1>> {
    if !entry_exists(path, "host_cache_state_invalid")? {
        return Ok(None);
    }
    load_required_state(path, owner_uid).map(Some)
}

fn entry_exists(path: &Path, reason: &'static str) -> HostResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(HostEnvelopeError::new(reason)),
    }
}

fn load_required_state(path: &Path, owner_uid: u32) -> HostResult<HostSlotStateV1> {
    let raw = read_private_regular(
        path,
        MAX_CONFIG_BYTES,
        Some(owner_uid),
        "host_cache_state_invalid",
    )?;
    let state: HostSlotStateV1 = decode_strict_json(&raw, "host_cache_state_invalid")?;
    let expected = state_integrity(&state)?;
    if state.integrity_hash != expected {
        return Err(HostEnvelopeError::new("host_cache_state_tampered"));
    }
    Ok(state)
}

fn state_integrity(state: &HostSlotStateV1) -> HostResult<String> {
    let mut unsigned = state.clone();
    unsigned.integrity_hash.clear();
    let raw = serde_json::to_vec(&unsigned)
        .map_err(|_| HostEnvelopeError::new("host_cache_state_invalid"))?;
    Ok(sha256_hex(&raw))
}

fn cached_generation(binding: &HostEnvelopeBindingV1, packet_sha256: &str) -> CachedGenerationV1 {
    CachedGenerationV1 {
        envelope_ref: binding.envelope_ref.clone(),
        operation_ref: binding.operation_ref.clone(),
        generation: binding.generation,
        revocation_epoch: binding.revocation_epoch,
        expires_at_unix_secs: binding.expires_at_unix_secs,
        packet_sha256: packet_sha256.to_string(),
    }
}

fn outcome(
    action: &str,
    binding: &HostEnvelopeBindingV1,
    phase: &str,
    reason_code: &str,
) -> HostExecutorOutcome {
    HostExecutorOutcome {
        action: action.to_string(),
        host_ref: binding.host_ref.clone(),
        service_ref: Some(binding.service_ref.clone()),
        slot_ref: Some(binding.slot_ref.clone()),
        operation_ref: Some(binding.operation_ref.clone()),
        generation: Some(binding.generation),
        phase: phase.to_string(),
        reason_code: reason_code.to_string(),
        value_returned: false,
    }
}

fn outcome_from_control(
    action: &str,
    request: &HostEnvelopeControlV1,
    phase: &str,
    reason_code: &str,
) -> HostExecutorOutcome {
    HostExecutorOutcome {
        action: action.to_string(),
        host_ref: request.host_ref.clone(),
        service_ref: Some(request.service_ref.clone()),
        slot_ref: Some(request.slot_ref.clone()),
        operation_ref: Some(request.operation_ref.clone()),
        generation: Some(request.generation),
        phase: phase.to_string(),
        reason_code: reason_code.to_string(),
        value_returned: false,
    }
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        (8..=80).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }) && value.len() <= 96
}

fn decode_strict_json<T>(raw: &[u8], reason: &'static str) -> HostResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer).map_err(|_| HostEnvelopeError::new(reason))?;
    deserializer
        .end()
        .map_err(|_| HostEnvelopeError::new(reason))?;
    Ok(value)
}

fn validate_state_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(raw: &[u8]) -> String {
    let digest = Sha256::digest(raw);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_seconds(now: SystemTime) -> HostResult<u64> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HostEnvelopeError::new("host_clock_invalid"))
}

fn monotonic_nonce() -> HostResult<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| HostEnvelopeError::new("host_clock_invalid"))
}

fn sync_dir(path: &Path, reason: &'static str) -> HostResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| HostEnvelopeError::new(reason))
}

/// Read a bounded packet from stdin-equivalent input.
pub fn read_bounded_input<R: Read>(reader: &mut R, maximum: usize) -> HostResult<Vec<u8>> {
    let mut raw = Vec::new();
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| HostEnvelopeError::new("host_executor_input_invalid"))?;
    if raw.is_empty() || raw.len() > maximum {
        raw.zeroize();
        return Err(HostEnvelopeError::new("host_executor_input_invalid"));
    }
    Ok(raw)
}

/// Parse a strict control request.
pub fn parse_control(raw: &[u8]) -> HostResult<HostEnvelopeControlV1> {
    decode_strict_json(raw, "host_envelope_control_invalid")
}

/// Maximum accepted install packet size.
pub const fn maximum_packet_bytes() -> usize {
    MAX_PACKET_BYTES
}

/// Maximum accepted control request size.
pub const fn maximum_control_bytes() -> usize {
    4096
}

#[cfg(test)]
mod tests;

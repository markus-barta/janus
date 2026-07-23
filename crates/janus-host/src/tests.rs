use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use tempfile::TempDir;

use super::*;

const NOW: u64 = 1_800_000_000;
const SCOPE_REF: &str = "scp_0123456789abcdef0123456789abcdef01234567";
const HOST_REF: &str = "host_58f36c72a91e";
const SERVICE_REF: &str = "svc_0bca8d31f7e2";
const SLOT_REF: &str = "slot_49c0e8a17d63";
const SECRET_REF: &str = "sec_7a6fd9e3b521";
const DECLARATION_REF: &str = "decl_a84f209c4b32";
const KEY_REF: &str = "key_7f4a29c10e8d";

struct Fixture {
    _temporary: TempDir,
    executor: HostExecutor,
    recipient: String,
    signing_key: SigningKey,
    cache_root: PathBuf,
    runtime_root: PathBuf,
    identity_path: PathBuf,
    owner_uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let cache_root = temporary.path().join("cache");
        let runtime_root = temporary.path().join("runtime");
        private_dir(&cache_root);
        private_dir(&runtime_root);
        let owner_uid = fs::metadata(&cache_root).expect("cache metadata").uid();
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_path = temporary.path().join("identity.txt");
        fs::write(
            &identity_path,
            identity.to_string().expose_secret().as_bytes(),
        )
        .expect("write identity");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("identity permissions");
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let config = config(&signing_key, owner_uid);
        let executor = HostExecutor::new(
            config,
            ExecutorPaths {
                identity: identity_path.clone(),
                cache_root: cache_root.clone(),
                runtime_root: runtime_root.clone(),
            },
        )
        .expect("executor");
        Self {
            _temporary: temporary,
            executor,
            recipient,
            signing_key,
            cache_root,
            runtime_root,
            identity_path,
            owner_uid,
        }
    }

    fn packet(&self, generation: u64, value: &[u8]) -> Vec<u8> {
        packet(
            generation,
            generation,
            value,
            &self.recipient,
            &self.signing_key,
            HOST_REF,
            format!("env_{generation:08x}"),
            format!("op_{generation:08x}"),
        )
    }

    fn runtime_target(&self) -> PathBuf {
        self.runtime_root
            .join(SERVICE_REF)
            .join(format!("{SLOT_REF}.env"))
    }

    fn slot_cache(&self) -> PathBuf {
        self.cache_root.join(SLOT_REF)
    }
}

fn config(signing_key: &SigningKey, owner_uid: u32) -> HostExecutorConfigV1 {
    HostExecutorConfigV1 {
        schema: CONFIG_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        host_ref: HOST_REF.to_string(),
        scope_ref: SCOPE_REF.to_string(),
        owner_uid,
        minimum_revocation_epoch: 1,
        retired: false,
        producer_keys: vec![HostProducerKeyV1 {
            key_id: KEY_REF.to_string(),
            public_key: STANDARD_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        }],
        revoked_envelope_refs: Vec::new(),
        slots: vec![HostSecretSlotV1 {
            service_ref: SERVICE_REF.to_string(),
            slot_ref: SLOT_REF.to_string(),
            secret_ref: SECRET_REF.to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            minimum_generation: 1,
            rollback_window_seconds: 300,
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn packet(
    generation: u64,
    revocation_epoch: u64,
    value: &[u8],
    recipient: &str,
    signing_key: &SigningKey,
    host_ref: &str,
    envelope_ref: String,
    operation_ref: String,
) -> Vec<u8> {
    seal_host_envelope(HostEnvelopeSealRequest {
        binding: HostEnvelopeBindingV1 {
            schema: PAYLOAD_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            envelope_ref,
            operation_ref,
            host_ref: host_ref.to_string(),
            service_ref: SERVICE_REF.to_string(),
            slot_ref: SLOT_REF.to_string(),
            secret_ref: SECRET_REF.to_string(),
            scope_ref: SCOPE_REF.to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            generation,
            revocation_epoch,
            issued_at_unix_secs: NOW - 10,
            expires_at_unix_secs: NOW + 3600,
        },
        host_recipient: recipient,
        signing_key_id: KEY_REF,
        signing_key,
        value: SecretValue::new(value.to_vec()),
    })
    .expect("seal packet")
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

fn private_dir(path: &Path) {
    fs::create_dir(path).expect("create private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory mode");
}

fn control(generation: u64) -> HostEnvelopeControlV1 {
    HostEnvelopeControlV1 {
        schema: CONTROL_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        operation_ref: format!("op_{generation:08x}"),
        host_ref: HOST_REF.to_string(),
        service_ref: SERVICE_REF.to_string(),
        slot_ref: SLOT_REF.to_string(),
        generation,
    }
}

#[test]
fn install_caches_only_ciphertext_and_materializes_private_runtime_value() {
    let fixture = Fixture::new();
    let canary = b"host-envelope-canary-not-for-cache";
    let outcome = fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .expect("install");
    assert_eq!(outcome.phase, "materialized");
    assert!(!outcome.value_returned);
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("runtime value"),
        canary
    );
    let runtime_metadata = fs::metadata(fixture.runtime_target()).expect("runtime metadata");
    assert_eq!(runtime_metadata.mode() & 0o777, 0o400);
    assert_eq!(runtime_metadata.uid(), fixture.owner_uid);
    let cache = fs::read(fixture.slot_cache().join("current.envelope")).expect("cached envelope");
    assert!(!cache.windows(canary.len()).any(|window| window == canary));
    let cache_metadata =
        fs::metadata(fixture.slot_cache().join("current.envelope")).expect("cache metadata");
    assert_eq!(cache_metadata.mode() & 0o777, 0o600);
    assert_eq!(cache_metadata.nlink(), 1);
    let status = fixture.executor.status().expect("status");
    assert_eq!(status[0].phase, "active");
    assert_eq!(status[0].generation, Some(1));
}

#[test]
fn recipient_and_janus_signature_are_both_required() {
    let fixture = Fixture::new();
    let packet = fixture.packet(1, b"recipient-canary");

    let other_identity = age::x25519::Identity::generate();
    fs::write(
        &fixture.identity_path,
        other_identity.to_string().expose_secret().as_bytes(),
    )
    .expect("replace identity");
    fs::set_permissions(&fixture.identity_path, fs::Permissions::from_mode(0o600))
        .expect("identity mode");
    assert_eq!(
        fixture.executor.install(&packet, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_decrypt_denied")
    );

    let fixture = Fixture::new();
    let mut signed: SignedHostEnvelopeV1 =
        serde_json::from_slice(&fixture.packet(1, b"signature-canary")).expect("packet");
    let mut ciphertext = STANDARD_NO_PAD
        .decode(signed.ciphertext.as_bytes())
        .expect("ciphertext");
    ciphertext[8] ^= 0x01;
    signed.ciphertext = STANDARD_NO_PAD.encode(ciphertext);
    let tampered = serde_json::to_vec(&signed).expect("tampered packet");
    assert_eq!(
        fixture.executor.install(&tampered, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_signature_invalid")
    );
}

#[test]
fn exact_host_scope_slot_declaration_epoch_and_generation_are_enforced() {
    let fixture = Fixture::new();
    let wrong_host = packet(
        1,
        1,
        b"wrong-host",
        &fixture.recipient,
        &fixture.signing_key,
        "host_ffffffffffff",
        "env_ffffffff".to_string(),
        "op_ffffffff".to_string(),
    );
    assert_eq!(
        fixture.executor.install(&wrong_host, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_binding_denied")
    );

    fixture
        .executor
        .install(&fixture.packet(2, b"generation-two"), now())
        .expect("new generation");
    assert_eq!(
        fixture
            .executor
            .install(&fixture.packet(1, b"downgrade"), now())
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_generation_downgrade")
    );

    let mut revoked_config = config(&fixture.signing_key, fixture.owner_uid);
    revoked_config.minimum_revocation_epoch = 5;
    let revoked = HostExecutor::new(
        revoked_config,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.join("revoked-cache"),
            runtime_root: fixture.runtime_root.join("revoked-runtime"),
        },
    )
    .expect("revocation executor");
    private_dir(&fixture.cache_root.join("revoked-cache"));
    private_dir(&fixture.runtime_root.join("revoked-runtime"));
    assert_eq!(
        revoked
            .install(
                &packet(
                    6,
                    4,
                    b"revoked-epoch",
                    &fixture.recipient,
                    &fixture.signing_key,
                    HOST_REF,
                    "env_00000006".to_string(),
                    "op_00000006".to_string(),
                ),
                now(),
            )
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_binding_denied")
    );
}

#[test]
fn replacement_preserves_one_bounded_rollback_generation_then_commit_destroys_it() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"first-generation"), now())
        .expect("first");
    fixture
        .executor
        .install(&fixture.packet(2, b"second-generation"), now())
        .expect("second");
    assert!(fixture.slot_cache().join("previous.envelope").is_file());
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("second runtime"),
        b"second-generation"
    );
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "staged"
    );
    fixture.executor.commit(&control(2)).expect("commit");
    assert!(!fixture.slot_cache().join("previous.envelope").exists());
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "active"
    );
    assert_eq!(
        fixture.executor.rollback(&control(2), now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_not_available")
    );
}

#[test]
fn rollback_and_offline_reboot_restore_the_exact_previous_generation() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable-generation"), now())
        .expect("first");
    fixture
        .executor
        .install(&fixture.packet(2, b"failed-generation"), now())
        .expect("second");
    let rollback = fixture
        .executor
        .rollback(&control(2), now() + Duration::from_secs(30))
        .expect("rollback");
    assert_eq!(rollback.phase, "rolled_back");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("rolled back runtime"),
        b"stable-generation"
    );
    fs::remove_file(fixture.runtime_target()).expect("simulate reboot tmpfs");
    let restored = fixture
        .executor
        .restore_all(now() + Duration::from_secs(60))
        .expect("offline restore");
    assert_eq!(restored[0].reason_code, "host_envelope_restored_offline");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("restored runtime"),
        b"stable-generation"
    );
}

#[test]
fn interrupted_atomic_replace_is_reconciled_without_accepting_partial_bytes() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable-before-crash"), now())
        .expect("first");
    let current = fixture.slot_cache().join("current.envelope");
    let previous = fixture.slot_cache().join("previous.envelope");

    fs::hard_link(&current, &previous).expect("simulate crash before replace");
    assert_eq!(
        fixture
            .executor
            .restore_all(now() + Duration::from_secs(5))
            .unwrap_err(),
        HostEnvelopeError::new("host_cache_current_unavailable")
    );
    fs::remove_file(&previous).expect("remove rejected hardlink");
    assert_eq!(fs::metadata(&current).expect("current metadata").nlink(), 1);

    atomic_write(
        &previous,
        &fs::read(&current).expect("current packet"),
        0o600,
        fixture.owner_uid,
        "test_write_failed",
    )
    .expect("preserve old generation");
    atomic_write(
        &current,
        &fixture.packet(2, b"new-after-crash"),
        0o600,
        fixture.owner_uid,
        "test_write_failed",
    )
    .expect("simulate replace before state");
    fs::remove_file(fixture.runtime_target()).expect("simulate tmpfs reset");
    fixture
        .executor
        .restore_all(now() + Duration::from_secs(10))
        .expect("state recovery");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("recovered runtime"),
        b"new-after-crash"
    );
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "staged"
    );
}

#[test]
fn expired_envelopes_and_expired_rollback_windows_fail_closed() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable"), now())
        .expect("first");
    fixture
        .executor
        .install(&fixture.packet(2, b"staged"), now())
        .expect("second");
    assert_eq!(
        fixture
            .executor
            .rollback(&control(2), now() + Duration::from_secs(301))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_expired")
    );
    assert_eq!(
        fixture
            .executor
            .restore_all(now() + Duration::from_secs(301))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_expired")
    );

    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .executor
            .install(
                &fixture.packet(1, b"expired"),
                now() + Duration::from_secs(3600),
            )
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_expired")
    );
}

#[test]
fn partial_symlink_hardlink_and_tampered_cache_objects_are_rejected() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"safe-cache"), now())
        .expect("install");
    let partial = fixture.slot_cache().join(".interrupted.tmp");
    fs::write(&partial, b"partial").expect("partial");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).expect("partial mode");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_partial_file")
    );
    fs::remove_file(&partial).expect("remove test partial");

    let current = fixture.slot_cache().join("current.envelope");
    let outside = fixture.cache_root.join("outside");
    fs::write(&outside, b"outside").expect("outside");
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
    fs::remove_file(&current).expect("remove current");
    symlink(&outside, &current).expect("symlink current");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_unsafe_entry")
    );

    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"hardlink-cache"), now())
        .expect("install");
    fs::hard_link(
        fixture.slot_cache().join("current.envelope"),
        fixture.cache_root.join("linked-envelope"),
    )
    .expect("hard link");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_unsafe_entry")
    );

    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"state-cache"), now())
        .expect("install");
    let state = fixture.slot_cache().join("state.json");
    let mut raw = fs::read(&state).expect("state");
    let byte = raw
        .iter_mut()
        .find(|byte| **byte == b'1')
        .expect("state digit");
    *byte = b'2';
    fs::write(&state, raw).expect("tamper state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).expect("state mode");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_state_tampered")
    );
}

#[test]
fn retired_host_removes_runtime_and_bounded_input_rejects_oversize() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"retired-host"), now())
        .expect("install");
    let mut retired_config = config(&fixture.signing_key, fixture.owner_uid);
    retired_config.retired = true;
    let retired = HostExecutor::new(
        retired_config,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.clone(),
            runtime_root: fixture.runtime_root.clone(),
        },
    )
    .expect("retired executor");
    assert_eq!(
        retired.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_executor_retired")
    );
    assert!(!fixture.runtime_target().exists());

    let mut oversized = Cursor::new(vec![b'x'; 17]);
    assert_eq!(
        read_bounded_input(&mut oversized, 16).unwrap_err(),
        HostEnvelopeError::new("host_executor_input_invalid")
    );
}

#[test]
fn errors_status_and_persisted_metadata_never_echo_the_canary() {
    let fixture = Fixture::new();
    let canary = b"literal-super-secret-canary";
    fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .expect("install");
    let status = serde_json::to_vec(&fixture.executor.status().expect("status")).expect("json");
    let state = fs::read(fixture.slot_cache().join("state.json")).expect("state");
    let packet = fs::read(fixture.slot_cache().join("current.envelope")).expect("packet");
    for surface in [&status[..], &state[..], &packet[..]] {
        assert!(!surface.windows(canary.len()).any(|window| window == canary));
    }
    let error = fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("canary"));
}

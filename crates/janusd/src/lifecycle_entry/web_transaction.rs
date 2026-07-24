//! Fixed-protocol local boundary between the web envelope and lifecycle entry.
//!
//! The peer selects only opaque declaration and operation references. Every
//! path, backend, hook, generation policy, and lifecycle transition comes from
//! the server-owned reviewed catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use janus_core::ReleaseAdmission;
use janus_host::{seal_host_envelope, HostEnvelopeBindingV1, HostEnvelopeSealRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use zeroize::Zeroize;

use super::{
    read_regular_bounded, scan_journal_summaries, stable_error_reason, validate_plan, EntryPhase,
    EntryPlan, EntryPlanFile, EntrySource, EntryStatus, EntryTransaction,
    ManagedEntryOperationKind,
};

const CATALOG_SCHEMA: &str = "inspr.janus.managed-web-transaction-catalog.v2";
const REQUEST_SCHEMA: &str = "inspr.janus.managed-web-transaction-request.v2";
const RESPONSE_SCHEMA: &str = "inspr.janus.managed-web-transaction-response.v2";
const DELIVERY_PLAN_SCHEMA: &str = "inspr.janus.managed-host-delivery-plan.v1";
const OUTBOX_SCHEMA: &str = "inspr.janus.managed-host-envelope-outbox.v1";
const SIGNING_KEY_SCHEMA: &str = "inspr.janus.host-envelope-signing-key.v1";
const HOST_PAYLOAD_SCHEMA: &str = "inspr.janus.host-envelope-payload.v1";
const SCHEMA_VERSION: u8 = 2;
const DELIVERY_SCHEMA_VERSION: u8 = 1;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CATALOG_ENTRIES: usize = 256;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const VALUE_WAIT: Duration = Duration::from_secs(30);
const MAX_SIGNING_KEY_BYTES: usize = 4096;
const MAX_OUTBOX_BYTES: usize = 512 * 1024;
const MAX_DELIVERY_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const EXTERNAL_HEALTH_FRESHNESS_SECONDS: u64 = 120;
const EXTERNAL_CLOCK_SKEW_SECONDS: u64 = 30;
const SOCKET_ENV: &str = "JANUS_MANAGED_WEB_TRANSACTION_SOCKET";
const CATALOG_ENV: &str = "JANUS_MANAGED_WEB_TRANSACTION_CATALOG_FILE";
const PEER_UID_ENV: &str = "JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionCatalog {
    schema: String,
    schema_version: u8,
    entries: Vec<TransactionCatalogEntry>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionCatalogEntry {
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    operation_kind: String,
    plan: EntryPlanFile,
    delivery: HostDeliveryPlan,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostDeliveryPlan {
    schema: String,
    schema_version: u8,
    host_recipient: String,
    producer_key_id: String,
    producer_signing_key_file: PathBuf,
    outbox_dir: PathBuf,
    generation: u64,
    revocation_epoch: u64,
    envelope_ttl_seconds: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostProducerSigningKeyFile {
    schema: String,
    schema_version: u8,
    key_id: String,
    private_key_base64: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalActivationEvidence {
    generation: u64,
    materialized: bool,
    process_state: String,
    probe_state: String,
    heartbeat_observed_at_unix_secs: u64,
    process_observed_at_unix_secs: u64,
    probe_observed_at_unix_secs: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalRemovalEvidence {
    generation: u64,
    runtime_absent: bool,
    process_state: String,
    cache_state: String,
    heartbeat_observed_at_unix_secs: u64,
    process_observed_at_unix_secs: u64,
    cache_observed_at_unix_secs: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostEnvelopeOutboxRecord {
    schema: String,
    schema_version: u8,
    operation_ref: String,
    operation_kind: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    secret_ref: String,
    scope_ref: String,
    declaration_fingerprint: String,
    envelope_ref: String,
    generation: u64,
    revocation_epoch: u64,
    prepared_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    packet_base64: String,
    value_returned: bool,
    integrity_hash: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionRequest {
    schema: String,
    schema_version: u8,
    action: String,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    #[serde(default)]
    purge_not_before_unix_secs: u64,
    external_evidence: Option<ExternalActivationEvidence>,
    #[serde(default)]
    external_removal_evidence: Option<ExternalRemovalEvidence>,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionResponse {
    schema: &'static str,
    schema_version: u8,
    operation_ref: Option<String>,
    secret_ref: Option<String>,
    mode: Option<String>,
    generation: Option<u64>,
    phase: String,
    reason_code: String,
    expects_value: bool,
    value_returned: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CatalogKey {
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    operation_kind: String,
    source: String,
}

#[derive(Clone)]
struct ReviewedCatalog {
    entries: BTreeMap<CatalogKey, TransactionCatalogEntry>,
}

struct SecretBuffer(Vec<u8>);

#[derive(Debug)]
struct WebTransactionError(&'static str);

impl std::fmt::Display for WebTransactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for WebTransactionError {}

impl SecretBuffer {
    fn into_secret_value(mut self) -> janus_core::SecretValue {
        janus_core::SecretValue::new(std::mem::take(&mut self.0))
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) async fn run_from_env() -> Result<()> {
    let socket_path = required_absolute_path(SOCKET_ENV)?;
    let catalog_path = required_absolute_path(CATALOG_ENV)?;
    let allowed_uid = required_uid()?;
    let catalog = Arc::new(load_catalog(&catalog_path)?);

    let principal =
        super::super::release_principal_from_env().context("web transaction principal denied")?;
    let release = janus_local::enforce_release_admission_from_env(&principal)
        .context("web transaction release admission denied")?;
    janus_local::enforce_migration_ready_from_env()
        .context("web transaction migration state denied")?;
    janus_local::enforce_scope_transfer_ready_from_env()
        .context("web transaction scope transfer state denied")?;

    reconcile_catalog(&catalog, &release)
        .await
        .context("web transaction startup reconciliation denied")?;
    let listener = bind_private_socket(&socket_path)?;
    let connections = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let permit = Arc::clone(&connections)
            .acquire_owned()
            .await
            .context("web transaction connection limiter unavailable")?;
        let (stream, _) = listener
            .accept()
            .await
            .context("web transaction socket accept failed")?;
        let peer = stream
            .peer_cred()
            .context("web transaction peer credentials unavailable")?;
        if peer.uid() != allowed_uid {
            let mut denied = stream;
            let _ = write_response(
                &mut denied,
                &denied_response(None, "web_transaction_peer_denied"),
            )
            .await;
            continue;
        }
        let catalog = Arc::clone(&catalog);
        let release = release.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(stream, &catalog, release).await;
        });
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    catalog: &ReviewedCatalog,
    release: ReleaseAdmission,
) {
    let request = match timeout(
        REQUEST_WAIT,
        read_json_frame::<TransactionRequest>(&mut stream, MAX_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Err(_) => {
            let _ = write_response(
                &mut stream,
                &denied_response(None, "web_transaction_request_timeout"),
            )
            .await;
            return;
        }
        Ok(Err(_)) => {
            let _ = write_response(
                &mut stream,
                &denied_response(None, "web_transaction_protocol_invalid"),
            )
            .await;
            return;
        }
    };
    let operation_ref = if valid_ref("op_", &request.operation_ref) {
        Some(request.operation_ref.clone())
    } else {
        None
    };
    let entry = match catalog.resolve(&request) {
        Ok(entry) => entry,
        Err(reason) => {
            let _ = write_response(&mut stream, &denied_response(operation_ref, reason)).await;
            return;
        }
    };
    let transaction = match transaction_for(entry, &request.operation_ref, release) {
        Ok(transaction) => transaction,
        Err(error) => {
            let _ = write_response(
                &mut stream,
                &denied_response(operation_ref, stable_web_error_reason(&error)),
            )
            .await;
            return;
        }
    };

    if request.action == "finalize" {
        let response = if request.operation_kind == "remove" {
            finalize_prepared_removal(&transaction, &request, SystemTime::now()).await
        } else {
            finalize_prepared_operation(&transaction, entry, &request, SystemTime::now()).await
        }
        .unwrap_or_else(|error| denied_response(operation_ref, stable_web_error_reason(&error)));
        let _ = write_response(&mut stream, &response).await;
        return;
    }
    if request.action == "purge" {
        let response = transaction
            .purge_removal(SystemTime::now())
            .await
            .map(|status| {
                response_from_status(
                    &request.operation_ref,
                    &status,
                    false,
                    Some(status.generation),
                )
            })
            .unwrap_or_else(|error| {
                denied_response(operation_ref, stable_web_error_reason(&error))
            });
        let _ = write_response(&mut stream, &response).await;
        return;
    }
    if request.action == "rollback" {
        let response = rollback_prepared_operation(&transaction, entry, &request)
            .await
            .unwrap_or_else(|error| {
                denied_response(operation_ref, stable_web_error_reason(&error))
            });
        let _ = write_response(&mut stream, &response).await;
        return;
    }

    if request.operation_kind == "remove" {
        let response = match transaction.status().await {
            Ok(status) if status.phase == EntryPhase::Validated => {
                prepared_removal_response(&request, &status)
            }
            Ok(status)
                if matches!(
                    status.phase,
                    EntryPhase::Completed | EntryPhase::Destroyed | EntryPhase::RolledBack
                ) =>
            {
                response_from_status(
                    &request.operation_ref,
                    &status,
                    false,
                    Some(status.generation),
                )
            }
            Ok(_) => denied_response(operation_ref, "web_transaction_removal_incomplete"),
            Err(_) => transaction
                .prepare_removal(SystemTime::now(), request.purge_not_before_unix_secs)
                .await
                .map(|status| prepared_removal_response(&request, &status))
                .unwrap_or_else(|error| {
                    denied_response(operation_ref, stable_web_error_reason(&error))
                }),
        };
        let _ = write_response(&mut stream, &response).await;
        return;
    }

    match transaction.status().await {
        Ok(status) if status.phase == EntryPhase::Completed => {
            let response = match transaction.finish_completed_cleanup().await {
                Ok(status) => response_from_status(
                    &request.operation_ref,
                    &status,
                    false,
                    Some(status.generation),
                ),
                Err(error) => denied_response(operation_ref, stable_web_error_reason(&error)),
            };
            let _ = write_response(&mut stream, &response).await;
            return;
        }
        Ok(status) if status.phase == EntryPhase::RolledBack => {
            let _ = write_response(
                &mut stream,
                &response_from_status(
                    &request.operation_ref,
                    &status,
                    false,
                    Some(status.generation),
                ),
            )
            .await;
            return;
        }
        Ok(status) if status.phase == EntryPhase::Validated => {
            let response =
                match load_bound_outbox(entry, &request, status.generation, SystemTime::now()) {
                    Ok(record) => prepared_response(&request, &status, record.generation),
                    Err(error) => {
                        let _ = transaction.rollback().await;
                        denied_response(operation_ref, stable_web_error_reason(&error))
                    }
                };
            let _ = write_response(&mut stream, &response).await;
            return;
        }
        Ok(_) => {
            let status = transaction.rollback().await;
            let response = match status {
                Ok(status) => response_from_status(
                    &request.operation_ref,
                    &status,
                    false,
                    Some(status.generation),
                ),
                Err(error) => denied_response(operation_ref, stable_web_error_reason(&error)),
            };
            let _ = write_response(&mut stream, &response).await;
            return;
        }
        Err(_) => {}
    }

    let preflight = match transaction.preflight(SystemTime::now()).await {
        Ok(status) => status,
        Err(error) => {
            let _ = write_response(
                &mut stream,
                &denied_response(operation_ref, stable_web_error_reason(&error)),
            )
            .await;
            return;
        }
    };
    let expects_value = matches!(entry.plan.source, EntrySource::Import);
    if write_response(
        &mut stream,
        &response_from_status(&request.operation_ref, &preflight, expects_value, None),
    )
    .await
    .is_err()
    {
        let _ = transaction.rollback().await;
        return;
    }

    let applied = match &entry.plan.source {
        EntrySource::Generated { .. } => transaction.apply_generated(SystemTime::now()).await,
        EntrySource::Import => {
            let value = match timeout(
                VALUE_WAIT,
                read_raw_frame(&mut stream, entry.plan.input_max_bytes),
            )
            .await
            {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => {
                    let _ = transaction.rollback().await;
                    let _ = write_response(
                        &mut stream,
                        &denied_response(operation_ref, "web_transaction_value_invalid"),
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    let _ = transaction.rollback().await;
                    let _ = write_response(
                        &mut stream,
                        &denied_response(operation_ref, "web_transaction_value_timeout"),
                    )
                    .await;
                    return;
                }
            };
            transaction
                .apply_import_value(value.into_secret_value(), SystemTime::now())
                .await
        }
        EntrySource::Remove => {
            Err(WebTransactionError("web_transaction_removal_value_denied").into())
        }
    };
    if let Err(error) = applied {
        let _ = transaction.rollback().await;
        let _ = write_response(
            &mut stream,
            &denied_response(operation_ref, stable_web_error_reason(&error)),
        )
        .await;
        return;
    }
    let response =
        match prepare_host_delivery(&transaction, entry, &request, SystemTime::now()).await {
            Ok((status, generation)) => prepared_response(&request, &status, generation),
            Err(error) => {
                let _ = transaction.rollback().await;
                denied_response(operation_ref, stable_web_error_reason(&error))
            }
        };
    let _ = write_response(&mut stream, &response).await;
}

impl ReviewedCatalog {
    fn resolve(
        &self,
        request: &TransactionRequest,
    ) -> std::result::Result<&TransactionCatalogEntry, &'static str> {
        if request.schema != REQUEST_SCHEMA
            || request.schema_version != SCHEMA_VERSION
            || !matches!(
                request.action.as_str(),
                "prepare" | "finalize" | "rollback" | "purge"
            )
            || !valid_ref("op_", &request.operation_ref)
            || !valid_ref("host_", &request.host_ref)
            || !valid_ref("svc_", &request.service_ref)
            || !valid_ref("slot_", &request.slot_ref)
            || !valid_ref("decl_", &request.declaration_fingerprint)
            || !matches!(
                request.operation_kind.as_str(),
                "create" | "replace" | "remove"
            )
            || !matches!(request.source.as_str(), "generated" | "import" | "remove")
            || (request.operation_kind == "remove") != (request.source == "remove")
            || request.operation_kind == "remove" && request.purge_not_before_unix_secs == 0
            || request.operation_kind != "remove" && request.purge_not_before_unix_secs != 0
            || request.action == "prepare"
                && (request.external_evidence.is_some()
                    || request.external_removal_evidence.is_some())
            || request.action == "rollback"
                && (request.external_evidence.is_some()
                    || request.external_removal_evidence.is_some())
            || request.action == "purge"
                && (request.operation_kind != "remove"
                    || request.external_evidence.is_some()
                    || request.external_removal_evidence.is_some())
            || request.action == "finalize"
                && match request.operation_kind.as_str() {
                    "remove" => {
                        request.external_evidence.is_some()
                            || request.external_removal_evidence.is_none()
                    }
                    "create" | "replace" => {
                        request.external_evidence.is_none()
                            || request.external_removal_evidence.is_some()
                    }
                    _ => true,
                }
        {
            return Err("web_transaction_request_invalid");
        }
        let key = CatalogKey {
            host_ref: request.host_ref.clone(),
            service_ref: request.service_ref.clone(),
            slot_ref: request.slot_ref.clone(),
            declaration_fingerprint: request.declaration_fingerprint.clone(),
            operation_kind: request.operation_kind.clone(),
            source: request.source.clone(),
        };
        self.entries
            .get(&key)
            .ok_or("web_transaction_declaration_denied")
    }
}

fn load_catalog(path: &Path) -> Result<ReviewedCatalog> {
    let bytes = read_regular_bounded(path, MAX_CATALOG_BYTES, true)?;
    let catalog: TransactionCatalog = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("web transaction catalog is invalid"))?;
    if catalog.schema != CATALOG_SCHEMA
        || catalog.schema_version != SCHEMA_VERSION
        || catalog.entries.is_empty()
        || catalog.entries.len() > MAX_CATALOG_ENTRIES
    {
        anyhow::bail!("web transaction catalog contract is invalid");
    }
    let mut entries = BTreeMap::new();
    for entry in catalog.entries {
        validate_catalog_entry(&entry)?;
        let key = CatalogKey {
            host_ref: entry.host_ref.clone(),
            service_ref: entry.service_ref.clone(),
            slot_ref: entry.slot_ref.clone(),
            declaration_fingerprint: entry.declaration_fingerprint.clone(),
            operation_kind: entry.operation_kind.clone(),
            source: if entry.operation_kind == "remove" {
                "remove".to_string()
            } else {
                entry.plan.source.mode().to_string()
            },
        };
        if entries.insert(key, entry).is_some() {
            anyhow::bail!("web transaction catalog entries must be unique");
        }
    }
    Ok(ReviewedCatalog { entries })
}

fn validate_catalog_entry(entry: &TransactionCatalogEntry) -> Result<()> {
    if !valid_ref("host_", &entry.host_ref)
        || !valid_ref("svc_", &entry.service_ref)
        || !valid_ref("slot_", &entry.slot_ref)
        || !valid_ref("decl_", &entry.declaration_fingerprint)
        || !matches!(
            entry.operation_kind.as_str(),
            "create" | "replace" | "remove"
        )
        || entry.plan.operation_id != "web-transaction-template"
    {
        anyhow::bail!("web transaction catalog entry is invalid");
    }
    validate_delivery_plan(&entry.delivery)?;
    let mut plan = entry.plan.clone();
    if entry.operation_kind == "remove" {
        plan.source = EntrySource::Remove;
    }
    validate_plan(&plan, SystemTime::now())?;
    Ok(())
}

fn validate_delivery_plan(plan: &HostDeliveryPlan) -> Result<()> {
    if plan.schema != DELIVERY_PLAN_SCHEMA
        || plan.schema_version != DELIVERY_SCHEMA_VERSION
        || !valid_ref("key_", &plan.producer_key_id)
        || !plan.host_recipient.starts_with("ssh-ed25519 ")
        || plan.host_recipient.len() > 1024
        || !plan.producer_signing_key_file.is_absolute()
        || plan.producer_signing_key_file.file_name().is_none()
        || !plan.outbox_dir.is_absolute()
        || plan.outbox_dir.file_name().is_none()
        || plan.generation == 0
        || plan.revocation_epoch == 0
        || !(60..=MAX_DELIVERY_TTL_SECONDS).contains(&plan.envelope_ttl_seconds)
    {
        anyhow::bail!("web transaction delivery plan is invalid");
    }
    load_signing_key(plan)?;
    super::ensure_private_dir(&plan.outbox_dir)?;
    Ok(())
}

fn load_signing_key(plan: &HostDeliveryPlan) -> Result<SigningKey> {
    let raw = read_regular_bounded(&plan.producer_signing_key_file, MAX_SIGNING_KEY_BYTES, true)
        .map_err(|_| WebTransactionError("web_transaction_signing_key_unavailable"))?;
    let document: HostProducerSigningKeyFile = serde_json::from_slice(&raw)
        .map_err(|_| WebTransactionError("web_transaction_signing_key_invalid"))?;
    if document.schema != SIGNING_KEY_SCHEMA
        || document.schema_version != DELIVERY_SCHEMA_VERSION
        || document.key_id != plan.producer_key_id
    {
        return Err(WebTransactionError("web_transaction_signing_key_invalid").into());
    }
    let raw_key = STANDARD_NO_PAD
        .decode(document.private_key_base64.as_bytes())
        .map_err(|_| WebTransactionError("web_transaction_signing_key_invalid"))?;
    let key_bytes: [u8; 32] = raw_key
        .try_into()
        .map_err(|_| WebTransactionError("web_transaction_signing_key_invalid"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

async fn prepare_host_delivery(
    transaction: &EntryTransaction,
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
    now: SystemTime,
) -> Result<(EntryStatus, u64)> {
    let status = transaction.status().await?;
    if status.phase != EntryPhase::Validated
        || status.operation_kind != request.operation_kind
        || status.generation == 0
    {
        return Err(WebTransactionError("web_transaction_delivery_phase_invalid").into());
    }
    let generation = status.generation;
    let existing_path = outbox_path(entry, &request.operation_ref)?;
    if existing_path.exists() {
        let existing = load_bound_outbox(entry, request, generation, now)?;
        return Ok((status, existing.generation));
    }
    let prepared_at = unix_seconds(now)?;
    let expires_at = prepared_at
        .checked_add(entry.delivery.envelope_ttl_seconds)
        .ok_or(WebTransactionError("web_transaction_delivery_invalid"))?;
    let value = transaction.staged_value_for_host_delivery().await?;
    let signing_key = load_signing_key(&entry.delivery)?;
    let envelope_ref = deterministic_envelope_ref(&request.operation_ref, generation);
    let packet = seal_host_envelope(HostEnvelopeSealRequest {
        binding: HostEnvelopeBindingV1 {
            schema: HOST_PAYLOAD_SCHEMA.to_string(),
            schema_version: DELIVERY_SCHEMA_VERSION,
            envelope_ref: envelope_ref.clone(),
            operation_ref: request.operation_ref.clone(),
            host_ref: request.host_ref.clone(),
            service_ref: request.service_ref.clone(),
            slot_ref: request.slot_ref.clone(),
            secret_ref: entry.plan.secret_ref.clone(),
            scope_ref: entry.plan.expected_scope_ref.clone(),
            declaration_fingerprint: request.declaration_fingerprint.clone(),
            generation,
            revocation_epoch: entry.delivery.revocation_epoch,
            issued_at_unix_secs: prepared_at,
            expires_at_unix_secs: expires_at,
        },
        host_recipient: &entry.delivery.host_recipient,
        signing_key_id: &entry.delivery.producer_key_id,
        signing_key: &signing_key,
        value,
    })
    .map_err(|_| WebTransactionError("web_transaction_delivery_seal_failed"))?;
    let mut record = HostEnvelopeOutboxRecord {
        schema: OUTBOX_SCHEMA.to_string(),
        schema_version: DELIVERY_SCHEMA_VERSION,
        operation_ref: request.operation_ref.clone(),
        operation_kind: request.operation_kind.clone(),
        host_ref: request.host_ref.clone(),
        service_ref: request.service_ref.clone(),
        slot_ref: request.slot_ref.clone(),
        secret_ref: entry.plan.secret_ref.clone(),
        scope_ref: entry.plan.expected_scope_ref.clone(),
        declaration_fingerprint: request.declaration_fingerprint.clone(),
        envelope_ref,
        generation,
        revocation_epoch: entry.delivery.revocation_epoch,
        prepared_at_unix_secs: prepared_at,
        expires_at_unix_secs: expires_at,
        packet_base64: STANDARD_NO_PAD.encode(packet),
        value_returned: false,
        integrity_hash: String::new(),
    };
    record.integrity_hash = outbox_hash(&record)?;
    let mut encoded = serde_json::to_vec_pretty(&record)
        .map_err(|_| WebTransactionError("web_transaction_delivery_invalid"))?;
    encoded.push(b'\n');
    super::write_private_atomic(&outbox_path(entry, &request.operation_ref)?, &encoded)
        .map_err(|_| WebTransactionError("web_transaction_delivery_persistence_failed"))?;
    Ok((status, record.generation))
}

fn load_bound_outbox(
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
    expected_generation: u64,
    now: SystemTime,
) -> Result<HostEnvelopeOutboxRecord> {
    load_bound_outbox_internal(entry, request, expected_generation, now, false)
}

fn load_bound_outbox_internal(
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
    expected_generation: u64,
    now: SystemTime,
    allow_expired: bool,
) -> Result<HostEnvelopeOutboxRecord> {
    let raw = read_regular_bounded(
        &outbox_path(entry, &request.operation_ref)?,
        MAX_OUTBOX_BYTES,
        true,
    )
    .map_err(|_| WebTransactionError("web_transaction_delivery_unavailable"))?;
    let record: HostEnvelopeOutboxRecord = serde_json::from_slice(&raw)
        .map_err(|_| WebTransactionError("web_transaction_delivery_invalid"))?;
    let now = unix_seconds(now)?;
    if record.schema != OUTBOX_SCHEMA
        || record.schema_version != DELIVERY_SCHEMA_VERSION
        || record.operation_ref != request.operation_ref
        || record.operation_kind != request.operation_kind
        || record.host_ref != request.host_ref
        || record.service_ref != request.service_ref
        || record.slot_ref != request.slot_ref
        || record.secret_ref != entry.plan.secret_ref
        || record.scope_ref != entry.plan.expected_scope_ref
        || record.declaration_fingerprint != request.declaration_fingerprint
        || record.generation != expected_generation
        || record.generation < entry.delivery.generation
        || record.revocation_epoch != entry.delivery.revocation_epoch
        || record.prepared_at_unix_secs == 0
        || record.expires_at_unix_secs <= record.prepared_at_unix_secs
        || !allow_expired && now >= record.expires_at_unix_secs
        || record.value_returned
        || !valid_ref("env_", &record.envelope_ref)
        || record.integrity_hash != outbox_hash(&record)?
    {
        return Err(WebTransactionError("web_transaction_delivery_invalid").into());
    }
    let packet = STANDARD_NO_PAD
        .decode(record.packet_base64.as_bytes())
        .map_err(|_| WebTransactionError("web_transaction_delivery_invalid"))?;
    if packet.is_empty() || packet.len() > janus_host::maximum_packet_bytes() {
        return Err(WebTransactionError("web_transaction_delivery_invalid").into());
    }
    Ok(record)
}

async fn finalize_prepared_operation(
    transaction: &EntryTransaction,
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
    now: SystemTime,
) -> Result<TransactionResponse> {
    let status = transaction.status().await?;
    if status.operation_kind != request.operation_kind || status.generation == 0 {
        return Err(WebTransactionError("web_transaction_finalize_phase_invalid").into());
    }
    if status.phase == EntryPhase::Completed {
        let status = transaction.finish_completed_cleanup().await?;
        remove_outbox_if_present(entry, request, status.generation)?;
        return Ok(response_from_status(
            &request.operation_ref,
            &status,
            false,
            Some(status.generation),
        ));
    }
    if status.phase != EntryPhase::Validated {
        return Err(WebTransactionError("web_transaction_finalize_phase_invalid").into());
    }
    let record = load_bound_outbox(entry, request, status.generation, now)?;
    validate_external_evidence(
        request
            .external_evidence
            .as_ref()
            .ok_or(WebTransactionError("web_transaction_evidence_invalid"))?,
        &record,
        now,
    )?;
    let completed = transaction
        .activate_after_external_verification(now)
        .await?;
    remove_outbox_if_present(entry, request, record.generation)?;
    Ok(response_from_status(
        &request.operation_ref,
        &completed,
        false,
        Some(record.generation),
    ))
}

async fn finalize_prepared_removal(
    transaction: &EntryTransaction,
    request: &TransactionRequest,
    now: SystemTime,
) -> Result<TransactionResponse> {
    let status = transaction.status().await?;
    if status.operation_kind != "remove"
        || status.generation == 0
        || status.generation
            != request
                .external_removal_evidence
                .as_ref()
                .map(|evidence| evidence.generation)
                .unwrap_or_default()
    {
        return Err(WebTransactionError("web_transaction_evidence_invalid").into());
    }
    if status.phase == EntryPhase::Completed {
        return Ok(response_from_status(
            &request.operation_ref,
            &status,
            false,
            Some(status.generation),
        ));
    }
    if !matches!(status.phase, EntryPhase::Validated | EntryPhase::Activating) {
        return Err(WebTransactionError("web_transaction_finalize_phase_invalid").into());
    }
    validate_external_removal_evidence(
        request
            .external_removal_evidence
            .as_ref()
            .ok_or(WebTransactionError("web_transaction_evidence_invalid"))?,
        now,
    )?;
    let completed = transaction
        .finalize_removal(now, request.purge_not_before_unix_secs)
        .await?;
    Ok(response_from_status(
        &request.operation_ref,
        &completed,
        false,
        Some(completed.generation),
    ))
}

fn validate_external_removal_evidence(
    evidence: &ExternalRemovalEvidence,
    now: SystemTime,
) -> Result<()> {
    let now = unix_seconds(now)?;
    let oldest = [
        evidence.heartbeat_observed_at_unix_secs,
        evidence.process_observed_at_unix_secs,
        evidence.cache_observed_at_unix_secs,
    ]
    .into_iter()
    .min()
    .unwrap_or_default();
    let newest = [
        evidence.heartbeat_observed_at_unix_secs,
        evidence.process_observed_at_unix_secs,
        evidence.cache_observed_at_unix_secs,
    ]
    .into_iter()
    .max()
    .unwrap_or_default();
    if evidence.generation == 0
        || !evidence.runtime_absent
        || evidence.process_state != "stopped"
        || evidence.cache_state != "quarantined"
        || oldest == 0
        || newest > now.saturating_add(EXTERNAL_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(oldest) > EXTERNAL_HEALTH_FRESHNESS_SECONDS
    {
        return Err(WebTransactionError("web_transaction_evidence_invalid").into());
    }
    Ok(())
}

async fn rollback_prepared_operation(
    transaction: &EntryTransaction,
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
) -> Result<TransactionResponse> {
    let status = transaction.status().await?;
    if status.operation_kind != request.operation_kind || status.generation == 0 {
        return Err(WebTransactionError("web_transaction_rollback_phase_invalid").into());
    }
    if status.phase == EntryPhase::Completed {
        return Err(WebTransactionError("web_transaction_completed_rollback_denied").into());
    }
    let rolled_back = if status.phase == EntryPhase::RolledBack {
        status
    } else {
        transaction.rollback().await?
    };
    remove_outbox_if_present(entry, request, rolled_back.generation)?;
    Ok(response_from_status(
        &request.operation_ref,
        &rolled_back,
        false,
        Some(rolled_back.generation),
    ))
}

fn validate_external_evidence(
    evidence: &ExternalActivationEvidence,
    record: &HostEnvelopeOutboxRecord,
    now: SystemTime,
) -> Result<()> {
    let now = unix_seconds(now)?;
    let oldest = [
        evidence.heartbeat_observed_at_unix_secs,
        evidence.process_observed_at_unix_secs,
        evidence.probe_observed_at_unix_secs,
    ]
    .into_iter()
    .min()
    .unwrap_or_default();
    let newest = [
        evidence.heartbeat_observed_at_unix_secs,
        evidence.process_observed_at_unix_secs,
        evidence.probe_observed_at_unix_secs,
    ]
    .into_iter()
    .max()
    .unwrap_or_default();
    if evidence.generation != record.generation
        || !evidence.materialized
        || evidence.process_state != "running"
        || evidence.probe_state != "healthy"
        || oldest < record.prepared_at_unix_secs
        || newest > now.saturating_add(EXTERNAL_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(oldest) > EXTERNAL_HEALTH_FRESHNESS_SECONDS
    {
        return Err(WebTransactionError("web_transaction_evidence_invalid").into());
    }
    Ok(())
}

fn outbox_path(entry: &TransactionCatalogEntry, operation_ref: &str) -> Result<PathBuf> {
    if !valid_ref("op_", operation_ref) {
        return Err(WebTransactionError("web_transaction_operation_invalid").into());
    }
    Ok(entry
        .delivery
        .outbox_dir
        .join(format!("{operation_ref}.json")))
}

fn remove_outbox_if_present(
    entry: &TransactionCatalogEntry,
    request: &TransactionRequest,
    expected_generation: u64,
) -> Result<()> {
    let path = outbox_path(entry, &request.operation_ref)?;
    super::reject_symlink(&path)?;
    if !path.exists() {
        return Ok(());
    }
    // A removal is permitted only after the file was opened and validated as
    // the exact operation-bound private record.
    let _ =
        load_bound_outbox_internal(entry, request, expected_generation, SystemTime::now(), true)?;
    fs::remove_file(&path)
        .map_err(|_| WebTransactionError("web_transaction_delivery_persistence_failed"))?;
    fs::File::open(&entry.delivery.outbox_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WebTransactionError("web_transaction_delivery_persistence_failed"))?;
    Ok(())
}

fn outbox_hash(record: &HostEnvelopeOutboxRecord) -> Result<String> {
    let mut unsigned = record.clone();
    unsigned.integrity_hash.clear();
    let encoded = serde_json::to_vec(&unsigned)
        .map_err(|_| WebTransactionError("web_transaction_delivery_invalid"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn deterministic_envelope_ref(operation_ref: &str, generation: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"inspr.janus.managed-host-envelope-ref.v1\0");
    hasher.update(operation_ref.as_bytes());
    hasher.update(generation.to_be_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("env_{}", &digest[..24])
}

fn unix_seconds(now: SystemTime) -> Result<u64> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WebTransactionError("web_transaction_clock_invalid").into())
}

fn transaction_for(
    entry: &TransactionCatalogEntry,
    operation_ref: &str,
    release: ReleaseAdmission,
) -> Result<EntryTransaction> {
    if !valid_ref("op_", operation_ref) {
        anyhow::bail!("web transaction operation reference is invalid");
    }
    let mut file = entry.plan.clone();
    file.operation_id = internal_operation_id(operation_ref)?;
    if entry.operation_kind == "remove" {
        file.source = EntrySource::Remove;
    }
    validate_plan(&file, SystemTime::now())?;
    let encoded = serde_json::to_vec(&file)
        .map_err(|_| anyhow::anyhow!("web transaction plan encoding failed"))?;
    let plan = EntryPlan {
        file,
        fingerprint: hex::encode(Sha256::digest(encoded)),
    };
    EntryTransaction::new_managed(
        plan,
        release,
        super::entry_principal_from_env()?,
        ManagedEntryOperationKind::parse(&entry.operation_kind)?,
        entry.delivery.generation,
    )
}

async fn reconcile_catalog(catalog: &ReviewedCatalog, release: &ReleaseAdmission) -> Result<()> {
    let mut state_dirs = BTreeSet::new();
    for entry in catalog.entries.values() {
        state_dirs.insert(entry.plan.state_dir.clone());
    }
    for state_dir in state_dirs {
        if !state_dir.exists() {
            continue;
        }
        for summary in scan_journal_summaries(&state_dir, release, 4096, 64 * 1024)? {
            let Some(operation_ref) = external_operation_ref(&summary.operation_id) else {
                continue;
            };
            if !summary.release_matches {
                anyhow::bail!("web transaction journal release binding changed");
            }
            if matches!(
                summary.phase.as_str(),
                "completed" | "destroyed" | "rolled_back"
            ) {
                continue;
            }
            let mut matching = None;
            for entry in catalog.entries.values().filter(|entry| {
                entry.plan.state_dir == state_dir
                    && entry.plan.secret_ref == summary.secret_ref.as_str()
            }) {
                let candidate = transaction_for(entry, &operation_ref, release.clone())?;
                if candidate.status().await.is_ok() {
                    if matching.is_some() {
                        anyhow::bail!("web transaction journal catalog binding is ambiguous");
                    }
                    matching = Some((entry, candidate));
                }
            }
            let (matching_entry, transaction) = matching
                .context("web transaction journal has no current reviewed catalog binding")?;
            // A managed removal has already crossed its declaration-detach
            // boundary before it reaches this daemon. Preserve every
            // non-terminal journal across restarts so the bridge can resume
            // the exact operation; never turn process restart into an
            // implicit secret restore.
            if matching_entry.operation_kind == "remove" {
                continue;
            }
            let request = request_for_entry(matching_entry, &operation_ref, "prepare", None);
            let journal_generation = if summary.generation == 0 {
                matching_entry.delivery.generation
            } else {
                summary.generation
            };
            if summary.phase == "validated" {
                let path = outbox_path(matching_entry, &operation_ref)?;
                if path.exists() {
                    let record = load_bound_outbox_internal(
                        matching_entry,
                        &request,
                        journal_generation,
                        SystemTime::now(),
                        true,
                    )
                    .context("web transaction prepared outbox is invalid")?;
                    if unix_seconds(SystemTime::now())? < record.expires_at_unix_secs {
                        continue;
                    }
                }
            }
            transaction
                .rollback()
                .await
                .context("web transaction partial journal rollback failed")?;
            remove_outbox_if_present(matching_entry, &request, journal_generation)?;
        }
    }
    Ok(())
}

fn request_for_entry(
    entry: &TransactionCatalogEntry,
    operation_ref: &str,
    action: &str,
    external_evidence: Option<ExternalActivationEvidence>,
) -> TransactionRequest {
    TransactionRequest {
        schema: REQUEST_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        action: action.to_string(),
        operation_ref: operation_ref.to_string(),
        operation_kind: entry.operation_kind.clone(),
        source: if entry.operation_kind == "remove" {
            "remove".to_string()
        } else {
            entry.plan.source.mode().to_string()
        },
        host_ref: entry.host_ref.clone(),
        service_ref: entry.service_ref.clone(),
        slot_ref: entry.slot_ref.clone(),
        declaration_fingerprint: entry.declaration_fingerprint.clone(),
        purge_not_before_unix_secs: 0,
        external_evidence,
        external_removal_evidence: None,
    }
}

fn bind_private_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .context("web transaction socket has no parent")?;
    super::ensure_private_dir(parent)?;
    super::reject_symlink(path)?;
    if path.exists() {
        let metadata = fs::metadata(path).context("web transaction socket unavailable")?;
        if !metadata.file_type().is_socket() {
            anyhow::bail!("web transaction socket path is not a socket");
        }
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => anyhow::bail!("web transaction socket is already active"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(_) => anyhow::bail!("web transaction stale socket state is ambiguous"),
        }
        fs::remove_file(path).context("web transaction stale socket removal failed")?;
    }
    let listener = UnixListener::bind(path).context("web transaction socket bind failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("web transaction socket permissions failed")?;
    Ok(listener)
}

fn required_absolute_path(name: &str) -> Result<PathBuf> {
    let raw = std::env::var(name)
        .map_err(|_| anyhow::anyhow!("web transaction configuration is incomplete"))?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() || path.file_name().is_none() {
        anyhow::bail!("web transaction path configuration is invalid");
    }
    Ok(path)
}

fn required_uid() -> Result<u32> {
    let raw = std::env::var(PEER_UID_ENV)
        .map_err(|_| anyhow::anyhow!("web transaction peer configuration is incomplete"))?;
    let uid = raw
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("web transaction peer configuration is invalid"))?;
    if raw != uid.to_string() {
        anyhow::bail!("web transaction peer configuration is invalid");
    }
    Ok(uid)
}

async fn read_json_frame<T>(stream: &mut UnixStream, limit: usize) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = read_raw_frame(stream, limit).await?;
    serde_json::from_slice(&bytes.0)
        .map_err(|_| anyhow::anyhow!("web transaction JSON frame is invalid"))
}

async fn read_raw_frame(stream: &mut UnixStream, limit: usize) -> Result<SecretBuffer> {
    let length = stream
        .read_u32()
        .await
        .context("web transaction frame header unavailable")?;
    let length = usize::try_from(length).context("web transaction frame length invalid")?;
    if length == 0 || length > limit {
        anyhow::bail!("web transaction frame length denied");
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("web transaction frame truncated")?;
    Ok(SecretBuffer(bytes))
}

async fn write_response(stream: &mut UnixStream, response: &TransactionResponse) -> Result<()> {
    let encoded = serde_json::to_vec(response)
        .map_err(|_| anyhow::anyhow!("web transaction response encoding failed"))?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("web transaction response length denied");
    }
    let length = u32::try_from(encoded.len()).context("web transaction response length invalid")?;
    stream
        .write_u32(length)
        .await
        .context("web transaction response header failed")?;
    stream
        .write_all(&encoded)
        .await
        .context("web transaction response write failed")?;
    stream
        .flush()
        .await
        .context("web transaction response flush failed")
}

fn response_from_status(
    operation_ref: &str,
    status: &EntryStatus,
    expects_value: bool,
    generation: Option<u64>,
) -> TransactionResponse {
    TransactionResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(operation_ref.to_string()),
        secret_ref: Some(status.secret_ref.clone()),
        mode: Some(status.mode.clone()),
        generation,
        phase: status.phase.as_str().to_string(),
        reason_code: status.reason_code.clone(),
        expects_value,
        value_returned: status.value_returned,
    }
}

fn prepared_response(
    request: &TransactionRequest,
    status: &EntryStatus,
    generation: u64,
) -> TransactionResponse {
    TransactionResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(request.operation_ref.clone()),
        secret_ref: Some(status.secret_ref.clone()),
        mode: Some(status.mode.clone()),
        generation: Some(generation),
        phase: "prepared".to_string(),
        reason_code: "entry_delivery_prepared".to_string(),
        expects_value: false,
        value_returned: false,
    }
}

fn prepared_removal_response(
    request: &TransactionRequest,
    status: &EntryStatus,
) -> TransactionResponse {
    TransactionResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(request.operation_ref.clone()),
        secret_ref: Some(status.secret_ref.clone()),
        mode: Some("remove".to_string()),
        generation: Some(status.generation),
        phase: "prepared".to_string(),
        reason_code: "entry_removal_prepared".to_string(),
        expects_value: false,
        value_returned: false,
    }
}

fn denied_response(
    operation_ref: Option<String>,
    reason_code: &'static str,
) -> TransactionResponse {
    TransactionResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref,
        secret_ref: None,
        mode: None,
        generation: None,
        phase: "denied".to_string(),
        reason_code: reason_code.to_string(),
        expects_value: false,
        value_returned: false,
    }
}

fn stable_web_error_reason(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<WebTransactionError>() {
            return error.0;
        }
    }
    let lifecycle = stable_error_reason(error);
    if lifecycle != "entry_transaction_denied" {
        return lifecycle;
    }
    "web_transaction_denied"
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn internal_operation_id(operation_ref: &str) -> Result<String> {
    if !valid_ref("op_", operation_ref) {
        anyhow::bail!("web transaction operation reference is invalid");
    }
    Ok(format!("webtx_{}", &operation_ref["op_".len()..]))
}

fn external_operation_ref(operation_id: &str) -> Option<String> {
    let suffix = operation_id.strip_prefix("webtx_")?;
    let operation_ref = format!("op_{suffix}");
    valid_ref("op_", &operation_ref).then_some(operation_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> TransactionRequest {
        TransactionRequest {
            schema: REQUEST_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            action: "prepare".to_string(),
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            purge_not_before_unix_secs: 0,
            external_evidence: None,
            external_removal_evidence: None,
        }
    }

    #[test]
    fn response_is_value_free_and_has_no_debug_surface() {
        let response = denied_response(
            Some("op_0123456789abcdef".to_string()),
            "web_transaction_value_invalid",
        );
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("\"value_returned\":false"));
        assert!(!encoded.contains("SENSITIVE_WEB_TRANSACTION_CANARY"));
    }

    #[test]
    fn outbox_integrity_hash_matches_the_go_bridge_contract() {
        let record = HostEnvelopeOutboxRecord {
            schema: OUTBOX_SCHEMA.to_string(),
            schema_version: DELIVERY_SCHEMA_VERSION,
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            secret_ref: "sec_0123456789abcdef".to_string(),
            scope_ref: "scp_0123456789abcdef0123456789abcdef01234567".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            envelope_ref: "env_0123456789abcdef".to_string(),
            generation: 1,
            revocation_epoch: 1,
            prepared_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_000_900,
            packet_base64: "cGFja2V0".to_string(),
            value_returned: false,
            integrity_hash: String::new(),
        };
        assert_eq!(
            outbox_hash(&record).expect("outbox hash"),
            "7da188178df0cd5c18c3340c6d7474a8d89d630dbcfdba3ca004ffd8039b21aa"
        );
    }

    #[test]
    fn resolver_accepts_only_an_exact_reviewed_key() {
        let mut request = request();
        let key = CatalogKey {
            host_ref: request.host_ref.clone(),
            service_ref: request.service_ref.clone(),
            slot_ref: request.slot_ref.clone(),
            declaration_fingerprint: request.declaration_fingerprint.clone(),
            operation_kind: request.operation_kind.clone(),
            source: request.source.clone(),
        };
        let mut catalog = ReviewedCatalog {
            entries: BTreeMap::from([(
                key,
                TransactionCatalogEntry {
                    host_ref: request.host_ref.clone(),
                    service_ref: request.service_ref.clone(),
                    slot_ref: request.slot_ref.clone(),
                    declaration_fingerprint: request.declaration_fingerprint.clone(),
                    operation_kind: request.operation_kind.clone(),
                    plan: super::super::tests::sample_plan(),
                    delivery: HostDeliveryPlan {
                        schema: DELIVERY_PLAN_SCHEMA.to_string(),
                        schema_version: DELIVERY_SCHEMA_VERSION,
                        host_recipient: "ssh-ed25519 fixture".to_string(),
                        producer_key_id: "key_0123456789abcdef".to_string(),
                        producer_signing_key_file: PathBuf::from("/fixture/signing-key.json"),
                        outbox_dir: PathBuf::from("/fixture/outbox"),
                        generation: 1,
                        revocation_epoch: 1,
                        envelope_ttl_seconds: 3600,
                    },
                },
            )]),
        };
        assert!(catalog.resolve(&request).is_ok());
        request.source = "generated".to_string();
        assert_eq!(
            catalog.resolve(&request).err(),
            Some("web_transaction_declaration_denied")
        );
        request.source = "import".to_string();
        request.operation_kind = "replace".to_string();
        assert_eq!(
            catalog.resolve(&request).err(),
            Some("web_transaction_declaration_denied")
        );
        let mut replacement_entry = catalog.entries.values().next().unwrap().clone();
        replacement_entry.operation_kind = "replace".to_string();
        catalog.entries.insert(
            CatalogKey {
                host_ref: request.host_ref.clone(),
                service_ref: request.service_ref.clone(),
                slot_ref: request.slot_ref.clone(),
                declaration_fingerprint: request.declaration_fingerprint.clone(),
                operation_kind: request.operation_kind.clone(),
                source: request.source.clone(),
            },
            replacement_entry,
        );
        assert!(catalog.resolve(&request).is_ok());
    }

    #[test]
    fn references_do_not_admit_paths_or_uppercase() {
        for value in [
            "op_../../escape",
            "op_UPPERCASE00",
            "op_short",
            "op_01234567/argv",
        ] {
            assert!(!valid_ref("op_", value));
        }
        assert!(valid_ref("op_", "op_0123456789abcdef"));
        assert_eq!(
            internal_operation_id("op_0123456789abcdef").unwrap(),
            "webtx_0123456789abcdef"
        );
        assert_eq!(
            external_operation_ref("webtx_0123456789abcdef").as_deref(),
            Some("op_0123456789abcdef")
        );
        assert!(external_operation_ref("entry-admin-operation").is_none());
    }

    #[tokio::test]
    async fn live_socket_cannot_be_replaced_and_is_private() {
        let directory = tempfile::Builder::new()
            .prefix("jtx.")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("tx.sock");
        let listener = bind_private_socket(&socket).unwrap();
        let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let error = bind_private_socket(&socket).err().unwrap().to_string();
        assert!(error.contains("already active"));
        drop(listener);
    }

    #[test]
    fn request_json_rejects_value_and_path_fields() {
        let mut encoded = serde_json::to_value(request()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("raw_value".to_string(), serde_json::json!("canary"));
        assert!(serde_json::from_value::<TransactionRequest>(encoded).is_err());

        let mut encoded = serde_json::to_value(request()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("plan_path".to_string(), serde_json::json!("/tmp/plan"));
        assert!(serde_json::from_value::<TransactionRequest>(encoded).is_err());
    }
}

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
use std::time::SystemTime;

use anyhow::{Context, Result};
use janus_core::ReleaseAdmission;
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
};

const CATALOG_SCHEMA: &str = "inspr.janus.managed-web-transaction-catalog.v1";
const REQUEST_SCHEMA: &str = "inspr.janus.managed-web-transaction-request.v1";
const RESPONSE_SCHEMA: &str = "inspr.janus.managed-web-transaction-response.v1";
const SCHEMA_VERSION: u8 = 1;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CATALOG_ENTRIES: usize = 256;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const VALUE_WAIT: Duration = Duration::from_secs(30);
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
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionRequest {
    schema: String,
    schema_version: u8,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionResponse {
    schema: &'static str,
    schema_version: u8,
    operation_ref: Option<String>,
    secret_ref: Option<String>,
    mode: Option<String>,
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

    match transaction.status().await {
        Ok(status) if matches!(status.phase, EntryPhase::Completed | EntryPhase::RolledBack) => {
            let _ = write_response(
                &mut stream,
                &response_from_status(&request.operation_ref, &status, false),
            )
            .await;
            return;
        }
        Ok(_) => {
            let status = transaction.rollback().await;
            let response = match status {
                Ok(status) => response_from_status(&request.operation_ref, &status, false),
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
        &response_from_status(&request.operation_ref, &preflight, expects_value),
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
    let response = match transaction.activate(SystemTime::now()).await {
        Ok(status) => response_from_status(&request.operation_ref, &status, false),
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
            || !valid_ref("op_", &request.operation_ref)
            || !valid_ref("host_", &request.host_ref)
            || !valid_ref("svc_", &request.service_ref)
            || !valid_ref("slot_", &request.slot_ref)
            || !valid_ref("decl_", &request.declaration_fingerprint)
            || request.operation_kind != "create"
            || !matches!(request.source.as_str(), "generated" | "import")
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
            source: entry.plan.source.mode().to_string(),
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
        || entry.operation_kind != "create"
        || entry.plan.operation_id != "web-transaction-template"
    {
        anyhow::bail!("web transaction catalog entry is invalid");
    }
    validate_plan(&entry.plan, SystemTime::now())?;
    Ok(())
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
    validate_plan(&file, SystemTime::now())?;
    let encoded = serde_json::to_vec(&file)
        .map_err(|_| anyhow::anyhow!("web transaction plan encoding failed"))?;
    let plan = EntryPlan {
        file,
        fingerprint: hex::encode(Sha256::digest(encoded)),
    };
    EntryTransaction::new(plan, release, super::entry_principal_from_env()?)
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
            if matches!(summary.phase.as_str(), "completed" | "rolled_back") {
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
                    matching = Some(candidate);
                }
            }
            let transaction = matching
                .context("web transaction journal has no current reviewed catalog binding")?;
            transaction
                .rollback()
                .await
                .context("web transaction partial journal rollback failed")?;
        }
    }
    Ok(())
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
) -> TransactionResponse {
    TransactionResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(operation_ref.to_string()),
        secret_ref: Some(status.secret_ref.clone()),
        mode: Some(status.mode.clone()),
        phase: status.phase.as_str().to_string(),
        reason_code: status.reason_code.clone(),
        expects_value,
        value_returned: status.value_returned,
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
        phase: "denied".to_string(),
        reason_code: reason_code.to_string(),
        expects_value: false,
        value_returned: false,
    }
}

fn stable_web_error_reason(error: &anyhow::Error) -> &'static str {
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
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
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
        let catalog = ReviewedCatalog {
            entries: BTreeMap::from([(
                key,
                TransactionCatalogEntry {
                    host_ref: request.host_ref.clone(),
                    service_ref: request.service_ref.clone(),
                    slot_ref: request.slot_ref.clone(),
                    declaration_fingerprint: request.declaration_fingerprint.clone(),
                    operation_kind: request.operation_kind.clone(),
                    plan: super::super::tests::sample_plan(),
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
            Some("web_transaction_request_invalid")
        );
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

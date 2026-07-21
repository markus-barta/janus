use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::{JanusError, JanusResult, SafeLabel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const ENTRY_SCHEMA: &str = "inspr.pharos.beacon-token-entry.v2";
pub(crate) const GENERATION_SCHEMA: &str = "inspr.pharos.beacon-token-generation.v2";
pub(crate) const CURRENT_FILE: &str = "current";
const MAX_CURRENT_BYTES: u64 = 65;
const MAX_GENERATION_BYTES: u64 = 1024 * 1024;
const MAX_GENERATION_HOSTS: usize = 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenEntryFile {
    schema: String,
    host: TokenHost,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenHost {
    name: String,
    token_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenGeneration {
    schema: String,
    generation: String,
    hosts: Vec<TokenHost>,
}

pub(crate) fn write_entry(
    mut writer: impl Write,
    subject: &SafeLabel,
    value: &[u8],
) -> JanusResult<String> {
    if !valid_host_name(subject.as_str()) {
        return Err(JanusError::InvalidManifest {
            detail: "Pharos token generation subject must be a canonical host name".to_string(),
        });
    }
    let token_sha256 = sha256_hex(value);
    serde_json::to_writer(
        &mut writer,
        &TokenEntryFile {
            schema: ENTRY_SCHEMA.to_string(),
            host: TokenHost {
                name: subject.as_str().to_string(),
                token_sha256: token_sha256.clone(),
            },
        },
    )
    .and_then(|_| writer.write_all(b"\n").map_err(serde_json::Error::io))
    .map_err(|_| JanusError::StoreUnavailable {
        detail: "failed to write Pharos token generation entry".to_string(),
    })?;
    Ok(token_sha256)
}

pub(crate) fn publish_entry(
    root: &Path,
    subject: &SafeLabel,
    token_sha256: &str,
) -> JanusResult<String> {
    if !valid_host_name(subject.as_str()) || !is_sha256_hex(token_sha256) {
        return Err(JanusError::InvalidManifest {
            detail: "Pharos token generation entry is invalid".to_string(),
        });
    }
    with_generation_lock(root, |mut hosts| {
        hosts.insert(subject.as_str().to_string(), token_sha256.to_string());
        publish_generation(root, hosts)
    })
}

/// Publish or replace one value-free host verifier in the current immutable
/// generation. Callers never provide or receive a plaintext credential.
pub fn publish_host(root: &Path, host: &str, token_sha256: &str) -> JanusResult<String> {
    let subject = SafeLabel::new(host).map_err(|_| JanusError::InvalidManifest {
        detail: "Pharos token generation host is invalid".to_string(),
    })?;
    publish_entry(root, &subject, token_sha256)
}

/// Remove one host from the immutable Pharos verifier generation and publish
/// the new current pointer before retirement can progress.
pub fn retire_host(root: &Path, host: &str) -> JanusResult<String> {
    if !valid_host_name(host) {
        return Err(JanusError::InvalidManifest {
            detail: "Pharos token retirement host must be canonical".to_string(),
        });
    }
    with_generation_lock(root, |mut hosts| {
        hosts.remove(host);
        publish_generation(root, hosts)
    })
}

fn with_generation_lock<T>(
    root: &Path,
    operation: impl FnOnce(BTreeMap<String, String>) -> JanusResult<T>,
) -> JanusResult<T> {
    validate_private_root(root)?;
    let lock_path = root.join(".generation.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(lock_path)
        .map_err(|_| generation_unavailable("failed to open generation lock"))?;
    lock.lock_exclusive()
        .map_err(|_| generation_unavailable("failed to acquire generation lock"))?;
    let hosts = load_current_generation(root)?;
    let outcome = operation(hosts);
    let _ = FileExt::unlock(&lock);
    outcome
}

fn load_current_generation(root: &Path) -> JanusResult<BTreeMap<String, String>> {
    let current_path = root.join(CURRENT_FILE);
    let current = match read_bounded(&current_path, MAX_CURRENT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(generation_unavailable("failed to read current generation")),
    };
    let current = std::str::from_utf8(&current)
        .map_err(|_| generation_unavailable("current generation is invalid"))?
        .strip_suffix('\n')
        .unwrap_or_else(|| std::str::from_utf8(&current).unwrap_or_default());
    if !is_sha256_hex(current) {
        return Err(generation_unavailable("current generation is invalid"));
    }
    let generation_path = root.join(format!("generation-{current}.json"));
    let bytes = read_bounded(&generation_path, MAX_GENERATION_BYTES)
        .map_err(|_| generation_unavailable("failed to read current generation payload"))?;
    parse_generation(&bytes, current)
}

fn parse_generation(bytes: &[u8], expected_id: &str) -> JanusResult<BTreeMap<String, String>> {
    let payload: TokenGeneration = serde_json::from_slice(bytes)
        .map_err(|_| generation_unavailable("current generation payload is invalid"))?;
    if payload.schema != GENERATION_SCHEMA || payload.generation != expected_id {
        return Err(generation_unavailable(
            "current generation contract is unsupported",
        ));
    }
    if payload.hosts.len() > MAX_GENERATION_HOSTS {
        return Err(generation_unavailable("current generation is too large"));
    }
    let mut hosts = BTreeMap::new();
    for host in payload.hosts {
        if !valid_host_name(&host.name) || !is_sha256_hex(&host.token_sha256) {
            return Err(generation_unavailable(
                "current generation entry is invalid",
            ));
        }
        if hosts.insert(host.name, host.token_sha256).is_some() {
            return Err(generation_unavailable(
                "current generation contains duplicate hosts",
            ));
        }
    }
    if generation_id(&hosts) != expected_id {
        return Err(generation_unavailable(
            "current generation integrity check failed",
        ));
    }
    Ok(hosts)
}

fn publish_generation(root: &Path, hosts: BTreeMap<String, String>) -> JanusResult<String> {
    if hosts.len() > MAX_GENERATION_HOSTS {
        return Err(generation_unavailable("generation host bound exceeded"));
    }
    let generation = generation_id(&hosts);
    let payload = TokenGeneration {
        schema: GENERATION_SCHEMA.to_string(),
        generation: generation.clone(),
        hosts: hosts
            .into_iter()
            .map(|(name, token_sha256)| TokenHost { name, token_sha256 })
            .collect(),
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|_| generation_unavailable("failed to encode generation"))?;
    if bytes.len() as u64 > MAX_GENERATION_BYTES {
        return Err(generation_unavailable("generation size bound exceeded"));
    }

    let generation_path = root.join(format!("generation-{generation}.json"));
    match OpenOptions::new().read(true).open(&generation_path) {
        Ok(_) => {
            let existing = read_bounded(&generation_path, MAX_GENERATION_BYTES)
                .map_err(|_| generation_unavailable("existing generation is unreadable"))?;
            if existing != bytes {
                return Err(generation_unavailable(
                    "immutable generation content mismatch",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_immutable_synced(&generation_path, &bytes)?;
        }
        Err(_) => return Err(generation_unavailable("generation path is unavailable")),
    }

    replace_synced(
        root.join(CURRENT_FILE),
        format!("{generation}\n").as_bytes(),
    )?;
    sync_directory(root)?;
    Ok(generation)
}

fn write_immutable_synced(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| generation_unavailable("generation parent is invalid"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| generation_unavailable("generation name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        write_new_synced(&temp, bytes)?;
        match fs::hard_link(&temp, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_bounded(path, MAX_GENERATION_BYTES)
                    .map_err(|_| generation_unavailable("existing generation is unreadable"))?;
                if existing != bytes {
                    return Err(generation_unavailable(
                        "immutable generation content mismatch",
                    ));
                }
            }
            Err(_) => {
                return Err(generation_unavailable(
                    "failed to publish immutable generation",
                ));
            }
        }
        Ok(())
    })();
    let cleanup = fs::remove_file(temp);
    result?;
    cleanup.map_err(|_| generation_unavailable("failed to remove generation temporary file"))?;
    sync_directory(parent)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| generation_unavailable("failed to create immutable generation"))?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| generation_unavailable("failed to sync immutable generation"))
}

fn replace_synced(path: PathBuf, bytes: &[u8]) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| generation_unavailable("generation pointer parent is invalid"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| generation_unavailable("generation pointer name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        write_new_synced(&temp, bytes)?;
        fs::rename(&temp, &path)
            .map_err(|_| generation_unavailable("failed to publish generation pointer"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn read_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsafe or oversized generation file",
        ));
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::take(&mut file, max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized generation file",
        ));
    }
    Ok(bytes)
}

fn validate_private_root(root: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| generation_unavailable("generation root is unavailable"))?;
    if !root.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(generation_unavailable("generation root is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(generation_unavailable("generation root must be private"));
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> JanusResult<()> {
    let directory = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| generation_unavailable("failed to open generation directory"))?;
    directory
        .sync_all()
        .map_err(|_| generation_unavailable("failed to sync generation directory"))
}

pub(crate) fn generation_id(hosts: &BTreeMap<String, String>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"inspr.pharos.beacon-token-generation.v2\0");
    for (host, hash) in hosts {
        digest.update((host.len() as u64).to_be_bytes());
        digest.update(host.as_bytes());
        digest.update(hash.as_bytes());
    }
    hex(&digest.finalize())
}

pub(crate) fn valid_host_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(CHARS[(byte >> 4) as usize] as char);
        output.push(CHARS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn generation_unavailable(detail: &str) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "janus-pharos-generation-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn private_root(label: &str) -> PathBuf {
        let path = root(label);
        fs::create_dir(&path).expect("create generation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure generation root");
        }
        path
    }

    #[test]
    fn published_generations_are_immutable_strict_and_retirement_aware() {
        let root = private_root("publish");
        let ares = SafeLabel::new("ares").expect("host label");
        let athena = SafeLabel::new("athena").expect("host label");
        let ares_hash = sha256_hex(b"fixture-a");
        let athena_hash = sha256_hex(b"fixture-b");

        let first = publish_entry(&root, &ares, &ares_hash).expect("publish first host");
        let second = publish_entry(&root, &athena, &athena_hash).expect("publish second host");
        assert_ne!(first, second);
        let hosts = load_current_generation(&root).expect("load complete generation");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.get("ares"), Some(&ares_hash));
        assert_eq!(hosts.get("athena"), Some(&athena_hash));

        let retired = retire_host(&root, "ares").expect("publish retirement generation");
        assert_ne!(second, retired);
        let hosts = load_current_generation(&root).expect("load retired generation");
        assert_eq!(hosts.len(), 1);
        assert!(!hosts.contains_key("ares"));
        assert_eq!(hosts.get("athena"), Some(&athena_hash));
    }

    #[test]
    fn entry_contract_has_required_schema_and_no_literal() {
        let mut output = Vec::new();
        let host = SafeLabel::new("csb0").expect("host label");
        let hash = write_entry(&mut output, &host, b"fixture-secret").expect("write entry");
        let payload: TokenEntryFile = serde_json::from_slice(&output).expect("strict entry parses");
        assert_eq!(payload.schema, ENTRY_SCHEMA);
        assert_eq!(payload.host.name, "csb0");
        assert_eq!(payload.host.token_sha256, hash);
        assert!(!String::from_utf8(output)
            .expect("entry is utf8")
            .contains("fixture-secret"));
    }

    #[test]
    fn shared_contract_fixture_is_a_valid_producer_generation() {
        let fixture = include_bytes!("../../../contracts/pharos-beacon-token-generation-v2.json");
        let expected = "17fa715d01efa6a7a08c8ebccbe93d1e0239b5601ee455ff1f22675dff3233f4";
        let hosts = parse_generation(fixture, expected).expect("shared fixture is producer-valid");

        assert_eq!(hosts.len(), 2);
        assert_eq!(generation_id(&hosts), expected);
    }

    #[test]
    fn concurrent_publishers_do_not_lose_hosts() {
        let root = private_root("concurrent");
        let mut threads = Vec::new();
        for index in 0..16 {
            let root = root.clone();
            threads.push(std::thread::spawn(move || {
                let host = format!("host-{index}");
                let token_sha256 = sha256_hex(host.as_bytes());
                publish_host(&root, &host, &token_sha256).expect("publish concurrent host");
            }));
        }
        for thread in threads {
            thread.join().expect("publisher thread completes");
        }

        let hosts = load_current_generation(&root).expect("load concurrent generation");
        assert_eq!(hosts.len(), 16);
        assert!((0..16).all(|index| hosts.contains_key(&format!("host-{index}"))));
        assert_eq!(
            fs::read_dir(&root)
                .expect("read generation root")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }
}

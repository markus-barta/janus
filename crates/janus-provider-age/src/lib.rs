//! Native age-backed `SecretStore`.
//!
//! The manifest/catalog is the allowlist. The filesystem stores only encrypted
//! values, never the source of truth for what secrets exist.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use age::{Decryptor, Encryptor};
use async_trait::async_trait;
use janus_core::{
    HealthStatus, JanusError, JanusResult, ManifestCatalog, ProfileId, ProjectId, RotationOutcome,
    RotationSpec, RotationStrategy, SafeLabel, ScopeRef, SecretDescriptor, SecretMeta, SecretName,
    SecretStore, SecretValue, StoreCapabilities, TrustLevel,
};
use secretspec as secretspec_crate;
use zeroize::Zeroize;

/// Native age-backed store.
pub struct AgeSecretStore {
    project: ProjectId,
    profile: String,
    root_dir: PathBuf,
    identity_files: Vec<PathBuf>,
    recipients: Vec<String>,
    catalog: ManifestCatalog,
}

impl AgeSecretStore {
    /// Build an age store from an already-reviewed manifest catalog.
    pub fn from_catalog(
        project: ProjectId,
        profile: impl Into<String>,
        root_dir: impl Into<PathBuf>,
        catalog: ManifestCatalog,
        identity_files: Vec<PathBuf>,
        recipients: Vec<String>,
    ) -> JanusResult<Self> {
        let profile = profile.into();
        let root_dir = root_dir.into();
        if identity_files.is_empty() {
            return Err(JanusError::StoreUnavailable {
                detail: "age identity file is required".to_string(),
            });
        }
        if recipients.is_empty() {
            return Err(JanusError::StoreUnavailable {
                detail: "at least one age recipient is required".to_string(),
            });
        }
        for entry in catalog.entries() {
            safe_name_path(&entry.name).map_err(|err| JanusError::InvalidManifest {
                detail: format!("age store secret path is invalid: {err}"),
            })?;
        }
        Ok(Self {
            project,
            profile,
            root_dir,
            identity_files,
            recipients,
            catalog,
        })
    }

    /// Load a `secretspec.toml` manifest as the Janus allowlist, but use age as
    /// the native value backend.
    pub fn load_from_secretspec_manifest(
        config_path: impl AsRef<Path>,
        profile: impl Into<String>,
        root_dir: impl Into<PathBuf>,
        identity_files: Vec<PathBuf>,
        recipients: Vec<String>,
    ) -> JanusResult<Self> {
        let profile = profile.into();
        let config = secretspec_crate::Config::try_from(config_path.as_ref()).map_err(|err| {
            JanusError::StoreUnavailable {
                detail: format!("secretspec manifest load failed: {err}"),
            }
        })?;
        config
            .validate()
            .map_err(|err| JanusError::InvalidManifest {
                detail: format!("secretspec manifest validation failed: {err}"),
            })?;

        let project = ProjectId::new(config.project.name.clone())?;
        let profile_config =
            config
                .get_profile(&profile)
                .ok_or_else(|| JanusError::InvalidManifest {
                    detail: format!("missing secretspec profile {profile}"),
                })?;

        let mut entries = Vec::new();
        for (name, secret) in profile_config.iter() {
            let name = SecretName::new(name.clone())?;
            let required = secret
                .required
                .or_else(|| {
                    profile_config
                        .defaults
                        .as_ref()
                        .and_then(|defaults| defaults.required)
                })
                .unwrap_or(true);
            entries.push(SecretMeta {
                secret_ref: janus_core::SecretRef::for_manifest_entry(&project, &name),
                name: name.clone(),
                label: SafeLabel::new(
                    secret
                        .description
                        .clone()
                        .unwrap_or_else(|| "Manifest-declared secret".to_string()),
                )?,
                scope: ScopeRef::new(format!("{}/{}", project.as_str(), profile))?,
                required,
                trust_level: TrustLevel::L1,
                allowed_uses: vec![ProfileId::new(format!("profile.{}", name.as_str()))?],
            });
        }

        Self::from_catalog(
            project,
            profile,
            root_dir,
            ManifestCatalog::new(entries)?,
            identity_files,
            recipients,
        )
    }

    /// Safe value-free catalog descriptors.
    pub fn catalog(&self) -> &ManifestCatalog {
        &self.catalog
    }

    fn ensure_manifest(&self, name: &SecretName) -> JanusResult<&SecretMeta> {
        self.catalog.meta_by_name(name)
    }

    fn scope_dir(&self) -> PathBuf {
        self.root_dir
            .join(self.project.as_str())
            .join(self.profile.as_str())
    }

    fn path_for(&self, name: &SecretName) -> JanusResult<PathBuf> {
        let mut path = self.scope_dir();
        for component in safe_name_path(name)? {
            path.push(component);
        }
        path.set_extension("age");
        Ok(path)
    }

    fn ensure_scope_dir(&self) -> JanusResult<()> {
        let project_dir = self.root_dir.join(self.project.as_str());
        let scope_dir = project_dir.join(self.profile.as_str());
        for path in [&self.root_dir, &project_dir, &scope_dir] {
            fs::create_dir_all(path).map_err(map_store_io)?;
            set_dir_private(path)?;
        }
        Ok(())
    }
}

#[async_trait]
impl SecretStore for AgeSecretStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            write: true,
            delete: true,
            generated_rotate: true,
            rotate_native: false,
            versioning: false,
            leasing: false,
            native_audit: false,
            backend_key_custody: false,
        }
    }

    async fn health(&self) -> JanusResult<HealthStatus> {
        self.ensure_scope_dir()?;
        parse_recipients(&self.recipients)?;
        parse_identity_files(&self.identity_files)?;
        Ok(HealthStatus {
            backend: "age",
            ok: true,
            detail: format!(
                "age store configured; manifest_entries={}",
                self.catalog.entries().len()
            ),
        })
    }

    async fn list(&self) -> JanusResult<Vec<SecretDescriptor>> {
        self.ensure_scope_dir()?;
        let mut descriptors = Vec::new();
        for meta in self.catalog.entries() {
            descriptors.push(meta.descriptor(self.path_for(&meta.name)?.is_file()));
        }
        Ok(descriptors)
    }

    async fn get(&self, name: &SecretName) -> JanusResult<SecretValue> {
        self.ensure_manifest(name)?;
        let path = self.path_for(name)?;
        if !path.is_file() {
            return Err(JanusError::NotFound {
                name: name.as_str().to_string(),
            });
        }
        let identity_files = self.identity_files.clone();
        let plaintext = tokio::task::spawn_blocking(move || decrypt_file(&path, &identity_files))
            .await
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("age decrypt task failed: {err}"),
            })??;
        Ok(SecretValue::new(plaintext))
    }

    async fn set(&mut self, name: &SecretName, value: SecretValue) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        self.ensure_scope_dir()?;
        let path = self.path_for(name)?;
        let scope_dir = self.scope_dir();
        let recipients = self.recipients.clone();
        let mut plaintext = value.expose_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let result = encrypt_to_file(&path, &scope_dir, &recipients, &plaintext);
            plaintext.zeroize();
            result
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age encrypt task failed: {err}"),
        })??;
        Ok(())
    }

    async fn rotate(
        &mut self,
        name: &SecretName,
        spec: &RotationSpec,
    ) -> JanusResult<RotationOutcome> {
        self.ensure_manifest(name)?;
        if spec.strategy != RotationStrategy::Generated {
            return Err(JanusError::Unsupported {
                capability: "rotation_strategy",
            });
        }
        let value = spec
            .generated_value
            .as_ref()
            .ok_or(JanusError::Unsupported {
                capability: "generated_value",
            })?;
        self.set(name, SecretValue::new(value.expose_bytes().to_vec()))
            .await?;
        let descriptor = self.catalog.descriptor_by_name(name, true)?;
        Ok(RotationOutcome::rotated(descriptor.secret_ref))
    }

    async fn delete(&mut self, name: &SecretName) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        let path = self.path_for(name)?;
        if !path.is_file() {
            return Err(JanusError::NotFound {
                name: name.as_str().to_string(),
            });
        }
        fs::remove_file(&path).map_err(map_store_io)?;
        prune_empty_secret_dirs(path.parent(), &self.scope_dir())?;
        Ok(())
    }
}

fn encrypt_to_file(
    path: &Path,
    scope_dir: &Path,
    recipient_strings: &[String],
    plaintext: &[u8],
) -> JanusResult<()> {
    let recipients = parse_recipients(recipient_strings)?;
    let recipient_refs = recipients
        .iter()
        .map(|recipient| recipient.as_ref() as &dyn age::Recipient);
    let encryptor = Encryptor::with_recipients(recipient_refs).map_err(map_age_encrypt)?;
    let mut encrypted = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(map_store_io)?;
        writer.write_all(plaintext).map_err(map_store_io)?;
        writer.finish().map_err(map_store_io)?;
    }
    write_atomically(path, scope_dir, &encrypted)
}

fn decrypt_file(path: &Path, identity_files: &[PathBuf]) -> JanusResult<Vec<u8>> {
    let encrypted = fs::read(path).map_err(map_store_io)?;
    let identities = parse_identity_files(identity_files)?;
    let identity_refs = identities
        .iter()
        .map(|identity| identity.as_ref() as &dyn age::Identity);
    let decryptor = Decryptor::new_buffered(&encrypted[..]).map_err(map_age_decrypt)?;
    let mut reader = decryptor.decrypt(identity_refs).map_err(map_age_decrypt)?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext).map_err(map_store_io)?;
    Ok(plaintext)
}

fn parse_recipients(values: &[String]) -> JanusResult<Vec<Box<dyn age::Recipient + Send>>> {
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(recipient) = trimmed.parse::<age::x25519::Recipient>() {
            recipients.push(Box::new(recipient));
            continue;
        }
        if let Ok(recipient) = trimmed.parse::<age::ssh::Recipient>() {
            recipients.push(Box::new(recipient));
            continue;
        }
        return Err(JanusError::StoreUnavailable {
            detail: "invalid age recipient".to_string(),
        });
    }
    if recipients.is_empty() {
        return Err(JanusError::StoreUnavailable {
            detail: "at least one age recipient is required".to_string(),
        });
    }
    Ok(recipients)
}

fn parse_identity_files(paths: &[PathBuf]) -> JanusResult<Vec<Box<dyn age::Identity + Send>>> {
    let mut identities: Vec<Box<dyn age::Identity + Send>> = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(path).map_err(|_| JanusError::StoreUnavailable {
            detail: "age identity file could not be read".to_string(),
        })?;
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Err(JanusError::StoreUnavailable {
                detail: "age identity file is empty".to_string(),
            });
        }
        if let Ok(identity) = trimmed.parse::<age::x25519::Identity>() {
            identities.push(Box::new(identity));
            continue;
        }
        let reader = BufReader::new(contents.as_bytes());
        let identity = age::ssh::Identity::from_buffer(reader, None).map_err(|_| {
            JanusError::StoreUnavailable {
                detail: "age ssh identity could not be parsed".to_string(),
            }
        })?;
        identities.push(Box::new(identity));
    }
    if identities.is_empty() {
        return Err(JanusError::StoreUnavailable {
            detail: "age identity file is required".to_string(),
        });
    }
    Ok(identities)
}

fn write_atomically(path: &Path, scope_dir: &Path, bytes: &[u8]) -> JanusResult<()> {
    let parent = path.parent().ok_or_else(|| JanusError::StoreUnavailable {
        detail: "age store path has no parent".to_string(),
    })?;
    create_secret_parent_dirs(parent, scope_dir)?;
    let tmp = parent.join(format!(
        ".janus-age-{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("system clock before unix epoch: {err}"),
            })?
            .as_nanos()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(map_store_io)?;
    set_file_private(&file)?;
    file.write_all(bytes).map_err(map_store_io)?;
    file.sync_all().map_err(map_store_io)?;
    drop(file);
    fs::rename(&tmp, path).map_err(map_store_io)?;
    sync_dir(parent)?;
    Ok(())
}

fn create_secret_parent_dirs(parent: &Path, scope_dir: &Path) -> JanusResult<()> {
    fs::create_dir_all(parent).map_err(map_store_io)?;
    let relative = parent
        .strip_prefix(scope_dir)
        .map_err(|_| JanusError::StoreUnavailable {
            detail: "age store path escaped scope directory".to_string(),
        })?;
    let mut current = scope_dir.to_path_buf();
    set_dir_private(&current)?;
    for component in relative.components() {
        current.push(component.as_os_str());
        set_dir_private(&current)?;
    }
    Ok(())
}

fn set_dir_private(path: &Path) -> JanusResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(map_store_io)?;
    }
    Ok(())
}

fn set_file_private(file: &File) -> JanusResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(map_store_io)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(map_store_io)
}

fn prune_empty_secret_dirs(start: Option<&Path>, stop: &Path) -> JanusResult<()> {
    let mut current = match start {
        Some(path) => path,
        None => return Ok(()),
    };
    while current != stop {
        match fs::remove_dir(current) {
            Ok(()) => {
                current = match current.parent() {
                    Some(parent) => parent,
                    None => break,
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                if fs::read_dir(current)
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false)
                {
                    break;
                }
                return Err(map_store_io(err));
            }
        }
    }
    Ok(())
}

fn safe_name_path(name: &SecretName) -> JanusResult<Vec<&str>> {
    let mut components = Vec::new();
    for component in name.as_str().split('/') {
        if component.is_empty() || component == "." || component == ".." || component.contains('\\')
        {
            return Err(JanusError::InvalidIdentifier {
                kind: "secret_name_path",
            });
        }
        components.push(component);
    }
    Ok(components)
}

fn map_age_encrypt(err: age::EncryptError) -> JanusError {
    JanusError::StoreUnavailable {
        detail: format!("age encryption failed: {err}"),
    }
}

fn map_age_decrypt(err: age::DecryptError) -> JanusError {
    JanusError::StoreUnavailable {
        detail: format!("age decryption failed: {err}"),
    }
}

fn map_store_io(err: std::io::Error) -> JanusError {
    JanusError::StoreUnavailable {
        detail: format!("age store I/O failed: {}", err.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use janus_core::{ManifestCatalog, SecretRef};
    use tempfile::TempDir;

    const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const TEST_SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";

    struct Fixture {
        _tmp: TempDir,
        store_dir: PathBuf,
        identity_file: PathBuf,
        admin_identity_file: PathBuf,
        recipients: Vec<String>,
        catalog: ManifestCatalog,
        canary: SecretName,
    }

    fn catalog(project: &ProjectId, canary: &SecretName) -> ManifestCatalog {
        ManifestCatalog::new(vec![SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(project, canary),
            name: canary.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: ScopeRef::new("janus/default").unwrap(),
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.CANARY").unwrap()],
        }])
        .unwrap()
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let host = age::x25519::Identity::generate();
        let admin = age::x25519::Identity::generate();
        let identity_file = tmp.path().join("host.identity");
        let admin_identity_file = tmp.path().join("admin.identity");
        let host_identity = host.to_string();
        let admin_identity = admin.to_string();
        fs::write(&identity_file, host_identity.expose_secret()).unwrap();
        fs::write(&admin_identity_file, admin_identity.expose_secret()).unwrap();
        let project = ProjectId::new("janus").unwrap();
        let canary = SecretName::new("CANARY").unwrap();
        Fixture {
            store_dir: tmp.path().join("store"),
            identity_file,
            admin_identity_file,
            recipients: vec![host.to_public().to_string(), admin.to_public().to_string()],
            catalog: catalog(&project, &canary),
            canary,
            _tmp: tmp,
        }
    }

    fn store(fixture: &Fixture, identity_file: PathBuf) -> AgeSecretStore {
        AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![identity_file],
            fixture.recipients.clone(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn age_store_passes_core_contract_and_keeps_descriptors_value_free() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"expected-canary".to_vec()),
            )
            .await
            .unwrap();

        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        assert!(listed[0].secret_ref.as_str().starts_with("sec_"));
        assert_eq!(listed[0].label.as_str(), "Canary token");
        assert!(!format!("{listed:?}").contains("expected-canary"));

        janus_conformance::run_store_contract(
            &mut store,
            &janus_conformance::StoreFixture {
                canary: fixture.canary.clone(),
                expected_value: b"expected-canary".to_vec(),
                not_in_manifest: SecretName::new("OTHER").unwrap(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn age_store_encrypts_to_each_configured_recipient() {
        let fixture = fixture();
        let mut host_store = store(&fixture, fixture.identity_file.clone());
        host_store
            .set(
                &fixture.canary,
                SecretValue::new(b"multi-recipient-canary".to_vec()),
            )
            .await
            .unwrap();

        let admin_store = store(&fixture, fixture.admin_identity_file.clone());
        let recovered = admin_store.get(&fixture.canary).await.unwrap();
        assert_eq!(recovered.expose_bytes(), b"multi-recipient-canary");
    }

    #[tokio::test]
    async fn age_store_supports_ssh_ed25519_identities() {
        let tmp = TempDir::new().unwrap();
        let identity_file = tmp.path().join("ssh_host_ed25519_key");
        fs::write(&identity_file, TEST_SSH_ED25519_SK).unwrap();
        let project = ProjectId::new("janus").unwrap();
        let canary = SecretName::new("CANARY").unwrap();
        let mut store = AgeSecretStore::from_catalog(
            project,
            "default",
            tmp.path().join("store"),
            catalog(&ProjectId::new("janus").unwrap(), &canary),
            vec![identity_file],
            vec![TEST_SSH_ED25519_PK.to_string()],
        )
        .unwrap();
        store
            .set(&canary, SecretValue::new(b"ssh-canary".to_vec()))
            .await
            .unwrap();
        let recovered = store.get(&canary).await.unwrap();
        assert_eq!(recovered.expose_bytes(), b"ssh-canary");
    }

    #[tokio::test]
    async fn delete_removes_manifest_value_without_listing_files_as_truth() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(&fixture.canary, SecretValue::new(b"delete-me".to_vec()))
            .await
            .unwrap();
        assert!(store.list().await.unwrap()[0].present);
        store.delete(&fixture.canary).await.unwrap();
        assert!(!store.list().await.unwrap()[0].present);
        assert!(matches!(
            store.get(&fixture.canary).await,
            Err(JanusError::NotFound { .. })
        ));
        assert!(matches!(
            store.delete(&fixture.canary).await,
            Err(JanusError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn secretspec_manifest_loads_as_age_allowlist() {
        let fixture = fixture();
        let manifest = fixture._tmp.path().join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "janus"
revision = "1.0"

[profiles.default]
CANARY = { description = "Canary token", required = true }
"#,
        )
        .unwrap();
        let mut store = AgeSecretStore::load_from_secretspec_manifest(
            &manifest,
            "default",
            fixture.store_dir.clone(),
            vec![fixture.identity_file.clone()],
            fixture.recipients.clone(),
        )
        .unwrap();
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"manifest-canary".to_vec()),
            )
            .await
            .unwrap();

        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].present);
        assert_eq!(listed[0].label.as_str(), "Canary token");
        assert!(!format!("{listed:?}").contains("manifest-canary"));
    }

    #[test]
    fn rejects_path_escape_names_before_use() {
        let project = ProjectId::new("janus").unwrap();
        let name = SecretName::new("../CANARY").unwrap();
        let err = match AgeSecretStore::from_catalog(
            project.clone(),
            "default",
            "/tmp/janus-age-test",
            catalog(&project, &name),
            vec![PathBuf::from("identity")],
            vec!["age1unused".to_string()],
        ) {
            Ok(_) => panic!("path escape manifest entry should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, JanusError::InvalidManifest { .. }));
    }
}

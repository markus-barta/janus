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
    AuditAction, AuditEvent, AuditOutcome, AuditSink, HealthStatus, JanusError, JanusResult,
    ManifestCatalog, PrincipalChain, ProfileId, ProjectId, RotationOutcome, RotationSpec,
    RotationStrategy, SafeLabel, ScopeRef, SecretDescriptor, SecretMeta, SecretName, SecretStore,
    SecretValue, Severity, StoreCapabilities, TrustLevel,
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

/// Value-free result for age admin operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeAdminOutcome {
    /// Stable admin action label.
    pub action: &'static str,
    /// Whether encrypted material was rewritten.
    pub changed: bool,
    /// Number of manifest-present secret files considered.
    pub present_secrets: usize,
    /// Number of configured recipients after the operation.
    pub recipient_count: usize,
    /// Admin operations never return secret values.
    pub value_returned: bool,
}

/// Value-free recoverability check report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeRecoverabilityReport {
    /// Number of manifest-present secret files checked.
    pub checked: usize,
    /// Whether every checked file decrypted with the supplied identity set.
    pub recoverable: bool,
    /// Recoverability checks never return secret values.
    pub value_returned: bool,
}

/// Value-free recipient/key rotation dry-run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeReencryptPlan {
    /// Number of manifest-present secret files that would be considered.
    pub present_secrets: usize,
    /// Current recipient count.
    pub current_recipient_count: usize,
    /// Proposed recipient count after validation/deduplication.
    pub proposed_recipient_count: usize,
    /// Whether the proposed recipient set differs from the current set.
    pub would_change: bool,
    /// Dry-runs never return secret values.
    pub value_returned: bool,
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

    /// Value-free count of configured recipients.
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Plan a recipient-set change without decrypting or writing values.
    pub fn key_rotation_dry_run(
        &self,
        proposed_recipients: Vec<String>,
    ) -> JanusResult<AgeReencryptPlan> {
        let proposed_recipients = normalize_recipient_strings(proposed_recipients)?;
        Ok(AgeReencryptPlan {
            present_secrets: self.present_secret_paths()?.len(),
            current_recipient_count: self.recipients.len(),
            proposed_recipient_count: proposed_recipients.len(),
            would_change: proposed_recipients != self.recipients,
            value_returned: false,
        })
    }

    /// Plan a recipient-set change with value-free audit evidence.
    pub fn key_rotation_dry_run_with_audit<A>(
        &self,
        proposed_recipients: Vec<String>,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<AgeReencryptPlan>
    where
        A: AuditSink,
    {
        match self.key_rotation_dry_run(proposed_recipients) {
            Ok(plan) => {
                audit.record(AuditEvent::new(
                    AuditAction::AdminReencrypt,
                    AuditOutcome::Allowed,
                    "dry_run",
                    Severity::Notice,
                    None,
                    principal,
                ))?;
                Ok(plan)
            }
            Err(err) => {
                audit.record(AuditEvent::new(
                    AuditAction::AdminReencrypt,
                    AuditOutcome::Denied,
                    "dry_run_failed",
                    Severity::Warning,
                    None,
                    principal,
                ))?;
                Err(err)
            }
        }
    }

    /// Prove a break-glass/admin identity can decrypt every present manifest
    /// entry, without returning plaintext.
    pub async fn verify_recoverability(
        &self,
        identity_files: Vec<PathBuf>,
    ) -> JanusResult<AgeRecoverabilityReport> {
        let paths = self.present_secret_paths()?;
        let checked = paths.len();
        tokio::task::spawn_blocking(move || verify_recoverability_paths(&paths, &identity_files))
            .await
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("age recoverability task failed: {err}"),
            })??;
        Ok(AgeRecoverabilityReport {
            checked,
            recoverable: true,
            value_returned: false,
        })
    }

    /// Prove recoverability with value-free audit evidence.
    pub async fn verify_recoverability_with_audit<A>(
        &self,
        identity_files: Vec<PathBuf>,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<AgeRecoverabilityReport>
    where
        A: AuditSink,
    {
        match self.verify_recoverability(identity_files).await {
            Ok(report) => {
                audit.record(AuditEvent::new(
                    AuditAction::BackendHealth,
                    AuditOutcome::Allowed,
                    "recoverability_ok",
                    Severity::Notice,
                    None,
                    principal,
                ))?;
                Ok(report)
            }
            Err(err) => {
                audit.record(AuditEvent::new(
                    AuditAction::BackendHealth,
                    AuditOutcome::Denied,
                    "recoverability_failed",
                    Severity::Warning,
                    None,
                    principal,
                ))?;
                Err(err)
            }
        }
    }

    /// Add a recipient and re-encrypt present files to the expanded set.
    pub async fn add_recipient(
        &mut self,
        recipient: impl Into<String>,
    ) -> JanusResult<AgeAdminOutcome> {
        let recipient = recipient.into();
        let mut recipients = self.recipients.clone();
        if !recipients
            .iter()
            .any(|existing| existing.trim() == recipient.trim())
        {
            recipients.push(recipient);
        }
        self.reencrypt_all(recipients).await
    }

    /// Add a recipient only after required audit evidence is accepted.
    pub async fn add_recipient_with_audit<A>(
        &mut self,
        recipient: impl Into<String>,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<AgeAdminOutcome>
    where
        A: AuditSink,
    {
        record_admin_reencrypt_preflight(audit, principal, "recipient_add")?;
        self.add_recipient(recipient).await
    }

    /// Remove a recipient and re-encrypt present files to the reduced set.
    pub async fn remove_recipient(&mut self, recipient: &str) -> JanusResult<AgeAdminOutcome> {
        let recipients = self
            .recipients
            .iter()
            .filter(|existing| existing.trim() != recipient.trim())
            .cloned()
            .collect::<Vec<_>>();
        if recipients.len() == self.recipients.len() {
            return Ok(AgeAdminOutcome {
                action: "admin.reencrypt",
                changed: false,
                present_secrets: self.present_secret_paths()?.len(),
                recipient_count: self.recipients.len(),
                value_returned: false,
            });
        }
        self.reencrypt_all(recipients).await
    }

    /// Remove a recipient only after required audit evidence is accepted.
    pub async fn remove_recipient_with_audit<A>(
        &mut self,
        recipient: &str,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<AgeAdminOutcome>
    where
        A: AuditSink,
    {
        record_admin_reencrypt_preflight(audit, principal, "recipient_remove")?;
        self.remove_recipient(recipient).await
    }

    /// Re-encrypt every present manifest entry to a new recipient set.
    pub async fn reencrypt_all(&mut self, recipients: Vec<String>) -> JanusResult<AgeAdminOutcome> {
        let recipients = normalize_recipient_strings(recipients)?;
        let paths = self.present_secret_paths()?;
        let present_secrets = paths.len();
        if recipients == self.recipients {
            return Ok(AgeAdminOutcome {
                action: "admin.reencrypt",
                changed: false,
                present_secrets,
                recipient_count: self.recipients.len(),
                value_returned: false,
            });
        }

        let scope_dir = self.scope_dir();
        let identity_files = self.identity_files.clone();
        let next_recipients = recipients.clone();
        tokio::task::spawn_blocking(move || {
            reencrypt_paths(&paths, &scope_dir, &identity_files, &next_recipients)
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age reencrypt task failed: {err}"),
        })??;
        self.recipients = recipients;
        Ok(AgeAdminOutcome {
            action: "admin.reencrypt",
            changed: true,
            present_secrets,
            recipient_count: self.recipients.len(),
            value_returned: false,
        })
    }

    /// Re-encrypt all present entries only after required audit evidence is accepted.
    pub async fn reencrypt_all_with_audit<A>(
        &mut self,
        recipients: Vec<String>,
        audit: &mut A,
        principal: &PrincipalChain,
    ) -> JanusResult<AgeAdminOutcome>
    where
        A: AuditSink,
    {
        record_admin_reencrypt_preflight(audit, principal, "reencrypt_all")?;
        self.reencrypt_all(recipients).await
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

    fn present_secret_paths(&self) -> JanusResult<Vec<PathBuf>> {
        self.ensure_scope_dir()?;
        let mut paths = Vec::new();
        for meta in self.catalog.entries() {
            let path = self.path_for(&meta.name)?;
            if path.is_file() {
                paths.push(path);
            }
        }
        Ok(paths)
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
    let encrypted = encrypt_to_bytes(recipient_strings, plaintext)?;
    write_atomically(path, scope_dir, &encrypted)
}

fn encrypt_to_bytes(recipient_strings: &[String], plaintext: &[u8]) -> JanusResult<Vec<u8>> {
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
    Ok(encrypted)
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

fn verify_recoverability_paths(paths: &[PathBuf], identity_files: &[PathBuf]) -> JanusResult<()> {
    parse_identity_files(identity_files)?;
    for path in paths {
        let mut plaintext = decrypt_file(path, identity_files)?;
        plaintext.zeroize();
    }
    Ok(())
}

fn reencrypt_paths(
    paths: &[PathBuf],
    scope_dir: &Path,
    identity_files: &[PathBuf],
    recipients: &[String],
) -> JanusResult<()> {
    let mut encrypted = Vec::with_capacity(paths.len());
    for path in paths {
        let mut plaintext = decrypt_file(path, identity_files)?;
        let ciphertext = encrypt_to_bytes(recipients, &plaintext)?;
        plaintext.zeroize();
        encrypted.push((path.clone(), ciphertext));
    }
    for (path, ciphertext) in encrypted {
        write_atomically(&path, scope_dir, &ciphertext)?;
    }
    Ok(())
}

fn record_admin_reencrypt_preflight<A>(
    audit: &mut A,
    principal: &PrincipalChain,
    reason_code: &'static str,
) -> JanusResult<()>
where
    A: AuditSink,
{
    audit.record(AuditEvent::new(
        AuditAction::AdminReencrypt,
        AuditOutcome::Allowed,
        reason_code,
        Severity::High,
        None,
        principal,
    ))
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

fn normalize_recipient_strings(values: Vec<String>) -> JanusResult<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || normalized.iter().any(|existing| existing == value) {
            continue;
        }
        normalized.push(value.to_string());
    }
    parse_recipients(&normalized)?;
    Ok(normalized)
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
    use janus_core::{
        AuditWrite, ManifestCatalog, Principal, PrincipalId, PrincipalKind, SecretRef,
    };
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
        host_recipient: String,
        admin_recipient: String,
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
        let host_recipient = host.to_public().to_string();
        let admin_recipient = admin.to_public().to_string();
        let project = ProjectId::new("janus").unwrap();
        let canary = SecretName::new("CANARY").unwrap();
        Fixture {
            store_dir: tmp.path().join("store"),
            identity_file,
            admin_identity_file,
            host_recipient: host_recipient.clone(),
            admin_recipient: admin_recipient.clone(),
            recipients: vec![host_recipient, admin_recipient],
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

    fn extra_identity(fixture: &Fixture, filename: &str) -> (PathBuf, String) {
        let identity = age::x25519::Identity::generate();
        let identity_file = fixture._tmp.path().join(filename);
        let identity_string = identity.to_string();
        fs::write(&identity_file, identity_string.expose_secret()).unwrap();
        (identity_file, identity.to_public().to_string())
    }

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("age-admin").unwrap(),
            ),
            ScopeRef::new("janus/default").unwrap(),
        )
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
    async fn recoverability_check_is_value_free_and_denies_wrong_identity() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"break-glass-canary".to_vec()),
            )
            .await
            .unwrap();

        let report = store
            .verify_recoverability(vec![fixture.admin_identity_file.clone()])
            .await
            .unwrap();
        assert_eq!(
            report,
            AgeRecoverabilityReport {
                checked: 1,
                recoverable: true,
                value_returned: false,
            }
        );
        assert!(!format!("{report:?}").contains("break-glass-canary"));

        let (wrong_identity, _) = extra_identity(&fixture, "wrong.identity");
        assert!(matches!(
            store.verify_recoverability(vec![wrong_identity]).await,
            Err(JanusError::StoreUnavailable { .. })
        ));
    }

    #[tokio::test]
    async fn audited_recoverability_records_value_free_evidence() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        let principal = principal();
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"recoverability-audit-canary".to_vec()),
            )
            .await
            .unwrap();

        let mut audit = AuditWrite::accepting();
        let report = store
            .verify_recoverability_with_audit(
                vec![fixture.admin_identity_file.clone()],
                &mut audit,
                &principal,
            )
            .await
            .unwrap();
        assert_eq!(report.checked, 1);
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::BackendHealth);
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "recoverability_ok");
        assert_eq!(event.severity, Severity::Notice);
        assert!(!event.value_returned);
        assert!(event
            .event_hash
            .as_ref()
            .is_some_and(|hash| hash.len() == 64));
        assert!(!format!("{event:?}").contains("recoverability-audit-canary"));

        let (wrong_identity, _) = extra_identity(&fixture, "wrong-recovery.identity");
        let mut denied_audit = AuditWrite::accepting();
        assert!(matches!(
            store
                .verify_recoverability_with_audit(
                    vec![wrong_identity],
                    &mut denied_audit,
                    &principal
                )
                .await,
            Err(JanusError::StoreUnavailable { .. })
        ));
        let denied = &denied_audit.events()[0];
        assert_eq!(denied.action, AuditAction::BackendHealth);
        assert_eq!(denied.outcome, AuditOutcome::Denied);
        assert_eq!(denied.reason_code, "recoverability_failed");
        assert_eq!(denied.severity, Severity::Warning);
        assert!(!denied.value_returned);
    }

    #[tokio::test]
    async fn recipient_admin_ops_reencrypt_without_returning_values() {
        let fixture = fixture();
        let (new_identity, new_recipient) = extra_identity(&fixture, "new-admin.identity");
        let mut host_store = store(&fixture, fixture.identity_file.clone());
        host_store
            .set(
                &fixture.canary,
                SecretValue::new(b"recipient-admin-canary".to_vec()),
            )
            .await
            .unwrap();

        let plan = host_store
            .key_rotation_dry_run(vec![
                fixture.host_recipient.clone(),
                fixture.admin_recipient.clone(),
                new_recipient.clone(),
            ])
            .unwrap();
        assert_eq!(plan.present_secrets, 1);
        assert_eq!(plan.current_recipient_count, 2);
        assert_eq!(plan.proposed_recipient_count, 3);
        assert!(plan.would_change);
        assert!(!plan.value_returned);

        let added = host_store
            .add_recipient(new_recipient.clone())
            .await
            .unwrap();
        assert_eq!(
            added,
            AgeAdminOutcome {
                action: "admin.reencrypt",
                changed: true,
                present_secrets: 1,
                recipient_count: 3,
                value_returned: false,
            }
        );
        assert!(!format!("{added:?}").contains("recipient-admin-canary"));

        let new_reader = AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![new_identity],
            vec![new_recipient.clone()],
        )
        .unwrap();
        let recovered = new_reader.get(&fixture.canary).await.unwrap();
        assert_eq!(recovered.expose_bytes(), b"recipient-admin-canary");

        let removed = host_store
            .remove_recipient(&fixture.admin_recipient)
            .await
            .unwrap();
        assert_eq!(removed.recipient_count, 2);
        assert!(removed.changed);
        let old_admin_reader = AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![fixture.admin_identity_file.clone()],
            vec![fixture.admin_recipient.clone()],
        )
        .unwrap();
        assert!(matches!(
            old_admin_reader.get(&fixture.canary).await,
            Err(JanusError::StoreUnavailable { .. })
        ));

        let host_recovered = host_store.get(&fixture.canary).await.unwrap();
        assert_eq!(host_recovered.expose_bytes(), b"recipient-admin-canary");

        let unchanged = host_store
            .reencrypt_all(vec![fixture.host_recipient.clone(), new_recipient])
            .await
            .unwrap();
        assert!(!unchanged.changed);
        assert_eq!(unchanged.present_secrets, 1);
        assert!(!unchanged.value_returned);
    }

    #[tokio::test]
    async fn audited_recipient_admin_ops_record_and_fail_closed() {
        let fixture = fixture();
        let (new_identity, new_recipient) = extra_identity(&fixture, "audited-admin.identity");
        let mut store = store(&fixture, fixture.identity_file.clone());
        let principal = principal();
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"audited-admin-canary".to_vec()),
            )
            .await
            .unwrap();

        let mut dry_run_audit = AuditWrite::accepting();
        let plan = store
            .key_rotation_dry_run_with_audit(
                vec![
                    fixture.host_recipient.clone(),
                    fixture.admin_recipient.clone(),
                    new_recipient.clone(),
                ],
                &mut dry_run_audit,
                &principal,
            )
            .unwrap();
        assert!(plan.would_change);
        let dry_run_event = &dry_run_audit.events()[0];
        assert_eq!(dry_run_event.action, AuditAction::AdminReencrypt);
        assert_eq!(dry_run_event.outcome, AuditOutcome::Allowed);
        assert_eq!(dry_run_event.reason_code, "dry_run");
        assert_eq!(dry_run_event.severity, Severity::Notice);
        assert!(!dry_run_event.value_returned);

        let mut failing_audit = AuditWrite::failing();
        assert!(matches!(
            store
                .remove_recipient_with_audit(
                    &fixture.admin_recipient,
                    &mut failing_audit,
                    &principal
                )
                .await,
            Err(JanusError::AuditUnavailable { .. })
        ));
        assert_eq!(store.recipient_count(), 2);
        let admin_reader = AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![fixture.admin_identity_file.clone()],
            vec![fixture.admin_recipient.clone()],
        )
        .unwrap();
        let admin_recovered = admin_reader.get(&fixture.canary).await.unwrap();
        assert_eq!(admin_recovered.expose_bytes(), b"audited-admin-canary");

        let mut audit = AuditWrite::accepting();
        let added = store
            .add_recipient_with_audit(new_recipient.clone(), &mut audit, &principal)
            .await
            .unwrap();
        assert!(added.changed);
        assert_eq!(added.recipient_count, 3);
        let event = &audit.events()[0];
        assert_eq!(event.action, AuditAction::AdminReencrypt);
        assert_eq!(event.outcome, AuditOutcome::Allowed);
        assert_eq!(event.reason_code, "recipient_add");
        assert_eq!(event.severity, Severity::High);
        assert!(!event.value_returned);
        assert!(!format!("{event:?}").contains("audited-admin-canary"));

        let new_reader = AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![new_identity],
            vec![new_recipient],
        )
        .unwrap();
        let new_recovered = new_reader.get(&fixture.canary).await.unwrap();
        assert_eq!(new_recovered.expose_bytes(), b"audited-admin-canary");
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

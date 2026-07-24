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
use fs2::FileExt;
use janus_core::{
    load_secretspec_manifest_catalog, AuditAction, AuditEvent, AuditOutcome, AuditSink,
    HealthStatus, JanusError, JanusResult, ManifestCatalog, PrincipalChain, ProjectId,
    RotationOutcome, RotationSpec, RotationStrategy, ScopeRef, SecretDescriptor, SecretMeta,
    SecretMetadataOverlay, SecretName, SecretRef, SecretStore, SecretValue, Severity,
    StoreCapabilities,
};
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

struct StoreLock {
    file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
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

/// Value-free handle to encrypted rollback material for a generated rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeRollbackMaterial {
    /// Secret that can be restored by this rollback handle.
    pub secret_ref: SecretRef,
    /// Opaque rollback-material identifier.
    pub rollback_id: String,
    /// Rollback handles never return secret values.
    pub value_returned: bool,
}

impl AgeSecretStore {
    /// Create encrypted material only when the manifest-declared target is absent.
    ///
    /// This is the entry-transaction primitive. Unlike [`SecretStore::set`], it
    /// cannot overwrite existing ciphertext, even if another writer creates the
    /// final path between the initial absence check and installation.
    pub async fn create_if_absent(
        &mut self,
        name: &SecretName,
        value: SecretValue,
    ) -> JanusResult<AgeAdminOutcome> {
        self.ensure_manifest(name)?;
        self.ensure_scope_dir()?;
        let path = self.path_for(name)?;
        let scope_dir = self.scope_dir();
        let recipients = self.recipients.clone();
        let recipient_count = recipients.len();
        let mut plaintext = value.expose_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let result = encrypt_to_new_file(&path, &scope_dir, &recipients, &plaintext);
            plaintext.zeroize();
            result
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age create task failed: {err}"),
        })??;
        Ok(AgeAdminOutcome {
            action: "entry.create",
            changed: true,
            present_secrets: 1,
            recipient_count,
            value_returned: false,
        })
    }

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
        scope: ScopeRef,
    ) -> JanusResult<Self> {
        Self::load_from_secretspec_manifest_with_metadata(
            config_path,
            profile,
            root_dir,
            identity_files,
            recipients,
            scope,
            None,
        )
    }

    /// Load a `secretspec.toml` allowlist with an optional Janus metadata overlay.
    pub fn load_from_secretspec_manifest_with_metadata(
        config_path: impl AsRef<Path>,
        profile: impl Into<String>,
        root_dir: impl Into<PathBuf>,
        identity_files: Vec<PathBuf>,
        recipients: Vec<String>,
        scope: ScopeRef,
        metadata: Option<&SecretMetadataOverlay>,
    ) -> JanusResult<Self> {
        let profile = profile.into();
        let (project, catalog) =
            load_secretspec_manifest_catalog(config_path, &profile, &scope, metadata)?;

        Self::from_catalog(
            project,
            profile,
            root_dir,
            catalog,
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

    /// Store a generated replacement value while preserving the current
    /// encrypted material for rollback.
    pub async fn prepare_generated_rotation(
        &mut self,
        name: &SecretName,
        value: SecretValue,
    ) -> JanusResult<AgeRollbackMaterial> {
        let rollback_id = generated_rollback_id()?;
        self.prepare_generated_rotation_with_id(name, value, rollback_id)
            .await
    }

    /// Store a replacement with a caller-bound opaque rollback id.
    ///
    /// The lifecycle journal persists the id before value-bearing work starts,
    /// so restart recovery can always find and restore the old ciphertext.
    pub async fn prepare_generated_rotation_with_id(
        &mut self,
        name: &SecretName,
        value: SecretValue,
        rollback_id: String,
    ) -> JanusResult<AgeRollbackMaterial> {
        let secret_ref = self.ensure_manifest(name)?.secret_ref.clone();
        validate_rollback_id(&rollback_id)?;
        self.ensure_scope_dir()?;
        let path = self.path_for(name)?;
        let rollback_path = self.rollback_path_for(name, &rollback_id)?;
        let scope_dir = self.scope_dir();
        let recipients = self.recipients.clone();
        let not_found_name = secret_ref.as_str().to_string();
        let mut plaintext = value.expose_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let result = prepare_generated_rotation_locked(
                &path,
                &rollback_path,
                &scope_dir,
                &recipients,
                &plaintext,
                &not_found_name,
            );
            plaintext.zeroize();
            result
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation prepare task failed: {err}"),
        })??;
        Ok(AgeRollbackMaterial {
            secret_ref,
            rollback_id,
            value_returned: false,
        })
    }

    /// Commit a prepared generated rotation by deleting encrypted rollback
    /// material after external validation has succeeded.
    pub async fn commit_generated_rotation(
        &mut self,
        rollback: &AgeRollbackMaterial,
    ) -> JanusResult<AgeAdminOutcome> {
        let name = self.catalog.meta_by_ref(&rollback.secret_ref)?.name.clone();
        let rollback_path = self.rollback_path_for(&name, &rollback.rollback_id)?;
        let scope_dir = self.scope_dir();
        let not_found_name = rollback.secret_ref.as_str().to_string();
        let recipient_count = self.recipients.len();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            commit_generated_rotation_locked(&rollback_path, &not_found_name)?;
            Ok(AgeAdminOutcome {
                action: "rotation.commit",
                changed: true,
                present_secrets: 1,
                recipient_count,
                value_returned: false,
            })
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation commit task failed: {err}"),
        })?
    }

    /// Restore a generated rotation from encrypted rollback material.
    pub async fn rollback_generated_rotation(
        &mut self,
        rollback: &AgeRollbackMaterial,
    ) -> JanusResult<AgeAdminOutcome> {
        let name = self.catalog.meta_by_ref(&rollback.secret_ref)?.name.clone();
        let path = self.path_for(&name)?;
        let rollback_path = self.rollback_path_for(&name, &rollback.rollback_id)?;
        let scope_dir = self.scope_dir();
        let not_found_name = rollback.secret_ref.as_str().to_string();
        let recipient_count = self.recipients.len();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            rollback_generated_rotation_locked(&path, &rollback_path, &scope_dir, &not_found_name)?;
            Ok(AgeAdminOutcome {
                action: "rotation.rollback",
                changed: true,
                present_secrets: 1,
                recipient_count,
                value_returned: false,
            })
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation rollback task failed: {err}"),
        })?
    }

    /// Idempotently discard rollback material after a committed replacement.
    pub async fn commit_generated_rotation_if_present(
        &mut self,
        rollback: &AgeRollbackMaterial,
    ) -> JanusResult<AgeAdminOutcome> {
        let name = self.catalog.meta_by_ref(&rollback.secret_ref)?.name.clone();
        let rollback_path = self.rollback_path_for(&name, &rollback.rollback_id)?;
        let scope_dir = self.scope_dir();
        let recipient_count = self.recipients.len();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let changed = if rollback_path.is_file() {
                fs::remove_file(&rollback_path).map_err(map_store_io)?;
                sync_dir(&scope_dir)?;
                true
            } else {
                false
            };
            Ok(AgeAdminOutcome {
                action: "rotation.commit",
                changed,
                present_secrets: 1,
                recipient_count,
                value_returned: false,
            })
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation commit task failed: {err}"),
        })?
    }

    /// Idempotently restore rollback material when preparation may have
    /// stopped before the journal could observe the backend result.
    pub async fn rollback_generated_rotation_if_present(
        &mut self,
        rollback: &AgeRollbackMaterial,
    ) -> JanusResult<AgeAdminOutcome> {
        let name = self.catalog.meta_by_ref(&rollback.secret_ref)?.name.clone();
        let path = self.path_for(&name)?;
        let rollback_path = self.rollback_path_for(&name, &rollback.rollback_id)?;
        let scope_dir = self.scope_dir();
        let recipient_count = self.recipients.len();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let changed = if rollback_path.is_file() {
                let encrypted = fs::read(&rollback_path).map_err(map_store_io)?;
                write_atomically(&path, &scope_dir, &encrypted)?;
                fs::remove_file(&rollback_path).map_err(map_store_io)?;
                sync_dir(&scope_dir)?;
                true
            } else {
                false
            };
            Ok(AgeAdminOutcome {
                action: "rotation.rollback",
                changed,
                present_secrets: 1,
                recipient_count,
                value_returned: false,
            })
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation rollback task failed: {err}"),
        })?
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
        let scope_dir = self.scope_dir();
        let candidate_paths = self.catalog_secret_paths()?;
        let identity_files = self.identity_files.clone();
        let next_recipients = recipients.clone();
        let current_recipients = self.recipients.clone();
        let next_recipient_count = next_recipients.len();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let paths = present_paths(candidate_paths);
            let present_secrets = paths.len();
            if next_recipients == current_recipients {
                return Ok(AgeAdminOutcome {
                    action: "admin.reencrypt",
                    changed: false,
                    present_secrets,
                    recipient_count: current_recipients.len(),
                    value_returned: false,
                });
            }
            reencrypt_paths(&paths, &scope_dir, &identity_files, &next_recipients)?;
            Ok(AgeAdminOutcome {
                action: "admin.reencrypt",
                changed: true,
                present_secrets,
                recipient_count: next_recipient_count,
                value_returned: false,
            })
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age reencrypt task failed: {err}"),
        })?
        .inspect(|outcome| {
            if outcome.changed {
                self.recipients = recipients;
            }
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

    fn rollback_path_for(&self, name: &SecretName, rollback_id: &str) -> JanusResult<PathBuf> {
        validate_rollback_id(rollback_id)?;
        let path = self.path_for(name)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| JanusError::StoreUnavailable {
                detail: "age rollback path has no file name".to_string(),
            })?;
        let mut rollback_file_name = file_name.to_os_string();
        rollback_file_name.push(format!(".rollback.{rollback_id}"));
        Ok(path.with_file_name(rollback_file_name))
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
        let paths = present_paths(self.catalog_secret_paths()?);
        Ok(paths)
    }

    fn catalog_secret_paths(&self) -> JanusResult<Vec<PathBuf>> {
        self.catalog
            .entries()
            .iter()
            .map(|meta| self.path_for(&meta.name))
            .collect()
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
            let _lock = try_lock_store_exclusive(&scope_dir)?;
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
        let secret_ref = self.ensure_manifest(name)?.secret_ref.clone();
        self.ensure_scope_dir()?;
        let path = self.path_for(name)?;
        let rollback_id = generated_rollback_id()?;
        let rollback_path = self.rollback_path_for(name, &rollback_id)?;
        let scope_dir = self.scope_dir();
        let recipients = self.recipients.clone();
        let not_found_name = secret_ref.as_str().to_string();
        let mut plaintext = value.expose_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            let result = (|| {
                prepare_generated_rotation_locked(
                    &path,
                    &rollback_path,
                    &scope_dir,
                    &recipients,
                    &plaintext,
                    &not_found_name,
                )?;
                commit_generated_rotation_locked(&rollback_path, &not_found_name)
            })();
            plaintext.zeroize();
            result
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age generated rotation task failed: {err}"),
        })??;
        Ok(RotationOutcome::rotated(secret_ref))
    }

    async fn delete(&mut self, name: &SecretName) -> JanusResult<()> {
        self.ensure_manifest(name)?;
        let path = self.path_for(name)?;
        let scope_dir = self.scope_dir();
        let name = name.as_str().to_string();
        tokio::task::spawn_blocking(move || {
            let _lock = try_lock_store_exclusive(&scope_dir)?;
            if !path.is_file() {
                return Err(JanusError::NotFound { name });
            }
            fs::remove_file(&path).map_err(map_store_io)?;
            prune_empty_secret_dirs(path.parent(), &scope_dir)
        })
        .await
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("age delete task failed: {err}"),
        })?
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

fn encrypt_to_new_file(
    path: &Path,
    scope_dir: &Path,
    recipient_strings: &[String],
    plaintext: &[u8],
) -> JanusResult<()> {
    let encrypted = encrypt_to_bytes(recipient_strings, plaintext)?;
    write_atomically_create_new(path, scope_dir, &encrypted)
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

fn prepare_generated_rotation_locked(
    path: &Path,
    rollback_path: &Path,
    scope_dir: &Path,
    recipients: &[String],
    plaintext: &[u8],
    not_found_name: &str,
) -> JanusResult<()> {
    if !path.is_file() {
        return Err(JanusError::NotFound {
            name: not_found_name.to_string(),
        });
    }
    if rollback_path.exists() {
        return Err(JanusError::StoreUnavailable {
            detail: "age rotation rollback material already exists".to_string(),
        });
    }
    let current = fs::read(path).map_err(map_store_io)?;
    write_atomically(rollback_path, scope_dir, &current)?;
    encrypt_to_file(path, scope_dir, recipients, plaintext)
}

fn commit_generated_rotation_locked(rollback_path: &Path, not_found_name: &str) -> JanusResult<()> {
    if !rollback_path.is_file() {
        return Err(JanusError::NotFound {
            name: not_found_name.to_string(),
        });
    }
    fs::remove_file(rollback_path).map_err(map_store_io)?;
    if let Some(parent) = rollback_path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn rollback_generated_rotation_locked(
    path: &Path,
    rollback_path: &Path,
    scope_dir: &Path,
    not_found_name: &str,
) -> JanusResult<()> {
    if !rollback_path.is_file() {
        return Err(JanusError::NotFound {
            name: not_found_name.to_string(),
        });
    }
    let encrypted = fs::read(rollback_path).map_err(map_store_io)?;
    write_atomically(path, scope_dir, &encrypted)?;
    fs::remove_file(rollback_path).map_err(map_store_io)?;
    if let Some(parent) = rollback_path.parent() {
        sync_dir(parent)?;
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

fn present_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|path| path.is_file()).collect()
}

fn generated_rollback_id() -> JanusResult<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| JanusError::StoreUnavailable {
            detail: format!("system clock before unix epoch: {err}"),
        })?
        .as_nanos();
    Ok(format!("rb_{}_{}", std::process::id(), nanos))
}

fn validate_rollback_id(value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(JanusError::InvalidIdentifier {
            kind: "age_rollback_id",
        });
    }
    Ok(())
}

fn try_lock_store_exclusive(scope_dir: &Path) -> JanusResult<StoreLock> {
    fs::create_dir_all(scope_dir).map_err(map_store_io)?;
    set_dir_private(scope_dir)?;
    let lock_path = scope_dir.join(".janus-age.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(map_store_io)?;
    set_file_private(&file)?;
    file.try_lock_exclusive().map_err(|err| {
        if err.kind() == std::io::ErrorKind::WouldBlock {
            JanusError::StoreUnavailable {
                detail: "age store lock is already held".to_string(),
            }
        } else {
            map_store_io(err)
        }
    })?;
    Ok(StoreLock { file })
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
        if !trimmed.starts_with("ssh-ed25519 ") {
            return Err(JanusError::StoreUnavailable {
                detail: "only native age and ssh-ed25519 recipients are supported".to_string(),
            });
        }
        if let Ok(recipient) = trimmed.parse::<age::ssh::Recipient>() {
            match recipient {
                age::ssh::Recipient::SshEd25519(_, _) => {
                    recipients.push(Box::new(recipient));
                    continue;
                }
                age::ssh::Recipient::SshRsa(_, _) => {
                    return Err(JanusError::StoreUnavailable {
                        detail: "ssh-rsa recipients are not supported".to_string(),
                    });
                }
            }
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
        let identity_lines = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        if identity_lines.len() == 1 {
            if let Ok(identity) = identity_lines[0].parse::<age::x25519::Identity>() {
                identities.push(Box::new(identity));
                continue;
            }
        }
        if let Ok(identity) = trimmed.parse::<age::x25519::Identity>() {
            identities.push(Box::new(identity));
            continue;
        }
        ensure_ssh_ed25519_identity(trimmed)?;
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

fn ensure_ssh_ed25519_identity(contents: &str) -> JanusResult<()> {
    if contents.contains("BEGIN RSA PRIVATE KEY") {
        return Err(JanusError::StoreUnavailable {
            detail: "ssh-rsa identities are not supported".to_string(),
        });
    }
    let identity = ssh_key::PrivateKey::from_openssh(contents.as_bytes()).map_err(|_| {
        JanusError::StoreUnavailable {
            detail: "age ssh identity could not be parsed".to_string(),
        }
    })?;
    if identity.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(JanusError::StoreUnavailable {
            detail: "only ssh-ed25519 identities are supported".to_string(),
        });
    }
    Ok(())
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

fn write_atomically_create_new(path: &Path, scope_dir: &Path, bytes: &[u8]) -> JanusResult<()> {
    let parent = path.parent().ok_or_else(|| JanusError::StoreUnavailable {
        detail: "age store path has no parent".to_string(),
    })?;
    create_secret_parent_dirs(parent, scope_dir)?;
    let tmp = parent.join(format!(
        ".janus-age-entry-{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| JanusError::StoreUnavailable {
                detail: format!("system clock before unix epoch: {err}"),
            })?
            .as_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(map_store_io)?;
        set_file_private(&file)?;
        file.write_all(bytes).map_err(map_store_io)?;
        file.sync_all().map_err(map_store_io)?;
        drop(file);
        fs::hard_link(&tmp, path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                JanusError::policy_denied(
                    "entry_target_present",
                    "entry transaction cannot overwrite existing encrypted material",
                )
            } else {
                map_store_io(err)
            }
        })?;
        if let Err(err) = fs::remove_file(&tmp) {
            let _ = fs::remove_file(path);
            return Err(map_store_io(err));
        }
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
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
        AuditWrite, ManifestCatalog, OwnerRef, Principal, PrincipalId, PrincipalKind, ProfileId,
        SafeLabel, ScopePathV1, SecretClass, SecretLifecycle, SecretMeta, SecretRef, TrustLevel,
    };
    use tempfile::TempDir;

    const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref()
    }
    const TEST_SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn supported_ssh_key_policy_accepts_only_ed25519() {
        ensure_ssh_ed25519_identity(TEST_SSH_ED25519_SK).unwrap();
        assert_eq!(
            parse_recipients(&[TEST_SSH_ED25519_PK.to_string()])
                .unwrap()
                .len(),
            1
        );

        for unsupported in [
            "ssh-rsa SYNTHETIC_NON_KEY",
            "ecdsa-sha2-nistp256 SYNTHETIC_NON_KEY",
        ] {
            assert!(matches!(
                parse_recipients(&[unsupported.to_string()]),
                Err(JanusError::StoreUnavailable { .. })
            ));
        }
        assert!(matches!(
            ensure_ssh_ed25519_identity(
                "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_NON_KEY\n-----END RSA PRIVATE KEY-----"
            ),
            Err(JanusError::StoreUnavailable { .. })
        ));
    }

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

    fn catalog(_project: &ProjectId, canary: &SecretName) -> ManifestCatalog {
        ManifestCatalog::new(vec![SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&scope(), canary),
            name: canary.clone(),
            label: SafeLabel::new("Canary token").unwrap(),
            scope: scope(),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
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

    fn metadata_overlay() -> SecretMetadataOverlay {
        SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            "#,
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

    #[test]
    fn age_keygen_annotated_identity_file_is_accepted() {
        let fixture = fixture();
        let secret = fs::read_to_string(&fixture.identity_file).unwrap();
        let annotated = fixture._tmp.path().join("annotated.identity");
        fs::write(
            &annotated,
            format!(
                "# created by age-keygen\n# public key: {}\n{}\n",
                fixture.host_recipient,
                secret.trim()
            ),
        )
        .unwrap();
        assert_eq!(parse_identity_files(&[annotated]).unwrap().len(), 1);
    }

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("age-admin").unwrap(),
            ),
            scope(),
        )
    }

    fn assert_lock_error(err: JanusError) {
        match err {
            JanusError::StoreUnavailable { detail } => {
                assert!(detail.contains("lock"));
                assert!(!detail.contains("canary"));
            }
            other => panic!("expected lock StoreUnavailable error, got {other:?}"),
        }
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
    async fn entry_create_is_create_new_and_never_overwrites_ciphertext() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        let outcome = store
            .create_if_absent(
                &fixture.canary,
                SecretValue::new(b"entry-original-canary".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.action, "entry.create");
        assert!(outcome.changed);
        assert!(!outcome.value_returned);
        let path = store.path_for(&fixture.canary).unwrap();
        let original_ciphertext = fs::read(&path).unwrap();

        let error = store
            .create_if_absent(
                &fixture.canary,
                SecretValue::new(b"entry-overwrite-canary".to_vec()),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "entry_target_present",
                ..
            }
        ));
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);
        let recovered = store.get(&fixture.canary).await.unwrap();
        assert_eq!(recovered.expose_bytes(), b"entry-original-canary");
    }

    #[tokio::test]
    async fn generated_rotation_rollback_restores_encrypted_material_without_values() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"rollback-original-canary".to_vec()),
            )
            .await
            .unwrap();
        let path = store.path_for(&fixture.canary).unwrap();
        let original_ciphertext = fs::read(&path).unwrap();

        let rollback = store
            .prepare_generated_rotation(
                &fixture.canary,
                SecretValue::new(b"rollback-replacement-canary".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            rollback.secret_ref,
            fixture
                .catalog
                .meta_by_name(&fixture.canary)
                .unwrap()
                .secret_ref
        );
        assert!(!rollback.value_returned);
        assert!(!format!("{rollback:?}").contains("rollback-original-canary"));
        assert!(!format!("{rollback:?}").contains("rollback-replacement-canary"));

        let rollback_path = store
            .rollback_path_for(&fixture.canary, &rollback.rollback_id)
            .unwrap();
        assert_eq!(fs::read(&rollback_path).unwrap(), original_ciphertext);
        let replacement = store.get(&fixture.canary).await.unwrap();
        assert_eq!(replacement.expose_bytes(), b"rollback-replacement-canary");

        let lock = try_lock_store_exclusive(&store.scope_dir()).unwrap();
        assert_lock_error(
            store
                .rollback_generated_rotation(&rollback)
                .await
                .unwrap_err(),
        );
        drop(lock);

        let outcome = store.rollback_generated_rotation(&rollback).await.unwrap();
        assert_eq!(
            outcome,
            AgeAdminOutcome {
                action: "rotation.rollback",
                changed: true,
                present_secrets: 1,
                recipient_count: 2,
                value_returned: false,
            }
        );
        assert!(!rollback_path.exists());
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);
        let restored = store.get(&fixture.canary).await.unwrap();
        assert_eq!(restored.expose_bytes(), b"rollback-original-canary");
    }

    #[tokio::test]
    async fn generated_rotation_commit_discards_rollback_material() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"commit-original-canary".to_vec()),
            )
            .await
            .unwrap();

        let rollback = store
            .prepare_generated_rotation(
                &fixture.canary,
                SecretValue::new(b"commit-replacement-canary".to_vec()),
            )
            .await
            .unwrap();
        let rollback_path = store
            .rollback_path_for(&fixture.canary, &rollback.rollback_id)
            .unwrap();
        assert!(rollback_path.is_file());

        let lock = try_lock_store_exclusive(&store.scope_dir()).unwrap();
        assert_lock_error(
            store
                .commit_generated_rotation(&rollback)
                .await
                .unwrap_err(),
        );
        drop(lock);

        let outcome = store.commit_generated_rotation(&rollback).await.unwrap();
        assert_eq!(
            outcome,
            AgeAdminOutcome {
                action: "rotation.commit",
                changed: true,
                present_secrets: 1,
                recipient_count: 2,
                value_returned: false,
            }
        );
        assert!(!rollback_path.exists());
        let committed = store.get(&fixture.canary).await.unwrap();
        assert_eq!(committed.expose_bytes(), b"commit-replacement-canary");
        assert!(matches!(
            store.commit_generated_rotation(&rollback).await,
            Err(JanusError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn journal_bound_rotation_recovery_is_idempotent_and_never_overwrites_rollback() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"journal-original-canary".to_vec()),
            )
            .await
            .unwrap();
        let path = store.path_for(&fixture.canary).unwrap();
        let original_ciphertext = fs::read(&path).unwrap();

        let rollback = store
            .prepare_generated_rotation_with_id(
                &fixture.canary,
                SecretValue::new(b"journal-first-replacement".to_vec()),
                "rb_journalbound0001".to_string(),
            )
            .await
            .unwrap();
        let first_replacement_ciphertext = fs::read(&path).unwrap();
        assert_ne!(first_replacement_ciphertext, original_ciphertext);

        let duplicate = store
            .prepare_generated_rotation_with_id(
                &fixture.canary,
                SecretValue::new(b"journal-second-replacement".to_vec()),
                rollback.rollback_id.clone(),
            )
            .await
            .unwrap_err();
        assert!(matches!(duplicate, JanusError::StoreUnavailable { .. }));
        assert_eq!(fs::read(&path).unwrap(), first_replacement_ciphertext);

        let restored = store
            .rollback_generated_rotation_if_present(&rollback)
            .await
            .unwrap();
        assert!(restored.changed);
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);
        let duplicate_restore = store
            .rollback_generated_rotation_if_present(&rollback)
            .await
            .unwrap();
        assert!(!duplicate_restore.changed);
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);

        let committed = store
            .prepare_generated_rotation_with_id(
                &fixture.canary,
                SecretValue::new(b"journal-committed-replacement".to_vec()),
                "rb_journalbound0002".to_string(),
            )
            .await
            .unwrap();
        let committed_ciphertext = fs::read(&path).unwrap();
        assert!(
            store
                .commit_generated_rotation_if_present(&committed)
                .await
                .unwrap()
                .changed
        );
        assert!(
            !store
                .commit_generated_rotation_if_present(&committed)
                .await
                .unwrap()
                .changed
        );
        assert_eq!(fs::read(&path).unwrap(), committed_ciphertext);
    }

    #[tokio::test]
    async fn generated_rotate_commits_rollback_material_after_success() {
        let fixture = fixture();
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(
                &fixture.canary,
                SecretValue::new(b"trait-rotation-original".to_vec()),
            )
            .await
            .unwrap();

        let outcome = store
            .rotate(
                &fixture.canary,
                &RotationSpec::generated(SecretValue::new(b"trait-rotation-new".to_vec())),
            )
            .await
            .unwrap();
        assert!(!outcome.value_returned);
        let rotated = store.get(&fixture.canary).await.unwrap();
        assert_eq!(rotated.expose_bytes(), b"trait-rotation-new");

        let path = store.path_for(&fixture.canary).unwrap();
        let file_name = path.file_name().unwrap().to_string_lossy();
        let rollback_prefix = format!("{file_name}.rollback.");
        let has_rollback_file = fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&rollback_prefix)
        });
        assert!(!has_rollback_file);
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
    async fn write_paths_fail_closed_when_store_lock_is_held() {
        let fixture = fixture();
        let (new_identity, new_recipient) = extra_identity(&fixture, "locked-admin.identity");
        let mut store = store(&fixture, fixture.identity_file.clone());
        store
            .set(&fixture.canary, SecretValue::new(b"locked-canary".to_vec()))
            .await
            .unwrap();

        let lock = try_lock_store_exclusive(&store.scope_dir()).unwrap();
        assert_lock_error(
            store
                .set(
                    &fixture.canary,
                    SecretValue::new(b"should-not-write".to_vec()),
                )
                .await
                .unwrap_err(),
        );
        assert_lock_error(
            store
                .reencrypt_all(vec![
                    fixture.host_recipient.clone(),
                    fixture.admin_recipient.clone(),
                    new_recipient.clone(),
                ])
                .await
                .unwrap_err(),
        );
        assert_lock_error(store.delete(&fixture.canary).await.unwrap_err());
        drop(lock);

        let value = store.get(&fixture.canary).await.unwrap();
        assert_eq!(value.expose_bytes(), b"locked-canary");
        store
            .add_recipient(new_recipient.clone())
            .await
            .expect("write should succeed after lock release");
        let new_reader = AgeSecretStore::from_catalog(
            ProjectId::new("janus").unwrap(),
            "default",
            fixture.store_dir.clone(),
            fixture.catalog.clone(),
            vec![new_identity],
            vec![new_recipient],
        )
        .unwrap();
        let recovered = new_reader.get(&fixture.canary).await.unwrap();
        assert_eq!(recovered.expose_bytes(), b"locked-canary");
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
        let incomplete = AgeSecretStore::load_from_secretspec_manifest(
            &manifest,
            "default",
            fixture.store_dir.clone(),
            vec![fixture.identity_file.clone()],
            fixture.recipients.clone(),
            scope(),
        )
        .unwrap();
        let incomplete_listed = incomplete.list().await.unwrap();
        assert_eq!(incomplete_listed.len(), 1);
        assert!(!incomplete_listed[0].metadata_complete());

        let metadata = metadata_overlay();
        let mut store = AgeSecretStore::load_from_secretspec_manifest_with_metadata(
            &manifest,
            "default",
            fixture.store_dir.clone(),
            vec![fixture.identity_file.clone()],
            fixture.recipients.clone(),
            scope(),
            Some(&metadata),
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
        assert!(listed[0].metadata_complete());
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

//! # janusd — the Janus daemon
//!
//! Wires `janus-core` + `janus-warden` + `janus-forge` into the serving binary
//! that will supersede the Go envelope's serving role at `vault.barta.cm`.
//! The deployed service is still `../../go-envelope`; this binary is growing
//! narrow engine execution surfaces behind value-free broker contracts.

#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use janus_core::{
    BlastRadius, ConsumerDescriptor, ConsumerKind, ConsumerRef, ConsumerRegistry, Environment,
    JanusError, OwnerRef, Principal, PrincipalChain, PrincipalId, PrincipalKind, ReloadMethod,
    SafeLabel, ScopeRef, SecretName, SecretStore, ValidationProbe,
};
use janus_forge::{
    ConsumerRotationHooks, GeneratedAlphabet, GeneratedRotationBroker, GeneratedValuePolicy,
    RotationApproval,
};
use janus_provider_age::AgeSecretStore;

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::ForgeRotateGenerated(config) => run_forge_rotate_generated(config).await,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Help,
    ForgeRotateGenerated(ForgeRotateGeneratedConfig),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForgeRotateGeneratedConfig {
    secret: SecretName,
    reason: SafeLabel,
    consumer_ref: ConsumerRef,
    validation_probe: ValidationProbe,
    alphabet: GeneratedAlphabet,
    length: usize,
    allow_noop_hooks: bool,
}

impl Default for ForgeRotateGeneratedConfig {
    fn default() -> Self {
        Self {
            secret: SecretName::new("UNSET").expect("static secret name"),
            reason: SafeLabel::new("UNSET").expect("static reason"),
            consumer_ref: ConsumerRef::new("consumer.unset").expect("static consumer ref"),
            validation_probe: ValidationProbe::new("unset").expect("static probe"),
            alphabet: GeneratedAlphabet::UrlSafe,
            length: 48,
            allow_noop_hooks: false,
        }
    }
}

async fn run_forge_rotate_generated(config: ForgeRotateGeneratedConfig) -> Result<()> {
    if !config.allow_noop_hooks {
        anyhow::bail!(
            "--allow-noop-hooks is required until JANUS connector reload/validation hooks land"
        );
    }

    let store = load_age_store_from_env()?;
    let descriptors = store
        .list()
        .await
        .context("failed to list age manifest descriptors")?;
    let descriptor = descriptors
        .into_iter()
        .find(|descriptor| descriptor.name == config.secret)
        .ok_or_else(|| JanusError::NotInManifest {
            name: config.secret.as_str().to_string(),
        })?;
    let secret_ref = descriptor.secret_ref.clone();
    let registry = ConsumerRegistry::new(vec![ConsumerDescriptor {
        consumer_ref: config.consumer_ref.clone(),
        secret_ref: secret_ref.clone(),
        kind: ConsumerKind::ManagedCommand,
        owner: OwnerRef::new("janusd-forge")?,
        environment: Environment::new("admin")?,
        reload: ReloadMethod::None,
        validation: vec![config.validation_probe.clone()],
        supports_dual_value: false,
        blast_radius: BlastRadius::new("single generated secret rotation")?,
        declared: true,
    }]);
    let approval = RotationApproval::new(secret_ref, config.reason.clone());
    let policy = GeneratedValuePolicy::new(config.alphabet, config.length)?;
    let principal = forge_principal_from_env()?;
    let mut broker = GeneratedRotationBroker::new(
        store,
        registry,
        janus_core::AuditWrite::accepting(),
        NoopHooks,
    );
    let outcome = broker
        .rotate_generated(&config.secret, &policy, &approval, &principal)
        .await?;

    println!(
        "janusd forge rotate-generated ok secret_ref={} phase={:?} reason_code={} value_returned={}",
        outcome.secret_ref.as_str(),
        outcome.phase,
        outcome.reason_code,
        outcome.value_returned
    );
    Ok(())
}

struct NoopHooks;

#[async_trait]
impl ConsumerRotationHooks for NoopHooks {
    async fn validate(&mut self, _probe: &ValidationProbe) -> janus_core::JanusResult<()> {
        Ok(())
    }

    async fn reload(
        &mut self,
        _consumer: &ConsumerRef,
        _method: &ReloadMethod,
    ) -> janus_core::JanusResult<()> {
        Ok(())
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() || args == ["--help"] || args == ["help"] {
        return Ok(Command::Help);
    }
    match args.as_slice() {
        [forge, rotate, rest @ ..] if forge == "forge" && rotate == "rotate-generated" => {
            parse_forge_rotate_generated(rest.iter().cloned()).map(Command::ForgeRotateGenerated)
        }
        _ => anyhow::bail!("unsupported janusd command; run `janusd --help`"),
    }
}

fn parse_forge_rotate_generated(
    args: impl IntoIterator<Item = String>,
) -> Result<ForgeRotateGeneratedConfig> {
    let mut config = ForgeRotateGeneratedConfig::default();
    let mut secret_set = false;
    let mut reason_set = false;
    let mut consumer_set = false;
    let mut validation_set = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--secret" => {
                config.secret = SecretName::new(required_arg("--secret", args.next())?)?;
                secret_set = true;
            }
            "--reason" => {
                config.reason = SafeLabel::new(required_arg("--reason", args.next())?)?;
                reason_set = true;
            }
            "--consumer-ref" => {
                config.consumer_ref =
                    ConsumerRef::new(required_arg("--consumer-ref", args.next())?)?;
                consumer_set = true;
            }
            "--validation" => {
                config.validation_probe =
                    ValidationProbe::new(required_arg("--validation", args.next())?)?;
                validation_set = true;
            }
            "--alphabet" => {
                config.alphabet = parse_alphabet(&required_arg("--alphabet", args.next())?)?;
            }
            "--length" => {
                let value = required_arg("--length", args.next())?;
                config.length = value.parse::<usize>().context("invalid --length")?;
            }
            "--allow-noop-hooks" => config.allow_noop_hooks = true,
            "--value" | "--generated-value" => {
                anyhow::bail!(
                    "{arg} is intentionally unsupported; Forge generates values internally"
                )
            }
            other if other.starts_with('-') => {
                anyhow::bail!("unsupported forge rotate-generated flag {other}")
            }
            _ => anyhow::bail!("unsupported forge rotate-generated argument"),
        }
    }
    if !secret_set {
        anyhow::bail!("--secret is required");
    }
    if !reason_set {
        anyhow::bail!("--reason is required");
    }
    if !consumer_set {
        anyhow::bail!("--consumer-ref is required");
    }
    if !validation_set {
        anyhow::bail!("--validation is required");
    }
    GeneratedValuePolicy::new(config.alphabet, config.length)?;
    Ok(config)
}

fn parse_alphabet(value: &str) -> Result<GeneratedAlphabet> {
    match value {
        "url-safe" => Ok(GeneratedAlphabet::UrlSafe),
        "alphanumeric" => Ok(GeneratedAlphabet::Alphanumeric),
        "hex" => Ok(GeneratedAlphabet::Hex),
        _ => anyhow::bail!("unsupported generated alphabet"),
    }
}

fn required_arg(flag: &'static str, value: Option<String>) -> Result<String> {
    value.with_context(|| format!("{flag} requires a value"))
}

fn load_age_store_from_env() -> Result<AgeSecretStore> {
    let manifest = env_first(&[
        "JANUS_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_SECRETSPEC_FILE",
    ])
    .context("JANUS_AGE_MANIFEST_FILE is required")?;
    let profile = env_first(&["JANUS_AGE_PROFILE", "JANUS_WARDEN_AGE_PROFILE"])
        .unwrap_or_else(|| "default".to_string());
    let store_dir = env_first(&["JANUS_AGE_STORE_DIR", "JANUS_WARDEN_AGE_STORE_DIR"])
        .unwrap_or_else(|| "/var/lib/janus/secrets".to_string());
    let identity_files = age_identity_files_from_env()?;
    let recipients = age_recipients_from_env()?;
    AgeSecretStore::load_from_secretspec_manifest(
        manifest,
        profile,
        store_dir,
        identity_files,
        recipients,
    )
    .context("failed to load age backend for janusd forge")
}

fn age_identity_files_from_env() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for key in ["JANUS_AGE_IDENTITY_FILE", "JANUS_WARDEN_AGE_IDENTITY_FILE"] {
        if let Ok(value) = env::var(key) {
            files.push(PathBuf::from(value));
        }
    }
    for key in [
        "JANUS_AGE_IDENTITY_FILES",
        "JANUS_WARDEN_AGE_IDENTITY_FILES",
    ] {
        if let Ok(value) = env::var(key) {
            files.extend(
                value
                    .split(':')
                    .filter(|part| !part.trim().is_empty())
                    .map(PathBuf::from),
            );
        }
    }
    if files.is_empty() {
        anyhow::bail!("JANUS_AGE_IDENTITY_FILE or JANUS_AGE_IDENTITY_FILES is required");
    }
    Ok(files)
}

fn age_recipients_from_env() -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    for key in ["JANUS_AGE_RECIPIENT", "JANUS_WARDEN_AGE_RECIPIENT"] {
        if let Ok(value) = env::var(key) {
            recipients.push(value);
        }
    }
    for key in [
        "JANUS_AGE_RECIPIENTS_FILE",
        "JANUS_WARDEN_AGE_RECIPIENTS_FILE",
    ] {
        if let Ok(path) = env::var(key) {
            recipients.extend(read_recipient_file(Path::new(&path))?);
        }
    }
    if recipients.is_empty() {
        anyhow::bail!("JANUS_AGE_RECIPIENT or JANUS_AGE_RECIPIENTS_FILE is required");
    }
    Ok(recipients)
}

fn read_recipient_file(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path).context("failed to read age recipients file")?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn forge_principal_from_env() -> Result<PrincipalChain> {
    let executor = env::var("JANUS_FORGE_EXECUTOR").unwrap_or_else(|_| "forge-cli".to_string());
    let scope = env::var("JANUS_FORGE_SCOPE").unwrap_or_else(|_| "janus/default".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        ScopeRef::new(scope)?,
    ))
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env::var(key).ok())
}

fn print_usage() {
    eprintln!(
        "janusd\n\nCommands:\n  forge rotate-generated --secret NAME --reason REASON --consumer-ref REF \\\n    --validation PROBE --allow-noop-hooks [--alphabet url-safe|alphanumeric|hex] [--length N]\n\nForge generates replacement values internally; no --value argument exists."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> ForgeRotateGeneratedConfig {
        match parse_args(args.iter().map(|arg| arg.to_string())).unwrap() {
            Command::ForgeRotateGenerated(config) => config,
            Command::Help => panic!("expected forge config"),
        }
    }

    #[test]
    fn parses_forge_rotate_generated_without_secret_literals() {
        let config = parse_ok(&[
            "forge",
            "rotate-generated",
            "--secret",
            "CANARY",
            "--reason",
            "JANUS-21 planned rotation",
            "--consumer-ref",
            "consumer.deploy",
            "--validation",
            "deploy-smoke",
            "--alphabet",
            "hex",
            "--length",
            "32",
            "--allow-noop-hooks",
        ]);
        assert_eq!(config.secret.as_str(), "CANARY");
        assert_eq!(config.reason.as_str(), "JANUS-21 planned rotation");
        assert_eq!(config.consumer_ref.as_str(), "consumer.deploy");
        assert_eq!(config.validation_probe.as_str(), "deploy-smoke");
        assert_eq!(config.alphabet, GeneratedAlphabet::Hex);
        assert_eq!(config.length, 32);
        assert!(config.allow_noop_hooks);
    }

    #[test]
    fn rejects_literal_replacement_values() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--value",
                "do-not-accept-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(!err.to_string().contains("do-not-accept-me"));
    }

    #[test]
    fn requires_approval_reason_and_reviewed_noop_flag() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--reason"));

        let config = parse_ok(&[
            "forge",
            "rotate-generated",
            "--secret",
            "CANARY",
            "--reason",
            "JANUS-21",
            "--consumer-ref",
            "consumer.deploy",
            "--validation",
            "deploy-smoke",
        ]);
        assert!(!config.allow_noop_hooks);
    }

    #[test]
    fn rejects_invalid_generation_policy() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "--length",
                "0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("generated_value_length"));
    }

    #[test]
    fn rejects_unknown_literal_arguments_without_echoing_them() {
        let err = parse_args(
            [
                "forge",
                "rotate-generated",
                "--secret",
                "CANARY",
                "--reason",
                "JANUS-21",
                "--consumer-ref",
                "consumer.deploy",
                "--validation",
                "deploy-smoke",
                "do-not-echo-me",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(!err.to_string().contains("do-not-echo-me"));
    }
}

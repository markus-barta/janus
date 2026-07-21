use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, AuditWrite, JanusError, OwnerRef, Principal,
    PrincipalChain, PrincipalId, PrincipalKind, ReleaseAdmission, SafeLabel, ScopeRef, SecretClass,
    SecretDescriptor, SecretLifecycle, SecretRef, SecretStore, Severity, StaleSecretPolicy,
    StaleSecretReportRow, StaleSecretReporter,
};
use janus_local::{
    FileLifecycleEvidenceRegistry, FileTombstoneRegistry, JsonlAuditSink, SecretTombstoneRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lifecycle_entry::EntryJournalSummary;

const SNAPSHOT_SCHEMA_VERSION: u8 = 1;
const MAX_ROWS: usize = 10_000;
const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_STALE_AFTER_DAYS: u64 = 90;
const DEFAULT_MISSING_EVIDENCE_AFTER_DAYS: u64 = 7;

const ACTION_CODES: &[&str] = &[
    "complete_or_remove_draft",
    "complete_metadata",
    "investigate_destroy_lifecycle",
    "investigate_entry_conflict",
    "investigate_entry_metadata",
    "investigate_entry_release",
    "investigate_entry_rollback",
    "investigate_missing_material",
    "investigate_orphan_tombstone",
    "migrate_or_disable",
    "record_activity_evidence",
    "record_destroy_tombstone",
    "recover_entry_transaction",
    "repair_consumer_profile",
    "restore_tombstone_or_investigate",
    "resume_or_rollback_entry",
    "review_disabled_secret",
    "review_rotate_or_disable",
    "run_destroy_finalize",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QueueConfig {
    format: QueueFormat,
    action_required_only: bool,
    owner: Option<OwnerRef>,
    lifecycle: Option<SecretLifecycle>,
    action: Option<String>,
    metadata_file: Option<PathBuf>,
    profile_manifest: PathBuf,
    entry_state_dir: PathBuf,
    evidence_file: Option<PathBuf>,
    audit_path: PathBuf,
    output: Option<PathBuf>,
    stale_after: Duration,
    missing_evidence_after: Duration,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LifecycleActionQueueSnapshotV1 {
    schema_version: u8,
    scope_ref: String,
    observed_at_unix_secs: u64,
    source_posture: SourcePostureV1,
    owner_summaries: Vec<OwnerSummaryV1>,
    state_summaries: Vec<StateSummaryV1>,
    action_summaries: Vec<ActionSummaryV1>,
    rows: Vec<LifecycleActionRowV1>,
    snapshot_fingerprint: String,
    value_returned: bool,
    provider_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourcePostureV1 {
    manifest_metadata: String,
    lifecycle_evidence: String,
    tombstones: String,
    entry_journals: String,
    consumer_profiles: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnerSummaryV1 {
    owner: String,
    total: usize,
    action_required: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StateSummaryV1 {
    lifecycle: String,
    total: usize,
    action_required: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActionSummaryV1 {
    action: String,
    total: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LifecycleActionRowV1 {
    secret_ref: String,
    scope_ref: String,
    owner: String,
    classification: String,
    lifecycle: String,
    present: bool,
    age_bucket: String,
    last_activity_age_seconds: Option<u64>,
    entry_phase: String,
    tombstone_state: String,
    consumer_posture: String,
    status: String,
    reason_codes: Vec<String>,
    action_required: bool,
    next_actions: Vec<String>,
    value_returned: bool,
    provider_deleted: bool,
}

pub(super) fn is_action_queue_command(args: &[String]) -> bool {
    matches!(args, [lifecycle, action_queue, ..] if lifecycle == "lifecycle" && action_queue == "action-queue")
}

pub(super) async fn run(args: &[String], release: ReleaseAdmission) -> Result<()> {
    if let Err(error) = run_inner(args, release).await {
        anyhow::bail!(
            "janusd-admin lifecycle action-queue denied reason_code={} value_returned=false provider_deleted=false",
            stable_error_reason(&error)
        );
    }
    Ok(())
}

async fn run_inner(args: &[String], release: ReleaseAdmission) -> Result<()> {
    let config = parse(args)?;
    let principal = queue_principal_from_env()?;
    let now = SystemTime::now();
    let snapshot = build_runtime_snapshot(&config, &release, &principal, now).await?;
    let encoded = encode_snapshot(&snapshot, config.format)?;
    if encoded.len() > MAX_OUTPUT_BYTES {
        return Err(JanusError::policy_denied(
            "queue_output_limit_exceeded",
            "lifecycle queue output exceeds the reviewed limit",
        )
        .into());
    }
    audit_snapshot(&config.audit_path, &snapshot, &principal)?;
    emit(&config, &encoded)?;
    Ok(())
}

async fn build_runtime_snapshot(
    config: &QueueConfig,
    release: &ReleaseAdmission,
    principal: &PrincipalChain,
    now: SystemTime,
) -> Result<LifecycleActionQueueSnapshotV1> {
    let metadata_file = super::lifecycle_metadata_file_path(
        config.metadata_file.as_deref(),
        super::METADATA_ENV_KEYS,
    )?;
    if !metadata_file.is_absolute() {
        anyhow::bail!("lifecycle queue paths must be absolute");
    }
    check_reviewed_file(&metadata_file, MAX_PROFILE_MANIFEST_BYTES)?;
    check_reviewed_file(&config.profile_manifest, MAX_PROFILE_MANIFEST_BYTES)?;
    if let Some(path) = config.evidence_file.as_deref() {
        check_reviewed_file(path, MAX_PROFILE_MANIFEST_BYTES)?;
    }
    check_distinct_paths(config, &metadata_file)?;

    let store = super::load_age_store_from_env_with_metadata_path(Some(&metadata_file))?;
    let descriptors = store
        .list()
        .await
        .context("lifecycle queue manifest source denied")?;
    if descriptors.len() > MAX_ROWS {
        return Err(JanusError::policy_denied(
            "queue_row_limit_exceeded",
            "lifecycle queue row count exceeds the reviewed limit",
        )
        .into());
    }
    if descriptors
        .iter()
        .any(|descriptor| descriptor.scope != principal.scope)
    {
        return Err(JanusError::policy_denied(
            "queue_scope_mismatch",
            "lifecycle queue source contains a foreign scope",
        )
        .into());
    }

    let evidence_registry =
        FileLifecycleEvidenceRegistry::new(super::lifecycle_evidence_registry_dir());
    let mut evidence = evidence_registry
        .list_existing_bounded(MAX_ROWS, MAX_SOURCE_FILE_BYTES)?
        .into_iter()
        .map(|record| (record.secret_ref.clone(), record))
        .collect::<BTreeMap<_, _>>();
    super::merge_stale_evidence(
        &mut evidence,
        super::load_stale_evidence(config.evidence_file.as_deref())?.into_values(),
    );
    let descriptor_refs = descriptors
        .iter()
        .map(|descriptor| descriptor.secret_ref.clone())
        .collect::<BTreeSet<_>>();
    if evidence
        .keys()
        .any(|secret_ref| !descriptor_refs.contains(secret_ref))
    {
        return Err(JanusError::policy_denied(
            "queue_evidence_target_missing",
            "lifecycle evidence does not resolve to the exact manifest",
        )
        .into());
    }

    let tombstone_registry = FileTombstoneRegistry::new(super::lifecycle_tombstone_registry_dir());
    let tombstones = tombstone_registry.list_existing_bounded(MAX_ROWS, MAX_SOURCE_FILE_BYTES)?;
    let entry_journals = super::lifecycle_entry::scan_journal_summaries(
        &config.entry_state_dir,
        release,
        MAX_ROWS,
        MAX_SOURCE_FILE_BYTES as usize,
    )?;
    let profile_text = read_reviewed_string(&config.profile_manifest, MAX_PROFILE_MANIFEST_BYTES)?;
    let profiles =
        super::ManagedCommandProfileCatalog::parse_with_scope(&profile_text, &principal.scope)
            .context("lifecycle queue consumer source denied")?;

    let stale_policy = StaleSecretPolicy::new(config.stale_after, config.missing_evidence_after);
    let mut memory_audit = AuditWrite::accepting();
    let stale_rows = StaleSecretReporter::new(stale_policy).report(
        &descriptors,
        &evidence,
        now,
        principal,
        &mut memory_audit,
    )?;
    build_snapshot(
        descriptors,
        stale_rows,
        tombstones,
        entry_journals,
        &profiles,
        principal.scope.clone(),
        now,
        config,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_snapshot(
    descriptors: Vec<SecretDescriptor>,
    stale_rows: Vec<StaleSecretReportRow>,
    tombstones: Vec<SecretTombstoneRecord>,
    entry_journals: Vec<EntryJournalSummary>,
    profiles: &super::ManagedCommandProfileCatalog,
    scope: ScopeRef,
    now: SystemTime,
    config: &QueueConfig,
) -> Result<LifecycleActionQueueSnapshotV1> {
    let stale_by_ref = stale_rows
        .into_iter()
        .map(|row| (row.secret_ref.clone(), row))
        .collect::<BTreeMap<_, _>>();
    let tombstone_by_ref = tombstones
        .iter()
        .map(|record| (record.secret_ref.clone(), record))
        .collect::<BTreeMap<_, _>>();
    if tombstone_by_ref.len() != tombstones.len() {
        return Err(JanusError::policy_denied(
            "queue_duplicate_source",
            "lifecycle queue tombstone source contains duplicates",
        )
        .into());
    }
    let descriptor_refs = descriptors
        .iter()
        .map(|descriptor| descriptor.secret_ref.clone())
        .collect::<BTreeSet<_>>();
    let mut entry_by_ref = BTreeMap::<SecretRef, Vec<EntryJournalSummary>>::new();
    for journal in entry_journals {
        entry_by_ref
            .entry(journal.secret_ref.clone())
            .or_default()
            .push(journal);
    }
    if entry_by_ref
        .keys()
        .any(|secret_ref| !descriptor_refs.contains(secret_ref))
    {
        return Err(JanusError::policy_denied(
            "queue_entry_target_missing",
            "lifecycle entry journal does not resolve to the exact manifest",
        )
        .into());
    }

    let mut rows = Vec::with_capacity(descriptors.len() + tombstones.len());
    for descriptor in &descriptors {
        let stale = stale_by_ref.get(&descriptor.secret_ref).ok_or_else(|| {
            JanusError::policy_denied(
                "queue_source_incomplete",
                "lifecycle queue stale classification is incomplete",
            )
        })?;
        rows.push(classify_descriptor(
            descriptor,
            stale,
            tombstone_by_ref.contains_key(&descriptor.secret_ref),
            entry_by_ref
                .get(&descriptor.secret_ref)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            profiles,
        ));
    }
    for tombstone in tombstones {
        if !descriptor_refs.contains(&tombstone.secret_ref) {
            rows.push(orphan_tombstone_row(&tombstone.secret_ref, &scope));
        }
    }

    rows.retain(|row| row_matches(row, config));
    rows.sort_by(|left, right| left.secret_ref.cmp(&right.secret_ref));
    let observed_at_unix_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            JanusError::policy_denied("queue_clock_invalid", "lifecycle queue clock is invalid")
        })?
        .as_secs();
    let mut snapshot = LifecycleActionQueueSnapshotV1 {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        scope_ref: scope.as_str().to_string(),
        observed_at_unix_secs,
        source_posture: SourcePostureV1 {
            manifest_metadata: "ok".to_string(),
            lifecycle_evidence: "ok".to_string(),
            tombstones: "ok".to_string(),
            entry_journals: "ok".to_string(),
            consumer_profiles: "ok".to_string(),
        },
        owner_summaries: owner_summaries(&rows),
        state_summaries: state_summaries(&rows),
        action_summaries: action_summaries(&rows),
        rows,
        snapshot_fingerprint: String::new(),
        value_returned: false,
        provider_deleted: false,
    };
    snapshot.snapshot_fingerprint = snapshot_fingerprint(&snapshot)?;
    Ok(snapshot)
}

fn classify_descriptor(
    descriptor: &SecretDescriptor,
    stale: &StaleSecretReportRow,
    tombstone_present: bool,
    entry_journals: &[EntryJournalSummary],
    profiles: &super::ManagedCommandProfileCatalog,
) -> LifecycleActionRowV1 {
    let mut reasons = Vec::new();
    let mut actions = Vec::new();
    let mut entry_phase = "none".to_string();

    if !descriptor.present
        && !matches!(
            descriptor.lifecycle,
            SecretLifecycle::Draft | SecretLifecycle::Destroyed
        )
    {
        add_action(
            &mut reasons,
            &mut actions,
            "lifecycle_material_missing",
            "investigate_missing_material",
        );
    }

    let active_entries = entry_journals
        .iter()
        .filter(|entry| !matches!(entry.phase.as_str(), "completed" | "rolled_back"))
        .count();
    if active_entries > 1 {
        add_action(
            &mut reasons,
            &mut actions,
            "entry_operation_conflict",
            "investigate_entry_conflict",
        );
    }
    if let Some(entry) = entry_journals.last() {
        entry_phase.clone_from(&entry.phase);
        if !entry.release_matches {
            add_action(
                &mut reasons,
                &mut actions,
                "entry_release_mismatch",
                "investigate_entry_release",
            );
        }
        match entry.phase.as_str() {
            "preflighted" => add_action(
                &mut reasons,
                &mut actions,
                "entry_preflighted_action_required",
                "resume_or_rollback_entry",
            ),
            "applying" | "stored" | "validated" | "activating" | "rolling_back" | "failed" => {
                add_action(
                    &mut reasons,
                    &mut actions,
                    "entry_recovery_action_required",
                    "recover_entry_transaction",
                )
            }
            "completed" if descriptor.lifecycle != SecretLifecycle::Active => add_action(
                &mut reasons,
                &mut actions,
                "entry_completed_metadata_mismatch",
                "investigate_entry_metadata",
            ),
            "rolled_back"
                if descriptor.lifecycle != SecretLifecycle::Draft || descriptor.present =>
            {
                add_action(
                    &mut reasons,
                    &mut actions,
                    "entry_rollback_state_mismatch",
                    "investigate_entry_rollback",
                )
            }
            _ => {}
        }
    }

    let tombstone_state = if tombstone_present {
        "present"
    } else if matches!(
        descriptor.lifecycle,
        SecretLifecycle::PendingDelete | SecretLifecycle::Destroyed
    ) {
        "missing"
    } else {
        "not_applicable"
    };
    match (descriptor.lifecycle, tombstone_present) {
        (SecretLifecycle::PendingDelete, true) => add_action(
            &mut reasons,
            &mut actions,
            "destroy_tombstone_pending_finalize",
            "run_destroy_finalize",
        ),
        (SecretLifecycle::PendingDelete, false) => add_action(
            &mut reasons,
            &mut actions,
            "pending_delete_missing_tombstone",
            "record_destroy_tombstone",
        ),
        (SecretLifecycle::Destroyed, false) => add_action(
            &mut reasons,
            &mut actions,
            "destroyed_missing_tombstone",
            "restore_tombstone_or_investigate",
        ),
        (lifecycle, true)
            if !matches!(
                lifecycle,
                SecretLifecycle::PendingDelete | SecretLifecycle::Destroyed
            ) =>
        {
            add_action(
                &mut reasons,
                &mut actions,
                "destroy_tombstone_lifecycle_mismatch",
                "investigate_destroy_lifecycle",
            )
        }
        _ => {}
    }

    if let Some((reason, _)) = descriptor.metadata_use_denial() {
        add_action(&mut reasons, &mut actions, reason, "complete_metadata");
    }
    let consumer_posture = consumer_posture(descriptor, profiles);
    if matches!(consumer_posture, "missing" | "mismatch") {
        add_action(
            &mut reasons,
            &mut actions,
            if consumer_posture == "missing" {
                "consumer_profile_missing"
            } else {
                "consumer_profile_mismatch"
            },
            "repair_consumer_profile",
        );
    }

    match descriptor.lifecycle {
        SecretLifecycle::Draft if active_entries == 0 => add_action(
            &mut reasons,
            &mut actions,
            "draft_without_active_entry",
            "complete_or_remove_draft",
        ),
        SecretLifecycle::Disabled => add_action(
            &mut reasons,
            &mut actions,
            "disabled_review_required",
            "review_disabled_secret",
        ),
        SecretLifecycle::Deprecated => add_action(
            &mut reasons,
            &mut actions,
            "deprecated_review_required",
            "migrate_or_disable",
        ),
        SecretLifecycle::Active | SecretLifecycle::Rotating if stale.action_required => {
            add_action(&mut reasons, &mut actions, stale.reason_code, stale.action);
        }
        _ => {}
    }

    LifecycleActionRowV1 {
        secret_ref: descriptor.secret_ref.as_str().to_string(),
        scope_ref: descriptor.scope.as_str().to_string(),
        owner: descriptor
            .owner
            .as_ref()
            .map(OwnerRef::as_str)
            .unwrap_or("unassigned")
            .to_string(),
        classification: descriptor
            .classification
            .map(SecretClass::as_str)
            .unwrap_or("unclassified")
            .to_string(),
        lifecycle: descriptor.lifecycle.as_str().to_string(),
        present: descriptor.present,
        age_bucket: stale.status.as_str().to_string(),
        last_activity_age_seconds: stale.last_activity_age_seconds,
        entry_phase,
        tombstone_state: tombstone_state.to_string(),
        consumer_posture: consumer_posture.to_string(),
        status: if actions.is_empty() {
            "healthy".to_string()
        } else {
            "action_required".to_string()
        },
        action_required: !actions.is_empty(),
        reason_codes: reasons,
        next_actions: actions,
        value_returned: false,
        provider_deleted: false,
    }
}

fn orphan_tombstone_row(secret_ref: &SecretRef, scope: &ScopeRef) -> LifecycleActionRowV1 {
    LifecycleActionRowV1 {
        secret_ref: secret_ref.as_str().to_string(),
        scope_ref: scope.as_str().to_string(),
        owner: "unassigned".to_string(),
        classification: "unclassified".to_string(),
        lifecycle: "missing".to_string(),
        present: false,
        age_bucket: "missing".to_string(),
        last_activity_age_seconds: None,
        entry_phase: "none".to_string(),
        tombstone_state: "orphan".to_string(),
        consumer_posture: "not_applicable".to_string(),
        status: "action_required".to_string(),
        reason_codes: vec!["destroy_tombstone_metadata_missing".to_string()],
        action_required: true,
        next_actions: vec!["investigate_orphan_tombstone".to_string()],
        value_returned: false,
        provider_deleted: false,
    }
}

fn consumer_posture(
    descriptor: &SecretDescriptor,
    profiles: &super::ManagedCommandProfileCatalog,
) -> &'static str {
    if descriptor.lifecycle == SecretLifecycle::Destroyed {
        return "not_applicable";
    }
    if descriptor.allowed_uses.is_empty() {
        return "missing";
    }
    let mut missing = false;
    for profile_id in &descriptor.allowed_uses {
        match profiles.profile_binding(profile_id) {
            Some(binding) if binding.secret_ref == descriptor.secret_ref => {}
            Some(_) => return "mismatch",
            None => missing = true,
        }
    }
    if missing {
        "missing"
    } else {
        "declared"
    }
}

fn add_action(reasons: &mut Vec<String>, actions: &mut Vec<String>, reason: &str, action: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
    if !actions.iter().any(|existing| existing == action) {
        actions.push(action.to_string());
    }
}

fn row_matches(row: &LifecycleActionRowV1, config: &QueueConfig) -> bool {
    (!config.action_required_only || row.action_required)
        && match &config.owner {
            Some(owner) => row.owner == owner.as_str(),
            None => true,
        }
        && match config.lifecycle {
            Some(lifecycle) => row.lifecycle == lifecycle.as_str(),
            None => true,
        }
        && match &config.action {
            Some(action) => row.next_actions.contains(action),
            None => true,
        }
}

fn owner_summaries(rows: &[LifecycleActionRowV1]) -> Vec<OwnerSummaryV1> {
    let mut counts = BTreeMap::<String, (usize, usize)>::new();
    for row in rows {
        let entry = counts.entry(row.owner.clone()).or_default();
        entry.0 += 1;
        entry.1 += usize::from(row.action_required);
    }
    counts
        .into_iter()
        .map(|(owner, (total, action_required))| OwnerSummaryV1 {
            owner,
            total,
            action_required,
        })
        .collect()
}

fn state_summaries(rows: &[LifecycleActionRowV1]) -> Vec<StateSummaryV1> {
    let mut counts = BTreeMap::<String, (usize, usize)>::new();
    for row in rows {
        let entry = counts.entry(row.lifecycle.clone()).or_default();
        entry.0 += 1;
        entry.1 += usize::from(row.action_required);
    }
    counts
        .into_iter()
        .map(|(lifecycle, (total, action_required))| StateSummaryV1 {
            lifecycle,
            total,
            action_required,
        })
        .collect()
}

fn action_summaries(rows: &[LifecycleActionRowV1]) -> Vec<ActionSummaryV1> {
    let mut counts = BTreeMap::<String, usize>::new();
    for row in rows {
        for action in &row.next_actions {
            *counts.entry(action.clone()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|(action, total)| ActionSummaryV1 { action, total })
        .collect()
}

fn snapshot_fingerprint(snapshot: &LifecycleActionQueueSnapshotV1) -> Result<String> {
    let mut unsigned = snapshot.clone();
    unsigned.snapshot_fingerprint.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|_| {
        JanusError::policy_denied(
            "queue_snapshot_invalid",
            "lifecycle queue snapshot could not be encoded",
        )
    })?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn encode_snapshot(
    snapshot: &LifecycleActionQueueSnapshotV1,
    format: QueueFormat,
) -> Result<Vec<u8>> {
    match format {
        QueueFormat::Json => {
            let mut output = serde_json::to_vec_pretty(snapshot).map_err(|_| {
                JanusError::policy_denied(
                    "queue_snapshot_invalid",
                    "lifecycle queue snapshot could not be encoded",
                )
            })?;
            output.push(b'\n');
            Ok(output)
        }
        QueueFormat::Text => {
            let mut output = Vec::new();
            writeln!(
                output,
                "janusd-admin lifecycle action-queue ok scope_ref={} observed_at_unix_secs={} rows={} action_required={} snapshot_fingerprint={} value_returned=false provider_deleted=false",
                snapshot.scope_ref,
                snapshot.observed_at_unix_secs,
                snapshot.rows.len(),
                snapshot.rows.iter().filter(|row| row.action_required).count(),
                snapshot.snapshot_fingerprint,
            )?;
            for row in &snapshot.rows {
                writeln!(
                    output,
                    "secret_ref={} scope_ref={} owner={} class={} lifecycle={} present={} age_bucket={} age_seconds={} entry_phase={} tombstone={} consumer={} status={} reason_codes={} next_actions={} value_returned=false provider_deleted=false",
                    row.secret_ref,
                    row.scope_ref,
                    row.owner,
                    row.classification,
                    row.lifecycle,
                    row.present,
                    row.age_bucket,
                    row.last_activity_age_seconds.map_or_else(|| "unknown".to_string(), |age| age.to_string()),
                    row.entry_phase,
                    row.tombstone_state,
                    row.consumer_posture,
                    row.status,
                    join_or_none(&row.reason_codes),
                    join_or_none(&row.next_actions),
                )?;
            }
            Ok(output)
        }
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn audit_snapshot(
    path: &Path,
    snapshot: &LifecycleActionQueueSnapshotV1,
    principal: &PrincipalChain,
) -> Result<()> {
    let action_required = snapshot
        .rows
        .iter()
        .filter(|row| row.action_required)
        .count();
    let evidence = SafeLabel::new(format!(
        "snapshot-{}-actions-{action_required}",
        &snapshot.snapshot_fingerprint[..12]
    ))?;
    let mut audit = JsonlAuditSink::open(path)?;
    audit.record(
        AuditEvent::new(
            AuditAction::SecretLifecycleQueue,
            AuditOutcome::Allowed,
            "lifecycle_action_queue_snapshot_ok",
            if action_required == 0 {
                Severity::Notice
            } else {
                Severity::High
            },
            None,
            principal,
        )
        .with_evidence(evidence),
    )?;
    Ok(())
}

fn emit(config: &QueueConfig, encoded: &[u8]) -> Result<()> {
    if let Some(path) = config.output.as_deref() {
        return write_private_atomic(path, encoded);
    }
    std::io::stdout()
        .lock()
        .write_all(encoded)
        .context("lifecycle queue output failed")
}

fn parse(args: &[String]) -> Result<QueueConfig> {
    if !is_action_queue_command(args) {
        anyhow::bail!("unsupported lifecycle queue command");
    }
    let mut format = QueueFormat::Text;
    let mut format_set = false;
    let mut action_required_only = false;
    let mut owner = None;
    let mut lifecycle = None;
    let mut action = None;
    let mut metadata_file = None;
    let mut profile_manifest = None;
    let mut entry_state_dir = None;
    let mut evidence_file = None;
    let mut audit_path = None;
    let mut output = None;
    let mut stale_after_days = DEFAULT_STALE_AFTER_DAYS;
    let mut missing_evidence_after_days = DEFAULT_MISSING_EVIDENCE_AFTER_DAYS;
    let mut stale_after_set = false;
    let mut missing_evidence_after_set = false;
    let mut index = 2;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        match flag.as_str() {
            "--format" => {
                if format_set {
                    anyhow::bail!("--format may only be provided once");
                }
                let value = take_arg(args, &mut index, "--format")?;
                format = match value {
                    "text" => QueueFormat::Text,
                    "json" => QueueFormat::Json,
                    _ => anyhow::bail!("unsupported lifecycle queue output format"),
                };
                format_set = true;
            }
            "--action-required-only" => {
                if action_required_only {
                    anyhow::bail!("--action-required-only may only be provided once");
                }
                action_required_only = true;
            }
            "--owner" => {
                let value = unique_arg(&owner, args, &mut index, "--owner")?;
                validate_filter_token(value)?;
                owner = Some(OwnerRef::new(value.to_string())?);
            }
            "--lifecycle" => {
                let value = take_arg(args, &mut index, "--lifecycle")?;
                if lifecycle.replace(SecretLifecycle::parse(value)?).is_some() {
                    anyhow::bail!("--lifecycle may only be provided once");
                }
            }
            "--action" => {
                let value = take_arg(args, &mut index, "--action")?;
                if !ACTION_CODES.contains(&value) {
                    anyhow::bail!("unsupported lifecycle queue action filter");
                }
                if action.replace(value.to_string()).is_some() {
                    anyhow::bail!("--action may only be provided once");
                }
            }
            "--metadata-file" => set_path(&mut metadata_file, args, &mut index, "--metadata-file")?,
            "--profile-manifest" => set_path(
                &mut profile_manifest,
                args,
                &mut index,
                "--profile-manifest",
            )?,
            "--entry-state-dir" => {
                set_path(&mut entry_state_dir, args, &mut index, "--entry-state-dir")?
            }
            "--evidence-file" => set_path(&mut evidence_file, args, &mut index, "--evidence-file")?,
            "--audit-path" => set_path(&mut audit_path, args, &mut index, "--audit-path")?,
            "--output" => set_path(&mut output, args, &mut index, "--output")?,
            "--stale-after-days" => {
                if stale_after_set {
                    anyhow::bail!("--stale-after-days may only be provided once");
                }
                stale_after_days = parse_days(take_arg(args, &mut index, flag)?)?;
                stale_after_set = true;
            }
            "--missing-evidence-after-days" => {
                if missing_evidence_after_set {
                    anyhow::bail!("--missing-evidence-after-days may only be provided once");
                }
                missing_evidence_after_days = parse_days(take_arg(args, &mut index, flag)?)?;
                missing_evidence_after_set = true;
            }
            "--secret" | "--name" | "--value" | "--raw-value" | "--provider" | "--identity"
            | "--recipient" | "--command" | "--destination" => {
                return Err(JanusError::policy_denied(
                    "queue_literal_argument_denied",
                    "lifecycle queue accepts only value-free reporting arguments",
                )
                .into())
            }
            _ => anyhow::bail!("unsupported lifecycle queue argument"),
        }
    }

    let profile_manifest = profile_manifest
        .or_else(|| std::env::var_os("JANUS_MANAGED_PROFILE_MANIFEST").map(PathBuf::from))
        .context("--profile-manifest or JANUS_MANAGED_PROFILE_MANIFEST is required")?;
    let entry_state_dir = entry_state_dir
        .or_else(|| std::env::var_os("JANUS_LIFECYCLE_ENTRY_STATE_DIR").map(PathBuf::from))
        .context("--entry-state-dir or JANUS_LIFECYCLE_ENTRY_STATE_DIR is required")?;
    let audit_path = audit_path
        .or_else(|| std::env::var_os("JANUS_LIFECYCLE_QUEUE_AUDIT_FILE").map(PathBuf::from))
        .context("--audit-path or JANUS_LIFECYCLE_QUEUE_AUDIT_FILE is required")?;
    for path in [
        metadata_file.as_ref(),
        Some(&profile_manifest),
        Some(&entry_state_dir),
        evidence_file.as_ref(),
        Some(&audit_path),
        output.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !path.is_absolute() {
            anyhow::bail!("lifecycle queue paths must be absolute");
        }
    }
    if output.is_some() && format != QueueFormat::Json {
        anyhow::bail!("--output requires --format json");
    }
    Ok(QueueConfig {
        format,
        action_required_only,
        owner,
        lifecycle,
        action,
        metadata_file,
        profile_manifest,
        entry_state_dir,
        evidence_file,
        audit_path,
        output,
        stale_after: days_duration(stale_after_days)?,
        missing_evidence_after: days_duration(missing_evidence_after_days)?,
    })
}

fn take_arg<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str> {
    let value = args
        .get(*index)
        .with_context(|| format!("{flag} requires a value"))?;
    *index += 1;
    if value.is_empty() || value.starts_with("--") {
        anyhow::bail!("lifecycle queue argument value is invalid");
    }
    Ok(value)
}

fn unique_arg<'a, T>(
    target: &Option<T>,
    args: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str> {
    if target.is_some() {
        anyhow::bail!("{flag} may only be provided once");
    }
    take_arg(args, index, flag)
}

fn set_path(
    target: &mut Option<PathBuf>,
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<()> {
    if target.is_some() {
        anyhow::bail!("{flag} may only be provided once");
    }
    *target = Some(PathBuf::from(take_arg(args, index, flag)?));
    Ok(())
}

fn parse_days(value: &str) -> Result<u64> {
    let days = value
        .parse::<u64>()
        .context("lifecycle queue day threshold is invalid")?;
    if days == 0 || days > 3_650 {
        anyhow::bail!("lifecycle queue day threshold is outside the reviewed bound");
    }
    Ok(days)
}

fn days_duration(days: u64) -> Result<Duration> {
    days.checked_mul(24 * 60 * 60)
        .map(Duration::from_secs)
        .context("lifecycle queue day threshold is too large")
}

fn validate_filter_token(value: &str) -> Result<()> {
    if value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
    {
        anyhow::bail!("lifecycle queue filter is invalid");
    }
    Ok(())
}

fn queue_principal_from_env() -> Result<PrincipalChain> {
    let executor = std::env::var("JANUS_LIFECYCLE_QUEUE_EXECUTOR")
        .unwrap_or_else(|_| "janusd-lifecycle-queue".to_string());
    Ok(PrincipalChain::new(
        Principal::new(PrincipalKind::Executor, PrincipalId::new(executor)?),
        super::runtime_scope_from_env()?,
    ))
}

fn check_reviewed_file(path: &Path, max_bytes: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        JanusError::policy_denied(
            "queue_source_unavailable",
            "lifecycle queue source unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(JanusError::policy_denied(
            "queue_source_invalid",
            "lifecycle queue source is not a bounded regular file",
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(JanusError::policy_denied(
                "queue_source_insecure",
                "lifecycle queue reviewed source is mutable by group or world",
            )
            .into());
        }
    }
    Ok(())
}

fn read_reviewed_string(path: &Path, max_bytes: u64) -> Result<String> {
    check_reviewed_file(path, max_bytes)?;
    fs::read_to_string(path).map_err(|_| {
        JanusError::policy_denied(
            "queue_source_unavailable",
            "lifecycle queue source unavailable",
        )
        .into()
    })
}

fn check_distinct_paths(config: &QueueConfig, metadata_file: &Path) -> Result<()> {
    let evidence_dir = super::lifecycle_evidence_registry_dir();
    let tombstone_dir = super::lifecycle_tombstone_registry_dir();
    if !evidence_dir.is_absolute() || !tombstone_dir.is_absolute() {
        anyhow::bail!("lifecycle queue paths must be absolute");
    }
    let mut paths = vec![
        metadata_file.to_path_buf(),
        config.profile_manifest.clone(),
        config.entry_state_dir.clone(),
        config.audit_path.clone(),
        evidence_dir,
        tombstone_dir,
    ];
    if let Some(path) = &config.evidence_file {
        paths.push(path.clone());
    }
    if let Some(path) = &config.output {
        paths.push(path.clone());
    }
    let unique = paths.iter().collect::<BTreeSet<_>>();
    if unique.len() != paths.len() {
        return Err(JanusError::policy_denied(
            "queue_path_conflict",
            "lifecycle queue source and output paths must be distinct",
        )
        .into());
    }
    if let Some(output) = &config.output {
        for directory in [&config.entry_state_dir, &paths[4], &paths[5]] {
            if output.starts_with(directory) {
                return Err(JanusError::policy_denied(
                    "queue_path_conflict",
                    "lifecycle queue output must not overlap source state",
                )
                .into());
            }
        }
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("lifecycle queue output has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| {
        JanusError::policy_denied(
            "queue_output_unavailable",
            "lifecycle queue output directory is unavailable",
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        anyhow::bail!("lifecycle queue output directory is invalid");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("lifecycle queue output directory is not private");
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("lifecycle queue output target is invalid");
        }
    }
    let temp = parent.join(format!(
        ".lifecycle-queue-{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.context("lifecycle queue output persistence failed")
}

fn stable_error_reason(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<JanusError>() {
            return match error {
                JanusError::PolicyDenied { reason_code, .. }
                    if reason_code.starts_with("queue_") =>
                {
                    reason_code
                }
                JanusError::AuditUnavailable { .. } => "queue_audit_unavailable",
                JanusError::StoreUnavailable { .. } => "queue_source_unavailable",
                JanusError::InvalidIdentifier { .. } | JanusError::InvalidManifest { .. } => {
                    "queue_contract_invalid"
                }
                _ => "queue_generation_denied",
            };
        }
    }
    "queue_generation_denied"
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        EnvironmentId, OrganizationId, ProfileId, ProjectId, RepositoryId, SafeLabel, ScopePathV1,
        SecretName, TrustLevel,
    };

    fn scope() -> ScopeRef {
        ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("fixture-project").unwrap(),
            RepositoryId::new("fixture-repo").unwrap(),
            EnvironmentId::new("dev").unwrap(),
        )
        .scope_ref()
    }

    fn descriptor(
        name: &str,
        lifecycle: SecretLifecycle,
        owner: Option<&str>,
        class: Option<SecretClass>,
        present: bool,
    ) -> SecretDescriptor {
        let scope = scope();
        let name = SecretName::new(name).unwrap();
        SecretDescriptor {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("safe fixture").unwrap(),
            scope,
            owner: owner.map(|owner| OwnerRef::new(owner).unwrap()),
            classification: class,
            lifecycle,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.fixture").unwrap()],
            present,
        }
    }

    fn stale_row(descriptor: &SecretDescriptor, action_required: bool) -> StaleSecretReportRow {
        StaleSecretReportRow {
            secret_ref: descriptor.secret_ref.clone(),
            owner: descriptor.owner.clone(),
            lifecycle: descriptor.lifecycle,
            status: if action_required {
                janus_core::StaleSecretStatus::Stale
            } else {
                janus_core::StaleSecretStatus::Fresh
            },
            reason_code: if action_required {
                "stale_activity_age_exceeded"
            } else {
                "stale_activity_fresh"
            },
            action_required,
            action: if action_required {
                "review_rotate_or_disable"
            } else {
                "none"
            },
            last_activity_age_seconds: Some(100),
            value_returned: false,
        }
    }

    fn profiles_for(descriptor: &SecretDescriptor) -> super::super::ManagedCommandProfileCatalog {
        let input = format!(
            r#"
            [[profiles]]
            id = "profile.fixture"
            secret_ref = "{}"
            executor = "executor.fixture"
            destination = "destination.fixture"
            env = "TOKEN"
            binary = "/bin/true"
            allowed_args = []
            [profiles.consumer]
            consumer_ref = "consumer.fixture"
            owner = "infra"
            environment = "dev"
            reload = "none"
            validation = ["probe.fixture"]
            blast_radius = "fixture"
            "#,
            descriptor.secret_ref.as_str()
        );
        super::super::ManagedCommandProfileCatalog::parse_with_scope(&input, &scope()).unwrap()
    }

    fn config() -> QueueConfig {
        QueueConfig {
            format: QueueFormat::Json,
            action_required_only: false,
            owner: None,
            lifecycle: None,
            action: None,
            metadata_file: None,
            profile_manifest: PathBuf::from("/fixture/profiles.toml"),
            entry_state_dir: PathBuf::from("/fixture/entries"),
            evidence_file: None,
            audit_path: PathBuf::from("/fixture/audit.jsonl"),
            output: None,
            stale_after: Duration::from_secs(100),
            missing_evidence_after: Duration::from_secs(50),
        }
    }

    #[test]
    fn precedence_keeps_destroy_entry_metadata_and_stale_actions_visible() {
        let descriptor = descriptor(
            "MIXED",
            SecretLifecycle::PendingDelete,
            None,
            Some(SecretClass::HighValue),
            false,
        );
        let row = classify_descriptor(
            &descriptor,
            &stale_row(&descriptor, true),
            false,
            &[EntryJournalSummary {
                operation_id: "entry-fixture".to_string(),
                secret_ref: descriptor.secret_ref.clone(),
                phase: "failed".to_string(),
                reason_code: "entry_fixture_failed".to_string(),
                preflighted_at_unix_secs: 1,
                release_matches: false,
            }],
            &profiles_for(&descriptor),
        );
        assert!(row.action_required);
        assert_eq!(row.next_actions[0], "investigate_missing_material");
        assert!(row
            .next_actions
            .contains(&"recover_entry_transaction".to_string()));
        assert!(row
            .next_actions
            .contains(&"record_destroy_tombstone".to_string()));
        assert!(row.next_actions.contains(&"complete_metadata".to_string()));
        assert!(!format!("{row:?}").contains("MIXED"));
    }

    #[test]
    fn snapshot_is_canonical_filterable_and_rejects_unknown_schema_fields() {
        let active = descriptor(
            "ACTIVE",
            SecretLifecycle::Active,
            Some("infra"),
            Some(SecretClass::Normal),
            true,
        );
        let disabled = descriptor(
            "DISABLED",
            SecretLifecycle::Disabled,
            Some("security"),
            Some(SecretClass::HighValue),
            true,
        );
        let profiles = profiles_for(&active);
        let snapshot = build_snapshot(
            vec![disabled.clone(), active.clone()],
            vec![stale_row(&disabled, false), stale_row(&active, true)],
            Vec::new(),
            Vec::new(),
            &profiles,
            scope(),
            UNIX_EPOCH + Duration::from_secs(1_000),
            &config(),
        )
        .unwrap();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.rows.len(), 2);
        assert!(snapshot.rows[0].secret_ref < snapshot.rows[1].secret_ref);
        assert_eq!(snapshot.snapshot_fingerprint.len(), 64);
        assert!(!snapshot.value_returned);

        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let parsed: LifecycleActionQueueSnapshotV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(parsed, snapshot);
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LifecycleActionQueueSnapshotV1>(value).is_err());
    }

    #[test]
    fn parser_rejects_literal_duplicate_relative_and_unbounded_inputs() {
        let base = vec![
            "lifecycle",
            "action-queue",
            "--profile-manifest",
            "/fixture/profiles.toml",
            "--entry-state-dir",
            "/fixture/entries",
            "--audit-path",
            "/fixture/audit.jsonl",
        ];
        let parse_strings =
            |values: Vec<&str>| parse(&values.into_iter().map(str::to_string).collect::<Vec<_>>());
        assert!(parse_strings(base.clone()).is_ok());
        let mut literal = base.clone();
        literal.extend(["--value", "canary-secret"]);
        let error = parse_strings(literal).unwrap_err();
        assert_eq!(stable_error_reason(&error), "queue_literal_argument_denied");
        let mut duplicate = base.clone();
        duplicate.extend(["--owner", "infra", "--owner", "security"]);
        assert!(parse_strings(duplicate).is_err());
        let mut relative = base.clone();
        relative[3] = "profiles.toml";
        assert!(parse_strings(relative).is_err());
        let mut unbounded = base;
        unbounded.extend(["--stale-after-days", "3651"]);
        assert!(parse_strings(unbounded).is_err());
    }

    #[test]
    fn stable_error_boundary_never_renders_inner_canaries() {
        let error =
            anyhow::anyhow!("raw-name=TOP_SECRET path=/private/identity value=literal-canary");
        assert_eq!(stable_error_reason(&error), "queue_generation_denied");
        assert!(!stable_error_reason(&error).contains("canary"));
    }
}

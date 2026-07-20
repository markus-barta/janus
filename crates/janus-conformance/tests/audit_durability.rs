use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{Duration, SystemTime};

use janus_core::{
    Destination, EgressMode, ExecutorRef, JanusError, ManifestCatalog, OwnerRef, Principal,
    PrincipalChain, PrincipalId, PrincipalKind, ProfileId, ProfilePolicy, Purpose, SafeLabel,
    ScopePathV1, ScopeRef, SecretBroker, SecretClass, SecretLifecycle, SecretMeta, SecretName,
    SecretRef, TrustLevel, UseProfile, UseRequest,
};
use janus_local::JsonlAuditSink;
use janus_mock::MockStore;
use serde_json::Value;
use tempfile::tempdir;

const CANARY: &[u8] = b"SENSITIVE_DURABLE_AUDIT_CANARY";

fn scope() -> ScopeRef {
    ScopePathV1::for_repository("fixture-org", "janus", "janus", "audit")
        .unwrap()
        .scope_ref()
}

fn principal() -> PrincipalChain {
    PrincipalChain::new(
        Principal::new(
            PrincipalKind::Executor,
            PrincipalId::new("runner-a").unwrap(),
        ),
        scope(),
    )
}

fn fixture() -> (MockStore, SecretRef, UseProfile) {
    let name = SecretName::new("CANARY").unwrap();
    let secret_ref = SecretRef::for_manifest_entry(&scope(), &name);
    let profile = UseProfile {
        id: ProfileId::new("profile.canary").unwrap(),
        scope: scope(),
        secret_ref: secret_ref.clone(),
        executor: ExecutorRef::new("runner-a").unwrap(),
        destination: Destination::new("deploy-api").unwrap(),
        egress: EgressMode::Connector,
        trust_level: TrustLevel::L2,
        ttl: Duration::from_secs(60),
        single_use: true,
        enabled: true,
    };
    let catalog = ManifestCatalog::new(vec![SecretMeta {
        secret_ref: secret_ref.clone(),
        name: name.clone(),
        label: SafeLabel::new("Durable audit canary").unwrap(),
        scope: scope(),
        owner: Some(OwnerRef::new("security").unwrap()),
        classification: Some(SecretClass::Normal),
        lifecycle: SecretLifecycle::Active,
        required: true,
        trust_level: TrustLevel::L1,
        allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
    }])
    .unwrap();
    let store = MockStore::new(catalog)
        .with_value(name, CANARY.to_vec())
        .unwrap();
    (store, secret_ref, profile)
}

fn request(secret_ref: SecretRef) -> UseRequest {
    UseRequest {
        scope: scope(),
        secret_ref,
        profile_id: ProfileId::new("profile.canary").unwrap(),
        destination: Destination::new("deploy-api").unwrap(),
        purpose: Purpose::new("durable audit conformance").unwrap(),
    }
}

fn records(path: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn durable_audit_tracer_survives_restart_and_truncated_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit/events.jsonl");
    let caller = principal();
    let (store, secret_ref, profile) = fixture();
    let sink = JsonlAuditSink::open(&path).unwrap();
    let mut broker = SecretBroker::new(store, ProfilePolicy::new(vec![profile.clone()]), sink);
    let permit = broker
        .request_use(
            &request(secret_ref.clone()),
            &caller,
            SystemTime::UNIX_EPOCH,
        )
        .await
        .unwrap();
    let (_store, _policy, sink) = broker.into_parts();
    assert_eq!(sink.last_sequence(), 2);
    let first_hash = sink.last_event_hash().to_string();
    drop(sink);

    let reopened = JsonlAuditSink::open(&path).unwrap();
    assert_eq!(reopened.recovery().last_sequence, 2);
    assert_eq!(reopened.recovery().last_event_hash, first_hash);
    let (store, _, _) = fixture();
    let mut broker = SecretBroker::new(store, ProfilePolicy::new(vec![profile.clone()]), reopened);
    let value = broker
        .use_permit(
            &permit,
            &caller,
            &ExecutorRef::new("runner-a").unwrap(),
            &Destination::new("deploy-api").unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_eq!(value.expose_bytes(), CANARY);
    let (_store, _policy, sink) = broker.into_parts();
    assert_eq!(sink.last_sequence(), 3);
    drop(sink);

    let partial = br#"{"fabricated":true,"sequence":999"#;
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(partial)
        .unwrap();
    let recovered = JsonlAuditSink::open(&path).unwrap();
    assert_eq!(recovered.recovery().last_sequence, 3);
    assert_eq!(
        recovered.recovery().truncated_tail_bytes,
        partial.len() as u64
    );
    let (store, _, _) = fixture();
    let mut broker = SecretBroker::new(store, ProfilePolicy::new(vec![profile]), recovered);
    broker.describe(&secret_ref, &caller).await.unwrap();
    let (_store, _policy, sink) = broker.into_parts();
    assert_eq!(sink.last_sequence(), 4);

    let events = records(&path);
    assert_eq!(events.len(), 4);
    assert_eq!(events[0]["sequence"], 1);
    assert_eq!(events[1]["sequence"], 2);
    assert_eq!(events[2]["sequence"], 3);
    assert_eq!(events[3]["sequence"], 4);
    assert_eq!(events[1]["prev_hash"], events[0]["event_hash"]);
    assert_eq!(events[2]["prev_hash"], events[1]["event_hash"]);
    assert_eq!(events[3]["prev_hash"], events[2]["event_hash"]);
    let rendered = fs::read_to_string(&path).unwrap();
    assert!(!rendered.contains("fabricated"));
    assert!(!rendered.contains(std::str::from_utf8(CANARY).unwrap()));
}

#[test]
fn durable_audit_conformance_rejects_corruption_and_unavailable_paths() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit/events.jsonl");
    {
        let mut sink = JsonlAuditSink::open(&path).unwrap();
        use janus_core::{AuditAction, AuditEvent, AuditOutcome, AuditSink, Severity};
        sink.record(AuditEvent::new(
            AuditAction::SecretUse,
            AuditOutcome::Allowed,
            "ok",
            Severity::Notice,
            None,
            &principal(),
        ))
        .unwrap();
    }

    let mut record = records(&path).remove(0);
    record["sequence"] = Value::from(2_u64);
    record["reason_code"] = Value::String("SENSITIVE_DURABLE_AUDIT_CANARY".to_string());
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();
    let error = match JsonlAuditSink::open(&path) {
        Err(error) => error,
        Ok(_) => panic!("invalid audit chain was accepted"),
    };
    assert!(matches!(error, JanusError::AuditUnavailable { .. }));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("SENSITIVE_DURABLE_AUDIT_CANARY"));

    let unavailable = dir.path().join("not-a-file.jsonl");
    fs::create_dir(&unavailable).unwrap();
    assert!(matches!(
        JsonlAuditSink::open(unavailable),
        Err(JanusError::AuditUnavailable { .. })
    ));
}

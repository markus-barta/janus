use std::cell::RefCell;
use std::env;
use std::fmt;

use janus_core::{
    MigrationManifest, RecoveryComponentKind, RecoveryDrillManifest, ReleaseAdmissionReceipt,
    ReleaseChannelPolicy, ScopePathV1, ScopeTransferManifest, SecretMetadataOverlay,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngAlgorithm, TestRng, TestRunner};

const POLICY: &str = include_str!("../../../config/release-channels/v1.json");
const RECEIPT: &str = include_str!("../../../fixtures/release-admission/trusted.json");
const MIGRATION_TEMPLATE: &str =
    include_str!("../../../config/migrations/approval-registry-v0-v1.json.in");

#[derive(Clone)]
struct RedactedInput(Vec<u8>);

impl fmt::Debug for RedactedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-generated-input>")
    }
}

fn env_usize(name: &str, fallback: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn property_config(local_cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: env_usize("JANUS_PROPERTY_CASES", local_cases as usize)
            .try_into()
            .unwrap_or(u32::MAX),
        max_shrink_iters: env_usize("JANUS_PROPERTY_MAX_SHRINK_ITERATIONS", 4096)
            .try_into()
            .unwrap_or(u32::MAX),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/security_properties.txt"
        )))),
        ..ProptestConfig::default()
    }
}

fn max_input_bytes() -> usize {
    env_usize("JANUS_PROPERTY_MAX_INPUT_BYTES", 8192)
}

fn arbitrary_input() -> impl Strategy<Value = RedactedInput> {
    proptest::collection::vec(any::<u8>(), 0..=max_input_bytes()).prop_map(RedactedInput)
}

fn valid_migration() -> String {
    MIGRATION_TEMPLATE
        .replace("@TARGET_ROOT@", "/tmp/janus-property-target")
        .replace("@STATE_ROOT@", "/tmp/janus-property-state")
        .replace("@AUDIT_PATH@", "/tmp/janus-property-audit.jsonl")
}

fn valid_transfer() -> String {
    let destination =
        ScopePathV1::for_repository("fixture-org", "janus", "property-destination", "test")
            .unwrap();
    let destination_ref = destination.scope_ref();
    serde_json::json!({
        "schema_version": 1,
        "operation_id": "property-transfer",
        "mode": "exact_scope_recovery",
        "source_scope_ref": destination_ref.as_str(),
        "destination_scope": destination,
        "expected_destination_scope_ref": destination_ref.as_str(),
        "source_inventory_fingerprint": format!("sha256:{}", "a".repeat(64)),
        "expected_target_fingerprint": format!("sha256:{}", "b".repeat(64)),
        "source_root": "/tmp/janus-property-source",
        "target_root": "/tmp/janus-property-target",
        "state_root": "/tmp/janus-property-state",
        "audit_path": "/tmp/janus-property-audit.jsonl",
        "minimum_free_bytes": 1,
        "preflight_max_age_seconds": 60
    })
    .to_string()
}

fn valid_scope() -> String {
    r#"{
        "schema_version": 1,
        "organization": "fixture-org",
        "project": "janus",
        "repository": "janus",
        "environment": "property",
        "namespace": "runtime",
        "workload": "warden"
    }"#
    .to_string()
}

fn valid_metadata() -> String {
    r#"
        [defaults]
        owner = "security"
        classification = "high_value"
        lifecycle = "active"

        [[secrets]]
        name = "CANARY"
        owner = "runtime"
    "#
    .to_string()
}

fn valid_recovery() -> String {
    let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", "property")
        .unwrap()
        .scope_ref();
    let components = RecoveryComponentKind::ALL
        .iter()
        .map(|kind| {
            serde_json::json!({
                "kind": kind.as_str(),
                "source_path": format!("/tmp/janus-property-source/{}", kind.as_str()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "operation_id": "property-recovery",
        "scope_ref": scope.as_str(),
        "release_artifact": "not_required:self_hosted",
        "expected_bundle_fingerprint": format!("sha256:{}", "a".repeat(64)),
        "components": components,
        "config_bindings": [{
            "name": "secretspec",
            "path": "/tmp/janus-property-secretspec.toml",
            "expected_fingerprint": format!("sha256:{}", "b".repeat(64)),
        }],
        "permit_source_path": "/tmp/janus-property-permits",
        "bundle_root": "/tmp/janus-property-bundle",
        "target_root": "/tmp/janus-property-target",
        "state_root": "/tmp/janus-property-state",
        "operation_audit_path": "/tmp/janus-property-audit.jsonl",
        "evidence_path": "/tmp/janus-property-evidence.json",
        "minimum_free_bytes": 1,
        "maximum_bundle_bytes": 1048576,
        "maximum_bundle_files": 1024,
        "preflight_max_age_seconds": 60,
        "evidence_max_age_seconds": 86400,
    })
    .to_string()
}

fn parser_accepts(kind: u8, contents: &str) -> bool {
    match kind % 7 {
        0 => ReleaseChannelPolicy::parse_json(contents).is_ok(),
        1 => ReleaseAdmissionReceipt::parse_json(contents).is_ok(),
        2 => MigrationManifest::parse_json(contents).is_ok(),
        3 => ScopeTransferManifest::parse_json(contents).is_ok(),
        4 => ScopePathV1::parse_json(contents).is_ok(),
        5 => RecoveryDrillManifest::parse_json(contents).is_ok(),
        _ => SecretMetadataOverlay::parse_toml(contents).is_ok(),
    }
}

fn valid_document(kind: u8) -> String {
    match kind % 7 {
        0 => POLICY.to_string(),
        1 => RECEIPT.to_string(),
        2 => valid_migration(),
        3 => valid_transfer(),
        4 => valid_scope(),
        5 => valid_recovery(),
        _ => valid_metadata(),
    }
}

fn structured_invalid(kind: u8, mutation: u8, split: usize) -> String {
    let valid = valid_document(kind);
    if kind % 7 == 6 {
        return match mutation % 5 {
            0 => format!("{}\n[", &valid[..split % valid.len()]),
            1 => format!("{valid}\nSENSITIVE_TRAILING_CANARY"),
            2 => format!("{valid}\nunknown_field = true"),
            3 => valid.replace(
                "owner = \"security\"",
                &format!("owner = \"{}\"", "a".repeat(max_input_bytes())),
            ),
            _ => format!(
                "{}\n{valid}",
                "[nested]\n".repeat(env_usize("JANUS_PROPERTY_MAX_DEPTH", 8) + 1)
            ),
        };
    }
    let trimmed = valid.trim();
    match mutation % 6 {
        0 => trimmed[..split % trimmed.len()].to_string(),
        1 => format!("{trimmed}SENSITIVE_TRAILING_CANARY"),
        2 => {
            let end = trimmed.rfind('}').unwrap();
            format!(
                "{},\"unknown_security_property_field\":true{}",
                &trimmed[..end],
                &trimmed[end..]
            )
        }
        3 => {
            let mut value: serde_json::Value = serde_json::from_str(trimmed).unwrap();
            value["schema_version"] = serde_json::json!(2);
            value.to_string()
        }
        4 => trimmed.replacen('{', "{\"schema_version\":1,", 1),
        _ => format!(
            "{}{}{}",
            "[".repeat(env_usize("JANUS_PROPERTY_MAX_DEPTH", 8) + 1),
            trimmed,
            "]".repeat(env_usize("JANUS_PROPERTY_MAX_DEPTH", 8) + 1)
        ),
    }
}

proptest! {
    #![proptest_config(property_config(96))]

    #[test]
    fn security_property_bounded_parser_inputs_never_panic(
        kind in any::<u8>(),
        input in arbitrary_input(),
    ) {
        let contents = String::from_utf8_lossy(&input.0);
        let _ = parser_accepts(kind, &contents);
    }

    #[test]
    fn security_property_structured_parser_attacks_fail_closed(
        kind in any::<u8>(),
        mutation in any::<u8>(),
        split in any::<usize>(),
    ) {
        let valid = valid_document(kind);
        prop_assert!(parser_accepts(kind, &valid));
        let invalid = structured_invalid(kind, mutation, split);
        prop_assert!(!parser_accepts(kind, &invalid));
    }

    #[test]
    fn security_property_scope_refs_are_exact_stable_and_opaque(
        organization in "[a-z][a-z0-9_-]{1,30}[a-z0-9]",
        project in "[a-z][a-z0-9_-]{1,30}[a-z0-9]",
        repository in "[a-z][a-z0-9_-]{1,30}[a-z0-9]",
        environment in "[a-z][a-z0-9_-]{1,30}[a-z0-9]",
        other_environment in "[a-z][a-z0-9_-]{1,30}[a-z0-9]",
    ) {
        let path = ScopePathV1::for_repository(&organization, &project, &repository, &environment).unwrap();
        let repeated = ScopePathV1::for_repository(&organization, &project, &repository, &environment).unwrap();
        prop_assert_eq!(path.scope_ref(), repeated.scope_ref());
        let rendered = format!("{:?}", path.scope_ref());
        prop_assert!(!rendered.contains(&organization));
        prop_assert!(!rendered.contains(&project));
        prop_assert!(!rendered.contains(&repository));
        if environment != other_environment {
            let other = ScopePathV1::for_repository(&organization, &project, &repository, other_environment).unwrap();
            prop_assert_ne!(path.scope_ref(), other.scope_ref());
        }
    }
}

#[test]
fn security_property_committed_seed_replays_identically() {
    fn sequence() -> Vec<(u64, Vec<u8>)> {
        let mut config = property_config(32);
        config.cases = 32;
        config.failure_persistence = None;
        let seed = [0x4a_u8; 16];
        let rng = TestRng::from_seed(RngAlgorithm::XorShift, &seed);
        let mut runner = TestRunner::new_with_rng(config, rng);
        let strategy = (any::<u64>(), proptest::collection::vec(any::<u8>(), 0..32));
        let values = RefCell::new(Vec::new());
        runner
            .run(&strategy, |value| {
                values.borrow_mut().push(value);
                Ok(())
            })
            .unwrap();
        values.into_inner()
    }

    assert_eq!(sequence(), sequence());
}

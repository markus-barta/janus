use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, TestRunner};

static INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn property_cases(local_cases: u32) -> u32 {
    if env::var("JANUS_PROPERTY_REPLAY_ONLY").as_deref() == Ok("1") {
        return 0;
    }
    env::var("JANUS_PROPERTY_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(local_cases)
}

fn property_config() -> ProptestConfig {
    let persistence = env::var("JANUS_PROPERTY_REPLAY_PROBE_PERSISTENCE")
        .expect("property replay probe persistence path is required");
    let persistence: &'static str = Box::leak(persistence.into_boxed_str());
    ProptestConfig {
        cases: property_cases(1),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(persistence))),
        ..ProptestConfig::default()
    }
}

#[test]
fn real_proptest_replay_probe() {
    let Ok(mode) = env::var("JANUS_PROPERTY_REPLAY_PROBE") else {
        return;
    };
    assert!(
        matches!(mode.as_str(), "pass-persisted" | "fail-persisted"),
        "unsupported property replay probe mode"
    );

    INVOCATIONS.store(0, Ordering::SeqCst);
    let mut runner = TestRunner::new(property_config());
    runner
        .run(&any::<u8>(), |_| {
            let invocation = INVOCATIONS.fetch_add(1, Ordering::SeqCst);
            match mode.as_str() {
                "pass-persisted" if invocation == 0 => Ok(()),
                "pass-persisted" => Err(TestCaseError::fail(
                    "novel case executed after persisted seed",
                )),
                "fail-persisted" => Err(TestCaseError::fail("persisted seed failure")),
                _ => unreachable!(),
            }
        })
        .expect("property replay probe failed");
}

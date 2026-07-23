# Security-property replay

The release property runner suppresses child-process output because generated
values can resemble secrets or operational identifiers. On a novel Proptest
failure it keeps only a bounded replay receipt:

- schema version;
- reviewed target identifier;
- effective case budget and release-mode marker;
- Proptest RNG seed; and
- a deterministic `rpl_...` identity derived from those fields.

The seed is random generator state, not the generated or minimized input. The
runner also removes Proptest's generated-value comment from a newly appended
regression line before saving the receipt. Raw stdout, stderr, shrink values,
and environment contents are never copied into the receipt or public failure
message.

## Replay a CI failure

Download the short-lived artifact into the ignored `.tmp` directory, then pass
the receipt to the same reviewed runner:

```bash
gh run download RUN_ID --name rust-property-replay --dir .tmp
python3 scripts/run-security-properties.py --replay .tmp/janus-property-replay.json
```

Replay validates every field and the derived identity, selects only the target
declared in `config/assurance/security-properties-v2.json`, temporarily stages
the exact seed in that target's reviewed persistence file, and restores the
file afterward. A still-present defect exits nonzero with
`reason=reproduced_failure`; a fixed defect reports that the replay no longer
fails.

Do not paste raw Cargo or Proptest failure output into a ticket. Record the
bounded `rpl_...` identity and CI run instead. The receipt artifact expires
after seven days; a safe seed promoted to a committed regression file remains
the long-term replay proof.

## Local checks

```bash
python3 scripts/run-security-properties.py --self-test
python3 scripts/run-security-properties.py --target core-security-contracts --release
```

The self-test injects a canary into both captured streams and Proptest's
generated-value comment, verifies that none reaches the public failure or
receipt, rejects malformed receipts, and replays an injected failure twice.

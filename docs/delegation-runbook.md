# Exact-Use Delegation Runbook

Janus delegation lets one already-authorized principal temporarily let one
other exact principal request the same reviewed normal-use path. It does not
copy a secret, broaden a profile, mint an approval, or bypass a permit.

This first slice is deliberately narrow:

- only the `use` action is supported;
- only `low` and `normal` secret classes are eligible;
- secret, scope, profile, executor, destination, egress, purpose, policy state,
  grantor, delegate, and expiry are exact-bound;
- grants expire within 1–3600 seconds and cannot be chained; and
- every use still requires a short-lived, single-use permit.

## Shared Runtime Configuration

Use one private delegation registry for `janusd-admin`, `janus-warden`, and
`janusd-use`:

```bash
export JANUS_DELEGATION_DIR=/var/lib/janus/delegations
export JANUS_WARDEN_DELEGATION_DIR="$JANUS_DELEGATION_DIR"
export JANUS_RUN_DELEGATION_DIR="$JANUS_DELEGATION_DIR"
```

`JANUS_WARDEN_DELEGATION_DIR` and `JANUS_RUN_DELEGATION_DIR` override the
shared variable. `janusd-admin` and `janusd-use` otherwise default to
`/var/lib/janus/delegations`; Warden keeps delegation disabled when neither of
its registry variables is set.

The Warden policy and approved-use manifest must describe the same current
executor and destination. Keep the normal scope, backend, profile manifest,
permit directory, and Warden destination/TTL configuration in place.

## Issue An Exact Grant

The executor is taken from the reviewed profile. Supply only the identity
parts that are present in each exact principal chain:

```bash
janusd-admin delegation issue \
  --secret-ref sec_... \
  --profile profile.deploy \
  --purpose "deploy reviewed release" \
  --reason "coverage" \
  --expires-in-seconds 900 \
  --grantor-human human-alice \
  --delegate-human human-bob \
  --delegate-agent 'session:session-42,model:codex' \
  --delegate-workload deploy-runner
```

Supported identity flags are `--grantor-human`, `--grantor-agent`,
`--grantor-workload`, `--delegate-human`, `--delegate-agent`, and
`--delegate-workload`. Omit parts that are absent, but the resulting grantor
and delegate chains must be distinct. The command returns a value-free
`dlg_...` identifier and safe exact-scope summary; it never prints either raw
principal binding.

## Request And Consume A Permit

The Warden process must reconstruct the live delegate chain exactly:

```bash
export JANUS_WARDEN_HUMAN=human-bob
export JANUS_WARDEN_AGENT_SESSION=session-42
export JANUS_WARDEN_AGENT_MODEL=codex
export JANUS_WARDEN_WORKLOAD=deploy-runner
```

Pass the opaque grant ID as the optional fourth `request_use` field:

```json
{
  "secret_ref": "sec_...",
  "profile_id": "profile.deploy",
  "purpose": "deploy reviewed release",
  "delegation_id": "dlg_..."
}
```

The resulting permit carries durable acting-as context and is capped by both
the profile TTL and grant expiry. Before `janusd-use` reads the secret, it
reloads the grant, reconstructs the live human/agent/workload chain, and
revalidates current descriptor and profile policy.

Set the same identity on the split use process when it does not inherit the
Warden environment:

```bash
export JANUS_RUN_HUMAN=human-bob
export JANUS_RUN_AGENT_SESSION=session-42
export JANUS_RUN_AGENT_MODEL=codex
export JANUS_RUN_WORKLOAD=deploy-runner

janusd-use run --profile profile.deploy --permit use_... -- release apply
```

`janusd-use env-file` follows the same evidence and identity checks.

## Inspect Or Revoke

Inventory and inspect commands return value-free summaries:

```bash
janusd-admin delegation list
janusd-admin delegation inspect --delegation dlg_...
```

Revoke without deleting the immutable grant:

```bash
janusd-admin delegation revoke \
  --delegation dlg_... \
  --reason "coverage ended"
```

Revocation immediately blocks an unused permit at consumption, even when the
permit was issued before the revocation. Expiry behaves the same way. A failed
revalidation consumes the single-use permit claim but never reads or returns
the secret.

## Evidence And Failure Checks

Delegation grant, denial, expiry, revocation, permit, and secret-use events are
audit chained. Delegated permit and audit records preserve exact acting-as
context across restart, while debug and operator output redact principal
bindings and fingerprints.

For incident triage, confirm:

1. all three processes point at the same private delegation directory;
2. Warden and `janusd-use` reconstruct the same delegate identity parts;
3. purpose, profile, destination, executor, scope, and TTL policy still match;
4. the grant is active and has no `.revoked.json` evidence; and
5. the permit has not already been claimed.

Do not repair a denial by editing registry JSON. Issue a new exact grant after
the current policy or identity mismatch is understood.

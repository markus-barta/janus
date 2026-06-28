# Env-file handoff operator runbook

This runbook covers the repo-local `janusd env-file` service handoff path. It
is the bridge between the working smoke and a future real host/service wiring.
Do not use it as a host deployment recipe by itself.

## What It Proves

`janusd env-file` lets an operator provide one approved secret to one reviewed
non-LLM service consumer as a private env file.

The model/operator supplies only:
- profile id
- opaque permit id

The reviewed profile supplies:
- secret ref
- executor
- destination
- env var name
- output path
- consumer metadata

The command must remain value-free: no secret literal in stdout, stderr, logs,
audit records, MCP output, or model-facing text.

## Checked Fixture

The checked nonprod bundle lives in:

```text
examples/env-file-handoff/
```

Run the fixture:

```bash
devenv shell -- ./scripts/smoke-janusd-env-file.sh
```

The smoke creates an isolated temp runtime, seeds an age-backed store, renders
the profile template, and exercises:

```bash
janusd env-file preflight ...
janusd approve issue ...
janusd approve permit ...
janusd env-file ...
```

It verifies:
- preflight checks the reviewed target without writing the env file
- output file mode is `0600`
- output path comes from the rendered profile
- env binding matches the reviewed profile
- fixture service consumes the env file by hash
- lifecycle evidence is written
- permit is consumed and cannot be reused
- captured output does not contain the fixture secret literal

## Preflight For A Real Consumer

Before wiring a real service/host, create a reviewed consumer contract with:
- `consumer_ref`
- owner
- environment
- secret name and opaque `SecretRef`
- profile id
- executor identity
- destination
- env var name
- absolute output path
- reload method
- validation probe
- dual-value support
- blast radius

The parent directory for the env file must already exist, must not be a symlink,
and must be private on Unix (`0700`). Existing env files must be regular files
and private (`0600`).

## Operator Flow

Set the runtime environment:

```bash
export JANUS_RUN_PROFILE_MANIFEST=/etc/janus/approved-use.toml
export JANUS_RUN_PERMIT_DIR=/run/janus/permits
export JANUS_APPROVAL_DIR=/run/janus/approvals
export JANUS_LIFECYCLE_EVIDENCE_DIR=/var/lib/janus/lifecycle-evidence
export JANUS_AGE_MANIFEST_FILE=/etc/janus/secretspec.toml
export JANUS_AGE_PROFILE=default
export JANUS_AGE_STORE_DIR=/var/lib/janus/secrets
export JANUS_AGE_IDENTITY_FILE=/run/janus/age/identity
export JANUS_AGE_RECIPIENT=age1...
export JANUS_AGE_METADATA_FILE=/etc/janus/metadata.toml
export JANUS_RUN_EXECUTOR=janus-run@HOST
export JANUS_RUN_SCOPE=janus/nonprod
```

Preflight the reviewed profile before issuing approval or permit material:

```bash
janusd env-file preflight --profile profile.SERVICE
```

Expected output is value-free and shaped like:

```text
janusd env-file preflight ok secret_ref=sec_... profile_id=profile.SERVICE output_path=/run/... consumer_ref=consumer... reason_code=ok value_returned=false
```

Issue an approval when policy requires it:

```bash
janusd approve issue \
  --secret-ref sec_... \
  --profile profile.SERVICE \
  --purpose "service env file handoff" \
  --reason "JANUS-..." \
  --egress connector \
  --expires-in-seconds 120
```

Issue a single-use permit:

```bash
janusd approve permit \
  --approval appr_... \
  --permit-ttl-seconds 60 \
  --revoke-approval
```

Render the env file:

```bash
janusd env-file --profile profile.SERVICE --permit use_...
```

Expected output is value-free and shaped like:

```text
janusd env-file ok secret_ref=sec_... profile_id=profile.SERVICE output_path=/run/... consumer_ref=consumer... reason_code=ok value_returned=false
```

## Rollback And Cleanup

If the env file was rendered but the consumer was not switched:
- stop the consumer before removing the env file
- remove the rendered env file deliberately
- leave lifecycle evidence intact
- issue a new approval/permit for retries; permits are single-use

If the profile/output path is wrong:
- remove the rendered env file if present
- fix the reviewed profile in source control
- rerun the smoke or host-specific nonprod check before retrying

Do not edit permit files by hand. A consumed or failed permit should be treated
as spent.

## Evidence To Keep

Keep value-free evidence only:
- commit that introduced/changed the reviewed profile
- `janusd env-file preflight` value-free outcome
- `janusd approve issue` output
- `janusd approve permit` output
- `janusd env-file` value-free outcome
- file mode/path check
- consumer validation result
- lifecycle evidence record

Do not store:
- rendered env file contents
- decrypted age payloads
- raw secret names in model-facing text unless already reviewed safe
- permit ids in casual logs beyond the operator evidence bundle

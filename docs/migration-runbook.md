# Approval registry migration runbook

JANUS ships one reviewed offline migration: legacy unversioned approval records
(schema v0) to explicitly versioned records (schema v1). It adds only the
record version and a registry marker. Approval authority, expiry, executor,
destination, class, egress, purpose, and reason must remain identical.

This runner does not migrate encrypted provider values, custody keys, remote
databases, or disaster-recovery material.

## Safety contract

- Stop every `janusd-use`, `janusd-admin`, and `janus-warden` instance that uses the approval
  registry. Preflight takes a local maintenance lock but cannot stop remote
  writers.
- Render the reviewed
  [`approval-registry-v0-v1.json.in`](../config/migrations/approval-registry-v0-v1.json.in)
  with absolute paths. Keep the target, state root, manifest, and audit path
  private and on trusted storage.
- Set `JANUS_MIGRATION_MANIFEST` to that rendered manifest on both runtimes.
  Startup is allowed before migration begins and after verified `completed` or
  `rolled_back` states. Any intermediate, failed, orphaned, or drifted state
  blocks startup.
- Production and enterprise commands also require the trusted release
  admission variables described in
  [Trusted release admission](release-admission.md). The release evidence is
  bound at preflight and cannot change during apply or postflight.

## Operator sequence

```bash
janusd-admin migrate preflight --manifest /etc/janus/migration.json
janusd-admin migrate status --manifest /etc/janus/migration.json
janusd-admin migrate apply --manifest /etc/janus/migration.json
janusd-admin migrate postflight --manifest /etc/janus/migration.json
janusd-admin migrate status --manifest /etc/janus/migration.json
```

Preflight is target-read-only: it validates every record, checks free space,
creates a byte-exact private rollback snapshot, and writes a content-bound
journal. Apply accepts only that exact, fresh source and snapshot, builds v1 in
a private staging directory, verifies unchanged authority, then atomically
swaps directories. Postflight rechecks the installed target and preserved v0
directory before writing the terminal journal.

All command output and audit evidence are value-free fingerprints, counts,
versions, phases, and reason codes. The audit actions are `upgrade.preflight`,
`migration.apply`, `upgrade.postflight`, and `upgrade.rollback`.

## Failure and rollback

Do not delete or edit the state root, snapshot, journal, or hidden work
directories. First repair the reported environmental cause (for example audit
availability or disk space), then inspect status:

```bash
janusd-admin migrate status --manifest /etc/janus/migration.json
```

To restore the verified v0 snapshot from any interrupted mutating phase:

```bash
janusd-admin migrate rollback --manifest /etc/janus/migration.json
janusd-admin migrate status --manifest /etc/janus/migration.json
```

Resume runtimes only after status reports `completed` or `rolled_back` and the
rollback/postflight audit event is durable. Escalate instead of bypassing the
guard if the snapshot, journal, manifest binding, terminal fingerprint, or
authority fingerprint does not verify.

## Scope-bound recovery and transfer

`janusd-admin scope-transfer` is a separate offline workflow for a private,
value-free `scope-state.json` bundle. The bundle may contain secret names for
ref derivation, classifications, owners, lifecycle timestamps, tombstones,
consumer relationships, approval records, and a permit count. It contains no
secret values, encrypted payloads, provider identities, or custody keys.

There are exactly two reviewed modes:

- `exact_scope_recovery`: source and destination derive the same opaque scope
  ref. Scope-derived identities and valid durable approvals remain unchanged.
- `boundary_changing_transfer`: source and destination refs differ. Every
  SecretRef and supported consumer relationship is recomputed for the exact
  destination; approvals are excluded and must be reissued there.

Permit bodies are never part of the bundle and `permit_count` is always reset
to zero in installed output. Missing, inferred, wildcard, parent/child,
one-to-many, many-to-one, partial, colliding, and ambiguous mappings fail
closed. Lifecycle, classification, ownership, and tombstones are preserved;
the workflow cannot activate, undelete, or declassify a record.

Render
[`scope-transfer-v1.json.in`](../config/migrations/scope-transfer-v1.json.in)
to a private regular file with absolute, non-overlapping roots. The destination
typed path must derive `expected_destination_scope_ref`. Configure the runtime
scope to that exact destination and set `JANUS_SCOPE_TRANSFER_MANIFEST` on
normal runtimes so incomplete or drifted transfer state blocks startup.

Before the first preflight, `status` safely discovers the canonical source,
current target, planned target, manifest, and mapping fingerprints. It does not
require the placeholder source/target fingerprints to match and never reads a
secret value. Copy the reported `source_inventory_fingerprint` and
`target_fingerprint` into the reviewed manifest, then make that manifest
read-only to untrusted writers.

```bash
janusd-admin scope-transfer status --manifest /etc/janus/scope-transfer.json
janusd-admin scope-transfer preflight --manifest /etc/janus/scope-transfer.json
janusd-admin scope-transfer apply --manifest /etc/janus/scope-transfer.json
janusd-admin scope-transfer postflight --manifest /etc/janus/scope-transfer.json
janusd-admin scope-transfer status --manifest /etc/janus/scope-transfer.json
```

Preflight verifies source and target fingerprints, exact operation class,
record relationships, collision freedom, private paths, free space, release
admission, and a rollback snapshot. Apply accepts only that fresh evidence,
builds and verifies private staged output, and atomically swaps the target.
Postflight must pass before runtime resumes. Audit actions are
`scope_transfer.preflight`, `scope_transfer.apply`,
`scope_transfer.postflight`, and `scope_transfer.rollback`.

To recover the exact preflight target from any interrupted or applied phase:

```bash
janusd-admin scope-transfer rollback --manifest /etc/janus/scope-transfer.json
janusd-admin scope-transfer status --manifest /etc/janus/scope-transfer.json
```

Do not edit the journal, snapshot, or hidden work directories. A completed or
rolled-back terminal fingerprint mismatch is a hard startup denial. Encrypted
backend backup, age identities and recipients, remote replication, and key
custody disaster recovery are deliberately outside this workflow.

# Destroy lifecycle operator runbook

This runbook covers the metadata-only Janus destroy path. It blocks normal
approved use, records durable value-free tombstone evidence, finalizes metadata,
and reconciles metadata against tombstones. It does not delete provider values.

## Scope

Use this flow when a reviewed secret is intentionally retired from Janus use and
must remain represented by metadata plus tombstone evidence.

Do not use this flow for emergency provider-side deletion. Janus intentionally
keeps this path value-free and non-destructive at the provider layer:

- No command accepts a secret value.
- No command accepts `--delete` or `--provider-delete`.
- Outputs include `value_returned=false`.
- Destroy outputs include `provider_deleted=false`.

## Required context

Run commands from a reviewed Janus operator environment with the same backend
context used by normal janusd operations:

- `JANUS_AGE_MANIFEST_FILE`, `JANUS_WARDEN_AGE_MANIFEST_FILE`, or
  `JANUS_WARDEN_SECRETSPEC_FILE`.
- `JANUS_AGE_STORE_DIR`, unless the default `/var/lib/janus/secrets` is right.
- Age identity via `JANUS_AGE_IDENTITY_FILE`, `JANUS_AGE_IDENTITY_FILES`, or the
  warden equivalents.
- Age recipients via `JANUS_AGE_RECIPIENT`, `JANUS_AGE_RECIPIENTS_FILE`, or the
  warden equivalents.
- A metadata overlay via `--metadata-file`, `JANUS_AGE_METADATA_FILE`,
  `JANUS_WARDEN_AGE_METADATA_FILE`, or `JANUS_METADATA_FILE`.
- A durable tombstone registry via `JANUS_LIFECYCLE_TOMBSTONE_DIR` or
  `JANUS_TOMBSTONE_DIR`; default is `/var/lib/janus/tombstones`.
- Optional audit identity via `JANUS_LIFECYCLE_EXECUTOR` and
  `JANUS_LIFECYCLE_SCOPE`.

Record the operator reason in the tracking ticket before running commands. Use
the stable `SecretRef` from the manifest, not the secret name or value.

## Preflight

Confirm these points before changing lifecycle metadata:

- Consumers have migrated away or the service owner accepts the outage.
- The target secret is present in the manifest and metadata overlay.
- The metadata overlay is reviewed and can be diffed or restored.
- The tombstone directory is durable and local to the Janus environment.
- The reason is a short reviewed label, not a raw ticket body or secret value.

Optional stale context:

```bash
janusd lifecycle stale-report \
  --stale-after-days 90 \
  --missing-evidence-after-days 30
```

The stale report is value-free. It can help show whether the secret has recent
rotation or managed-command evidence, but it is not required for destroy.

## Command sequence

Set local shell variables to keep the sequence readable:

```bash
SECRET_REF=sec_example
METADATA_FILE=/etc/janus/metadata.toml
REASON=reviewed-retirement
RETAIN_DAYS=365
```

1. Disable normal approved use.

```bash
janusd lifecycle transition \
  --secret-ref "$SECRET_REF" \
  --to disabled \
  --reason "$REASON" \
  --metadata-file "$METADATA_FILE"
```

Expected shape:

```text
janusd lifecycle transition ok secret_ref=sec_example from=active to=disabled reason_code=lifecycle_transition_ok value_returned=false
```

2. Move from disabled to pending delete.

```bash
janusd lifecycle transition \
  --secret-ref "$SECRET_REF" \
  --to pending_delete \
  --reason "$REASON" \
  --metadata-file "$METADATA_FILE"
```

Expected shape:

```text
janusd lifecycle transition ok secret_ref=sec_example from=disabled to=pending_delete reason_code=lifecycle_transition_ok value_returned=false
```

3. Record the value-free destroy tombstone.

```bash
janusd lifecycle destroy-record \
  --secret-ref "$SECRET_REF" \
  --reason "$REASON" \
  --retain-for-days "$RETAIN_DAYS" \
  --metadata-file "$METADATA_FILE"
```

Expected shape:

```text
janusd lifecycle destroy-record ok secret_ref=sec_example from=pending_delete to=destroyed reason_code=tombstone_recorded retain_until_unix_secs=1790000000 value_returned=false provider_deleted=false
```

This step writes tombstone evidence only. Metadata remains `pending_delete` until
the finalize step succeeds.

4. Finalize metadata as destroyed.

```bash
janusd lifecycle destroy-finalize \
  --secret-ref "$SECRET_REF" \
  --metadata-file "$METADATA_FILE"
```

Expected shape:

```text
janusd lifecycle destroy-finalize ok secret_ref=sec_example from=pending_delete to=destroyed reason_code=destroy_metadata_finalized metadata_finalized=true value_returned=false provider_deleted=false
```

If metadata is already `destroyed` and a tombstone exists, the command reports
`reason_code=destroy_metadata_already_finalized` and leaves metadata unchanged.

5. Reconcile metadata and tombstones.

```bash
janusd lifecycle destroy-reconcile \
  --metadata-file "$METADATA_FILE"
```

Expected final row:

```text
janusd lifecycle destroy-reconcile secret_ref=sec_example status=ok reason_code=destroy_tombstone_reconcile_ok action_required=false action=none metadata_lifecycle=destroyed tombstone=present value_returned=false provider_deleted=false
```

## Reconcile results

| Status | Reason code | Action |
|---|---|---|
| `ok` | `destroy_tombstone_reconcile_ok` | No action. Metadata is `destroyed` and tombstone is present. |
| `needs_finalize` | `destroy_tombstone_pending_finalize` | Run `lifecycle destroy-finalize` for the row's `secret_ref`. |
| `drift` | `destroyed_missing_tombstone` | Restore the tombstone from backup or investigate before accepting the destroyed metadata. |
| `drift` | `destroy_tombstone_lifecycle_mismatch` | Investigate why a tombstone exists while metadata is not `pending_delete` or `destroyed`. |
| `drift` | `destroy_tombstone_metadata_missing` | Investigate the orphan tombstone before pruning metadata or tombstone records. |

Treat every `action_required=true` row as a reviewed follow-up item. Do not paper
over drift by deleting evidence just to make the report quiet.

## Recovery notes

- `lifecycle transition` only supports reviewed policy paths such as
  `active -> disabled` and `disabled -> pending_delete`; unsupported reversals
  are denied.
- `destroy-record` requires current metadata lifecycle `pending_delete`.
- `destroy-finalize` requires both a tombstone and current metadata lifecycle
  `pending_delete`, unless metadata is already finalized as `destroyed`.
- If a command fails while writing metadata, inspect the metadata overlay before
  rerunning; Janus writes the overlay atomically, so the file should be either
  old or new rather than partially written.
- Provider deletion, if ever needed, is a separate manual provider operation with
  its own review trail. This runbook does not authorize it.

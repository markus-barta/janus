# Managed-service web transaction boundary

`janusd-web-transactiond` is the only local bridge from the authenticated Go
web envelope to Janus lifecycle entry. It is not an HTTP API and it does not
dispatch admin commands. The binary accepts no arguments and listens on one
private Unix socket.

The web peer may submit only these signed-intent fields:

- an opaque operation reference;
- create/replace with a generated/import source, or value-free removal;
- opaque host, service, and slot references; and
- the exact declaration fingerprint.

The daemon resolves that tuple in a root-owned reviewed catalog. The catalog,
not the peer, supplies the secret reference, scope, manifest/profile/backend
paths, consumer, probes, hooks, generation policy, state directory, audit
sink, activation reason, and host-delivery binding. Version 2 admits create,
safe replacement, and explicit removal after a reviewed declaration detach.

## Protocol

Frames use a four-byte big-endian length followed by bytes. The first frame is
strict JSON with schema
`inspr.janus.managed-web-transaction-request.v2`. The daemon replies with
strict, value-free JSON:

- `preflighted` before it will read an import value;
- `prepared` after encrypted host delivery is durably staged;
- `completed` only after fresh host activation evidence is accepted;
- `completed` for removal only after exact stopped/runtime-absent/quarantined
  evidence is accepted;
- `destroyed` only after the recovery deadline and tombstone write;
- `rolled_back` for an already reconciled operation; or
- `denied` with a stable reason code.

An import uses exactly one bounded raw frame after the preflight response.
Generated material is created inside Rust and has no value frame. Removal also
has no value frame: it carries only the reviewed target, active generation,
recovery deadline, and value-free absence evidence. Responses
contain only opaque operation/secret references, mode, phase, reason code,
`expects_value`, and `value_returned=false`.

Disconnect before or during import rolls the transaction back. Apply failures
use the lifecycle rollback. On startup, the daemon scans nonterminal journals
that still bind to its reviewed catalog. A valid, unexpired prepared host
delivery remains resumable; incomplete or expired create/replace work is
rolled back. A nonterminal removal is preserved and resumed explicitly;
process restart never restores a detached service secret. A duplicate terminal
operation returns its existing status without applying again.

Web journals use a deterministic `webtx_` namespace derived from the external
`op_` reference. Startup recovery ignores lifecycle-entry journals from other
entry points, so starting the daemon cannot take over an operator CLI
transaction.

Accepting the complete import frame is only the preparation point. It is not a
claim that the service uses the value. The host installs a signed, encrypted
packet, reloads the declared service, and submits fresh generation-bound
health evidence through Pharos. Janus then commits the central transaction.
Lost responses are retry-safe because the journal, host outbox, bridge state,
and host executor all use the same operation and generation binding.

## Replacement safety

Replace is admitted only for an exact reviewed declaration with a current
healthy generation. Before changing the central ciphertext, Janus records a
deterministic rollback identifier in the integrity-protected journal and
preserves the old encrypted ciphertext in a private rollback file. The host
likewise retains exactly one previous encrypted generation while it stages the
new generation.

The new generation becomes final only after install, declared reload, and
fresh process, probe, and heartbeat evidence all agree. Janus commits the
central transaction before the host destroys its previous generation. If
packet delivery, reload, verification, restart recovery, or evidence checking
fails, the host must prove that the previous generation is healthy; Pharos
then reports `rolled_back`, and Janus restores the matching central
ciphertext. If recovery cannot be proven, the operation remains uncertain and
no new generation is accepted as active.

Create and replacement attempt generations increase monotonically. Removal
targets the generation that is actually active; after a failed replacement
this is the proven restored generation, not the larger failed-attempt number.
Create and replace for the same secret/slot cannot overlap. Replacement never
exposes a reveal or arbitrary edit API, and neither journals, responses,
Pharos state, nor audit events contain the secret value.

For a rolling upgrade, install the replacement-capable host agent before
Pharos starts issuing replacement leases. The new agent treats a predecessor
lease without `operation_kind` as create and omits empty replacement-only
evidence, so create remains compatible during that step. Upgrade Pharos and
the Janus bridge next, with the bridge before Pharos, then add reviewed
replacement catalog entries last.
Until the final step, Replace stays fail-closed.

## Removal safety

Removal is never inferred from a missing value, host cache, or service. The
Nix-owned declaration must first move the slot from `required` to `detached`,
clear its creation sources, retain an exact `compose_stop_and_verify` profile,
and be deployed. Only that reviewed declaration can produce a short-lived,
passwordless-confirmed removal intent.

Janus first disables active delivery without deleting ciphertext. The host
agent stops the exact declared Compose service, verifies both the Compose
service and reviewed container are stopped, removes runtime plaintext, and
moves the exact active encrypted packet into operation-bound quarantine.
Pharos accepts only fresh stopped/runtime-absent/quarantined evidence for the
same active generation. Janus then moves central ciphertext into deterministic
quarantine and records `pending_delete`.

The browser bridge uses a fixed 24-hour recovery deadline. Cancellation may
restore active delivery before quarantine. Once quarantine starts, rollback is
denied: failures stop for operator review rather than guessing that restore is
safe. At the deadline, host and central workers independently retry their exact
idempotent purge. Central purge writes a retained tombstone before deleting
quarantine material and persists lifecycle `destroyed`. Reveal and copy-back
remain unavailable throughout.

For rollout, deploy schema-v2 readers and the host agent before publishing v2
declarations. Keep slots `required` until create/replace compatibility is
green. Detach one canary slot in a separate reviewed Nix change, verify removal
and recovery evidence, then expand. A schema-v1 declaration is read as
`required` and can never authorize removal.

Up to 16 private peers may be processed concurrently. Further connections
remain in the kernel socket backlog until capacity is available; each accepted
request and value wait is bounded.

## Runtime configuration

The daemon requires:

```text
JANUS_MANAGED_WEB_TRANSACTION_SOCKET=/run/janus/web-transaction/transaction.sock
JANUS_MANAGED_WEB_TRANSACTION_CATALOG_FILE=/etc/janus/managed-web-transactions.json
JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID=65532
JANUS_LIFECYCLE_TOMBSTONE_DIR=/var/lib/janus/tombstones
```

It also uses the same exact-scope, Age backend, release-admission, migration,
and scope-transfer environment as lifecycle entry. The socket parent and
catalog must be private. The socket is mode `0600`, and the kernel-reported
peer UID must equal the configured UID.

The Go envelope requires the same
`JANUS_MANAGED_WEB_TRANSACTION_SOCKET` alongside its all-or-nothing managed
setup intent configuration. Filesystem access to that socket is its sole
lifecycle capability; it receives no admin binary, plan path, backend path, or
hook selector.

Startup intentionally fails closed if a nonterminal `webtx_` journal no longer
matches a current, non-stale catalog entry. Retire or replace catalog entries
only after the lifecycle queue shows no nonterminal web transaction. For
create/replace, restore the reviewed entry and let startup rollback finish.
For removal, restore the exact reviewed removal entry so it can resume; startup
deliberately does not roll it back.

## Catalog contract

The catalog is strict JSON:

```json
{
  "schema": "inspr.janus.managed-web-transaction-catalog.v2",
  "schema_version": 2,
  "entries": [
    {
      "host_ref": "host_opaque0001",
      "service_ref": "svc_opaque0001",
      "slot_ref": "slot_opaque0001",
      "declaration_fingerprint": "decl_opaque0001",
      "operation_kind": "create",
      "plan": {
        "operation_id": "web-transaction-template"
      },
      "delivery": {
        "schema": "inspr.janus.managed-host-delivery-plan.v1",
        "schema_version": 1,
        "host_recipient": "ssh-ed25519 reviewed-host-key",
        "producer_key_id": "key_opaque0001",
        "producer_signing_key_file": "/run/credentials/janus/signing-key.json",
        "outbox_dir": "/var/lib/janus/managed-host-outbox",
        "generation": 1,
        "revocation_epoch": 1,
        "envelope_ttl_seconds": 900
      }
    }
  ]
}
```

`plan` is the complete existing lifecycle-entry plan; the abbreviated object
above is illustrative and intentionally not deployable. `delivery` is the
reviewed host-encryption plan. Replacement and removal are separate catalog
entries with the same declaration tuple and `"operation_kind": "replace"` or
`"operation_kind": "remove"`. For removal, the daemon forces plan source
`remove`; no generated/import source or value frame is accepted. The daemon
replaces only the fixed template `operation_id`, using the validated opaque
operation reference. Every other field is validated at daemon startup and
remains server-owned.

Run `scripts/assure-engine-release.sh` to exercise the real Age store,
manifest/profile binding, preflight-before-value ordering, validation,
create, restart-safe replacement rollback, monotonic replacement commit,
cancel-before-quarantine, restart-safe removal, active-generation targeting,
deadline-bound quarantine/purge, tombstone retention, duplicate idempotency,
malformed request denial, and canary leak checks across output, audit, journal,
ciphertext, and daemon failure output.

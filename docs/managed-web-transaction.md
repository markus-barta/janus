# Managed-service web transaction boundary

`janusd-web-transactiond` is the only local bridge from the authenticated Go
web envelope to Janus lifecycle entry. It is not an HTTP API and it does not
dispatch admin commands. The binary accepts no arguments and listens on one
private Unix socket.

The web peer may submit only these signed-intent fields:

- an opaque operation reference;
- create or replace operation and generated/import source;
- opaque host, service, and slot references; and
- the exact declaration fingerprint.

The daemon resolves that tuple in a root-owned reviewed catalog. The catalog,
not the peer, supplies the secret reference, scope, manifest/profile/backend
paths, consumer, probes, hooks, generation policy, state directory, audit
sink, and activation reason. Version 2 admits create and safe replacement.
Removal remains closed until its dedicated lifecycle work is complete.

## Protocol

Frames use a four-byte big-endian length followed by bytes. The first frame is
strict JSON with schema
`inspr.janus.managed-web-transaction-request.v2`. The daemon replies with
strict, value-free JSON:

- `preflighted` before it will read an import value;
- `prepared` after encrypted host delivery is durably staged;
- `completed` only after fresh host activation evidence is accepted;
- `rolled_back` for an already reconciled operation; or
- `denied` with a stable reason code.

An import uses exactly one bounded raw frame after the preflight response.
Generated material is created inside Rust and has no value frame. Responses
contain only opaque operation/secret references, mode, phase, reason code,
`expects_value`, and `value_returned=false`.

Disconnect before or during import rolls the transaction back. Apply failures
use the lifecycle rollback. On startup, the daemon scans nonterminal journals
that still bind to its reviewed catalog. A valid, unexpired prepared host
delivery remains resumable; incomplete or expired work is rolled back. A
duplicate terminal operation returns its existing status without applying
again.

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

Generations increase monotonically across failed and successful attempts.
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

Up to 16 private peers may be processed concurrently. Further connections
remain in the kernel socket backlog until capacity is available; each accepted
request and value wait is bounded.

## Runtime configuration

The daemon requires:

```text
JANUS_MANAGED_WEB_TRANSACTION_SOCKET=/run/janus/web-transaction/transaction.sock
JANUS_MANAGED_WEB_TRANSACTION_CATALOG_FILE=/etc/janus/managed-web-transactions.json
JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID=65532
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
only after the lifecycle queue shows no nonterminal web transaction; otherwise
restore the reviewed entry and let startup rollback finish before changing the
catalog.

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
reviewed host-encryption plan. A replacement is a separate catalog entry with
the same declaration tuple and `"operation_kind": "replace"`. The daemon
replaces only the fixed template `operation_id`, using the validated opaque
operation reference. Every other field is validated at daemon startup and
remains server-owned.

Run `scripts/assure-engine-release.sh` to exercise the real Age store,
manifest/profile binding, preflight-before-value ordering, validation,
create, restart-safe replacement rollback, monotonic replacement commit,
duplicate idempotency, malformed request denial, and canary leak checks across
output, audit, journal, ciphertext, and daemon failure output.

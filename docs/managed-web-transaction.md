# Managed-service web transaction boundary

`janusd-web-transactiond` is the only local bridge from the authenticated Go
web envelope to Janus lifecycle entry. It is not an HTTP API and it does not
dispatch admin commands. The binary accepts no arguments and listens on one
private Unix socket.

The web peer may submit only these signed-intent fields:

- an opaque operation reference;
- create operation and generated/import source;
- opaque host, service, and slot references; and
- the exact declaration fingerprint.

The daemon resolves that tuple in a root-owned reviewed catalog. The catalog,
not the peer, supplies the secret reference, scope, manifest/profile/backend
paths, consumer, probes, hooks, generation policy, state directory, audit
sink, and activation reason. Version 1 admits create only. Replace and removal
remain closed until their dedicated lifecycle work is complete.

## Protocol

Frames use a four-byte big-endian length followed by bytes. The first frame is
strict JSON with schema
`inspr.janus.managed-web-transaction-request.v1`. The daemon replies with
strict, value-free JSON:

- `preflighted` before it will read an import value;
- `completed` after store, validation, activation, reload, journal, and audit;
- `rolled_back` for an already reconciled operation; or
- `denied` with a stable reason code.

An import uses exactly one bounded raw frame after the preflight response.
Generated material is created inside Rust and has no value frame. Responses
contain only opaque operation/secret references, mode, phase, reason code,
`expects_value`, and `value_returned=false`.

Disconnect before or during import rolls the transaction back. Apply and
activation failures use the existing lifecycle rollback. On startup, the
daemon scans nonterminal journals that still bind to its reviewed catalog and
rolls them back before binding the socket. A duplicate completed operation
returns its completed status without applying again.

Web journals use a deterministic `webtx_` namespace derived from the external
`op_` reference. Startup recovery ignores lifecycle-entry journals from other
entry points, so starting the daemon cannot take over an operator CLI
transaction.

Accepting the complete import frame is the commit point. A disconnect after
that point does not cancel an in-flight activation; the daemon finishes the
transaction and a retry discovers the terminal journal. This removes the
ambiguous “server committed but browser did not receive the response” replay
case.

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
  "schema": "inspr.janus.managed-web-transaction-catalog.v1",
  "schema_version": 1,
  "entries": [
    {
      "host_ref": "host_opaque0001",
      "service_ref": "svc_opaque0001",
      "slot_ref": "slot_opaque0001",
      "declaration_fingerprint": "decl_opaque0001",
      "operation_kind": "create",
      "plan": {
        "operation_id": "web-transaction-template"
      }
    }
  ]
}
```

`plan` is the complete existing lifecycle-entry plan; the abbreviated object
above is illustrative and is intentionally not deployable. The only field the
daemon replaces is the fixed template `operation_id`, using the validated
opaque operation reference. Every other field is validated at daemon startup
and remains server-owned.

Run `scripts/assure-engine-release.sh` to exercise the real Age store,
manifest/profile binding, preflight-before-value ordering, validation,
activation, crash/restart rollback, duplicate idempotency, malformed request
denial, and canary leak checks across output, audit, journal, ciphertext, and
daemon failure output.

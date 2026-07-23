# Managed-service secret contract

This contract is the value-free language shared by reviewed nixcfg
declarations, Pharos orchestration, Janus custody, a host executor, and fresh
service-health evidence. Its first product path is intentionally narrow:

- consumer: `managed_service`
- delivery: `private_env_file`
- sources: reviewed `generated` and/or bounded `import`
- actions: `create`, `replace`, and `remove`
- read surface: metadata and status only; no reveal or copy

The executable Rust contract lives in
`crates/janus-core/src/managed_service.rs`. The canonical cross-repository
fixture is `contracts/managed-service-secret-contract-v1.json`.

## Authority and state

No one system may claim an end-to-end outcome by itself.

| Fact or phase | Authoritative writer |
| --- | --- |
| Managed service and secret slot declaration | nixcfg |
| Setup request and detach request | Pharos |
| Preflight, encryption, activation, revocation, rollback, quarantine, destruction | Janus |
| Encrypted-envelope receipt, runtime materialization, reload, runtime removal | exact host executor |
| Post-generation service health | fresh health observer |

Create and replace follow:

```text
requested
  -> preflighted
  -> encrypted
  -> delivered
  -> materialized
  -> reloaded
  -> healthy
  -> active
```

After encryption and before activation, a checked failure may follow:

```text
... -> rolling_back -> rolled_back
```

Remove follows:

```text
requested
  -> preflighted
  -> detach_requested
  -> detached
  -> revoked
  -> removing
  -> removed
  -> quarantined
  -> destroyed
```

`failed` records both the exact phase that was attempted and how failure became
authoritative. `reported` is written only by the component that owns that
phase. `timed_out` is written only by Janus after a reviewed, server-owned
phase deadline expires; browsers and peers cannot choose or shorten deadlines.
This lets Janus close an operation when a host, health observer, Pharos, or
nixcfg is silent without pretending that the silent component reported its own
failure. Failure may name a terminal target such as `active`, `rolled_back`, or
`destroyed` when that final transition itself failed.

Completed terminal states cannot be advanced, and a late response after a
timeout cannot revive the operation. Cancellation is available only before a
declaration is detached; after detach, recovery must explicitly reconcile the
detached/revoked state instead of presenting a misleading clean cancellation.

The operation ref is the idempotency key. An exact duplicate request resolves
to the same durable operation and evidence; reuse with different bindings must
fail closed. A retry resumes the same non-terminal operation from its last
durable authoritative phase or starts a new operation with a new setup intent.
It never rewrites or deletes earlier evidence.

## Trust boundaries

### Browser

The browser will eventually carry plaintext only for a deliberate bounded
import after fresh passwordless step-up. This v1 shared contract never contains
the value. Values must not enter URLs, redirects, browser storage, rendered
responses, logs, traces, metrics, or audit. There is no reveal contract.

### Pharos

Pharos may request and observe an operation. It never receives plaintext,
ciphertext, host keys, Janus permits, backend paths, runtime files, or command
output. A Pharos `requested` fact is not an `executed` or `verified` fact.

### Janus

Janus owns encrypted custody, policy, lifecycle, audit, and activation. It may
not fabricate host delivery, runtime materialization, reload, or fresh service
health. Network-facing code must not expose a general admin or resolve API.

### Host executor

The executor is bound to one enrolled host and reviewed service/slot profiles.
It may not choose paths, commands, secret refs, destinations, or health rules.
Copying an operation or encrypted envelope to another host must fail.

### nixcfg and Nix

nixcfg declares value-free service slots and fixed profile references. Secret
values and plaintext runtime artifacts never enter Git, Nix evaluation, or the
Nix store. A merged declaration does not prove deployment.

### AI agents

Agents may see the same value-free references and phases as other orchestration
clients. They receive no value-bearing method and cannot select a destination.

### Replay

Setup intents are single-use, nonce-bound, action-bound, bound to the
declaration's complete reviewed source policy, tied to one human session and
declaration fingerprint, and accepted only when the request event is inside the
intent's half-open validity window. Janus binds the exact human-selected source
to the fresh passkey proof before consumption. Operation refs make exact
retries idempotent; changing that source or any other binding under the same
intent or operation ref fails closed. Late evidence cannot advance a terminal
operation.

### Logging and observability

Logs, traces, metrics, audit, errors, and UI status may contain only the closed
reason vocabulary, opaque refs, timestamps, source mode, and value-free phase
metadata. They must not contain request bodies, values, ciphertext, filesystem
paths, commands, callback URLs, or command output. Evidence carries explicit
`value_returned=false` and `request_body_returned=false` invariants.

### Compromised host

Host-specific encryption limits accidental cross-host disclosure but cannot
make a compromised host safe while it legitimately consumes a secret.
Retirement, key rotation, revocation, evidence, and secret replacement limit
the duration and blast radius; they do not erase this boundary.

## References and minimization

Authority uses domain-separated opaque refs (`host_`, `svc_`, `slot_`,
`delivery_`, `reload_`, `health_`, `intent_`, `hsn_`, `sys_`, `nonce_`,
`op_`, `sec_`, `gen_`, `evt_`, `decl_`) rather than raw names, paths, or URLs.
Safe display labels are bounded, trimmed, and reject control, bidirectional,
zero-width, and non-ordinary whitespace characters, but are never authority.
Reason codes use a closed lowercase vocabulary.

The setup intent names an allowlisted return target, not a callback URL. It
binds the exact action and complete reviewed source policy as well as host,
service, slot, human session, issuer, audience, nonce, declaration fingerprint,
and a maximum five-minute lifetime. Create and replace require one or more
canonical allowed sources; remove forbids them. The exact create/replace source
is selected in Janus, bound to fresh passwordless proof, and then copied into
the operation.

An operation binds the exact setup intent, declaration fingerprint, secret ref,
source mode, and delivery generation in addition to its host, service, and slot
refs. A generation is allocated when encryption succeeds; a failure while
attempting encryption therefore has no generation, while every subsequent
create/replace phase or failure does. Remove always identifies the generation
being retired. Create and replace require an explicit reviewed source; remove
forbids one. Operation and evidence documents require
`value_returned=false`; evidence also requires `request_body_returned=false`.
The canonical fixture includes the complete successful multi-authority event
sequence, not only Janus's final activation statement.

## Evolution

All wire documents reject unknown fields and unsupported schema versions. A
control plane may accept its own contract version and exactly its immediate
predecessor during a control-plane-first rolling upgrade. V1 therefore accepts
only v1. New consumer or delivery semantics require a new reviewed version;
unknown enum values never degrade into the current behavior.

Future mounted-file, certificate, provider-credential, CI, or manually managed
consumer work should extend the generic consumer/delivery/source vocabulary.
The current UI must not advertise those choices before their complete contract
and security behavior exists.

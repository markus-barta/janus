# Break-glass emergency-use runbook

Break glass is a loud, separately approved way to perform one exact reviewed
`managed_run.use` or `env_file.use` action during an incident. The
`break_glass_admin` role is only an eligibility marker: it has no normal
permission and never becomes a permanent administrator role.

## Safety contract

Every request fixes the eligible beneficiary identity, exact opaque scope,
action, secret reference supplied by the reviewed profile, private incident
reason, and an expiry of at most 15 minutes.

The activator, beneficiary, and approver must be different principal chains.
The eventual user must be the beneficiary. One admitted attempt consumes the
activation, even if execution later fails or the process is interrupted.
Revocation and expiry survive restart and recovery restore.

Break glass cannot reveal a raw value, suppress audit, grant role or custody
authority, broaden a reviewed profile, cross scope, or make itself permanent.
Every request, approval, denial, admitted attempt, completion, revocation, and
review writes critical value-free audit evidence. If that audit write fails,
the operation fails closed.

## Required runtime state

Use explicit enforced role authorization and private durable paths:

```bash
export JANUS_ROLE_AUTHORIZATION_MODE=enforced
export JANUS_ROLE_BINDINGS_ROOT=/var/lib/janus/role-bindings
export JANUS_BREAK_GLASS_ROOT=/var/lib/janus/break-glass
export JANUS_ROLE_AUDIT_FILE=/var/log/janus/authorization.jsonl
```

The break-glass directory must be `0700`; immutable records are `0600`. Include
`break_glass_state` in every reviewed recovery manifest. The postflight parser
rejects corrupt, unknown, orphaned, duplicated, symlinked, or publicly readable
records.

The normal approved-use profile, Age provider, permit registry, exact scope,
release admission, migration, recovery-freshness, and retention settings remain
required. Emergency authority does not bypass those controls.

## Operator flow

1. A security administrator creates a short request for an existing active
   `break_glass_admin` eligibility binding:

```bash
janusd-admin break-glass request \
  --eligibility-binding rbd_... \
  --permission managed_run.use \
  --target-ref sec_... \
  --reason "incident INC-..." \
  --expires-in-seconds 300
```

Use `env_file.use` for an env-file action. Other permissions are rejected.

2. A separate approver approves the returned request before it expires:

```bash
janusd-admin break-glass approve --request bgr_...
```

3. The eligible beneficiary performs the one exact action. The reviewed
   profile supplies the target, executor, destination, arguments, and output
   path:

```bash
janusd-use run \
  --profile profile.REVIEWED \
  --break-glass-activation bga_... \
  -- REVIEWED ARGUMENTS

# Or:
janusd-use env-file \
  --profile profile.REVIEWED \
  --break-glass-activation bga_...
```

Supplying both `--permit` and `--break-glass-activation` is rejected. Preflight
never accepts an activation.

4. Inspect state or revoke unused authority:

```bash
janusd-admin break-glass list
janusd-admin break-glass status --activation bga_...
janusd-admin break-glass revoke \
  --activation bga_... \
  --reason "incident contained"
```

5. After an admitted action, an independent auditor records findings,
   remediation, and a terminal closure. The reviewer cannot be the activator,
   approver, or beneficiary:

```bash
janusd-admin break-glass review \
  --activation bga_... \
  --findings "exact reviewed action only" \
  --remediation "none required" \
  --closure closed_no_findings
```

Use `closed_remediated` only after the stated remediation has been completed.
An admitted attempt without completion evidence remains visibly
`review_required`; it is never silently reusable.

## Evidence and recovery

Keep opaque IDs, scope/action/target metadata, timestamps, status, findings,
remediation, closure, and the critical audit chain. Never copy raw secret
values, principal claim material, private reasons, permit contents, or rendered
env-file contents into tickets or chat.

Recovery deliberately excludes portable use permits but restores
`break_glass_state`. Postflight validates the restored registry before runtime
admission, so an expired or revoked activation cannot become active again.

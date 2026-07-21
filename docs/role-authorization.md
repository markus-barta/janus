# Role authorization contract

Janus authorization is default-deny. Roles come only from a checked binding
source; a role or claim supplied by the caller is never authority. The shared,
versioned matrix is `config/authorization/role-matrix-v1.json`, and
`janus-core` rejects any snapshot that broadens the immutable code ceiling.

## Role boundaries

| Role | Intended authority | Hard boundary |
| --- | --- | --- |
| `viewer` | Value-free descriptors, health, lifecycle posture | No use or mutation |
| `operator` | Reviewed normal secret-use paths | No approval, policy, custody, or broadening |
| `owner` | Lifecycle, recovery, migration, retention, and exact delegation | No normal secret use or approval |
| `approver` | Exact approval issue, permit, read, and revoke | No execution or policy administration |
| `auditor` | Value-free evidence and policy inspection | No secret use or mutation except independent review |
| `security_admin` | Role bindings, authorization policy, emergency workflow administration | No secret use or backend custody |
| `break_glass_admin` | Eligibility marker only | No ordinary permission; an exact activation is still required |
| `service_admin` | Lifecycle administration for one exact service target | No untargeted or cross-target authority |
| `workload_admin` | Lifecycle administration for one exact workload target | No untargeted or cross-target authority |

The permission vocabulary intentionally has no permission for audit
suppression, backend custody, arbitrary command execution, blanket reveal, or
cross-scope bypass.

## Exact decision inputs

Every decision binds the current principal chain, opaque scope, action, time,
optional exact service/workload target, current owner fingerprint, secret class
and lifecycle, approval/delegation fingerprints, audit posture, and recorded
duties. Missing, expired, cross-scope, malformed, or ambiguous facts deny.

Service and workload administrator bindings are invalid without one exact
target. Other roles cannot carry a target constraint. Policy snapshots may
remove a permission from a role, but cannot add one outside its compiled
ceiling.

## Separation of duties

The following same-actor loops are hard denials within one exact scope:

- request and approve the same use;
- approve and execute the same use;
- grant and receive the same delegation;
- grant and receive a role, or change policy for personal benefit;
- activate and approve or use the same break-glass grant;
- use and review the same break-glass grant;
- operate and review the same recovery.

Decisions and their JSON/debug representations contain only closed vocabulary,
opaque references/fingerprints, and stable reason codes. Every checked action
must write audit evidence; an unavailable audit sink blocks the action.

The separate emergency lifecycle, one-action execution path, recovery rules,
and mandatory independent closure are documented in the
[break-glass runbook](break-glass-runbook.md).

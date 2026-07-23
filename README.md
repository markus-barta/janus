# Janus

**Govern secrets without turning people or AI agents into secret couriers.**

Janus is the INSPR governance and approved-use layer for credentials. It keeps
secret values behind a policy boundary, gives consumers opaque references and
single-use permits, emits value-free audit events, and persists value-free
lifecycle evidence on supported operator paths.

The result is one deliberate control plane for services, operators, and AI
agents - without making raw credentials part of prompts, command arguments,
logs, or application code.

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-1f7a72.svg)](LICENSE)
[![Rust engine](https://img.shields.io/badge/Rust_engine-v0.1.10-cb7c28.svg)](https://github.com/markus-barta/janus/releases/tag/rust-engine-v0.1.10)

[Product site](https://janus.inspr.at) ·
[Rust engine v0.1.10](https://github.com/markus-barta/janus/releases/tag/rust-engine-v0.1.10) ·
[INSPR](https://www.inspr.at)

## What Janus does

- **Reference-only discovery** - Warden exposes `SecretRef` metadata over MCP,
  never secret literals.
- **Policy-gated use** - approvals and short-lived, single-use `UsePermit`
  handles bind a secret to a reviewed purpose, executor, destination, and
  profile.
- **Managed execution** - `janusd-use run` launches exact reviewed commands and
  arguments without handing the credential back to the caller.
- **Private service handoff** - `janusd-use env-file` renders reviewed `0600` env
  files and optional value-free hash sidecars atomically.
- **Generated rotation** - Forge creates replacement values internally and can
  run reviewed validation and reload hooks. There is deliberately no
  caller-supplied `--value` argument.
- **Lifecycle evidence** - state transitions, stale reports, destroy
  tombstones, finalization, and reconciliation remain value-free.
- **Pharos retirement** - a declared host-retirement flow disables approved
  use, quarantines generated outputs, and records durable evidence.
- **Pharos verifier generations** - every beacon-token render publishes a
  value-free, immutable generation plus an atomic `current` pointer; concurrent
  renders are serialized and retirement publishes host removal before it can
  complete.
- **Backend portability** - the core contract is provider-neutral; the current
  self-hosted path uses native age encryption and secretspec allowlists.
- **Split process planes** - `janusd-use` can consume permits but cannot
  administer Janus; `janusd-admin` can administer Janus but cannot consume a
  permit or render a secret-bearing output.

## The boundary that matters

Janus is designed around one rule:

> A model or untrusted caller may name an approved capability. It must not
> receive the credential that powers it.

That rule is reflected in the API and runtime:

1. Warden lists and describes opaque references.
2. Policy evaluates a concrete purpose and reviewed profile.
3. When the policy class requires approval, Janus validates an exact grant.
4. Policy issues a bounded permit.
5. The executor consumes the permit once.
6. The credential is injected only inside the approved-use boundary.
7. Output and evidence contain outcomes, references, and reason codes - never
   the raw value.

Janus does not claim that software can erase every operational risk. Host
access, backend custody, profile review, and deployment hardening still matter.
What it does is make the credential boundary explicit, testable, and much
harder to bypass accidentally.

## Project status

Janus has two layers with different histories:

| Layer | Role | Language | Status |
|---|---|---|---|
| **Rust engine** | Secret store contracts, Warden, permits, approved-use execution, rotation, lifecycle, and operator CLI | Rust | Active and released. Current tag: `rust-engine-v0.1.10`. |
| **Go envelope** | Existing governance, audit, evidence, and oversight surface | Go | Shipped, operational, and transitional. New core capability work lands in Rust. |

The Rust engine is no longer a skeleton. Core execution paths ship with unit,
conformance, MCP, operator-flow, and container smoke tests. The project is
still pre-1.0: interfaces and deployment contracts may evolve as the Rust
engine absorbs the remaining envelope responsibilities.

## Architecture

```text
consumer / operator / AI agent
              |
              v
      Warden reference surface
              |
       policy + approval
              |
       opaque UsePermit
              |
              v
 janusd-use approved-use executor
              |
       reviewed profile
              |
              v
     SecretStore provider
```

### Workspace map

```text
crates/
  janus-core/          contracts, opaque handles, policy, and evidence
  janus-conformance/   reusable provider contract tests
  janus-executor/      permit consumption and approved-use execution
  janus-provider-age/  native age-backed encrypted store
  janus-providers/     provider adapters
  janus-local/         local runtime integrations
  janus-warden/        reference-only MCP server
  janus-forge/         generated rotation and reviewed hooks
  janus-mock/          in-memory test provider
  janusd/              hard-separated use and administration runtimes
go-envelope/           shipped transitional Go envelope
docs/                  focused operator and cutover runbooks
examples/              checked non-production handoff fixtures
scripts/               release assurance and smoke tests
```

Canonical architecture decisions live in PPM project **JANUS** at
`pm.barta.cm`, not as parallel design documents in this repository. Useful
entries include:

- `guideline/architecture-v1`
- `guideline/backend-decision`
- `guideline/rust-engine-assurance-scope-recovery`
- `guideline/repo-topology-adr`
- `guideline/where-janus-lives`

Fetch an entry with:

```bash
paimos knowledge get guideline architecture-v1 --project JANUS
```

## Build and test

Use the repo-local development shell:

```bash
direnv allow
direnv exec . cargo test --workspace --locked
```

Or enter it explicitly:

```bash
devenv shell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

On a supported Linux system, build the native Nix package:

```bash
nix build .#janus-engine
```

The package installs `janusd-use`, `janusd-admin`, `janus-warden`, and the
non-operational `janusd` migration helper for supported Linux systems. The
legacy helper cannot run either plane's commands.

### Release assurance

Run the Rust behavioral and process-plane assurance with:

```bash
devenv shell -- ./scripts/assure-engine-release.sh
```

It exercises:

- the locked Rust workspace test suite;
- the strict cross-surface minimization contract, bounded runner, and
  synthetic-canary diagnostics;
- the bounded security-property gate and its value-free replay receipt;
- a real reference-only Warden MCP session;
- the hard use/admin process boundary and retired mixed entry point;
- the approval-to-env-file operator flow;
- the versioned approval-registry migration and rollback flow;
- the exact-scope recovery and explicit boundary-transfer flow;
- the exact, single-use break-glass lifecycle and independent review flow;
- the Pharos beacon retirement flow.

That script does not run formatting, strict Clippy, or a Docker image build.
Run the complete local release-candidate gate with:

```bash
devenv shell -- cargo fmt --all -- --check
devenv shell -- cargo clippy --all-targets --all-features -- -D warnings
devenv shell -- ./scripts/assure-engine-release.sh
devenv shell -- ./scripts/smoke-engine-container.sh
devenv shell -- env JANUS_SECURITY_IMAGE=janus-engine:smoke ./scripts/run-security-gates.sh
```

The container smoke builds the engine image and requires a working Docker CLI
and daemon. It verifies the scratch filesystem (no runtime package database or
shell), exact numeric non-root identity, four installed static binaries,
read-only/capability-free/no-new-privileges/network-isolated execution, and
value-free Warden MCP behavior. The security gate adds pinned Cargo Audit,
Gitleaks, staticcheck, govulncheck, immutable-base verification, and Trivy. The
gate probes the actual local scanner invocations and fails before scanning when
any binary version differs from the reviewed policy. CI repeats that check on
every runner that installs a scanner, including fresh release-image runners.
Every external GitHub Action, including GitHub-owned Actions, is pinned to a
full commit SHA with its reviewed release beside it. The required security job
rejects mutable, shortened, dynamic, or undocumented Action references, and
weekly Dependabot pull requests provide the reviewed update path.
The default branch also has
[CodeQL merge protection](docs/codeql-merge-protection.md): security findings
of medium severity or higher and non-security errors or warnings block merges
independently of the required CodeQL status checks.
The behavioral assurance script is intentionally not presented as the complete
release gate; formatting, strict Clippy, container, and scanner checks remain
separate commands above and are combined by release CI.

When a novel security property fails, CI preserves a seven-day replay artifact
containing only its reviewed target, bounded budget, opaque RNG seed, and
derived replay identity. Download it with
`gh run download RUN_ID --name rust-property-replay --dir .tmp`, then run
`python3 scripts/run-security-properties.py --replay
.tmp/janus-property-replay.json`. The full handling contract lives in PPM
Knowledge at `runbook/security-property-replay`; do not copy raw generated test
diagnostics into logs or tickets.

Rust engine releases publish a GHCR image, SPDX SBOM, build provenance, a
keyless image signature, and a second keyless signature over a deterministic
source/tag/commit/image-digest manifest. Direct and merge commits are not
individually signed: the defined signed-source subset is the two released tag
families, with pre-policy releases grandfathered and no history rewrite.
The machine-enforced cutoff is `2026-07-22T14:00:17Z`. The only unsigned
pre-policy release that remains admissible is `go-envelope-v1.162` at its exact
tag, commit, and publication timestamp. Earlier Go and Rust releases remain
published history but are superseded and outside the admissible policy;
date-only interpretation is rejected.
Release CI scans, verifies, and smokes the exact digest it publishes.
Production and enterprise deployment admission is documented in
[Trusted release admission](docs/release-admission.md).
The reviewed offline schema upgrade is documented in the
[approval registry migration runbook](docs/migration-runbook.md).
That runbook also covers value-free scope-state recovery and transfer; encrypted
provider payload and key-custody disaster recovery remain separate concerns.

The transitional envelope remains independently testable:

```bash
cd go-envelope
go build ./...
go test ./...
cd ..
python3 scripts/run-minimization-proof.py --stack go
```

The reviewed surface inventory and only two allowed plaintext sinks live in
`config/assurance/minimization-proof-v1.json`. The runner rejects unknown
fields, missing proof IDs, uncovered surfaces, broadened sinks, arbitrary
commands, stale review dates, unresolved selectors, oversized output, and
timeouts without printing captured test or process output.

## Operator paths

Janus keeps caller input intentionally small. Profiles own the sensitive
bindings: secret reference, executor, destination, command, exact arguments,
environment name, output path, and consumer metadata.

Secret-bearing runtimes also require one canonical exact scope:

```bash
export JANUS_SCOPE_ORGANIZATION=acme
export JANUS_SCOPE_PROJECT=payments
export JANUS_SCOPE_REPOSITORY=payments-api
export JANUS_SCOPE_ENVIRONMENT=prod
```

Optional `JANUS_SCOPE_NAMESPACE` and `JANUS_SCOPE_WORKLOAD` refine the leaf
(workload requires namespace). Janus exposes only the derived opaque
`scp_...` reference, and never treats a parent or neighboring path as
authorized.

### Managed command

Preflight an executable and its exact argument vector without reading a
secret or consuming a permit:

```bash
janusd-use run preflight --profile profile.deploy -- release apply
```

After reviewed approval, consume the permit once:

```bash
janusd-use run --profile profile.deploy --permit use_... -- release apply
```

Claude Code can route this exact permit-bound shape while blocking raw secret
references in arbitrary tools. See
[`docs/claude-code-hooks.md`](docs/claude-code-hooks.md) for installation,
verification, and rollback.

### Service env file

Preflight the reviewed destination:

```bash
janusd-use env-file preflight --profile profile.deploy-env
```

Render it with a single-use permit:

```bash
janusd-use env-file --profile profile.deploy-env --permit use_...
```

The output path and environment variable come from the profile. Janus writes
the file atomically and privately, and reports only value-free outcome fields.
See [`docs/env-file-handoff-runbook.md`](docs/env-file-handoff-runbook.md) for
the complete checked flow.

### Exact-use delegation

An already-authorized principal can delegate one exact reviewed normal-use
path to one distinct human/agent/workload chain for up to one hour. Warden
accepts only the opaque `dlg_...` id in addition to its normal `request_use`
fields; `janusd-use` reloads and revalidates the grant immediately before the
secret read, so revoke and expiry also stop permits issued earlier. See the
[`exact-use delegation runbook`](docs/delegation-runbook.md) for issuance,
identity environment variables, inspection, revocation, and failure triage.

### Generated rotation

```bash
janusd-admin forge rotate-generated \
  --secret CANARY \
  --reason JANUS-reviewed-rotation \
  --consumer-ref consumer.deploy \
  --validation deploy-smoke \
  --reload exec-hook:reload-deploy \
  --hook-manifest /etc/janus/forge-hooks.toml
```

Hook programs and arguments come from reviewed local configuration. Hook stdio
is discarded and the environment is cleared before Janus adds value-free
context.

### Lifecycle and retirement

Lifecycle commands update metadata and evidence; they do not silently delete
provider values. The reviewed sequence is documented in
[`docs/destroy-lifecycle-runbook.md`](docs/destroy-lifecycle-runbook.md).

For a declared Pharos host retirement:

```bash
janusd-admin pharos-beacon retire \
  --host ares \
  --disposition destroyed \
  --intent-file /etc/janus/pharos-retirement.toml \
  --metadata-file /etc/janus/metadata.toml \
  --profile-manifest /etc/janus/approved-use.toml \
  --state-dir /var/lib/janus/pharos-retirements
```

Use `janusd-admin pharos-beacon reconcile` with the same host, disposition, intent,
metadata, profile-manifest, and state-directory controls to inspect interrupted
or drifted retirements without reading secret material.

Pharos beacon-token profiles use the
`pharos-beacon-token-generation-v2` hash-sidecar format. Janus writes a
per-host value-free entry, updates the immutable generation under an exclusive
lock, and advances `current` only after the generation is durable. Consumers
must read the pointed generation as one snapshot and fail closed when the
pointer, payload, schema, or generation digest is invalid.

## Contributing

Janus is security-sensitive infrastructure. Small, reviewable changes beat
clever shortcuts.

Before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

When a change touches an operator path, extend the corresponding smoke test and
assert that fixture secret values cannot appear in captured output.

## License

Janus is free and open-source software licensed under
[`AGPL-3.0-only`](LICENSE).

You can run it, inspect it, modify it, and redistribute it under those terms.
If you modify Janus and let users interact with that version over a network,
AGPL section 13 requires an offer of corresponding source for that modified
version.

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
[![Rust engine](https://img.shields.io/badge/Rust_engine-v0.1.6-cb7c28.svg)](https://github.com/markus-barta/janus/releases/tag/rust-engine-v0.1.6)

[Product site](https://janus.inspr.at) ·
[Rust engine v0.1.6](https://github.com/markus-barta/janus/releases/tag/rust-engine-v0.1.6) ·
[INSPR](https://www.inspr.at)

## What Janus does

- **Reference-only discovery** - Warden exposes `SecretRef` metadata over MCP,
  never secret literals.
- **Policy-gated use** - approvals and short-lived, single-use `UsePermit`
  handles bind a secret to a reviewed purpose, executor, destination, and
  profile.
- **Managed execution** - `janusd run` launches exact reviewed commands and
  arguments without handing the credential back to the caller.
- **Private service handoff** - `janusd env-file` renders reviewed `0600` env
  files and optional value-free hash sidecars atomically.
- **Generated rotation** - Forge creates replacement values internally and can
  run reviewed validation and reload hooks. There is deliberately no
  caller-supplied `--value` argument.
- **Lifecycle evidence** - state transitions, stale reports, destroy
  tombstones, finalization, and reconciliation remain value-free.
- **Pharos retirement** - a declared host-retirement flow disables approved
  use, quarantines generated outputs, and records durable evidence.
- **Backend portability** - the core contract is provider-neutral; the current
  self-hosted path uses native age encryption and secretspec allowlists.

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
| **Rust engine** | Secret store contracts, Warden, permits, approved-use execution, rotation, lifecycle, and operator CLI | Rust | Active and released. Current tag: `rust-engine-v0.1.6`. |
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
  janusd approved-use executor
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
  janusd/              approved-use runtime and operator CLI
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

The package installs both `janusd` and `janus-warden` for supported Linux
systems.

### Release assurance

Run the complete local gate with:

```bash
devenv shell -- ./scripts/assure-engine-release.sh
```

The complete gate requires a working Docker CLI and daemon in addition to the
tools supplied by the development shell.

It exercises:

- the locked Rust workspace test suite;
- a real reference-only Warden MCP session;
- the approval-to-env-file operator flow;
- the Pharos beacon retirement flow; and
- the engine container with the same value-free MCP assertions.

Rust engine releases publish a GHCR image, SPDX SBOM, build provenance, and a
keyless cosign signature. Release CI verifies and smokes the exact digest it
publishes.

The transitional envelope remains independently testable:

```bash
cd go-envelope
go build ./...
go test ./...
```

## Operator paths

Janus keeps caller input intentionally small. Profiles own the sensitive
bindings: secret reference, executor, destination, command, exact arguments,
environment name, output path, and consumer metadata.

### Managed command

Preflight an executable and its exact argument vector without reading a
secret or consuming a permit:

```bash
janusd run preflight --profile profile.deploy -- release apply
```

After reviewed approval, consume the permit once:

```bash
janusd run --profile profile.deploy --permit use_... -- release apply
```

### Service env file

Preflight the reviewed destination:

```bash
janusd env-file preflight --profile profile.deploy-env
```

Render it with a single-use permit:

```bash
janusd env-file --profile profile.deploy-env --permit use_...
```

The output path and environment variable come from the profile. Janus writes
the file atomically and privately, and reports only value-free outcome fields.
See [`docs/env-file-handoff-runbook.md`](docs/env-file-handoff-runbook.md) for
the complete checked flow.

### Generated rotation

```bash
janusd forge rotate-generated \
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
janusd pharos-beacon retire \
  --host ares \
  --disposition destroyed \
  --intent-file /etc/janus/pharos-retirement.toml \
  --metadata-file /etc/janus/metadata.toml \
  --profile-manifest /etc/janus/approved-use.toml \
  --state-dir /var/lib/janus/pharos-retirements
```

Use `janusd pharos-beacon reconcile` with the same host, disposition, intent,
metadata, profile-manifest, and state-directory controls to inspect interrupted
or drifted retirements without reading secret material.

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

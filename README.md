# Janus

The Inspire-family secrets/password **unification layer** — one brokered,
policy-gated, audited surface over your secrets for **services, users, and AI**
at once. secretspec-backed, vendor-neutral, runs from a laptop hobbyist install
to a big-corp fleet. Roman god of gates: one face to the consumer (service /
human / AI), one to the backend.

> **Canonical design & decisions live in PPM, not here.** This repo is code.
> The architecture, ADRs, and reference material are knowledge entries under
> PPM project **JANUS** (`pm.barta.cm`):
>
> - `guideline/architecture-v1` — the engineering design (the "how")
> - `guideline/backend-decision` — the storage-backend ADR (the "why we pivoted")
> - `guideline/repo-topology-adr` — repo + language ADR (why this repo exists)
> - `guideline/where-janus-lives` — the orientation map (three homes)
>
> Fetch e.g. `paimos knowledge get guideline architecture-v1 --project JANUS`.

## Status — envelope shipped, engine greenfield

Janus is being built in two layers, and they are at very different maturity:

| Layer | What | Language | State |
|---|---|---|---|
| **Envelope** | governance / audit / evidence / oversight plane | Go (REST) | **shipped & live** at `vault.barta.cm`, iterated V1.1→V1.146 by an autonomous loop. Brokers **no secret values** (`value_returned:false`). Lives in [`go-envelope/`](go-envelope/). |
| **Engine** | the secret-handling core: `SecretStore`, opaque handles, MCP warden, providers | **Rust** | **JANUS-14/21/22 slices landing** — async core contracts, mock/conformance, wrapped secretspec/dotenv, reference-only MCP stdio, and the first native age provider are in [`crates/`](crates/). Execution is next. |

**The plan (see `repo-topology-adr`):** build the missing engine fresh in Rust;
keep the Go envelope running and **frozen** (no rewrite); port/retire the
envelope into the Rust binary incrementally once the engine reaches parity. The
envelope is transitional, not throwaway — it is 144 iterations of working
oversight UX.

## Why Rust for the engine

It is a secret-handling security core (memory safety, zeroization, no-GC control
over secret material, constant-time comparisons), and the entire backend the
design already chose is Rust-native: **secretspec** (manifest = allowlist),
**age/rage** (self-host default key custody), and the official **MCP** Rust SDK
(`rmcp`) for the AI surface. Single static binary scales from laptop to fleet.

## Layout

```
janus/
├── crates/                  # the Rust engine (greenfield)
│   ├── janus-core/          # SecretStore trait, SecretRef/UsePermit, policy+audit  (JANUS-14, 28)
│   ├── janus-conformance/   # reusable SecretStore + broker contract battery       (JANUS-14)
│   ├── janus-mock/          # in-memory conformance/tracer backend                  (JANUS-14)
│   ├── janus-provider-age/  # native age encrypted-file SecretStore                 (JANUS-21)
│   ├── janus-warden/        # reference-only MCP surface (read side)                (JANUS-22)
│   ├── janus-forge/         # rotation/write broker — not MCP, not LLM-driven       (JANUS-219)
│   ├── janus-providers/     # wrapped secretspec adapter; OpenBao/keyring next      (JANUS-12)
│   └── janusd/              # the daemon that supersedes the envelope's serving
├── go-envelope/             # the shipped Go REST envelope (frozen, transitional)
├── docs/
│   └── extraction-cutover.md  # how to repoint the live nixcfg deploy at a published image
├── Cargo.toml               # Rust workspace
└── .github/workflows/       # rust CI + go-envelope build+sign+SBOM+provenance
```

## Build

Use the repo-local dev shell for local work:

```bash
direnv allow
direnv exec . cargo test --workspace --locked
# or: devenv shell -- cargo test --workspace --locked
```

**Engine (Rust):**
```bash
cargo build              # workspace build (skeleton until the engine tickets land)
cargo test --workspace --locked
cargo clippy --all-targets --all-features -- -D warnings
```

**Engine image:**
Publish a signed Rust engine image by creating a GitHub Release whose tag
matches `rust-engine-v*`:

```bash
gh release create rust-engine-v0.1.0 --target main \
  --title "Rust engine v0.1.0" \
  --notes "First signed Janus Rust engine image."
```

The release workflow pushes `ghcr.io/markus-barta/janus/janus-engine`, signs it
keyless with cosign, uploads an SPDX SBOM, and publishes build provenance.

**Envelope (Go):**
```bash
cd go-envelope
go build ./... && go test ./...
```

**Forge generated rotation (operator surface):**
```bash
janusd forge rotate-generated \
  --secret CANARY \
  --reason JANUS-28-reviewed-rotation \
  --consumer-ref consumer.deploy \
  --validation deploy-smoke \
  --reload exec-hook:reload-deploy \
  --hook-manifest /etc/janus/forge-hooks.toml
```

Hook manifests are reviewed local config. Programs must be absolute paths,
arguments are arrays, hook stdio is discarded, and the hook environment is
cleared before Janus adds value-free context variables.

```toml
[validation."deploy-smoke"]
program = "/usr/bin/true"
timeout_seconds = 30

[reload.exec_hook."reload-deploy"]
program = "/usr/local/libexec/janus/reload-deploy"
args = ["--service", "deploy"]
```

**Approved-use run handoff (JANUS-28):**
Warden issues opaque permits; `janusd run` consumes them through a local
single-use handoff directory. The directory is local to one host and is created
private (`0700`), with permit records written private (`0600`).

Both sides must agree on the identity and policy bindings:

```bash
export JANUS_PERMIT_DIR=/run/janus/permits
export JANUS_WARDEN_EXECUTOR=janus-run@csb1
export JANUS_RUN_EXECUTOR=janus-run@csb1
export JANUS_WARDEN_SCOPE=janus/prod
export JANUS_RUN_SCOPE=janus/prod
export JANUS_WARDEN_DESTINATION=deploy-api
export JANUS_RUN_PROFILE_MANIFEST=/etc/janus/managed-commands.toml
```

The managed command profile owns executor, destination, secret ref, binary, and
exact argv. Caller input supplies only the opaque permit id and candidate argv:

```toml
[[profiles]]
id = "profile.deploy"
secret_ref = "sec_deploy_token"
executor = "janus-run@csb1"
destination = "deploy-api"
env = "DEPLOY_TOKEN"
binary = "/usr/local/libexec/janus/deploy"
allowed_args = ["release", "apply"]

[profiles.consumer]
consumer_ref = "consumer.deploy"
owner = "janusd"
environment = "prod"
blast_radius = "deploy-api"
```

```bash
janusd run --profile profile.deploy --permit use_... -- release apply
```

The permit id is power-bearing and should not be logged casually. A copied or
stale permit still has to pass principal, executor, destination, profile, secret
ref, manifest membership, expiry, and audit checks before a value is read.

## Provenance

This repo was extracted from `nixcfg/hosts/csb1/docker/janus` with full history
(`git subtree split`, 2026-06-24). Public-repo hygiene applied:

- **License:** AGPL-3.0-only (matching the PAIMOS/INSPR family).
- **No infra inventory:** `agenix-catalog.json` (the deploy-time catalog of secret
  *names/sources/classifications*) was **scrubbed from all history** — it is not
  needed for the build (mounted at runtime from nixcfg) and is infra
  reconnaissance data that does not belong in a public repo.
- **No secret values, private keys, or `.age` files** are present — verified at
  extraction time and after the scrub. `bootstrap-zitadel-env.sh` only references
  env vars and *generates* secrets at runtime.

---

*History: extracted 2026-06-24 from nixcfg. Sits alongside **PAIMOS** and
**fleetcom** in the INSPR family.*

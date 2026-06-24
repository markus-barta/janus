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
| **Envelope** | governance / audit / evidence / oversight plane | Go (REST) | **shipped & live** at `vault.barta.cm`, iterated V1.1→V1.144 by an autonomous loop. Brokers **no secret values** (`value_returned:false`). Lives in [`go-envelope/`](go-envelope/). |
| **Engine** | the secret-handling core: `SecretStore`, opaque handles, MCP warden, providers | **Rust** | **greenfield** — being built in [`crates/`](crates/). The product the envelope has been waiting for. |

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
│   ├── janus-warden/        # reference-only MCP surface (read side)                (JANUS-22)
│   ├── janus-forge/         # rotation/write broker — not MCP, not LLM-driven       (JANUS-219)
│   ├── janus-providers/     # age/agenix, secretspec, OpenBao, OS keyring backends  (JANUS-21, 12)
│   └── janusd/              # the daemon that supersedes the envelope's serving
├── go-envelope/             # the shipped Go REST envelope (frozen, transitional)
├── docs/
│   └── extraction-cutover.md  # how to repoint the live nixcfg deploy at a published image
├── Cargo.toml               # Rust workspace
└── .github/workflows/       # rust CI + go-envelope build+sign+SBOM+provenance
```

## Build

**Engine (Rust):**
```bash
cargo build              # workspace build (skeleton until the engine tickets land)
cargo test --all
```

**Envelope (Go):**
```bash
cd go-envelope
go build ./... && go test ./...
```

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

# Janus

Inspire-family LLM-vault connector. Read-only by design; rotation is the
job of a separate sibling (Janus-Forge, future).

## Docs

- **Engineering design doc**: guideline `architecture-v0` in PAIMOS (https://pm.barta.cm)
- **High-level rationale**: `modules/janus/readme.md` in the `inspr` repo
- **Tracking epics**: `INSPR-180` (Janus-Warden), `INSPR-181` (Janus-Forge)

## Quick build

```bash
cargo build
cargo test --workspace
```

## Workspace layout

```
crates/
├── janus-core/         pure-lib traits + types (no backend deps)
├── janus-vaultwarden/  Vaultwarden / Bitwarden REST adapter (v1)
└── janus-mcp/          MCP server binary — the Janus-Warden surface
```

## Status

**v0 scaffold.** Open questions tracked in `architecture-v0 §13` (MCP SDK crate
choice, SIEM sink concretization, allowlist field naming, concealed-reveal
MFA, container base).

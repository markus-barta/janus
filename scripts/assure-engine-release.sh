#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

echo "==> janus engine release assurance: trusted release admission fixtures"
scripts/test-release-admission.sh

echo "==> janus engine release assurance: cargo tests"
cargo test --all --locked

echo "==> janus engine release assurance: build smoke binaries"
cargo build --locked -p janus-warden -p janusd

echo "==> janus engine release assurance: local Warden MCP smoke"
python3 scripts/smoke-warden-mcp.py --bin target/debug/janus-warden

echo "==> janus engine release assurance: local janusd env-file smoke"
JANUSD_BIN="${repo}/target/debug/janusd" scripts/smoke-janusd-env-file.sh

echo "==> janus engine release assurance: local janusd migration smoke"
JANUSD_BIN="${repo}/target/debug/janusd" scripts/smoke-janusd-migration.sh

echo "==> janus engine release assurance: local janusd scope-transfer smoke"
JANUSD_BIN="${repo}/target/debug/janusd" scripts/smoke-janusd-scope-transfer.sh

echo "==> janus engine release assurance: local Pharos retirement smoke"
JANUSD_BIN="${repo}/target/debug/janusd" scripts/smoke-janusd-pharos-retirement.sh

echo "==> janus engine release assurance: engine container Warden MCP smoke"
scripts/smoke-engine-container.sh

echo "ok: janus engine release assurance passed"

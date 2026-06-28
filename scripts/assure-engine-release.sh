#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

echo "==> janus engine release assurance: cargo tests"
cargo test --all --locked

echo "==> janus engine release assurance: local Warden MCP smoke"
python3 scripts/smoke-warden-mcp.py

echo "==> janus engine release assurance: local janusd env-file smoke"
scripts/smoke-janusd-env-file.sh

echo "==> janus engine release assurance: engine container Warden MCP smoke"
scripts/smoke-engine-container.sh

echo "ok: janus engine release assurance passed"

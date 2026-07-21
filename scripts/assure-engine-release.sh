#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

echo "==> janus engine release assurance: trusted release admission fixtures"
scripts/test-release-admission.sh

echo "==> janus engine release assurance: closed runtime endpoint policy matrix"
cargo test --locked -p janus-core runtime_endpoint_policy
cargo test --locked -p janus-warden endpoint_guard

echo "==> janus engine release assurance: bounded security properties"
python3 scripts/run-security-properties.py --self-test
python3 scripts/run-security-properties.py --release

echo "==> janus engine release assurance: minimization proof runner"
python3 scripts/run-minimization-proof.py --self-test

echo "==> janus engine release assurance: reviewed adversarial recovery corpus"
python3 scripts/run-adversarial-scenarios.py --self-test
python3 scripts/run-adversarial-scenarios.py

echo "==> janus engine release assurance: cargo tests"
cargo test --all --locked

echo "==> janus engine release assurance: build smoke binaries"
cargo build --locked -p janus-warden -p janusd

# Isolated fixtures have no durable operator binding registry. They must opt in
# explicitly to the only non-production compatibility posture; trusted product
# modes reject this value in the runtime loader.
export JANUS_ROLE_AUTHORIZATION_MODE="unsafe_disabled_dev"
export JANUS_PRODUCT_MODE="self_hosted"

echo "==> janus engine release assurance: runtime process-plane boundary smoke"
scripts/smoke-janusd-planes.sh

echo "==> janus engine release assurance: local Warden MCP smoke"
python3 scripts/smoke-warden-mcp.py --bin target/debug/janus-warden

echo "==> janus engine release assurance: split-plane env-file smoke"
JANUSD_USE_BIN="${repo}/target/debug/janusd-use" \
  JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" \
  scripts/smoke-janusd-env-file.sh

echo "==> janus engine release assurance: local janusd-admin migration smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-migration.sh

echo "==> janus engine release assurance: local janusd-admin scope-transfer smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-scope-transfer.sh

echo "==> janus engine release assurance: sealed clean-state recovery-drill smoke"
JANUSD_USE_BIN="${repo}/target/debug/janusd-use" \
  JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" \
  JANUS_WARDEN_BIN="${repo}/target/debug/janus-warden" \
  scripts/smoke-janusd-recovery-drill.sh

echo "==> janus engine release assurance: offline retention quarantine and purge smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-retention.sh

echo "==> janus engine release assurance: local janusd-admin lifecycle-entry smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-lifecycle-entry.sh

echo "==> janus engine release assurance: local janusd-admin lifecycle action queue smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-lifecycle-queue.sh

echo "==> janus engine release assurance: local Pharos retirement smoke"
JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-pharos-retirement.sh

echo "==> janus engine release assurance: cross-surface Rust minimization proof"
python3 scripts/run-minimization-proof.py --stack rust

echo "ok: janus engine release assurance passed"

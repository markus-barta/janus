#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

python3 scripts/check-action-pins.py --self-test
python3 scripts/smoke-warden-mcp.py --self-test
python3 scripts/check-security-gates.py --self-test
python3 scripts/check-security-gates.py --check-installed-tools
python3 scripts/test-docker-base-pins.py
python3 scripts/check-docker-base-pins.py
scripts/check-rust-audit.py --self-test
scripts/test-gitleaks.sh
(
  cd go-envelope
  go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
)

if [[ -n "${JANUS_SECURITY_IMAGE:-}" ]]; then
  report="$(mktemp)"
  summary="$(mktemp)"
  cleanup() { rm -f -- "${report}" "${summary}"; }
  trap cleanup EXIT
  trivy image --scanners vuln --format json --output "${report}" "${JANUS_SECURITY_IMAGE}"
  python3 scripts/check-security-gates.py --trivy-report "${report}" --summary "${summary}"
fi

echo "ok: local release-security parity gates passed"

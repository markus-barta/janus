#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${JANUS_ENGINE_SMOKE_IMAGE:-janus-engine:smoke}"

docker build -f "${repo}/Dockerfile.engine" -t "${image}" "${repo}"
python3 "${repo}/scripts/smoke-warden-mcp.py" --image "${image}"

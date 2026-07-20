#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${JANUS_ENGINE_SMOKE_IMAGE:-janus-engine:smoke}"

docker build -f "${repo}/Dockerfile.engine" -t "${image}" "${repo}"

python3 - "${image}" <<'PY'
import json
import subprocess
import sys

image = sys.argv[1]
metadata = json.loads(
    subprocess.check_output(["docker", "image", "inspect", image], text=True)
)[0]
config = metadata["Config"]
if config.get("User") != "janus":
    raise SystemExit(f"engine image must run as user janus, got {config.get('User')!r}")
if config.get("Entrypoint") != ["janusd-use"]:
    raise SystemExit(
        f"engine image must default to janusd-use, got {config.get('Entrypoint')!r}"
    )
if config.get("ExposedPorts") not in (None, {}):
    raise SystemExit(
        f"engine image must declare no exposed ports, got {config.get('ExposedPorts')!r}"
    )
print("engine image metadata ok user=janus entrypoint=janusd-use exposed_ports=none")
PY

docker run --rm --network none --entrypoint sh "${image}" -ceu '
  test "$(id -un)" = janus
  for binary in janusd janusd-use janusd-admin janus-warden; do
    command -v "${binary}" >/dev/null
  done
  for path in /run/janus/age /run/janus/permits /var/lib/janus/secrets; do
    test -d "${path}"
    test -w "${path}"
  done
  test -z "$(find /run/janus /var/lib/janus/secrets -perm -0002 -print -quit)"
  test ! -w /etc/janus/release-channels-v1.json
'

echo "engine image filesystem posture ok binaries=4 secret_state_world_writable=false"
python3 "${repo}/scripts/smoke-warden-mcp.py" --image "${image}"

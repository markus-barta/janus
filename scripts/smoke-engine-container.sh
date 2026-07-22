#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${JANUS_ENGINE_SMOKE_IMAGE:-janus-engine:smoke}"

docker build -f "${repo}/Dockerfile.engine" -t "${image}" "${repo}"

python3 - "${image}" <<'PY'
import json
import subprocess
import sys
import tarfile

image = sys.argv[1]
metadata = json.loads(
    subprocess.check_output(["docker", "image", "inspect", image], text=True)
)[0]
config = metadata["Config"]
if config.get("User") != "65532:65532":
    raise SystemExit(f"engine image must run as 65532:65532, got {config.get('User')!r}")
if config.get("Entrypoint") != ["/usr/local/bin/janusd-use"]:
    raise SystemExit(
        f"engine image must default to absolute janusd-use, got {config.get('Entrypoint')!r}"
    )
if config.get("ExposedPorts") not in (None, {}):
    raise SystemExit(
        f"engine image must declare no exposed ports, got {config.get('ExposedPorts')!r}"
    )

container = subprocess.check_output(["docker", "create", image], text=True).strip()
try:
    export = subprocess.Popen(["docker", "export", container], stdout=subprocess.PIPE)
    if export.stdout is None:
        raise SystemExit("docker export did not provide an image filesystem")
    members = {}
    with tarfile.open(fileobj=export.stdout, mode="r|*") as archive:
        for member in archive:
            members["/" + member.name.rstrip("/")] = member
    if export.wait() != 0:
        raise SystemExit("docker export failed")
finally:
    subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)

for binary in ("janusd", "janusd-use", "janusd-admin", "janus-warden"):
    path = f"/usr/local/bin/{binary}"
    member = members.get(path)
    if member is None or not member.isfile() or member.mode & 0o111 == 0:
        raise SystemExit(f"missing static executable: {path}")
    if (member.uid, member.gid) != (65532, 65532):
        raise SystemExit(f"wrong binary ownership: {path}")
for path in ("/run/janus/age", "/run/janus/permits", "/tmp", "/var/lib/janus/secrets"):
    member = members.get(path)
    if member is None or not member.isdir() or (member.uid, member.gid) != (65532, 65532):
        raise SystemExit(f"missing private state mount point: {path}")
for path in ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/env"):
    if path in members:
        raise SystemExit(f"runtime image must contain no shell/helper: {path}")
policy = members.get("/etc/janus/release-channels-v1.json")
if policy is None or not policy.isfile() or policy.mode & 0o022:
    raise SystemExit("release policy is absent or group/world writable")

print("engine image filesystem ok user=65532:65532 binaries=4 runtime_packages=0 shell=none")
PY

runtime=(
  docker run --rm
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --network none
  --user 65532:65532
  --tmpfs /tmp:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=0700
  --tmpfs /run/janus/age:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=0700
  --tmpfs /run/janus/permits:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=0700
  --tmpfs /var/lib/janus/secrets:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=0700
)
for binary in janusd janusd-use janusd-admin; do
  "${runtime[@]}" --entrypoint "/usr/local/bin/${binary}" "${image}" --help >/dev/null
done

echo "engine hardened runtime ok read_only=true cap_drop=ALL no_new_privileges=true network=none"
python3 "${repo}/scripts/smoke-warden-mcp.py" --image "${image}"

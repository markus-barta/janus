#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-scope-transfer-smoke.XXXXXX")"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping scope-transfer fixture at %s\n' "${tmp}" >&2
    return
  fi
  find "${tmp}" -depth -delete
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

runtime="${tmp}/runtime"
source_root="${runtime}/source"
target_root="${runtime}/target"
state_root="${runtime}/transfer-state"
audit_dir="${runtime}/audit"
audit_path="${audit_dir}/events.jsonl"
manifest="${runtime}/scope-transfer.json"
log="${runtime}/scope-transfer.log"

mkdir -p "${source_root}" "${target_root}" "${audit_dir}"
chmod 700 "${runtime}" "${source_root}" "${target_root}" "${audit_dir}"
: >"${log}"
chmod 600 "${log}"

SOURCE_ROOT="${source_root}" TARGET_ROOT="${target_root}" STATE_ROOT="${state_root}" \
AUDIT_PATH="${audit_path}" python3 - "${manifest}" <<'PY'
import hashlib
import json
import os
import pathlib
import struct
import sys

def field(value):
    data = value.encode()
    return struct.pack(">Q", len(data)) + data

def scope_ref(environment):
    encoded = b"".join([
        field("janus-scope-v1"),
        field("fixture-org"),
        field("janus"),
        field("janus"),
        field(environment),
        b"\x00",
        b"\x00",
    ])
    return "scp_" + hashlib.sha256(encoded).hexdigest()[:40]

def secret_ref(scope, name):
    encoded = b"janus-secret-ref-v2\0" + scope.encode() + b"\0" + name.encode()
    return "sec_" + hashlib.sha256(encoded).hexdigest()[:20]

source_scope = scope_ref("dev")
destination_scope = scope_ref("prod")
database_ref = secret_ref(source_scope, "database-password")
retired_ref = secret_ref(source_scope, "retired-token")
bundle = {
    "schema_version": 1,
    "scope_ref": source_scope,
    "records": [
        {
            "secret_name": "database-password",
            "secret_ref": database_ref,
            "class": "high_value",
            "owner": "team-platform",
            "lifecycle": "active",
            "declared_at_unix_secs": 100,
            "last_used_at_unix_secs": 200,
            "last_rotated_at_unix_secs": 150,
            "consumers": [{
                "consumer_ref": "con_database",
                "secret_ref": database_ref,
                "scope_ref": source_scope,
                "kind": "service",
                "owner": "team-platform",
                "environment": "dev",
                "declared": True,
            }],
        },
        {
            "secret_name": "retired-token",
            "secret_ref": retired_ref,
            "class": "break_glass",
            "owner": "team-security",
            "lifecycle": "destroyed",
            "declared_at_unix_secs": 50,
            "tombstone": {
                "reason": "reviewed retirement",
                "destroyed_at_unix_secs": 300,
                "retain_until_unix_secs": 600,
                "principal_binding": "source evidence binding",
            },
            "consumers": [],
        },
    ],
    "approvals": [{
        "approval_id": "appr_fixture",
        "scope_ref": source_scope,
        "secret_ref": database_ref,
        "profile_id": "profile.database",
        "executor": "janusd",
        "destination": "database-service",
        "class": "high_value",
        "egress": "connector",
        "purpose": "reviewed transfer fixture",
        "expires_at_unix_secs": 4102444800,
        "expires_at_subsec_nanos": 0,
        "reason": "reviewed fixture",
    }],
    "permit_count": 2,
}
source = pathlib.Path(os.environ["SOURCE_ROOT"]) / "scope-state.json"
source.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
source.chmod(0o600)
manifest = {
    "schema_version": 1,
    "operation_id": "smoke-dev-to-prod",
    "mode": "boundary_changing_transfer",
    "source_scope_ref": source_scope,
    "destination_scope": {
        "schema_version": 1,
        "organization": "fixture-org",
        "project": "janus",
        "repository": "janus",
        "environment": "prod",
    },
    "expected_destination_scope_ref": destination_scope,
    "source_inventory_fingerprint": "sha256:" + "0" * 64,
    "expected_target_fingerprint": "sha256:" + "0" * 64,
    "source_root": os.environ["SOURCE_ROOT"],
    "target_root": os.environ["TARGET_ROOT"],
    "state_root": os.environ["STATE_ROOT"],
    "audit_path": os.environ["AUDIT_PATH"],
    "minimum_free_bytes": 0,
    "preflight_max_age_seconds": 900,
}
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

if [ -z "${JANUSD_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_bin="${JANUSD_BIN:-${repo}/target/debug/janusd}"
[ -x "${janusd_bin}" ] || fail "janusd binary is not executable"

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="prod"

discovery="$(${janusd_bin} scope-transfer status --manifest "${manifest}" 2>&1)" || {
  printf '%s\n' "${discovery}" >>"${log}"
  fail "scope-transfer fingerprint discovery failed"
}
printf '%s\n' "${discovery}" >>"${log}"
source_fingerprint="$(printf '%s\n' "${discovery}" | tr ' ' '\n' | sed -n 's/^source_inventory_fingerprint=//p')"
target_fingerprint="$(printf '%s\n' "${discovery}" | tr ' ' '\n' | sed -n 's/^target_fingerprint=//p')"
[ -n "${source_fingerprint}" ] || fail "source fingerprint was not discovered"
[ -n "${target_fingerprint}" ] || fail "target fingerprint was not discovered"

SOURCE_FINGERPRINT="${source_fingerprint}" TARGET_FINGERPRINT="${target_fingerprint}" \
  python3 - "${manifest}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["source_inventory_fingerprint"] = os.environ["SOURCE_FINGERPRINT"]
manifest["expected_target_fingerprint"] = os.environ["TARGET_FINGERPRINT"]
path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

run_transfer() {
  local operation="$1"
  local expected_phase="$2"
  local output
  if ! output="$(${janusd_bin} scope-transfer "${operation}" --manifest "${manifest}" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "scope-transfer ${operation} failed"
  fi
  printf '%s\n' "${output}" >>"${log}"
  printf '%s\n' "${output}" | grep -F "phase=${expected_phase}" >/dev/null ||
    fail "scope-transfer ${operation} did not report ${expected_phase}"
  printf '%s\n' "${output}" | grep -F 'value_returned=false' >/dev/null ||
    fail "scope-transfer ${operation} was not value-free"
}

run_transfer preflight preflighted
run_transfer apply applied
run_transfer postflight completed
run_transfer status completed

python3 - "${source_root}/scope-state.json" "${target_root}/scope-state.json" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if after["scope_ref"] == before["scope_ref"]:
    raise SystemExit("boundary transfer retained the source scope")
if after["approvals"] or after["permit_count"] != 0:
    raise SystemExit("boundary transfer retained portable authority")
for source, target in zip(before["records"], after["records"]):
    if source["secret_ref"] == target["secret_ref"]:
        raise SystemExit("boundary transfer retained a source SecretRef")
    for key in ["secret_name", "class", "owner", "lifecycle", "tombstone"]:
        if source.get(key) != target.get(key):
            raise SystemExit(f"boundary transfer changed restrictive metadata: {key}")
    for consumer in target.get("consumers", []):
        if consumer["secret_ref"] != target["secret_ref"] or consumer["scope_ref"] != after["scope_ref"]:
            raise SystemExit("boundary transfer left a dangling consumer reference")
PY

for action in scope_transfer.preflight scope_transfer.apply scope_transfer.postflight; do
  grep -F "\"action\":\"${action}\"" "${audit_path}" >/dev/null ||
    fail "audit evidence missing ${action}"
done
if grep -F "database-password" "${log}" "${audit_path}" >/dev/null 2>&1; then
  fail "private record metadata leaked into operator output or audit"
fi

run_transfer rollback rolled_back
run_transfer status rolled_back
[ ! -e "${target_root}/scope-state.json" ] || fail "rollback did not restore the empty target"
grep -F '"action":"scope_transfer.rollback"' "${audit_path}" >/dev/null ||
  fail "audit evidence missing scope_transfer.rollback"

printf 'ok: janusd scope-transfer smoke passed dev-to-prod rewrite, authority exclusion, postflight, and rollback value_returned=false\n'

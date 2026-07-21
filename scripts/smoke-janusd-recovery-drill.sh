#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

canary_value="SENSITIVE_RECOVERY_SMOKE_CANARY_MUST_NOT_ESCAPE"
profile_id="profile.CANARY"
executor="janus-run@fixture"
destination="recovery-fixture-service"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-recovery-drill-smoke.XXXXXX")"
tmp="$(cd "${tmp}" && pwd -P)"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping recovery-drill fixture at %s\n' "${tmp}" >&2
    return
  fi
  find "${tmp}" -depth -delete
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

extract_field() {
  local field="$1"
  sed -n "s/.*${field}=\([^ ]*\).*/\1/p"
}

run_logged() {
  local label="$1"
  shift
  local output
  if ! output="$("$@" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "${label} failed"
  fi
  printf '%s\n' "${output}" >>"${log}"
  printf '%s\n' "${output}"
}

expect_denied() {
  local label="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "${label} unexpectedly succeeded"
  fi
  printf '%s\n' "${output}" >>"${log}"
}

runtime="${tmp}/runtime"
source_root="${runtime}/source"
age_source="${source_root}/age_ciphertext"
metadata_source="${source_root}/metadata_overlay"
audit_source="${source_root}/audit_log"
approval_source="${source_root}/approvals"
delegation_source="${source_root}/delegations"
lifecycle_source="${source_root}/lifecycle_evidence"
tombstone_source="${source_root}/tombstones"
lifecycle_entry_source="${source_root}/lifecycle_entry"
admin_state_source="${source_root}/admin_state"
permit_source="${runtime}/permits"
bundle_root="${runtime}/bundle"
target_root="${runtime}/target"
state_root="${runtime}/state"
operation_dir="${runtime}/operation"
operation_audit="${operation_dir}/audit.jsonl"
evidence_dir="${runtime}/evidence"
evidence_path="${evidence_dir}/recovery.json"
config_dir="${runtime}/config"
manifest="${runtime}/recovery-drill.json"
secretspec="${config_dir}/secretspec.toml"
profiles="${config_dir}/approved-use.toml"
identity="${runtime}/recovery.identity"
wrong_identity="${runtime}/wrong.identity"
recipient_log="${runtime}/recipient.log"
wrong_recipient_log="${runtime}/wrong-recipient.log"
env_output="${runtime}/recovered.env"
log="${runtime}/recovery-drill.log"

mkdir -p \
  "${age_source}/janus/default" \
  "${approval_source}" \
  "${delegation_source}" \
  "${lifecycle_source}" \
  "${tombstone_source}" \
  "${lifecycle_entry_source}" \
  "${admin_state_source}" \
  "${permit_source}" \
  "${operation_dir}" \
  "${evidence_dir}" \
  "${config_dir}"
chmod 700 \
  "${runtime}" "${source_root}" "${age_source}" "${age_source}/janus" \
  "${age_source}/janus/default" "${approval_source}" "${delegation_source}" \
  "${lifecycle_source}" "${tombstone_source}" "${lifecycle_entry_source}" \
  "${admin_state_source}" "${permit_source}" "${operation_dir}" \
  "${evidence_dir}" "${config_dir}"
: >"${audit_source}"
: >"${log}"
chmod 600 "${audit_source}" "${log}"

python3 - "${secretspec}" "${metadata_source}" "${profiles}" "${env_output}" <<'PY'
import pathlib
import sys

secretspec, metadata, profiles, output = map(pathlib.Path, sys.argv[1:])
secretspec.write_text(
    '''[project]
name = "janus"
revision = "1.0"

[profiles.default]
CANARY = { description = "Recovery fixture active token", required = true }
DISABLED = { description = "Recovery fixture disabled token", required = true }
DESTROYED = { description = "Recovery fixture destroyed token", required = true }
''',
    encoding="utf-8",
)
metadata.write_text(
    '''[defaults]
owner = "security"
classification = "normal"
lifecycle = "active"

[[secrets]]
name = "CANARY"
classification = "break_glass"

[[secrets]]
name = "DISABLED"
lifecycle = "disabled"

[[secrets]]
name = "DESTROYED"
lifecycle = "destroyed"
''',
    encoding="utf-8",
)
profiles.write_text(
    f'''[[env_files]]
id = "profile.CANARY"
secret_ref = "PLACEHOLDER_SECRET_REF"
executor = "janus-run@fixture"
destination = "recovery-fixture-service"
env = "SERVICE_TOKEN"
output = "{output}"

[env_files.consumer]
consumer_ref = "consumer.recovery_fixture"
kind = "service"
owner = "security"
environment = "test"
reload = "none"
validation = ["recovery-fixture-env"]
supports_dual_value = false
blast_radius = "recovery-fixture"
''',
    encoding="utf-8",
)
for path in (secretspec, metadata, profiles):
    path.chmod(0o600)
PY

secret_ref="$(python3 - CANARY <<'PY'
import hashlib
import struct
import sys

def field(value):
    data = value.encode()
    return struct.pack(">Q", len(data)) + data

scope = "scp_" + hashlib.sha256(b"".join(field(value) for value in (
    "janus-scope-v1", "fixture-org", "janus", "janus", "dev"
)) + b"\0\0").digest()[:20].hex()
name = sys.argv[1]
print("sec_" + hashlib.sha256(
    b"janus-secret-ref-v2\0" + scope.encode() + b"\0" + name.encode()
).digest()[:10].hex())
PY
)"
[ -n "${secret_ref}" ] || fail "fixture secret ref was not derived"

SECRET_REF="${secret_ref}" python3 - "${profiles}" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    path.read_text(encoding="utf-8").replace("PLACEHOLDER_SECRET_REF", os.environ["SECRET_REF"]),
    encoding="utf-8",
)
path.chmod(0o600)
PY

age-keygen 2>"${recipient_log}" | \
  awk '/^AGE-SECRET-KEY-/ { print; found=1 } END { exit found ? 0 : 1 }' >"${identity}"
age-keygen 2>"${wrong_recipient_log}" | \
  awk '/^AGE-SECRET-KEY-/ { print; found=1 } END { exit found ? 0 : 1 }' >"${wrong_identity}"
recipient="$(sed -n 's/^Public key: //p' "${recipient_log}")"
[ -n "${recipient}" ] || fail "fixture recipient was not generated"
chmod 600 "${identity}" "${wrong_identity}" "${recipient_log}" "${wrong_recipient_log}"
for name in CANARY DISABLED DESTROYED; do
  printf '%s' "${canary_value}-${name}" | \
    age -r "${recipient}" -o "${age_source}/janus/default/${name}.age" \
    >>"${log}" 2>&1
  chmod 600 "${age_source}/janus/default/${name}.age"
done

if [ -z "${JANUSD_ADMIN_BIN:-}" ] || [ -z "${JANUSD_USE_BIN:-}" ] || [ -z "${JANUS_WARDEN_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd -p janus-warden
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
janusd_use_bin="${JANUSD_USE_BIN:-${repo}/target/debug/janusd-use}"
warden_bin="${JANUS_WARDEN_BIN:-${repo}/target/debug/janus-warden}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"
[ -x "${janusd_use_bin}" ] || fail "janusd-use binary is not executable"
[ -x "${warden_bin}" ] || fail "janus-warden binary is not executable"

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="dev"
export JANUS_RUN_PROFILE_MANIFEST="${profiles}"
export JANUS_RUN_PERMIT_DIR="${permit_source}"
export JANUS_APPROVAL_DIR="${approval_source}"
export JANUS_DELEGATION_DIR="${delegation_source}"
export JANUS_LIFECYCLE_EVIDENCE_DIR="${lifecycle_source}"
export JANUS_LIFECYCLE_TOMBSTONE_DIR="${tombstone_source}"
export JANUS_AGE_MANIFEST_FILE="${secretspec}"
export JANUS_AGE_PROFILE="default"
export JANUS_AGE_STORE_DIR="${age_source}"
export JANUS_AGE_IDENTITY_FILE="${identity}"
export JANUS_AGE_RECIPIENT="${recipient}"
export JANUS_AGE_METADATA_FILE="${metadata_source}"
export JANUS_RUN_EXECUTOR="${executor}"
export JANUS_RUNTIME_AUDIT_FILE="${audit_source}"

expect_denied "wrong-plane audit fixture" \
  "${janusd_use_bin}" approve list
grep -F '"action":"runtime.plane"' "${audit_source}" >/dev/null ||
  fail "source audit chain fixture was not created"

approval_output="$(run_logged "pre-recovery approval" \
  "${janusd_admin_bin}" approve issue \
  --secret-ref "${secret_ref}" \
  --profile "${profile_id}" \
  --purpose "recovery normal use" \
  --reason "JANUS-294 recovery smoke" \
  --egress connector \
  --expires-in-seconds 900)"
approval_id="$(printf '%s\n' "${approval_output}" | extract_field approval_id)"
[ -n "${approval_id}" ] || fail "pre-recovery approval id missing"
permit_output="$(run_logged "pre-recovery permit" \
  "${janusd_admin_bin}" approve permit \
  --approval "${approval_id}" \
  --permit-ttl-seconds 60)"
stale_permit_id="$(printf '%s\n' "${permit_output}" | extract_field permit_id)"
[ -n "${stale_permit_id}" ] || fail "pre-recovery permit id missing"

python3 - "${metadata_source}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
temporary_class = '''[[secrets]]
name = "CANARY"
classification = "break_glass"

'''
contents = path.read_text(encoding="utf-8")
if contents.count(temporary_class) != 1:
    raise SystemExit("temporary break-glass fixture was not exact")
path.write_text(contents.replace(temporary_class, ""), encoding="utf-8")
path.chmod(0o600)
PY

issue_delegation() {
  local purpose="$1"
  local ttl="$2"
  local output
  output="$(run_logged "delegation ${purpose}" \
    "${janusd_admin_bin}" delegation issue \
    --secret-ref "${secret_ref}" \
    --profile "${profile_id}" \
    --purpose "${purpose}" \
    --reason "JANUS-294 recovery smoke" \
    --expires-in-seconds "${ttl}" \
    --grantor-human recovery-owner \
    --delegate-agent session:recovery-smoke)"
  printf '%s\n' "${output}" | extract_field delegation_id
}

active_delegation="$(issue_delegation "recovery delegated use" 900)"
revoked_delegation="$(issue_delegation "recovery revoked use" 900)"
expired_delegation="$(issue_delegation "recovery expired use" 1)"
for delegation in "${active_delegation}" "${revoked_delegation}" "${expired_delegation}"; do
  [ -n "${delegation}" ] || fail "pre-recovery delegation id missing"
done
run_logged "revoke delegation" \
  "${janusd_admin_bin}" delegation revoke \
  --delegation "${revoked_delegation}" \
  --reason "reviewed recovery revocation" >/dev/null

COMPONENT_ROOT="${source_root}" PERMIT_SOURCE="${permit_source}" \
BUNDLE_ROOT="${bundle_root}" TARGET_ROOT="${target_root}" STATE_ROOT="${state_root}" \
OPERATION_AUDIT="${operation_audit}" EVIDENCE_PATH="${evidence_path}" \
SECRETSPEC="${secretspec}" PROFILES="${profiles}" \
python3 - "${manifest}" <<'PY'
import hashlib
import json
import os
import pathlib
import struct
import sys

def field(value):
    data = value.encode()
    return struct.pack(">Q", len(data)) + data

scope = "scp_" + hashlib.sha256(b"".join(field(value) for value in (
    "janus-scope-v1", "fixture-org", "janus", "janus", "dev"
)) + b"\0\0").digest()[:20].hex()

root = pathlib.Path(os.environ["COMPONENT_ROOT"])
kinds = [
    "age_ciphertext", "metadata_overlay", "audit_log", "approvals", "delegations",
    "lifecycle_evidence", "tombstones", "lifecycle_entry", "admin_state",
]
configs = []
for name, key in (("secretspec", "SECRETSPEC"), ("approved-use", "PROFILES")):
    path = pathlib.Path(os.environ[key])
    configs.append({
        "name": name,
        "path": str(path),
        "expected_fingerprint": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    })
value = {
    "schema_version": 1,
    "operation_id": "recovery-smoke",
    "scope_ref": scope,
    "release_artifact": "not_required:self_hosted",
    "expected_bundle_fingerprint": "sha256:" + "0" * 64,
    "components": [
        {"kind": kind, "source_path": str(root / kind)} for kind in kinds
    ],
    "config_bindings": configs,
    "permit_source_path": os.environ["PERMIT_SOURCE"],
    "bundle_root": os.environ["BUNDLE_ROOT"],
    "target_root": os.environ["TARGET_ROOT"],
    "state_root": os.environ["STATE_ROOT"],
    "operation_audit_path": os.environ["OPERATION_AUDIT"],
    "evidence_path": os.environ["EVIDENCE_PATH"],
    "minimum_free_bytes": 0,
    "maximum_bundle_bytes": 16777216,
    "maximum_bundle_files": 4096,
    "preflight_max_age_seconds": 900,
    "evidence_max_age_seconds": 86400,
}
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

export JANUS_RECOVERY_AGE_MANIFEST_FILE="${secretspec}"
export JANUS_RECOVERY_AGE_PROFILE="default"
export JANUS_RECOVERY_AGE_IDENTITY_FILE="${identity}"
export JANUS_RECOVERY_AGE_RECIPIENT="${recipient}"

snapshot_output="$(run_logged "recovery snapshot" \
  "${janusd_admin_bin}" recovery-drill snapshot --manifest "${manifest}")"
bundle_fingerprint="$(printf '%s\n' "${snapshot_output}" | extract_field bundle_fingerprint)"
[ -n "${bundle_fingerprint}" ] || fail "recovery snapshot fingerprint missing"
printf '%s\n' "${snapshot_output}" | grep -F 'excluded_permit_count=1' >/dev/null ||
  fail "recovery snapshot did not count the excluded permit"

BUNDLE_FINGERPRINT="${bundle_fingerprint}" python3 - "${manifest}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["expected_bundle_fingerprint"] = os.environ["BUNDLE_FINGERPRINT"]
path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

payload="${bundle_root}/payload"
mv "${payload}/delegations" "${runtime}/missing-component"
expect_denied "missing sealed component" \
  "${janusd_admin_bin}" recovery-drill preflight --manifest "${manifest}"
mv "${runtime}/missing-component" "${payload}/delegations"

chmod 644 "${payload}/metadata_overlay/content"
expect_denied "insecure sealed component" \
  "${janusd_admin_bin}" recovery-drill preflight --manifest "${manifest}"
chmod 600 "${payload}/metadata_overlay/content"

cp "${payload}/audit_log/content" "${runtime}/sealed-audit.saved"
printf '%s\n' '{"corrupt":"audit"}' >"${payload}/audit_log/content"
chmod 600 "${payload}/audit_log/content"
expect_denied "corrupt sealed audit" \
  "${janusd_admin_bin}" recovery-drill preflight --manifest "${manifest}"
cp "${runtime}/sealed-audit.saved" "${payload}/audit_log/content"
chmod 600 "${payload}/audit_log/content"

cp "${manifest}" "${runtime}/manifest.saved"
python3 - "${manifest}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["schema_version"] = 2
path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY
expect_denied "unknown recovery manifest version" \
  "${janusd_admin_bin}" recovery-drill status --manifest "${manifest}"
cp "${runtime}/manifest.saved" "${manifest}"
chmod 600 "${manifest}"

export JANUS_RECOVERY_AGE_IDENTITY_FILE="${wrong_identity}"
expect_denied "wrong recovery identity" \
  "${janusd_admin_bin}" recovery-drill preflight --manifest "${manifest}"
export JANUS_RECOVERY_AGE_IDENTITY_FILE="${identity}"

run_recovery() {
  local operation="$1"
  local phase="$2"
  local output
  output="$(run_logged "recovery ${operation}" \
    "${janusd_admin_bin}" recovery-drill "${operation}" --manifest "${manifest}")"
  printf '%s\n' "${output}" | grep -F "phase=${phase}" >/dev/null ||
    fail "recovery ${operation} did not report ${phase}"
  printf '%s\n' "${output}" | grep -F 'value_returned=false' >/dev/null ||
    fail "recovery ${operation} was not value-free"
}

run_recovery preflight preflighted
run_recovery restore restored
run_recovery postflight completed
run_recovery status completed

[ ! -e "${target_root}/permits" ] || fail "portable permit registry survived recovery"
cmp -s \
  "${age_source}/janus/default/CANARY.age" \
  "${target_root}/age_ciphertext/janus/default/CANARY.age" ||
  fail "recovered ciphertext changed"
grep -F '"action":"runtime.plane"' "${target_root}/audit_log/content" >/dev/null ||
  fail "recovered audit lost its source chain"
grep -F '"action":"recovery.drill"' "${target_root}/audit_log/content" >/dev/null ||
  fail "recovered audit did not continue with recovery.drill"
grep -F '"action":"backend.health"' "${operation_audit}" >/dev/null ||
  fail "provider recovery verification was not audited"
[ -f "${evidence_path}" ] || fail "recovery evidence was not persisted"
if grep -F "${canary_value}" "${evidence_path}" "${operation_audit}" "${log}" >/dev/null 2>&1; then
  fail "recovery output or evidence leaked canary material"
fi

export JANUS_RECOVERY_DRILL_MANIFEST="${manifest}"
export JANUS_RECOVERY_DRILL_EVIDENCE="${evidence_path}"
run_logged "fresh recovery startup gate" \
  "${janusd_use_bin}" env-file preflight --profile "${profile_id}" >/dev/null
cp "${profiles}" "${runtime}/profiles.saved"
printf '\n# reviewed configuration drift\n' >>"${profiles}"
expect_denied "recovery config freshness drift" \
  "${janusd_use_bin}" env-file preflight --profile "${profile_id}"
cp "${runtime}/profiles.saved" "${profiles}"
chmod 600 "${profiles}"

mkdir "${target_root}/permits"
chmod 700 "${target_root}/permits"
export JANUS_RUN_PERMIT_DIR="${target_root}/permits"
export JANUS_APPROVAL_DIR="${target_root}/approvals"
export JANUS_DELEGATION_DIR="${target_root}/delegations"
export JANUS_LIFECYCLE_EVIDENCE_DIR="${target_root}/lifecycle_evidence"
export JANUS_LIFECYCLE_TOMBSTONE_DIR="${target_root}/tombstones"
export JANUS_AGE_STORE_DIR="${target_root}/age_ciphertext"
export JANUS_AGE_METADATA_FILE="${target_root}/metadata_overlay/content"

expect_denied "pre-recovery permit reuse" \
  "${janusd_use_bin}" env-file --profile "${profile_id}" --permit "${stale_permit_id}"

export JANUS_WARDEN_BACKEND="age"
export JANUS_WARDEN_AGE_MANIFEST_FILE="${secretspec}"
export JANUS_WARDEN_AGE_PROFILE="default"
export JANUS_WARDEN_AGE_STORE_DIR="${target_root}/age_ciphertext"
export JANUS_WARDEN_AGE_IDENTITY_FILE="${identity}"
export JANUS_WARDEN_AGE_RECIPIENT="${recipient}"
export JANUS_WARDEN_AGE_METADATA_FILE="${target_root}/metadata_overlay/content"
export JANUS_WARDEN_PERMIT_DIR="${target_root}/permits"
export JANUS_WARDEN_DELEGATION_DIR="${target_root}/delegations"
export JANUS_WARDEN_DESTINATION="${destination}"
export JANUS_WARDEN_EXECUTOR="${executor}"
export JANUS_WARDEN_SCOPE_ORGANIZATION="fixture-org"
export JANUS_WARDEN_SCOPE_PROJECT="janus"
export JANUS_WARDEN_SCOPE_REPOSITORY="janus"
export JANUS_WARDEN_SCOPE_ENVIRONMENT="dev"
export JANUS_WARDEN_AGENT_SESSION="recovery-smoke"

sleep 2
warden_permits="$(python3 - \
  "${repo}/scripts/smoke-warden-mcp.py" "${warden_bin}" \
  "${active_delegation}" "${revoked_delegation}" "${expired_delegation}" <<'PY'
import importlib.util
import subprocess
import sys

helper_path, binary, active, revoked, expired = sys.argv[1:]
spec = importlib.util.spec_from_file_location("janus_warden_smoke_helper", helper_path)
helper = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)
proc = subprocess.Popen(
    [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, bufsize=1,
)
smoke = helper.McpSmoke(proc)
try:
    smoke.request("initialize", {
        "protocolVersion": helper.PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "recovery-drill-smoke", "version": "0"},
    })
    smoke.notify("notifications/initialized", {})
    listed = helper.structured(smoke.request(
        "tools/call", {"name": "list_secrets", "arguments": {}}
    ))
    rows = {row["lifecycle_state"]: row for row in listed["result"]["secrets"]}
    for lifecycle in ("disabled", "destroyed"):
        denied = helper.structured_denial(smoke.request("tools/call", {
            "name": "request_use",
            "arguments": {
                "secret_ref": rows[lifecycle]["secret_ref"],
                "profile_id": rows[lifecycle]["allowed_uses"][0],
                "purpose": "recovery lifecycle denial",
            },
        }))
        if denied["value_returned"] is not False:
            raise AssertionError("lifecycle denial was not value-free")
    active_row = rows["active"]
    normal = helper.structured(smoke.request("tools/call", {
        "name": "request_use",
        "arguments": {
            "secret_ref": active_row["secret_ref"],
            "profile_id": active_row["allowed_uses"][0],
            "purpose": "recovery normal use",
        },
    }))
    if normal["value_returned"] is not False:
        raise AssertionError("normal permit response was not value-free")
    for delegation, purpose, expected in (
        (revoked, "recovery revoked use", "delegation_revoked"),
        (expired, "recovery expired use", "delegation_expired"),
    ):
        denied = helper.structured_denial(smoke.request("tools/call", {
            "name": "request_use",
            "arguments": {
                "secret_ref": active_row["secret_ref"],
                "profile_id": active_row["allowed_uses"][0],
                "purpose": purpose,
                "delegation_id": delegation,
            },
        }))
        if denied["error"]["reason_code"] != expected:
            raise AssertionError("recovered delegation denial changed")
    permitted = helper.structured(smoke.request("tools/call", {
        "name": "request_use",
        "arguments": {
            "secret_ref": active_row["secret_ref"],
            "profile_id": active_row["allowed_uses"][0],
            "purpose": "recovery delegated use",
            "delegation_id": active,
        },
    }))
    if permitted["value_returned"] is not False:
        raise AssertionError("delegated permit response was not value-free")
    print("normal_permit_id=" + normal["result"]["permit_id"])
    print("delegated_permit_id=" + permitted["result"]["permit_id"])
finally:
    smoke.close()
PY
)"
normal_permit_id="$(printf '%s\n' "${warden_permits}" | extract_field normal_permit_id)"
delegated_permit_id="$(printf '%s\n' "${warden_permits}" | extract_field delegated_permit_id)"
[ -n "${normal_permit_id}" ] || fail "recovered normal use did not issue a permit"
[ -n "${delegated_permit_id}" ] || fail "recovered delegation did not issue a permit"
export JANUS_RUN_AGENT_SESSION="recovery-smoke"
run_logged "normal recovered use" \
  "${janusd_use_bin}" env-file --profile "${profile_id}" --permit "${normal_permit_id}" >/dev/null
[ -f "${env_output}" ] || fail "normal recovered use did not render its reviewed output"
CANARY_VALUE="${canary_value}-CANARY" python3 - "${env_output}" <<'PY'
import os
import pathlib
import sys

values = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if line:
        key, value = line.split("=", 1)
        values[key] = value
if values.get("SERVICE_TOKEN") != os.environ["CANARY_VALUE"]:
    raise SystemExit("recovered normal use produced the wrong private value")
PY
mv "${env_output}" "${runtime}/normal-recovered.env"
run_logged "delegated recovered use" \
  "${janusd_use_bin}" env-file --profile "${profile_id}" --permit "${delegated_permit_id}" >/dev/null
[ -f "${env_output}" ] || fail "delegated recovered use did not render its reviewed output"
CANARY_VALUE="${canary_value}-CANARY" python3 - "${env_output}" <<'PY'
import os
import pathlib
import sys

values = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if line:
        key, value = line.split("=", 1)
        values[key] = value
if values.get("SERVICE_TOKEN") != os.environ["CANARY_VALUE"]:
    raise SystemExit("recovered delegated use produced the wrong private value")
PY

if grep -F "${canary_value}" "${log}" "${operation_audit}" "${evidence_path}" >/dev/null 2>&1; then
  fail "recovery drill leaked canary material after recovered use"
fi

run_recovery rollback rolled_back
[ -d "${target_root}" ] || fail "rollback did not restore the target directory"
[ "$(find "${target_root}" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = "0" ] ||
  fail "rollback did not restore the empty target"
[ ! -e "${evidence_path}" ] || fail "rollback retained completed evidence"

printf 'ok: janusd-admin recovery-drill smoke passed sealed Age recovery, audit continuation, authority/lifecycle preservation, stale-permit exclusion, freshness, and rollback value_returned=false\n'

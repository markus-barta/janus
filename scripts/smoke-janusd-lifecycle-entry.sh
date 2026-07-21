#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-lifecycle-entry-smoke.XXXXXX")"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping lifecycle-entry fixture at %s\n' "${tmp}" >&2
    return
  fi
  rm -rf "${tmp}"
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

runtime="${tmp}/runtime"
store_dir="${runtime}/age-store"
state_dir="${runtime}/entry-state"
audit_dir="${runtime}/audit"
audit_path="${audit_dir}/events.jsonl"
manifest="${runtime}/secretspec.toml"
metadata="${runtime}/metadata.toml"
profiles="${runtime}/approved-use.toml"
hooks="${runtime}/hooks.toml"
identity_file="${runtime}/age.identity"
recipient_log="${runtime}/age-keygen.log"
log="${runtime}/entry.log"
import_plan="${runtime}/import-plan.json"
generated_plan="${runtime}/generated-plan.json"
failure_plan="${runtime}/failure-plan.json"
import_canary="janus-lifecycle-entry-import-canary"

mkdir -p "${runtime}" "${store_dir}" "${state_dir}" "${audit_dir}"
chmod 700 "${runtime}" "${store_dir}" "${state_dir}" "${audit_dir}"
: >"${log}"
chmod 600 "${log}"

cat >"${manifest}" <<'TOML'
[project]
name = "janus"
revision = "1.0"

[profiles.default]
IMPORT_CANARY = { description = "Lifecycle entry import fixture", required = true }
GENERATED_CANARY = { description = "Lifecycle entry generated fixture", required = true }
FAILURE_CANARY = { description = "Lifecycle entry failure fixture", required = true }
TOML

cat >"${metadata}" <<'TOML'
[defaults]
owner = "janusd-smoke"
classification = "normal"
lifecycle = "draft"
TOML

scope_ref="$({
  python3 - <<'PY'
import hashlib
import struct

def field(value):
    encoded = value.encode()
    return struct.pack(">Q", len(encoded)) + encoded

canonical = b"".join(field(value) for value in (
    "janus-scope-v1", "fixture-org", "janus", "janus", "dev"
)) + b"\0\0"
print("scp_" + hashlib.sha256(canonical).digest()[:20].hex())
PY
})"

refs="$({
  SCOPE_REF="${scope_ref}" python3 - <<'PY'
import hashlib
import os

scope = os.environ["SCOPE_REF"].encode()
for name in ("IMPORT_CANARY", "GENERATED_CANARY", "FAILURE_CANARY"):
    digest = hashlib.sha256(b"janus-secret-ref-v2\0" + scope + b"\0" + name.encode()).digest()
    print("sec_" + digest[:10].hex())
PY
})"
import_ref="$(printf '%s\n' "${refs}" | sed -n '1p')"
generated_ref="$(printf '%s\n' "${refs}" | sed -n '2p')"
failure_ref="$(printf '%s\n' "${refs}" | sed -n '3p')"
[ -n "${import_ref}" ] && [ -n "${generated_ref}" ] && [ -n "${failure_ref}" ] ||
  fail "secret refs were not derived"

cat >"${profiles}" <<TOML
[[env_files]]
id = "profile.IMPORT_CANARY"
secret_ref = "${import_ref}"
executor = "entry-smoke"
destination = "entry-import-fixture"
env = "IMPORT_TOKEN"
output = "${runtime}/import.env"

[env_files.consumer]
consumer_ref = "consumer.entry_import"
kind = "service"
owner = "janusd-smoke"
environment = "dev"
reload = "none"
validation = ["entry-import-valid"]
supports_dual_value = false
blast_radius = "entry-import-fixture"

[[env_files]]
id = "profile.GENERATED_CANARY"
secret_ref = "${generated_ref}"
executor = "entry-smoke"
destination = "entry-generated-fixture"
env = "GENERATED_TOKEN"
output = "${runtime}/generated.env"

[env_files.consumer]
consumer_ref = "consumer.entry_generated"
kind = "service"
owner = "janusd-smoke"
environment = "dev"
reload = "none"
validation = ["entry-generated-valid"]
supports_dual_value = false
blast_radius = "entry-generated-fixture"

[[env_files]]
id = "profile.FAILURE_CANARY"
secret_ref = "${failure_ref}"
executor = "entry-smoke"
destination = "entry-failure-fixture"
env = "FAILURE_TOKEN"
output = "${runtime}/failure.env"

[env_files.consumer]
consumer_ref = "consumer.entry_failure"
kind = "service"
owner = "janusd-smoke"
environment = "dev"
reload = "none"
validation = ["entry-failure-probe"]
supports_dual_value = false
blast_radius = "entry-failure-fixture"
TOML

cat >"${hooks}" <<'TOML'
[validation]
entry-import-valid = { program = "/usr/bin/true", args = [] }
entry-generated-valid = { program = "/usr/bin/true", args = [] }
entry-failure-probe = { program = "/usr/bin/false", args = [] }
TOML

age-keygen -o "${identity_file}" >"${recipient_log}.stdout" 2>"${recipient_log}"
recipient="$(sed -n 's/^Public key: //p' "${recipient_log}")"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"
chmod 600 "${identity_file}" "${recipient_log}" "${recipient_log}.stdout" \
  "${manifest}" "${metadata}" "${profiles}" "${hooks}"

reviewed_at="$(date +%s)"
SCOPE_REF="${scope_ref}" IMPORT_REF="${import_ref}" GENERATED_REF="${generated_ref}" \
FAILURE_REF="${failure_ref}" \
MANIFEST="${manifest}" STORE_DIR="${store_dir}" METADATA="${metadata}" \
PROFILES="${profiles}" HOOKS="${hooks}" STATE_DIR="${state_dir}" \
AUDIT_PATH="${audit_path}" REVIEWED_AT="${reviewed_at}" \
IMPORT_PLAN="${import_plan}" GENERATED_PLAN="${generated_plan}" FAILURE_PLAN="${failure_plan}" \
python3 - <<'PY'
import json
import os
import pathlib

common = {
    "schema_version": 1,
    "expected_scope_ref": os.environ["SCOPE_REF"],
    "expected_owner": "janusd-smoke",
    "expected_classification": "normal",
    "input_max_bytes": 4096,
    "preflight_max_age_seconds": 900,
    "secretspec_manifest": os.environ["MANIFEST"],
    "secretspec_profile": "default",
    "age_store_dir": os.environ["STORE_DIR"],
    "metadata_file": os.environ["METADATA"],
    "profile_manifest": os.environ["PROFILES"],
    "hook_manifest": os.environ["HOOKS"],
    "state_dir": os.environ["STATE_DIR"],
    "audit_path": os.environ["AUDIT_PATH"],
    "reviewed_by": "janus-security",
    "reviewed_at_unix_secs": int(os.environ["REVIEWED_AT"]),
    "activation_reason": "JANUS-289 lifecycle entry smoke",
    "reload_strategy": "none",
}
plans = [
    (
        os.environ["IMPORT_PLAN"],
        common | {
            "operation_id": "entry-import-smoke",
            "secret_ref": os.environ["IMPORT_REF"],
            "expected_label": "Lifecycle entry import fixture",
            "profile_id": "profile.IMPORT_CANARY",
            "consumer_ref": "consumer.entry_import",
            "rotation_strategy": "import",
            "validation_probes": ["entry-import-valid"],
            "source": {"mode": "import"},
        },
    ),
    (
        os.environ["GENERATED_PLAN"],
        common | {
            "operation_id": "entry-generated-smoke",
            "secret_ref": os.environ["GENERATED_REF"],
            "expected_label": "Lifecycle entry generated fixture",
            "profile_id": "profile.GENERATED_CANARY",
            "consumer_ref": "consumer.entry_generated",
            "rotation_strategy": "generated",
            "validation_probes": ["entry-generated-valid"],
            "source": {"mode": "generated", "alphabet": "url_safe", "length": 48},
        },
    ),
    (
        os.environ["FAILURE_PLAN"],
        common | {
            "operation_id": "entry-failure-smoke",
            "secret_ref": os.environ["FAILURE_REF"],
            "expected_label": "Lifecycle entry failure fixture",
            "profile_id": "profile.FAILURE_CANARY",
            "consumer_ref": "consumer.entry_failure",
            "rotation_strategy": "generated",
            "validation_probes": ["entry-failure-probe"],
            "source": {"mode": "generated", "alphabet": "hex", "length": 32},
        },
    ),
]
for path, plan in plans:
    pathlib.Path(path).write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
PY
chmod 600 "${import_plan}" "${generated_plan}" "${failure_plan}"

if [ -z "${JANUSD_ADMIN_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"

export JANUS_AGE_IDENTITY_FILE="${identity_file}"
export JANUS_AGE_RECIPIENT="${recipient}"
export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="dev"

run_entry() {
  local operation="$1"
  local plan="$2"
  local expected_phase="$3"
  local output
  if ! output="$("${janusd_admin_bin}" lifecycle-entry "${operation}" --plan "${plan}" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "lifecycle-entry ${operation} failed"
  fi
  printf '%s\n' "${output}" >>"${log}"
  printf '%s\n' "${output}" | grep -F "phase=${expected_phase}" >/dev/null ||
    fail "lifecycle-entry ${operation} did not report ${expected_phase}"
  printf '%s\n' "${output}" | grep -F 'value_returned=false' >/dev/null ||
    fail "lifecycle-entry ${operation} was not value-free"
}

import_ciphertext="${store_dir}/janus/default/IMPORT_CANARY.age"
generated_ciphertext="${store_dir}/janus/default/GENERATED_CANARY.age"
failure_ciphertext="${store_dir}/janus/default/FAILURE_CANARY.age"
run_entry preflight "${import_plan}" preflighted
[ ! -e "${import_ciphertext}" ] || fail "import preflight created ciphertext"
printf '%s' "${import_canary}" | run_entry apply "${import_plan}" validated
[ -f "${import_ciphertext}" ] || fail "import apply did not create ciphertext"
grep -F 'lifecycle = "draft"' "${metadata}" >/dev/null ||
  fail "import apply activated metadata before explicit activation"
run_entry activate "${import_plan}" completed
run_entry status "${import_plan}" completed

expected="${runtime}/expected.secret"
decrypted="${runtime}/decrypted.secret"
printf '%s' "${import_canary}" >"${expected}"
chmod 600 "${expected}"
age -d -i "${identity_file}" -o "${decrypted}" "${import_ciphertext}" >>"${log}" 2>&1
chmod 600 "${decrypted}"
cmp -s "${expected}" "${decrypted}" || fail "import ciphertext did not recover the input stream"

run_entry preflight "${generated_plan}" preflighted
run_entry apply "${generated_plan}" validated
[ -f "${generated_ciphertext}" ] || fail "generated apply did not create ciphertext"
run_entry rollback "${generated_plan}" rolled_back
run_entry status "${generated_plan}" rolled_back
[ ! -e "${generated_ciphertext}" ] || fail "generated rollback retained ciphertext"

run_entry preflight "${failure_plan}" preflighted
if "${janusd_admin_bin}" lifecycle-entry apply --plan "${failure_plan}" >>"${log}" 2>&1; then
  fail "failing validation hook unexpectedly admitted entry apply"
fi
[ ! -e "${failure_ciphertext}" ] || fail "failed validation retained ciphertext"
jq -e '.phase == "rolled_back" and .created_by_operation == true' \
  "${state_dir}/entry-failure-smoke.json" >/dev/null ||
  fail "failed validation did not persist rolled-back recovery evidence"

for action in secret.lifecycle consumer.validate consumer.reload; do
  grep -F "\"action\":\"${action}\"" "${audit_path}" >/dev/null ||
    fail "entry audit evidence missing ${action}"
done
if grep -F "${import_canary}" "${log}" "${audit_path}" "${state_dir}"/*.json \
  "${import_ciphertext}" >/dev/null 2>&1; then
  fail "import canary leaked into value-free output, audit, journal, or ciphertext"
fi

printf 'ok: janusd-admin lifecycle-entry smoke passed import activation and generated rollback value_returned=false\n'

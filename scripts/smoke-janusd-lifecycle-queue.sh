#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-lifecycle-queue-smoke.XXXXXX")"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping lifecycle queue fixture at %s\n' "${tmp}" >&2
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
scope_store="${store_dir}/janus/default"
entry_state="${runtime}/entry-state"
evidence_dir="${runtime}/evidence"
tombstone_dir="${runtime}/tombstones"
audit_dir="${runtime}/audit"
queue_audit="${audit_dir}/queue.jsonl"
entry_audit="${audit_dir}/entry.jsonl"
output_dir="${runtime}/output"
manifest="${runtime}/secretspec.toml"
metadata="${runtime}/metadata.toml"
profiles="${runtime}/profiles.toml"
hooks="${runtime}/hooks.toml"
entry_plan="${runtime}/draft-entry-plan.json"
identity_file="${runtime}/age.identity"
recipient_log="${runtime}/age-keygen.log"
json_output="${output_dir}/queue.json"
filtered_output="${output_dir}/filtered.json"
file_output="${output_dir}/atomic.json"
text_output="${output_dir}/queue.txt"
negative_output="${output_dir}/negative.txt"
audit_failure_output="${output_dir}/audit-failure.json"
audit_failure_log="${output_dir}/audit-failure.txt"
secret_canary="janus-lifecycle-queue-secret-canary"

mkdir -p "${runtime}" "${scope_store}" "${entry_state}" "${evidence_dir}" \
  "${tombstone_dir}" "${audit_dir}" "${output_dir}"
chmod 700 "${runtime}" "${store_dir}" "${store_dir}/janus" "${scope_store}" \
  "${entry_state}" "${evidence_dir}" "${tombstone_dir}" "${audit_dir}" "${output_dir}"

cat >"${manifest}" <<'TOML'
[project]
name = "janus"
revision = "1.0"

[profiles.default]
HEALTHY_QUEUE_CANARY = { description = "Healthy lifecycle queue fixture", required = true }
STALE_QUEUE_CANARY = { description = "Stale lifecycle queue fixture", required = true }
DISABLED_QUEUE_CANARY = { description = "Disabled lifecycle queue fixture", required = true }
PENDING_QUEUE_CANARY = { description = "Pending lifecycle queue fixture", required = true }
DESTROYED_QUEUE_CANARY = { description = "Destroyed lifecycle queue fixture", required = true }
DRAFT_QUEUE_CANARY = { description = "Draft lifecycle queue fixture", required = true }
TOML

cat >"${metadata}" <<'TOML'
[defaults]
owner = "queue-smoke"
classification = "normal"
lifecycle = "active"

[[secrets]]
name = "STALE_QUEUE_CANARY"
owner = "security"
classification = "high_value"

[[secrets]]
name = "DISABLED_QUEUE_CANARY"
lifecycle = "disabled"

[[secrets]]
name = "PENDING_QUEUE_CANARY"
lifecycle = "pending_delete"

[[secrets]]
name = "DESTROYED_QUEUE_CANARY"
lifecycle = "destroyed"

[[secrets]]
name = "DRAFT_QUEUE_CANARY"
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
for name in (
    "HEALTHY_QUEUE_CANARY",
    "STALE_QUEUE_CANARY",
    "DISABLED_QUEUE_CANARY",
    "PENDING_QUEUE_CANARY",
    "DESTROYED_QUEUE_CANARY",
    "DRAFT_QUEUE_CANARY",
):
    digest = hashlib.sha256(b"janus-secret-ref-v2\0" + scope + b"\0" + name.encode()).digest()
    print("sec_" + digest[:10].hex())
PY
})"
healthy_ref="$(printf '%s\n' "${refs}" | sed -n '1p')"
stale_ref="$(printf '%s\n' "${refs}" | sed -n '2p')"
disabled_ref="$(printf '%s\n' "${refs}" | sed -n '3p')"
pending_ref="$(printf '%s\n' "${refs}" | sed -n '4p')"
destroyed_ref="$(printf '%s\n' "${refs}" | sed -n '5p')"
draft_ref="$(printf '%s\n' "${refs}" | sed -n '6p')"
orphan_ref="sec_queue_orphan_fixture"
[ -n "${draft_ref}" ] || fail "secret refs were not derived"

REFS="${refs}" RUNTIME="${runtime}" PROFILES="${profiles}" python3 - <<'PY'
import os
import pathlib

names = (
    "HEALTHY_QUEUE_CANARY",
    "STALE_QUEUE_CANARY",
    "DISABLED_QUEUE_CANARY",
    "PENDING_QUEUE_CANARY",
    "DESTROYED_QUEUE_CANARY",
    "DRAFT_QUEUE_CANARY",
)
refs = os.environ["REFS"].splitlines()
runtime = os.environ["RUNTIME"]
blocks = []
for name, secret_ref in zip(names, refs, strict=True):
    blocks.append(f'''[[env_files]]
id = "profile.{name}"
secret_ref = "{secret_ref}"
executor = "queue-smoke"
destination = "queue-fixture"
env = "TOKEN"
output = "{runtime}/{name.lower()}.env"

[env_files.consumer]
consumer_ref = "consumer.{name.lower()}"
kind = "service"
owner = "queue-smoke"
environment = "dev"
reload = "none"
validation = ["queue-valid"]
supports_dual_value = false
blast_radius = "queue-fixture"
''')
pathlib.Path(os.environ["PROFILES"]).write_text("\n".join(blocks), encoding="utf-8")
PY

cat >"${hooks}" <<'TOML'
[validation]
queue-valid = { program = "/usr/bin/true", args = [] }
TOML

age-keygen -o "${identity_file}" >"${recipient_log}.stdout" 2>"${recipient_log}"
recipient="$(sed -n 's/^Public key: //p' "${recipient_log}")"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"

for name in HEALTHY_QUEUE_CANARY STALE_QUEUE_CANARY DISABLED_QUEUE_CANARY \
  PENDING_QUEUE_CANARY DESTROYED_QUEUE_CANARY; do
  printf '%s-%s' "${secret_canary}" "${name}" |
    age -r "${recipient}" -o "${scope_store}/${name}.age"
  chmod 600 "${scope_store}/${name}.age"
done

now="$(date +%s)"
old="$((now - 100 * 24 * 60 * 60))"
HEALTHY_REF="${healthy_ref}" STALE_REF="${stale_ref}" ORPHAN_REF="${orphan_ref}" \
NOW="${now}" OLD="${old}" EVIDENCE_DIR="${evidence_dir}" TOMBSTONE_DIR="${tombstone_dir}" \
python3 - <<'PY'
import json
import os
import pathlib

evidence = (
    (os.environ["HEALTHY_REF"], int(os.environ["NOW"])),
    (os.environ["STALE_REF"], int(os.environ["OLD"])),
)
for secret_ref, used_at in evidence:
    record = {
        "version": 1,
        "secret_ref": secret_ref,
        "declared_at_unix_secs": used_at,
        "last_used_at_unix_secs": used_at,
        "last_rotated_at_unix_secs": None,
    }
    pathlib.Path(os.environ["EVIDENCE_DIR"], f"{secret_ref}.json").write_text(
        json.dumps(record) + "\n", encoding="utf-8"
    )

orphan = {
    "version": 1,
    "secret_ref": os.environ["ORPHAN_REF"],
    "reason": "reviewed orphan fixture",
    "destroyed_at_unix_secs": int(os.environ["OLD"]),
    "retain_until_unix_secs": int(os.environ["NOW"]) + 365 * 24 * 60 * 60,
    "principal_binding": "executor:queue-smoke|scope:fixture",
}
pathlib.Path(os.environ["TOMBSTONE_DIR"], f'{os.environ["ORPHAN_REF"]}.json').write_text(
    json.dumps(orphan) + "\n", encoding="utf-8"
)
PY

chmod 600 "${manifest}" "${metadata}" "${profiles}" "${hooks}" \
  "${identity_file}" "${recipient_log}" "${recipient_log}.stdout" \
  "${evidence_dir}"/*.json "${tombstone_dir}"/*.json

SCOPE_REF="${scope_ref}" DRAFT_REF="${draft_ref}" MANIFEST="${manifest}" \
STORE_DIR="${store_dir}" METADATA="${metadata}" PROFILES="${profiles}" HOOKS="${hooks}" \
STATE_DIR="${entry_state}" AUDIT_PATH="${entry_audit}" REVIEWED_AT="${now}" \
ENTRY_PLAN="${entry_plan}" python3 - <<'PY'
import json
import os
import pathlib

plan = {
    "schema_version": 1,
    "operation_id": "queue-draft-entry",
    "secret_ref": os.environ["DRAFT_REF"],
    "expected_scope_ref": os.environ["SCOPE_REF"],
    "expected_label": "Draft lifecycle queue fixture",
    "expected_owner": "queue-smoke",
    "expected_classification": "normal",
    "profile_id": "profile.DRAFT_QUEUE_CANARY",
    "consumer_ref": "consumer.draft_queue_canary",
    "rotation_strategy": "generated",
    "validation_probes": ["queue-valid"],
    "reload_strategy": "none",
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
    "reviewed_by": "queue-smoke",
    "reviewed_at_unix_secs": int(os.environ["REVIEWED_AT"]),
    "activation_reason": "queue fixture activation",
    "source": {"mode": "generated", "alphabet": "hex", "length": 32},
}
pathlib.Path(os.environ["ENTRY_PLAN"]).write_text(
    json.dumps(plan, indent=2) + "\n", encoding="utf-8"
)
PY
chmod 600 "${entry_plan}"

if [ -z "${JANUSD_ADMIN_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"

export JANUS_AGE_MANIFEST_FILE="${manifest}"
export JANUS_AGE_PROFILE="default"
export JANUS_AGE_STORE_DIR="${store_dir}"
export JANUS_AGE_IDENTITY_FILE="${identity_file}"
export JANUS_AGE_RECIPIENT="${recipient}"
export JANUS_AGE_METADATA_FILE="${metadata}"
export JANUS_MANAGED_PROFILE_MANIFEST="${profiles}"
export JANUS_LIFECYCLE_ENTRY_STATE_DIR="${entry_state}"
export JANUS_LIFECYCLE_EVIDENCE_DIR="${evidence_dir}"
export JANUS_LIFECYCLE_TOMBSTONE_DIR="${tombstone_dir}"
export JANUS_LIFECYCLE_QUEUE_AUDIT_FILE="${queue_audit}"
export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="dev"

"${janusd_admin_bin}" lifecycle-entry preflight --plan "${entry_plan}" >/dev/null

"${janusd_admin_bin}" lifecycle action-queue --format json >"${json_output}"
jq -e '
  .schema_version == 1 and
  .value_returned == false and
  .provider_deleted == false and
  .source_posture.manifest_metadata == "ok" and
  .source_posture.entry_journals == "ok" and
  (.snapshot_fingerprint | length) == 64
' "${json_output}" >/dev/null || fail "queue JSON contract is invalid"

assert_action() {
  local ref="$1"
  local action="$2"
  jq -e --arg ref "${ref}" --arg action "${action}" \
    '.rows[] | select(.secret_ref == $ref) | .next_actions | index($action) != null' \
    "${json_output}" >/dev/null || fail "queue row ${ref} is missing ${action}"
}

assert_action "${stale_ref}" "review_rotate_or_disable"
assert_action "${disabled_ref}" "review_disabled_secret"
assert_action "${pending_ref}" "record_destroy_tombstone"
assert_action "${destroyed_ref}" "restore_tombstone_or_investigate"
assert_action "${draft_ref}" "resume_or_rollback_entry"
assert_action "${orphan_ref}" "investigate_orphan_tombstone"
jq -e --arg ref "${healthy_ref}" \
  '.rows[] | select(.secret_ref == $ref) | .status == "healthy" and .next_actions == []' \
  "${json_output}" >/dev/null || fail "healthy queue row was not healthy"

"${janusd_admin_bin}" lifecycle action-queue --format json \
  --action-required-only --action record_destroy_tombstone >"${filtered_output}"
jq -e --arg ref "${pending_ref}" \
  '.rows | length == 1 and .[0].secret_ref == $ref' "${filtered_output}" >/dev/null ||
  fail "queue action filtering was not exact"

"${janusd_admin_bin}" lifecycle action-queue --format json --output "${file_output}"
[ -s "${file_output}" ] || fail "queue private output was not written"
[ "$(stat -c '%a' "${file_output}" 2>/dev/null || stat -f '%Lp' "${file_output}")" = "600" ] ||
  fail "queue private output mode is not 600"

"${janusd_admin_bin}" lifecycle action-queue --format text >"${text_output}"
grep -F 'value_returned=false provider_deleted=false' "${text_output}" >/dev/null ||
  fail "queue text output is not value-free"
grep -F "secret_ref=${pending_ref}" "${text_output}" >/dev/null ||
  fail "queue text output is missing the pending row"

if "${janusd_admin_bin}" lifecycle action-queue --value "${secret_canary}" \
  >"${negative_output}" 2>&1; then
  fail "queue accepted a literal-bearing argument"
fi
grep -F 'reason_code=queue_literal_argument_denied' "${negative_output}" >/dev/null ||
  fail "queue literal denial did not use the stable reason"

if JANUS_LIFECYCLE_QUEUE_AUDIT_FILE="${output_dir}" \
  "${janusd_admin_bin}" lifecycle action-queue --format json \
  --output "${audit_failure_output}" >"${audit_failure_log}" 2>&1; then
  fail "queue emitted output after its durable audit sink failed"
fi
[ ! -e "${audit_failure_output}" ] ||
  fail "queue persisted output before its durable audit completed"
grep -F 'reason_code=queue_audit_unavailable' "${audit_failure_log}" >/dev/null ||
  fail "queue audit failure did not use the stable reason"

audit_count="$(grep -c '"action":"secret.lifecycle_queue"' "${queue_audit}")"
[ "${audit_count}" = "4" ] || fail "queue audit did not record every emitted snapshot"

if grep -F -e "${secret_canary}" -e 'HEALTHY_QUEUE_CANARY' -e 'STALE_QUEUE_CANARY' \
  -e "${identity_file}" -e "${recipient}" "${json_output}" "${filtered_output}" \
  "${file_output}" "${text_output}" "${negative_output}" "${audit_failure_log}" \
  "${queue_audit}" >/dev/null; then
  fail "queue output or audit leaked forbidden source data"
fi

printf 'ok: janusd-admin lifecycle action queue smoke passed mixed-state text/json/filter/audit value_returned=false provider_deleted=false\n'

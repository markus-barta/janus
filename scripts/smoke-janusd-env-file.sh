#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

canary_value="janus-env-file-smoke-canary"
profile_id="profile.CANARY"
executor="janus-run@fixture"
destination="fixture-service"
env_name="SERVICE_TOKEN"
consumer_ref="consumer.fixture_service"
consumer_owner="janusd-smoke"
consumer_environment="test"
validation_probe="fixture-service-env"
blast_radius="fixture-service"
bundle="${JANUS_ENV_FILE_HANDOFF_BUNDLE:-${repo}/examples/env-file-handoff}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-env-file-smoke.XXXXXX")"
cleanup() {
  rm -rf "${tmp}"
}
if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
  printf 'debug: keeping smoke fixture at %s\n' "${tmp}" >&2
else
  trap cleanup EXIT
fi

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

assert_no_canary_in_file() {
  local path="$1"
  if grep -F "${canary_value}" "${path}" >/dev/null 2>&1; then
    fail "secret literal leaked into ${path}"
  fi
}

extract_field() {
  local field="$1"
  sed -n "s/.*${field}=\\([^ ]*\\).*/\\1/p"
}

run_janusd() {
  local label="$1"
  shift
  local output
  if ! output="$("${janusd_bin}" "$@" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log_file}"
    fail "${label} failed"
  fi
  printf '%s\n' "${output}" >>"${log_file}"
  printf '%s\n' "${output}"
}

runtime="${tmp}/runtime"
store_dir="${runtime}/age-store"
permit_dir="${runtime}/permits"
approval_dir="${runtime}/approvals"
evidence_dir="${runtime}/lifecycle-evidence"
env_dir="${runtime}/env"
log_file="${runtime}/janusd.log"
mkdir -p "${store_dir}/janus/default" "${permit_dir}" "${approval_dir}" "${evidence_dir}" "${env_dir}"
chmod 700 "${runtime}" "${store_dir}" "${store_dir}/janus" "${store_dir}/janus/default" \
  "${permit_dir}" "${approval_dir}" "${evidence_dir}" "${env_dir}"
: >"${log_file}"
chmod 600 "${log_file}"

manifest="${runtime}/secretspec.toml"
metadata="${runtime}/metadata.toml"
profiles="${runtime}/approved-use.toml"
identity_file="${runtime}/age.identity"
janus_identity_file="${runtime}/janus-age.identity"
recipient_log="${runtime}/age-keygen.log"
env_file="${env_dir}/fixture-service.env"
expected_file="${runtime}/expected.env"
fixture_marker="${runtime}/fixture-service.ok"

for path in \
  "${bundle}/secretspec.toml" \
  "${bundle}/metadata.toml" \
  "${bundle}/approved-use.env-file.toml.in" \
  "${bundle}/consumer-contract.md"
do
  [ -f "${path}" ] || fail "handoff bundle file missing: ${path}"
done
cp "${bundle}/secretspec.toml" "${manifest}"
cp "${bundle}/metadata.toml" "${metadata}"

secret_ref="$(
  python3 - <<'PY'
import hashlib
print("sec_" + hashlib.sha256(b"janus\0CANARY").digest()[:10].hex())
PY
)"

age-keygen -o "${identity_file}" >"${recipient_log}.stdout" 2>"${recipient_log}"
recipient="$(sed -n 's/^Public key: //p' "${recipient_log}")"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"
awk '/^AGE-SECRET-KEY-/ { print; found=1 } END { exit found ? 0 : 1 }' \
  "${identity_file}" >"${janus_identity_file}" || fail "age identity file missing secret key"
chmod 600 "${identity_file}" "${janus_identity_file}" "${recipient_log}" "${recipient_log}.stdout"

PROFILE_ID="${profile_id}" \
SECRET_REF="${secret_ref}" \
EXECUTOR="${executor}" \
DESTINATION="${destination}" \
ENV_NAME="${env_name}" \
OUTPUT_PATH="${env_file}" \
CONSUMER_REF="${consumer_ref}" \
CONSUMER_OWNER="${consumer_owner}" \
CONSUMER_ENVIRONMENT="${consumer_environment}" \
VALIDATION_PROBE="${validation_probe}" \
BLAST_RADIUS="${blast_radius}" \
python3 - "${bundle}/approved-use.env-file.toml.in" "${profiles}" <<'PY'
import os
import pathlib
import re
import sys

template = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for key in [
    "PROFILE_ID",
    "SECRET_REF",
    "EXECUTOR",
    "DESTINATION",
    "ENV_NAME",
    "OUTPUT_PATH",
    "CONSUMER_REF",
    "CONSUMER_OWNER",
    "CONSUMER_ENVIRONMENT",
    "VALIDATION_PROBE",
    "BLAST_RADIUS",
]:
    template = template.replace(f"@{key}@", os.environ[key])
if re.search(r"@[A-Z_]+@", template):
    raise SystemExit("unrendered placeholder remains in env-file profile template")
pathlib.Path(sys.argv[2]).write_text(template, encoding="utf-8")
PY

printf '%s' "${canary_value}" | age -r "${recipient}" -o "${store_dir}/janus/default/CANARY.age" \
  >>"${log_file}" 2>&1
chmod 600 "${store_dir}/janus/default/CANARY.age"

if [ -z "${JANUSD_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_bin="${JANUSD_BIN:-${repo}/target/debug/janusd}"
[ -x "${janusd_bin}" ] || fail "janusd binary is not executable"

export JANUS_RUN_PROFILE_MANIFEST="${profiles}"
export JANUS_RUN_PERMIT_DIR="${permit_dir}"
export JANUS_APPROVAL_DIR="${approval_dir}"
export JANUS_LIFECYCLE_EVIDENCE_DIR="${evidence_dir}"
export JANUS_AGE_MANIFEST_FILE="${manifest}"
export JANUS_AGE_PROFILE="default"
export JANUS_AGE_STORE_DIR="${store_dir}"
export JANUS_AGE_IDENTITY_FILE="${janus_identity_file}"
export JANUS_AGE_RECIPIENT="${recipient}"
export JANUS_AGE_METADATA_FILE="${metadata}"
export JANUS_RUN_EXECUTOR="${executor}"
export JANUS_RUN_SCOPE="janus/default"

preflight_output="$(
  run_janusd "env-file preflight" env-file preflight \
    --profile "${profile_id}"
)"
printf '%s\n' "${preflight_output}" | grep -F "value_returned=false" >/dev/null \
  || fail "env-file preflight outcome did not declare value_returned=false"
printf '%s\n' "${preflight_output}" | grep -F "consumer_ref=${consumer_ref}" >/dev/null \
  || fail "env-file preflight outcome did not include reviewed consumer"
[ ! -e "${env_file}" ] || fail "env-file preflight created the env file"

approval_output="$(
  run_janusd "approve issue" approve issue \
    --secret-ref "${secret_ref}" \
    --profile "${profile_id}" \
    --purpose "fixture env file handoff" \
    --reason "JANUS-259 smoke" \
    --egress connector \
    --expires-in-seconds 120
)"
approval_id="$(printf '%s\n' "${approval_output}" | extract_field "approval_id")"
[ -n "${approval_id}" ] || fail "approval id missing from approve issue output"

permit_output="$(
  run_janusd "approve permit" approve permit \
    --approval "${approval_id}" \
    --permit-ttl-seconds 60 \
    --revoke-approval
)"
permit_id="$(printf '%s\n' "${permit_output}" | extract_field "permit_id")"
[ -n "${permit_id}" ] || fail "permit id missing from approve permit output"

env_output="$(
  run_janusd "env-file" env-file \
    --profile "${profile_id}" \
    --permit "${permit_id}"
)"
printf '%s\n' "${env_output}" | grep -F "value_returned=false" >/dev/null \
  || fail "env-file outcome did not declare value_returned=false"

printf '%s=%s\n' "${env_name}" "${canary_value}" >"${expected_file}"
cmp -s "${expected_file}" "${env_file}" || fail "rendered env file did not match reviewed binding"
[ "$(file_mode "${env_file}")" = "600" ] || fail "rendered env file is not mode 0600"
[ ! -e "${permit_dir}/${permit_id}.json" ] || fail "permit file still exists after env-file consume"

expected_sha="$(
  CANARY_VALUE="${canary_value}" python3 - <<'PY'
import hashlib
import os
print(hashlib.sha256(os.environ["CANARY_VALUE"].encode()).hexdigest())
PY
)"
SERVICE_TOKEN_ENV_NAME="${env_name}" SERVICE_TOKEN_EXPECTED_SHA256="${expected_sha}" \
  python3 - "${env_file}" "${fixture_marker}" <<'PY'
import hashlib
import os
import pathlib
import sys

env_path = pathlib.Path(sys.argv[1])
marker_path = pathlib.Path(sys.argv[2])
values = {}
for line in env_path.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"):
        continue
    key, value = line.split("=", 1)
    values[key] = value
actual = hashlib.sha256(values.get(os.environ["SERVICE_TOKEN_ENV_NAME"], "").encode()).hexdigest()
if actual != os.environ["SERVICE_TOKEN_EXPECTED_SHA256"]:
    raise SystemExit("fixture service could not consume rendered env file")
marker_path.write_text("ok\n", encoding="utf-8")
PY
[ "$(cat "${fixture_marker}")" = "ok" ] || fail "fixture service marker missing"

if "${janusd_bin}" env-file --profile "${profile_id}" --permit "${permit_id}" \
  >>"${log_file}" 2>&1; then
  fail "consumed permit was reusable"
fi
grep -F "denied_unknown_permit" "${log_file}" >/dev/null \
  || fail "second env-file attempt did not fail as consumed permit"

evidence_file="${evidence_dir}/${secret_ref}.json"
[ -f "${evidence_file}" ] || fail "lifecycle evidence file missing"
grep -F '"last_used_at_unix_secs"' "${evidence_file}" >/dev/null \
  || fail "lifecycle evidence did not record last_used_at"

assert_no_canary_in_file "${log_file}"

printf 'ok: janusd env-file smoke passed secret_ref=%s profile_id=%s output_mode=%s value_returned=false\n' \
  "${secret_ref}" "${profile_id}" "$(file_mode "${env_file}")"

#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-pharos-retirement.XXXXXX")"

cleanup() {
	if [ "${JANUS_SMOKE_KEEP_FIXTURE:-0}" = "1" ]; then
		printf 'debug: keeping smoke fixture\n' >&2
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
store_dir="${runtime}/store"
beacon_dir="${runtime}/env/pharos/beacons"
hash_dir="${runtime}/env/pharos/beacon-token-hashes"
state_dir="${runtime}/pharos-retirements"
tombstone_dir="${runtime}/tombstones"
approval_dir="${runtime}/approvals"
mkdir -p \
	"${store_dir}/janus/default" \
	"${beacon_dir}" \
	"${hash_dir}" \
	"${tombstone_dir}" \
	"${approval_dir}"
chmod 700 \
	"${runtime}" \
	"${store_dir}" \
	"${store_dir}/janus" \
	"${store_dir}/janus/default" \
	"${runtime}/env" \
	"${runtime}/env/pharos" \
	"${beacon_dir}" \
	"${hash_dir}" \
	"${tombstone_dir}" \
	"${approval_dir}"

host="ares"
secret_name="PHAROS_BEACON_ARES_TOKEN"
profile_id="profile.PHAROS_BEACON_ARES_TOKEN"
secret_ref="$(
	SECRET_NAME="${secret_name}" python3 - <<'PY'
import hashlib
import os
import struct

def field(value):
    encoded = value.encode()
    return struct.pack(">Q", len(encoded)) + encoded

canonical = b"".join(field(value) for value in (
    "janus-scope-v1", "fixture-org", "janus", "janus", "test"
)) + b"\0\0"
scope_ref = "scp_" + hashlib.sha256(canonical).digest()[:20].hex()
secret = hashlib.sha256(
    b"janus-secret-ref-v2\0" + scope_ref.encode() + b"\0" + os.environ["SECRET_NAME"].encode()
).digest()[:10].hex()
print("sec_" + secret)
PY
)"
manifest="${runtime}/secretspec.toml"
metadata="${runtime}/metadata.toml"
profiles="${runtime}/managed-env-files.toml"
intent="${runtime}/retired-hosts.json"
identity="${runtime}/age.identity"
keygen_log="${runtime}/age-keygen.log"
env_file="${beacon_dir}/${host}.env"
hash_file="${hash_dir}/${host}.json"
provider_file="${store_dir}/janus/default/${secret_name}.age"
provider_before="${runtime}/provider.before.age"
fixture_value="janus-pharos-retirement-smoke-only"

cat >"${manifest}" <<'EOF'
[project]
name = "janus"
revision = "1.0"

[profiles.default]
PHAROS_BEACON_ARES_TOKEN = { description = "Disposable Pharos retirement fixture", required = true }
EOF

cat >"${metadata}" <<'EOF'
[defaults]
owner = "infra"
classification = "normal"
lifecycle = "active"
EOF

cat >"${profiles}" <<EOF
[[env_files]]
id = "${profile_id}"
secret_ref = "${secret_ref}"
executor = "janus-run@test"
destination = "pharos-beacon-${host}"
env = "PHAROS_TOKEN"
output = "${env_file}"

[env_files.hash_sidecar]
format = "pharos-beacon-token-generation-v2"
subject = "${host}"
output = "${hash_file}"

[env_files.consumer]
consumer_ref = "consumer.pharos_beacon_${host}"
kind = "service"
owner = "pharos"
environment = "test"
reload = "none"
validation = ["pharos-retirement-smoke"]
supports_dual_value = false
blast_radius = "disposable Pharos retirement fixture"
EOF

cat >"${intent}" <<EOF
{
  "schema": "inspr.pharos.janus-retirements.v1",
  "version": 1,
  "retirements": [
    {
      "host": "${host}",
      "disposition": "destroyed",
      "successor": null,
      "credential_retirement_required": true,
      "server_deletion": false
    }
  ]
}
EOF

chmod 600 "${manifest}" "${metadata}" "${profiles}" "${intent}"
printf 'PHAROS_TOKEN=%s\n' "${fixture_value}" >"${env_file}"
token_sha256="$(printf '%s' "${fixture_value}" | sha256sum | awk '{ print $1 }')"
generation="$({
	HOST_NAME="${host}" TOKEN_SHA256="${token_sha256}" python3 - <<'PY'
import hashlib
import os
import struct

host = os.environ["HOST_NAME"].encode()
token_hash = os.environ["TOKEN_SHA256"].encode()
digest = hashlib.sha256()
digest.update(b"inspr.pharos.beacon-token-generation.v2\0")
digest.update(struct.pack(">Q", len(host)))
digest.update(host)
digest.update(token_hash)
print(digest.hexdigest())
PY
})"
jq -n --arg host "${host}" --arg token_sha256 "${token_sha256}" \
	'{schema:"inspr.pharos.beacon-token-entry.v2",host:{name:$host,token_sha256:$token_sha256}}' \
	>"${hash_file}"
jq -n --arg generation "${generation}" --arg host "${host}" --arg token_sha256 "${token_sha256}" \
	'{schema:"inspr.pharos.beacon-token-generation.v2",generation:$generation,hosts:[{name:$host,token_sha256:$token_sha256}]}' \
	>"${hash_dir}/generation-${generation}.json"
printf '%s\n' "${generation}" >"${hash_dir}/current"
chmod 600 \
	"${env_file}" \
	"${hash_file}" \
	"${hash_dir}/current" \
	"${hash_dir}/generation-${generation}.json"

age-keygen -o "${identity}" >"${keygen_log}.stdout" 2>"${keygen_log}"
recipient="$(sed -n 's/^Public key: //p' "${keygen_log}")"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"
chmod 600 "${identity}" "${keygen_log}" "${keygen_log}.stdout"
printf '%s' "${fixture_value}" | age -r "${recipient}" -o "${provider_file}" >/dev/null 2>&1
chmod 600 "${provider_file}"
cp "${provider_file}" "${provider_before}"
chmod 600 "${provider_before}"

if [ -z "${JANUSD_ADMIN_BIN:-}" ]; then
	cargo build --quiet --locked -p janusd
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"

export JANUS_AGE_MANIFEST_FILE="${manifest}"
export JANUS_AGE_PROFILE="default"
export JANUS_AGE_STORE_DIR="${store_dir}"
export JANUS_AGE_IDENTITY_FILE="${identity}"
export JANUS_AGE_RECIPIENT="${recipient}"
export JANUS_AGE_METADATA_FILE="${metadata}"
export JANUS_RUN_PROFILE_MANIFEST="${profiles}"
export JANUS_APPROVAL_DIR="${approval_dir}"
export JANUS_LIFECYCLE_TOMBSTONE_DIR="${tombstone_dir}"
export JANUS_LIFECYCLE_EXECUTOR="janusd-pharos-retirement-smoke"
export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="test"

retirement_args=(
	--host "${host}"
	--disposition destroyed
	--intent-file "${intent}"
	--metadata-file "${metadata}"
	--profile-manifest "${profiles}"
	--state-dir "${state_dir}"
	--retain-for-days 365
)

before="$(${janusd_admin_bin} pharos-beacon reconcile "${retirement_args[@]}" 2>&1)" ||
	fail "initial reconcile failed"
printf '%s\n' "${before}" | grep -F 'state=action_required' >/dev/null ||
	fail "initial reconcile did not require retirement"

retired="$(${janusd_admin_bin} pharos-beacon retire "${retirement_args[@]}" 2>&1)" ||
	fail "retirement failed"
printf '%s\n' "${retired}" | grep -F 'state=complete' >/dev/null ||
	fail "retirement did not complete"
printf '%s\n' "${retired}" | grep -F 'value_returned=false' >/dev/null ||
	fail "retirement did not declare value-free output"
printf '%s\n' "${retired}" | grep -F 'provider_deleted=false' >/dev/null ||
	fail "retirement did not retain provider material"

[ ! -e "${env_file}" ] || fail "generated env output remained"
[ ! -e "${hash_file}" ] || fail "generated hash output remained"
[ -f "${provider_file}" ] || fail "encrypted provider material was deleted"
cmp -s "${provider_before}" "${provider_file}" || fail "encrypted provider material changed"
[ -f "${state_dir}/${host}.json" ] || fail "retirement state was not persisted"
[ -f "${tombstone_dir}/${secret_ref}.json" ] || fail "retirement tombstone was not persisted"
grep -F 'lifecycle = "destroyed"' "${metadata}" >/dev/null ||
	fail "metadata lifecycle was not finalized"

replayed="$(${janusd_admin_bin} pharos-beacon retire "${retirement_args[@]}" 2>&1)" ||
	fail "idempotent retirement replay failed"
printf '%s\n' "${replayed}" | grep -F 'state=complete' >/dev/null ||
	fail "retirement replay did not remain complete"

after="$(${janusd_admin_bin} pharos-beacon reconcile "${retirement_args[@]}" 2>&1)" ||
	fail "completed reconcile failed"
printf '%s\n' "${after}" | grep -F 'state=complete' >/dev/null ||
	fail "completed reconcile did not report complete"

if denied="$(${janusd_admin_bin} approve issue \
	--secret-ref "${secret_ref}" \
	--profile "${profile_id}" \
	--purpose "retired fixture use" \
	--reason "retirement smoke" \
	--egress connector \
	--expires-in-seconds 60 2>&1)"; then
	fail "destroyed credential remained available for approved use"
fi
printf '%s\n' "${denied}" | grep -F 'denied_lifecycle_destroyed' >/dev/null ||
	fail "approved use did not fail on destroyed lifecycle"

for output in "${before}" "${retired}" "${replayed}" "${after}" "${denied}"; do
	case "${output}" in
	*"${fixture_value}"*) fail "fixture value leaked into command output" ;;
	esac
done

printf 'ok: janusd-admin Pharos retirement smoke passed value_returned=false provider_deleted=false\n'

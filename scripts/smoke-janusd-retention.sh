#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-retention-smoke.XXXXXX")"
tmp="$(cd "${tmp}" && pwd -P)"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping retention fixture at %s\n' "${tmp}" >&2
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
approvals="${runtime}/approvals"
delegations="${runtime}/delegations"
lifecycle="${runtime}/lifecycle"
tombstones="${runtime}/tombstones"
admin_evidence="${runtime}/admin-evidence"
protected="${runtime}/protected"
operation="${runtime}/operation"
age_store="${runtime}/age-store"
quarantine="${runtime}/quarantine"
state="${runtime}/state"
manifest="${runtime}/secretspec.toml"
metadata="${runtime}/metadata.toml"
holds="${runtime}/holds.json"
audit="${runtime}/audit.jsonl"
policy="${runtime}/retention.json"
evidence="${protected}/retention.json"
identity="${runtime}/age.identity"
key_log="${runtime}/age-keygen.log"
log="${runtime}/retention.log"
canary="SENSITIVE_RETENTION_SMOKE_CANARY_MUST_NOT_ESCAPE"

mkdir -p "${approvals}" "${delegations}" "${lifecycle}" "${tombstones}" \
  "${admin_evidence}" "${protected}" "${operation}" "${age_store}"
chmod 700 "${runtime}" "${approvals}" "${delegations}" "${lifecycle}" \
  "${tombstones}" "${admin_evidence}" "${protected}" "${operation}" "${age_store}"

cat >"${manifest}" <<'TOML'
[project]
name = "janus"
revision = "1.0"

[profiles.default]
ACTIVE_RETENTION_FIXTURE = { description = "Active retention fixture", required = true }
TOML

cat >"${metadata}" <<'TOML'
[defaults]
owner = "security"
classification = "normal"
lifecycle = "active"
TOML

printf '{"schema_version":1,"scope_ref":"@SCOPE@","holds":[]}\n' >"${holds}"
: >"${audit}"
: >"${log}"

python3 - fixtures/migrations/approval-registry-v0/appr_fixture.json \
  "${approvals}/appr_fixture.json" "${canary}" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
record["expires_at_unix_secs"] = 1
record["expires_at_subsec_nanos"] = 0
record["reason"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(record) + "\n", encoding="utf-8")
PY

age-keygen -o "${identity}" >"${key_log}.stdout" 2>"${key_log}"
recipient="$(sed -n -e 's/^# public key: //p' -e 's/^Public key: //p' \
  "${key_log}" "${key_log}.stdout" "${identity}" | head -n 1)"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"

scope_ref="$(python3 - <<'PY'
import hashlib

def field(value):
    data = value.encode()
    return len(data).to_bytes(8, "big") + data

canonical = b"".join(field(value) for value in (
    "janus-scope-v1", "fixture-org", "janus", "janus", "test"
)) + b"\x00\x00"
print("scp_" + hashlib.sha256(canonical).digest()[:20].hex())
PY
)"
sed -i.bak "s/@SCOPE@/${scope_ref}/" "${holds}"
rm "${holds}.bak"

python3 - "${policy}" "${scope_ref}" "${manifest}" "${metadata}" "${approvals}" \
  "${delegations}" "${lifecycle}" "${tombstones}" "${audit}" "${protected}" \
  "${admin_evidence}" "${holds}" "${quarantine}" "${state}" "${operation}" \
  "${evidence}" <<'PY'
import hashlib
import json
import pathlib
import sys

(policy_path, scope, manifest, metadata, approvals, delegations, lifecycle,
 tombstones, audit, protected, admin, holds, quarantine, state, operation,
 evidence) = sys.argv[1:]

def fingerprint(path):
    return "sha256:" + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

classes = (
    "approvals", "delegations", "lifecycle_evidence", "audit", "denials",
    "tombstones", "recovery_evidence", "admin_evidence",
)
rules = []
for name in classes:
    if name in {"approvals", "delegations", "lifecycle_evidence"}:
        disposition = "quarantine_then_purge"
    elif name == "recovery_evidence":
        disposition = "replace_only"
    else:
        disposition = "retain"
    rules.append({"class": name, "disposition": disposition, "minimum_age_seconds": 1})

policy = {
    "schema_version": 1,
    "operation_id": "retention-smoke",
    "scope_ref": scope,
    "release_artifact": "not_required:self_hosted",
    "rules": rules,
    "config_bindings": [
        {"name": "secretspec", "path": manifest, "expected_fingerprint": fingerprint(manifest)},
        {"name": "metadata", "path": metadata, "expected_fingerprint": fingerprint(metadata)},
    ],
    "approval_root": approvals,
    "delegation_root": delegations,
    "lifecycle_evidence_root": lifecycle,
    "metadata_overlay_path": metadata,
    "tombstone_root": tombstones,
    "audit_path": audit,
    "recovery_evidence_path": str(pathlib.Path(protected) / "recovery.json"),
    "admin_evidence_root": admin,
    "hold_registry_path": holds,
    "quarantine_root": quarantine,
    "state_root": state,
    "operation_audit_path": str(pathlib.Path(operation) / "audit.jsonl"),
    "evidence_path": evidence,
    "minimum_free_bytes": 1,
    "maximum_records": 1024,
    "maximum_bytes": 1048576,
    "preflight_max_age_seconds": 60,
    "quarantine_grace_seconds": 1,
    "evidence_max_age_seconds": 86400,
}
pathlib.Path(policy_path).write_text(json.dumps(policy) + "\n", encoding="utf-8")
PY
chmod 600 "${manifest}" "${metadata}" "${holds}" "${audit}" "${policy}" \
  "${approvals}/appr_fixture.json" "${identity}" "${key_log}" "${key_log}.stdout" "${log}"

if [ -z "${JANUSD_ADMIN_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="test"
export JANUS_AGE_MANIFEST_FILE="${manifest}"
export JANUS_AGE_PROFILE="default"
export JANUS_AGE_STORE_DIR="${age_store}"
export JANUS_AGE_IDENTITY_FILE="${identity}"
export JANUS_AGE_RECIPIENT="${recipient}"

run_retention() {
  local action="$1"
  local phase="$2"
  local output
  if ! output="$("${janusd_admin_bin}" retention "${action}" --policy "${policy}" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "retention ${action} failed"
  fi
  printf '%s\n' "${output}" >>"${log}"
  printf '%s\n' "${output}" | grep -F "phase=${phase}" >/dev/null ||
    fail "retention ${action} did not report ${phase}"
  printf '%s\n' "${output}" | grep -F 'value_returned=false' >/dev/null ||
    fail "retention ${action} was not value-free"
}

run_retention preflight preflighted
run_retention quarantine quarantined
[ ! -e "${approvals}/appr_fixture.json" ] || fail "eligible approval was not quarantined"
[ -e "${quarantine}/approvals/appr_fixture.json" ] || fail "quarantine is incomplete"

if "${janusd_admin_bin}" retention purge --policy "${policy}" >>"${log}" 2>&1; then
  fail "purge ignored its reversible grace"
fi
sleep 2
run_retention purge completed
run_retention status completed
[ -e "${evidence}" ] || fail "retention completion evidence is missing"
[ ! -e "${quarantine}" ] || fail "purged quarantine remains"

export JANUS_RETENTION_POLICY="${policy}"
export JANUS_RETENTION_EVIDENCE="${evidence}"
cp fixtures/migrations/approval-registry-v0/appr_fixture.json "${approvals}/appr_drift.json"
chmod 600 "${approvals}/appr_drift.json"
if output="$("${janusd_admin_bin}" approve list 2>&1)"; then
  printf '%s\n' "${output}" >>"${log}"
  fail "runtime startup accepted source drift after retention evidence"
fi
printf '%s\n' "${output}" >>"${log}"
printf '%s\n' "${output}" | grep -F 'retention evidence denied runtime startup' >/dev/null ||
  fail "source drift did not fail at the retention readiness gate"

for action in retention.apply retention.expire; do
  grep -F "\"action\":\"${action}\"" "${operation}/audit.jsonl" >/dev/null ||
    fail "audit evidence missing ${action}"
done
if grep -F "${canary}" "${log}" "${operation}/audit.jsonl" "${evidence}" >/dev/null 2>&1; then
  fail "retained metadata leaked into value-free output or evidence"
fi

printf 'ok: janusd-admin retention smoke passed quarantine, grace, purge, and stale-startup denial value_returned=false\n'

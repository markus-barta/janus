#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-migration-smoke.XXXXXX")"
cleanup() {
  if [ "${JANUS_SMOKE_KEEP_TMP:-0}" = "1" ]; then
    printf 'debug: keeping migration fixture at %s\n' "${tmp}" >&2
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
target="${runtime}/approvals"
state="${runtime}/migration-state"
audit_dir="${runtime}/audit"
audit="${audit_dir}/events.jsonl"
manifest="${runtime}/migration.json"
original="${runtime}/original.json"
log="${runtime}/migration.log"
canary="janus-migration-smoke-canary"

mkdir -p "${target}" "${audit_dir}"
chmod 700 "${runtime}" "${target}" "${audit_dir}"
cp fixtures/migrations/approval-registry-v0/appr_fixture.json "${target}/appr_fixture.json"
cp "${target}/appr_fixture.json" "${original}"
chmod 600 "${target}/appr_fixture.json" "${original}"
: >"${log}"
chmod 600 "${log}"

TARGET_ROOT="${target}" STATE_ROOT="${state}" AUDIT_PATH="${audit}" \
  python3 - config/migrations/approval-registry-v0-v1.json.in "${manifest}" <<'PY'
import os
import pathlib
import re
import sys

contents = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for key in ["TARGET_ROOT", "STATE_ROOT", "AUDIT_PATH"]:
    contents = contents.replace(f"@{key}@", os.environ[key])
if re.search(r"@[A-Z_]+@", contents):
    raise SystemExit("unrendered migration manifest placeholder")
pathlib.Path(sys.argv[2]).write_text(contents, encoding="utf-8")
PY
chmod 600 "${manifest}"

if [ -z "${JANUSD_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_bin="${JANUSD_BIN:-${repo}/target/debug/janusd}"
[ -x "${janusd_bin}" ] || fail "janusd binary is not executable"

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="test"

run_migration() {
  local operation="$1"
  local expected_phase="$2"
  local output
  if ! output="$("${janusd_bin}" migrate "${operation}" --manifest "${manifest}" 2>&1)"; then
    printf '%s\n' "${output}" >>"${log}"
    fail "migration ${operation} failed"
  fi
  printf '%s\n' "${output}" >>"${log}"
  printf '%s\n' "${output}" | grep -F "phase=${expected_phase}" >/dev/null ||
    fail "migration ${operation} did not report ${expected_phase}"
  printf '%s\n' "${output}" | grep -F 'value_returned=false' >/dev/null ||
    fail "migration ${operation} was not value-free"
}

run_migration preflight preflighted
run_migration status preflighted
run_migration apply applied

python3 - "${original}" "${target}/appr_fixture.json" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if after.pop("version", None) != 1 or after != before:
    raise SystemExit("migrated approval changed an authority-bearing field")
PY

run_migration postflight completed
run_migration status completed
run_migration rollback rolled_back
run_migration status rolled_back

cmp -s "${original}" "${target}/appr_fixture.json" ||
  fail "rollback did not restore the byte-exact source record"
[ ! -e "${target}/.janus-schema" ] || fail "rollback retained the v1 schema marker"

for action in upgrade.preflight migration.apply upgrade.postflight upgrade.rollback; do
  grep -F "\"action\":\"${action}\"" "${audit}" >/dev/null ||
    fail "audit evidence missing ${action}"
done
if grep -F "${canary}" "${log}" "${audit}" >/dev/null 2>&1; then
  fail "record metadata leaked into value-free output or audit"
fi

printf 'ok: janusd migration smoke passed forward, postflight, and rollback value_returned=false\n'

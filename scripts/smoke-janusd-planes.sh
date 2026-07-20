#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-plane-smoke.XXXXXX")"
cleanup() {
  rm -rf -- "${tmp}"
}
trap cleanup EXIT

use_bin="${JANUSD_USE_BIN:-${repo}/target/debug/janusd-use}"
admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
legacy_bin="${JANUSD_LEGACY_BIN:-${repo}/target/debug/janusd}"
if [ -z "${JANUSD_USE_BIN:-}" ] || [ -z "${JANUSD_ADMIN_BIN:-}" ] || [ -z "${JANUSD_LEGACY_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd --bins
fi
for binary in "${use_bin}" "${admin_bin}" "${legacy_bin}"; do
  [ -x "${binary}" ] || fail "runtime binary is not executable: ${binary}"
done

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="test"

# Other-plane configuration must not widen an executable's hard-coded plane.
export JANUS_APPROVAL_DIR="/nonexistent/janus-plane-canary"
export JANUS_MIGRATION_MANIFEST="/nonexistent/janus-plane-canary"
export JANUS_RUN_PROFILE_MANIFEST="/nonexistent/janus-plane-canary"
export JANUS_RUN_PERMIT_DIR="/nonexistent/janus-plane-canary"
export JANUS_RUNTIME_AUDIT_FILE="${tmp}/audit/runtime-plane.jsonl"

canary="janus-plane-output-canary"

assert_wrong_plane() {
  local label="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    fail "${label} unexpectedly succeeded"
  fi
  case "${output}" in
    *denied_wrong_plane*value_returned=false*) ;;
    *) fail "${label} did not return the stable wrong-plane denial" ;;
  esac
  case "${output}" in
    *"${canary}"*) fail "${label} echoed caller input" ;;
  esac
}

# Every admin command family is denied by the use process before state opens.
assert_wrong_plane "use to approval issue" "${use_bin}" approve issue "${canary}"
assert_wrong_plane "use to approval permit" "${use_bin}" approve permit "${canary}"
assert_wrong_plane "use to approval list" "${use_bin}" approve list
assert_wrong_plane "use to approval revoke" "${use_bin}" approve revoke "${canary}"
assert_wrong_plane "use to lifecycle transition" "${use_bin}" lifecycle transition "${canary}"
assert_wrong_plane "use to lifecycle stale report" "${use_bin}" lifecycle stale-report "${canary}"
assert_wrong_plane "use to destroy record" "${use_bin}" lifecycle destroy-record "${canary}"
assert_wrong_plane "use to destroy finalize" "${use_bin}" lifecycle destroy-finalize "${canary}"
assert_wrong_plane "use to destroy reconcile" "${use_bin}" lifecycle destroy-reconcile "${canary}"
assert_wrong_plane "use to forge" "${use_bin}" forge rotate-generated "${canary}"
assert_wrong_plane "use to migration" "${use_bin}" migrate status --manifest "${canary}"
assert_wrong_plane "use to scope transfer" "${use_bin}" scope-transfer status --manifest "${canary}"
assert_wrong_plane "use to Pharos retire" "${use_bin}" pharos-beacon retire "${canary}"
assert_wrong_plane "use to Pharos reconcile" "${use_bin}" pharos-beacon reconcile "${canary}"

# Every permit-consuming command family is denied by the admin process.
assert_wrong_plane "admin to run preflight" "${admin_bin}" run preflight "${canary}"
assert_wrong_plane "admin to run" "${admin_bin}" run "${canary}"
assert_wrong_plane "admin to env preflight" "${admin_bin}" env-file preflight "${canary}"
assert_wrong_plane "admin to env" "${admin_bin}" env-file "${canary}"

# The retired mixed entry point cannot be recovered through either command set.
assert_wrong_plane "legacy to use" "${legacy_bin}" run "${canary}"
assert_wrong_plane "legacy to admin" "${legacy_bin}" approve list

audit_count="$(grep -c '"action":"runtime.plane"' "${JANUS_RUNTIME_AUDIT_FILE}")"
[ "${audit_count}" = "20" ] || fail "runtime-plane audit did not record every denial"
if grep -F "${canary}" "${JANUS_RUNTIME_AUDIT_FILE}" >/dev/null 2>&1; then
  fail "runtime-plane audit contained caller input"
fi

export JANUS_RUNTIME_AUDIT_FILE="${tmp}"
if audit_failure="$(${use_bin} approve list 2>&1)"; then
  fail "wrong-plane call succeeded with an unavailable required audit sink"
fi
case "${audit_failure}" in
  *audit_sink_unavailable*value_returned=false*) ;;
  *) fail "required-audit failure did not fail closed" ;;
esac

use_help="$(${use_bin} --help 2>&1)"
admin_help="$(${admin_bin} --help 2>&1)"
legacy_help="$(${legacy_bin} --help 2>&1)"
case "${use_help}" in *"Permit-bound use commands"*) ;; *) fail "use help is not plane-specific" ;; esac
case "${admin_help}" in *"Administration commands"*) ;; *) fail "admin help is not plane-specific" ;; esac
case "${legacy_help}" in *"mixed Janus runtime entry point is retired"*) ;; *) fail "legacy help lacks retirement guidance" ;; esac

printf 'ok: Janus runtime process-plane smoke passed use_to_admin=denied admin_to_use=denied legacy=retired value_returned=false\n'

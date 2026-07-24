#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/janus-lifecycle-entry-smoke.XXXXXX")"
socket_root="$(mktemp -d /tmp/janus-web-sock.XXXXXX)"
chmod 700 "${socket_root}"
web_daemon_pid=""
web_client_pid=""
cleanup() {
  if [ -n "${web_client_pid}" ]; then
    kill "${web_client_pid}" >/dev/null 2>&1 || true
  fi
  if [ -n "${web_daemon_pid}" ]; then
    kill "${web_daemon_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${socket_root}"
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
web_catalog="${runtime}/web-transaction-catalog.json"
web_signing_key="${runtime}/web-signing-key.json"
web_host_identity="${runtime}/web-host-ed25519"
web_outbox="${runtime}/web-outbox"
web_socket="${socket_root}/tx.sock"
web_log="${runtime}/web-transaction.log"
web_abort_ready="${runtime}/web-abort-ready"
import_canary="janus-lifecycle-entry-import-canary"
web_canary="SENSITIVE_WEB_TRANSACTION_CANARY_9d3e"

mkdir -p "${runtime}" "${store_dir}" "${state_dir}" "${audit_dir}" "${web_outbox}"
chmod 700 "${runtime}" "${store_dir}" "${state_dir}" "${audit_dir}" "${web_outbox}"
: >"${log}"
: >"${web_log}"
chmod 600 "${log}" "${web_log}"

cat >"${manifest}" <<'TOML'
[project]
name = "janus"
revision = "1.0"

[profiles.default]
IMPORT_CANARY = { description = "Lifecycle entry import fixture", required = true }
GENERATED_CANARY = { description = "Lifecycle entry generated fixture", required = true }
FAILURE_CANARY = { description = "Lifecycle entry failure fixture", required = true }
WEB_CANARY = { description = "Lifecycle entry web transaction fixture", required = true }
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
for name in ("IMPORT_CANARY", "GENERATED_CANARY", "FAILURE_CANARY", "WEB_CANARY"):
    digest = hashlib.sha256(b"janus-secret-ref-v2\0" + scope + b"\0" + name.encode()).digest()
    print("sec_" + digest[:10].hex())
PY
})"
import_ref="$(printf '%s\n' "${refs}" | sed -n '1p')"
generated_ref="$(printf '%s\n' "${refs}" | sed -n '2p')"
failure_ref="$(printf '%s\n' "${refs}" | sed -n '3p')"
web_ref="$(printf '%s\n' "${refs}" | sed -n '4p')"
[ -n "${import_ref}" ] && [ -n "${generated_ref}" ] && [ -n "${failure_ref}" ] &&
  [ -n "${web_ref}" ] ||
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

[[env_files]]
id = "profile.WEB_CANARY"
secret_ref = "${web_ref}"
executor = "entry-smoke"
destination = "entry-web-fixture"
env = "WEB_TOKEN"
output = "${runtime}/web.env"

[env_files.consumer]
consumer_ref = "consumer.entry_web"
kind = "service"
owner = "janusd-smoke"
environment = "dev"
reload = "none"
validation = ["entry-web-valid"]
supports_dual_value = false
blast_radius = "entry-web-fixture"
TOML

cat >"${hooks}" <<'TOML'
[validation]
entry-import-valid = { program = "/usr/bin/true", args = [] }
entry-generated-valid = { program = "/usr/bin/true", args = [] }
entry-failure-probe = { program = "/usr/bin/false", args = [] }
entry-web-valid = { program = "/usr/bin/true", args = [] }
TOML

age-keygen -o "${identity_file}" >"${recipient_log}.stdout" 2>"${recipient_log}"
recipient="$(sed -n 's/^Public key: //p' "${recipient_log}")"
[ -n "${recipient}" ] || fail "age-keygen did not produce a recipient"
ssh-keygen -q -t ed25519 -N '' -f "${web_host_identity}"
web_host_recipient="$(cat "${web_host_identity}.pub")"
[ -n "${web_host_recipient}" ] || fail "ssh-keygen did not produce a host recipient"
chmod 600 "${identity_file}" "${recipient_log}" "${recipient_log}.stdout" \
  "${manifest}" "${metadata}" "${profiles}" "${hooks}" "${web_host_identity}"

reviewed_at="$(date +%s)"
SCOPE_REF="${scope_ref}" IMPORT_REF="${import_ref}" GENERATED_REF="${generated_ref}" \
  FAILURE_REF="${failure_ref}" WEB_REF="${web_ref}" \
  MANIFEST="${manifest}" STORE_DIR="${store_dir}" METADATA="${metadata}" \
  PROFILES="${profiles}" HOOKS="${hooks}" STATE_DIR="${state_dir}" \
  AUDIT_PATH="${audit_path}" REVIEWED_AT="${reviewed_at}" \
  IMPORT_PLAN="${import_plan}" GENERATED_PLAN="${generated_plan}" FAILURE_PLAN="${failure_plan}" \
  WEB_CATALOG="${web_catalog}" WEB_SIGNING_KEY="${web_signing_key}" \
  WEB_HOST_RECIPIENT="${web_host_recipient}" WEB_OUTBOX="${web_outbox}" \
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

web_plan = common | {
    "operation_id": "web-transaction-template",
    "secret_ref": os.environ["WEB_REF"],
    "expected_label": "Lifecycle entry web transaction fixture",
    "profile_id": "profile.WEB_CANARY",
    "consumer_ref": "consumer.entry_web",
    "rotation_strategy": "import",
    "validation_probes": ["entry-web-valid"],
    "source": {"mode": "import"},
}
signing_key = {
    "schema": "inspr.janus.host-envelope-signing-key.v1",
    "schema_version": 1,
    "key_id": "key_websmoke0001",
    "private_key_base64": __import__("base64").b64encode(bytes(range(32))).decode().rstrip("="),
}
pathlib.Path(os.environ["WEB_SIGNING_KEY"]).write_text(
    json.dumps(signing_key, indent=2) + "\n", encoding="utf-8"
)
catalog = {
    "schema": "inspr.janus.managed-web-transaction-catalog.v2",
    "schema_version": 2,
    "entries": [{
        "host_ref": "host_0123456789abcdef",
        "service_ref": "svc_0123456789abcdef",
        "slot_ref": "slot_0123456789abcdef",
        "declaration_fingerprint": "decl_0123456789abcdef",
        "operation_kind": "create",
        "plan": web_plan,
        "delivery": {
            "schema": "inspr.janus.managed-host-delivery-plan.v1",
            "schema_version": 1,
            "host_recipient": os.environ["WEB_HOST_RECIPIENT"],
            "producer_key_id": "key_websmoke0001",
            "producer_signing_key_file": os.environ["WEB_SIGNING_KEY"],
            "outbox_dir": os.environ["WEB_OUTBOX"],
            "generation": 1,
            "revocation_epoch": 1,
            "envelope_ttl_seconds": 900,
        },
    }],
}
pathlib.Path(os.environ["WEB_CATALOG"]).write_text(
    json.dumps(catalog, indent=2) + "\n", encoding="utf-8"
)
PY
chmod 600 "${import_plan}" "${generated_plan}" "${failure_plan}" "${web_catalog}" \
  "${web_signing_key}"

if [ -z "${JANUSD_ADMIN_BIN:-}" ]; then
  cargo build --quiet --locked -p janusd
fi
janusd_admin_bin="${JANUSD_ADMIN_BIN:-${repo}/target/debug/janusd-admin}"
janusd_web_bin="${JANUSD_WEB_TRANSACTION_BIN:-${repo}/target/debug/janusd-web-transactiond}"
[ -x "${janusd_admin_bin}" ] || fail "janusd-admin binary is not executable"
[ -x "${janusd_web_bin}" ] || fail "janusd-web-transactiond binary is not executable"

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

export JANUS_MANAGED_WEB_TRANSACTION_SOCKET="${web_socket}"
export JANUS_MANAGED_WEB_TRANSACTION_CATALOG_FILE="${web_catalog}"
export JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID
JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID="$(id -u)"

start_web_daemon() {
  "${janusd_web_bin}" >>"${web_log}" 2>&1 &
  web_daemon_pid="$!"
  for _ in $(seq 1 100); do
    [ -S "${web_socket}" ] && return
    kill -0 "${web_daemon_pid}" >/dev/null 2>&1 ||
      fail "web transaction daemon exited before binding"
    sleep 0.05
  done
  fail "web transaction daemon did not bind its private socket"
}

start_web_daemon
WEB_SOCKET="${web_socket}" ABORT_READY="${web_abort_ready}" python3 - <<'PY' &
import json
import os
import socket
import struct
import time

request = {
    "schema": "inspr.janus.managed-web-transaction-request.v2",
    "schema_version": 2,
    "action": "prepare",
    "operation_ref": "op_webabort000001",
    "operation_kind": "create",
    "source": "import",
    "host_ref": "host_0123456789abcdef",
    "service_ref": "svc_0123456789abcdef",
    "slot_ref": "slot_0123456789abcdef",
    "declaration_fingerprint": "decl_0123456789abcdef",
    "external_evidence": None,
}
body = json.dumps(request, separators=(",", ":")).encode()
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.connect(os.environ["WEB_SOCKET"])
peer.sendall(struct.pack(">I", len(body)) + body)
size = struct.unpack(">I", peer.recv(4))[0]
response = json.loads(peer.recv(size))
if response["phase"] != "preflighted" or not response["expects_value"]:
    raise SystemExit("web abort fixture did not reach value-free preflight")
open(os.environ["ABORT_READY"], "w", encoding="utf-8").write("ready\n")
time.sleep(60)
PY
web_client_pid="$!"
for _ in $(seq 1 100); do
  [ -f "${web_abort_ready}" ] && break
  kill -0 "${web_client_pid}" >/dev/null 2>&1 ||
    fail "web abort client exited before preflight"
  sleep 0.05
done
[ -f "${web_abort_ready}" ] || fail "web abort client did not reach preflight"
kill "${web_daemon_pid}"
wait "${web_daemon_pid}" >/dev/null 2>&1 || true
web_daemon_pid=""
kill "${web_client_pid}" >/dev/null 2>&1 || true
wait "${web_client_pid}" >/dev/null 2>&1 || true
web_client_pid=""
jq -e '.phase == "preflighted" and .created_by_operation == false' \
  "${state_dir}/webtx_webabort000001.json" >/dev/null ||
  fail "web crash fixture did not preserve partial preflight journal"

start_web_daemon
for _ in $(seq 1 100); do
  if jq -e '.phase == "rolled_back"' "${state_dir}/webtx_webabort000001.json" >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
jq -e '.phase == "rolled_back" and .created_by_operation == false' \
  "${state_dir}/webtx_webabort000001.json" >/dev/null ||
  fail "web daemon restart did not reconcile partial preflight"

WEB_SOCKET="${web_socket}" WEB_CANARY="${web_canary}" WEB_OUTBOX="${web_outbox}" python3 - <<'PY'
import json
import os
import socket
import struct

def frame(peer, body):
    peer.sendall(struct.pack(">I", len(body)) + body)

def response(peer):
    header = peer.recv(4)
    if len(header) != 4:
        raise SystemExit("web transaction response header truncated")
    size = struct.unpack(">I", header)[0]
    chunks = []
    remaining = size
    while remaining:
        chunk = peer.recv(remaining)
        if not chunk:
            raise SystemExit("web transaction response truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    value = json.loads(b"".join(chunks))
    if value["value_returned"] is not False:
        raise SystemExit("web transaction response was not value-free")
    return value

request = {
    "schema": "inspr.janus.managed-web-transaction-request.v2",
    "schema_version": 2,
    "action": "prepare",
    "operation_ref": "op_websuccess0001",
    "operation_kind": "create",
    "source": "import",
    "host_ref": "host_0123456789abcdef",
    "service_ref": "svc_0123456789abcdef",
    "slot_ref": "slot_0123456789abcdef",
    "declaration_fingerprint": "decl_0123456789abcdef",
    "external_evidence": None,
}
body = json.dumps(request, separators=(",", ":")).encode()
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.connect(os.environ["WEB_SOCKET"])
frame(peer, body)
preflight = response(peer)
if preflight["phase"] != "preflighted" or not preflight["expects_value"]:
    raise SystemExit("web transaction did not gate import behind preflight")
secret = os.environ["WEB_CANARY"].encode()
frame(peer, secret)
prepared = response(peer)
if prepared["phase"] != "prepared" or prepared["expects_value"] or prepared["generation"] != 1:
    raise SystemExit(
        "web transaction did not prepare host delivery: "
        + prepared.get("reason_code", "missing_reason")
    )
peer.close()

outbox_path = os.path.join(os.environ["WEB_OUTBOX"], "op_websuccess0001.json")
outbox = json.loads(open(outbox_path, encoding="utf-8").read())
if outbox["value_returned"] is not False or os.environ["WEB_CANARY"] in json.dumps(outbox):
    raise SystemExit("host outbox was not ciphertext-only")

finalize = request | {
    "action": "finalize",
    "external_evidence": {
        "generation": 1,
        "materialized": True,
        "process_state": "running",
        "probe_state": "healthy",
        "heartbeat_observed_at_unix_secs": outbox["prepared_at_unix_secs"],
        "process_observed_at_unix_secs": outbox["prepared_at_unix_secs"],
        "probe_observed_at_unix_secs": outbox["prepared_at_unix_secs"],
    },
}
finalize_body = json.dumps(finalize, separators=(",", ":")).encode()
finalizer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
finalizer.connect(os.environ["WEB_SOCKET"])
frame(finalizer, finalize_body)
complete = response(finalizer)
if complete["phase"] != "completed" or complete["expects_value"] or complete["generation"] != 1:
    raise SystemExit("web transaction did not finalize external activation")
finalizer.close()
if os.path.exists(outbox_path):
    raise SystemExit("completed web transaction retained host outbox")

duplicate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
duplicate.connect(os.environ["WEB_SOCKET"])
frame(duplicate, body)
replayed = response(duplicate)
if replayed["phase"] != "completed" or replayed["expects_value"]:
    raise SystemExit("web transaction duplicate was not idempotent")
duplicate.close()

malformed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
malformed.connect(os.environ["WEB_SOCKET"])
bad = body[:-1] + b',"raw_value":"' + secret + b'"}'
frame(malformed, bad)
denied = response(malformed)
if denied["phase"] != "denied" or denied["reason_code"] != "web_transaction_protocol_invalid":
    raise SystemExit("web transaction malformed request did not fail closed")
malformed.close()
PY

web_ciphertext="${store_dir}/janus/default/WEB_CANARY.age"
[ -f "${web_ciphertext}" ] || fail "web transaction did not create ciphertext"
web_decrypted="${runtime}/web-decrypted.secret"
age -d -i "${identity_file}" -o "${web_decrypted}" "${web_ciphertext}" >>"${log}" 2>&1
chmod 600 "${web_decrypted}"
[ "$(cat "${web_decrypted}")" = "${web_canary}" ] ||
  fail "web transaction ciphertext did not recover the input stream"

for action in secret.lifecycle consumer.validate consumer.reload; do
  grep -F "\"action\":\"${action}\"" "${audit_path}" >/dev/null ||
    fail "entry audit evidence missing ${action}"
done
if grep -F "${import_canary}" "${log}" "${audit_path}" "${state_dir}"/*.json \
  "${import_ciphertext}" >/dev/null 2>&1; then
  fail "import canary leaked into value-free output, audit, journal, or ciphertext"
fi
if grep -F "${web_canary}" "${log}" "${web_log}" "${audit_path}" \
  "${state_dir}"/*.json "${web_ciphertext}" >/dev/null 2>&1; then
  fail "web canary leaked into output, audit, journal, crash output, or ciphertext"
fi

printf 'ok: lifecycle-entry smoke passed admin and private web transactions, crash reconciliation, duplicate idempotency, and value-free evidence value_returned=false\n'

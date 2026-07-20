#!/usr/bin/env bash
set -euo pipefail

policy=""
channel=""
mode=""
previous_mode=""
image=""
tag=""
digest=""
output=""

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

required_value() {
  if [[ "$#" -ne 2 || -z "$2" ]]; then
    fail "release_admission_invalid_arguments"
  fi
  printf '%s' "$2"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --policy)
      policy="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --channel)
      channel="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --mode)
      mode="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --previous-mode)
      previous_mode="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --image)
      image="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --tag)
      tag="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --digest)
      digest="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --output)
      output="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    *)
      fail "release_admission_invalid_arguments"
      ;;
  esac
done

[[ -n "${policy}" && -n "${channel}" && -n "${mode}" && -n "${previous_mode}" ]] ||
  fail "release_admission_invalid_arguments"
[[ -n "${image}" && -n "${tag}" && -n "${digest}" && -n "${output}" ]] ||
  fail "release_admission_invalid_arguments"
[[ -f "${policy}" && ! -L "${policy}" ]] || fail "release_policy_unavailable"
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "release_digest_invalid"

jq_bin="${JANUS_JQ_BIN:-jq}"
gh_bin="${JANUS_GH_BIN:-gh}"
cosign_bin="${JANUS_COSIGN_BIN:-cosign}"
command -v "${jq_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"
command -v "${gh_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"
command -v "${cosign_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"

policy_id="$("${jq_bin}" -er 'select(.schema_version == 1) | .policy_id | select(type == "string" and length > 0)' "${policy}")" ||
  fail "release_policy_invalid"
policy_version="$("${jq_bin}" -er '.policy_version | select(type == "number" and . > 0 and floor == .)' "${policy}")" ||
  fail "release_policy_invalid"
required_mode="$("${jq_bin}" -r --arg mode "${mode}" '
  if (.required_modes | type) == "array" then
    (.required_modes | index($mode) != null)
  else
    error("required_modes")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
[[ "${required_mode}" == "true" ]] || fail "release_mode_not_admissible"

mode_rank() {
  case "$1" in
    dev) printf '0' ;;
    self_hosted) printf '1' ;;
    production) printf '2' ;;
    enterprise) printf '3' ;;
    *) fail "release_mode_invalid" ;;
  esac
}

deny_downgrade="$("${jq_bin}" -r '
  if (.deny_mode_downgrade | type) == "boolean" then
    .deny_mode_downgrade
  else
    error("deny_mode_downgrade")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
if [[ "${deny_downgrade}" == "true" ]] &&
  (( $(mode_rank "${previous_mode}") > $(mode_rank "${mode}") )); then
  fail "release_mode_downgrade"
fi

channel_json="$(
  "${jq_bin}" -cer --arg channel "${channel}" '
    [.channels[] | select(.name == $channel)] |
    if length == 1 then .[0] else error("channel") end
  ' "${policy}"
)" || fail "release_channel_denied"

expected_image="$("${jq_bin}" -er '.image' <<<"${channel_json}")" || fail "release_policy_invalid"
tag_prefix="$("${jq_bin}" -er '.tag_prefix' <<<"${channel_json}")" || fail "release_policy_invalid"
repository="$("${jq_bin}" -er '.repository' <<<"${channel_json}")" || fail "release_policy_invalid"
signer_workflow="$("${jq_bin}" -er '.signer_workflow' <<<"${channel_json}")" || fail "release_policy_invalid"
identity_prefix="$("${jq_bin}" -er '.certificate_identity_prefix' <<<"${channel_json}")" || fail "release_policy_invalid"
oidc_issuer="$("${jq_bin}" -er '.oidc_issuer' <<<"${channel_json}")" || fail "release_policy_invalid"
provenance_predicate="$("${jq_bin}" -er '.provenance_predicate_type' <<<"${channel_json}")" || fail "release_policy_invalid"
sbom_predicate="$("${jq_bin}" -er '.sbom_predicate_type' <<<"${channel_json}")" || fail "release_policy_invalid"

[[ "${image}" == "${expected_image}" && "${tag}" == "${tag_prefix}"* ]] ||
  fail "release_channel_denied"
case "${tag,,}" in
  *-dev*|*.dev*|*snapshot*|*dirty*) fail "release_development_artifact" ;;
esac
revoked="$("${jq_bin}" -r --arg digest "${digest}" '
  if (.revoked_digests | type) == "array" then
    (.revoked_digests | index($digest) != null)
  else
    error("revoked_digests")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
[[ "${revoked}" == "false" ]] || fail "release_digest_revoked"

ref="${image}@${digest}"
source_ref="refs/tags/${tag}"
identity="${identity_prefix}${tag}"

"${cosign_bin}" verify "${ref}" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${oidc_issuer}" >/dev/null ||
  fail "release_signature_untrusted"

"${gh_bin}" attestation verify "oci://${ref}" \
  --bundle-from-oci \
  --repo "${repository}" \
  --signer-workflow "${signer_workflow}" \
  --source-ref "${source_ref}" \
  --cert-identity "${identity}" \
  --cert-oidc-issuer "${oidc_issuer}" \
  --predicate-type "${provenance_predicate}" >/dev/null ||
  fail "release_provenance_untrusted"

"${gh_bin}" attestation verify "oci://${ref}" \
  --bundle-from-oci \
  --repo "${repository}" \
  --signer-workflow "${signer_workflow}" \
  --source-ref "${source_ref}" \
  --cert-identity "${identity}" \
  --cert-oidc-issuer "${oidc_issuer}" \
  --predicate-type "${sbom_predicate}" >/dev/null ||
  fail "release_sbom_untrusted"

output_parent="$(dirname "${output}")"
[[ -d "${output_parent}" && ! -L "${output_parent}" && ! -L "${output}" ]] ||
  fail "release_receipt_unavailable"
umask 077
temporary="$(mktemp "${output}.tmp.XXXXXX")"
cleanup() {
  if [[ -n "${temporary:-}" && -e "${temporary}" ]]; then
    rm -f -- "${temporary}"
  fi
}
trap cleanup EXIT

"${jq_bin}" -n \
  --arg policy_id "${policy_id}" \
  --argjson policy_version "${policy_version}" \
  --arg channel "${channel}" \
  --arg mode "${mode}" \
  --arg previous_mode "${previous_mode}" \
  --arg image "${image}" \
  --arg tag "${tag}" \
  --arg digest "${digest}" \
  --arg identity "${identity}" \
  --arg oidc_issuer "${oidc_issuer}" \
  --arg repository "${repository}" \
  --arg signer_workflow "${signer_workflow}" \
  --arg source_ref "${source_ref}" \
  --arg provenance_predicate "${provenance_predicate}" \
  --arg sbom_predicate "${sbom_predicate}" '
  {
    schema_version: 1,
    policy_id: $policy_id,
    policy_version: $policy_version,
    channel: $channel,
    mode: $mode,
    previous_mode: $previous_mode,
    artifact: {
      image: $image,
      tag: $tag,
      digest: $digest,
      development: false
    },
    signature: {
      verified: true,
      identity: $identity,
      oidc_issuer: $oidc_issuer
    },
    provenance: {
      verified: true,
      repository: $repository,
      signer_workflow: $signer_workflow,
      source_ref: $source_ref,
      predicate_type: $provenance_predicate
    },
    sbom: {
      verified: true,
      predicate_type: $sbom_predicate
    }
  }
' >"${temporary}"
chmod 0444 "${temporary}"
mv -f -- "${temporary}" "${output}"
temporary=""
printf 'release_trust_ok policy=%s version=%s channel=%s artifact=%s\n' \
  "${policy_id}" "${policy_version}" "${channel}" "${ref}"

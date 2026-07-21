#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
admit="${repo}/scripts/admit-engine-release.sh"
policy="${repo}/config/release-channels/v1.json"
image="ghcr.io/markus-barta/janus/janus-engine"
tag="rust-engine-v0.1.7"
digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
revoked="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT

base_args=(
  --policy "${policy}"
  --channel stable
  --mode enterprise
  --previous-mode enterprise
  --image "${image}"
  --tag "${tag}"
  --digest "${digest}"
)

JANUS_COSIGN_BIN=true JANUS_GH_BIN=true \
  "${admit}" "${base_args[@]}" --output "${work}/trusted.json" >/dev/null
jq -e '
  .policy_id == "janus-engine-release-v1" and
  .channel == "stable" and
  .mode == "enterprise" and
  .artifact.digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .signature.verified and .provenance.verified and .sbom.verified
' "${work}/trusted.json" >/dev/null
[[ ! -w "${work}/trusted.json" ]]

expect_denied() {
  local expected="$1"
  shift
  local error_file="${work}/error"
  if JANUS_COSIGN_BIN="${JANUS_TEST_COSIGN_BIN:-true}" \
    JANUS_GH_BIN="${JANUS_TEST_GH_BIN:-true}" \
    "${admit}" "$@" --output "${work}/denied.json" >/dev/null 2>"${error_file}"; then
    printf 'expected admission denial: %s\n' "${expected}" >&2
    exit 1
  fi
  grep -qx "${expected}" "${error_file}"
}

expect_denied release_development_artifact \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}-dev" --digest "${digest}"
expect_denied release_digest_revoked \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${revoked}"
expect_denied release_channel_denied \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "ghcr.io/attacker/janus" --tag "${tag}" --digest "${digest}"
expect_denied release_mode_downgrade \
  --policy "${policy}" --channel stable --mode production --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${digest}"

JANUS_TEST_COSIGN_BIN=false expect_denied release_signature_untrusted "${base_args[@]}"
JANUS_TEST_GH_BIN=false expect_denied release_provenance_untrusted "${base_args[@]}"

compatible_gh="${work}/gh-compatible"
# shellcheck disable=SC2016 # literal lines for the fixture executable
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'args=" $* "' \
  '[[ "$args" == *" --signer-workflow "* ]]' \
  '[[ "$args" == *" --source-ref "* ]]' \
  '[[ "$args" == *" --cert-oidc-issuer "* ]]' \
  '[[ "$args" != *" --cert-identity "* ]]' \
  >"${compatible_gh}"
chmod 0700 "${compatible_gh}"
JANUS_COSIGN_BIN=true JANUS_GH_BIN="${compatible_gh}" \
  "${admit}" "${base_args[@]}" --output "${work}/gh-compatible.json" >/dev/null

sbom_failing_gh="${work}/gh-sbom-failing"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case "$*" in *spdx.dev/Document/v2.3*) exit 1 ;; *) exit 0 ;; esac' \
  >"${sbom_failing_gh}"
chmod 0700 "${sbom_failing_gh}"
JANUS_TEST_GH_BIN="${sbom_failing_gh}" expect_denied release_sbom_untrusted "${base_args[@]}"

printf 'ok: release admission fixtures passed\n'

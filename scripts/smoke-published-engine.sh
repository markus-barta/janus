#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${JANUS_PUBLISHED_ENGINE_IMAGE:-ghcr.io/markus-barta/janus/janus-engine}"
tag="${JANUS_PUBLISHED_ENGINE_TAG:-rust-engine-v0.1.10}"
platform="${JANUS_PUBLISHED_ENGINE_PLATFORM:-}"
digest="${JANUS_PUBLISHED_ENGINE_DIGEST:-}"
digest_source="provided"
policy="${JANUS_RELEASE_CHANNEL_POLICY:-${repo}/config/release-channels/v1.json}"
channel="${JANUS_RELEASE_CHANNEL:-stable}"
mode="${JANUS_PRODUCT_MODE:-enterprise}"
previous_mode="${JANUS_PREVIOUS_PRODUCT_MODE:-${mode}}"
receipt="${JANUS_PUBLISHED_ENGINE_ADMISSION_RECEIPT:-}"
temporary_dir=""

if [[ -z "${digest}" ]]; then
  digest_source="resolved"
  digest="$(
    docker buildx imagetools inspect "${image}:${tag}" |
      awk '/^Digest:/ { print $2; exit }'
  )"
fi

if [[ -z "${digest}" || "${digest}" != sha256:* ]]; then
  echo "failed to resolve digest for ${image}:${tag}" >&2
  exit 1
fi

ref="${image}@${digest}"
echo "${digest_source} ${image}:${tag} -> ${ref}"

if [[ -z "${receipt}" ]]; then
  temporary_dir="$(mktemp -d)"
  receipt="${temporary_dir}/release-admission.json"
fi
cleanup() {
  if [[ -n "${temporary_dir}" && -d "${temporary_dir}" ]]; then
    rm -rf -- "${temporary_dir}"
  fi
}
trap cleanup EXIT

"${repo}/scripts/admit-engine-release.sh" \
  --policy "${policy}" \
  --channel "${channel}" \
  --mode "${mode}" \
  --previous-mode "${previous_mode}" \
  --image "${image}" \
  --tag "${tag}" \
  --digest "${digest}" \
  --output "${receipt}"

smoke_args=("--image" "${ref}")
if [[ -n "${platform}" ]]; then
  smoke_args+=("--platform" "${platform}")
fi

python3 "${repo}/scripts/smoke-warden-mcp.py" "${smoke_args[@]}"

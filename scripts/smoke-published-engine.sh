#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${JANUS_PUBLISHED_ENGINE_IMAGE:-ghcr.io/markus-barta/janus/janus-engine}"
tag="${JANUS_PUBLISHED_ENGINE_TAG:-rust-engine-v0.1.1}"
platform="${JANUS_PUBLISHED_ENGINE_PLATFORM:-}"
repo_slug="${JANUS_PUBLISHED_ENGINE_REPO:-markus-barta/janus}"
signer_workflow="${JANUS_PUBLISHED_ENGINE_SIGNER_WORKFLOW:-${repo_slug}/.github/workflows/rust.yml}"
require_cosign="${JANUS_PUBLISHED_ENGINE_REQUIRE_COSIGN:-1}"
digest="${JANUS_PUBLISHED_ENGINE_DIGEST:-}"
digest_source="provided"

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

gh attestation verify "oci://${ref}" \
  --repo "${repo_slug}" \
  --signer-workflow "${signer_workflow}" \
  --source-ref "refs/tags/${tag}" >/dev/null
echo "github provenance verified for ${ref}"

if command -v cosign >/dev/null 2>&1; then
  cosign verify "${ref}" \
    --certificate-identity-regexp "https://github.com/${repo_slug}/.github/workflows/rust.yml@refs/tags/${tag}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
  echo "cosign signature verified for ${ref}"
elif [[ "${require_cosign}" == "1" || "${require_cosign}" == "true" ]]; then
  echo "cosign not found; keyless signature verification is required" >&2
  exit 1
else
  echo "cosign not found; skipped keyless signature verification" >&2
fi

smoke_args=("--image" "${ref}")
if [[ -n "${platform}" ]]; then
  smoke_args+=("--platform" "${platform}")
fi

python3 "${repo}/scripts/smoke-warden-mcp.py" "${smoke_args[@]}"

#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gitleaks_bin="${GITLEAKS_BIN:-gitleaks}"

if [[ ! -x "${gitleaks_bin}" ]] && ! command -v "${gitleaks_bin}" >/dev/null 2>&1; then
  echo "gitleaks binary unavailable" >&2
  exit 1
fi

ignore_count="$(awk '!/^#/ && NF { count++ } END { print count + 0 }' "${repo}/.gitleaksignore")"
if [[ "${ignore_count}" != "6" ]]; then
  echo "expected exactly six reviewed Gitleaks fingerprints, got ${ignore_count}" >&2
  exit 1
fi

cd "${repo}"
"${gitleaks_bin}" git \
  --gitleaks-ignore-path "${repo}/.gitleaksignore" \
  --redact=100 \
  --no-banner \
  --no-color \
  --log-level warn \
  --log-opts=--all

tracked_tree="$(mktemp -d)"
negative_repo="$(mktemp -d)"
cleanup() {
  rm -rf -- "${tracked_tree}" "${negative_repo}"
}
trap cleanup EXIT

git archive "$(git write-tree)" | tar -xf - -C "${tracked_tree}"
(
  cd "${tracked_tree}"
  "${gitleaks_bin}" dir \
    --gitleaks-ignore-path .gitleaksignore \
    --redact=100 \
    --no-banner \
    --no-color \
    --log-level warn \
    .
)

git -C "${negative_repo}" init -q
git -C "${negative_repo}" config user.name "Janus Gitleaks Fixture"
git -C "${negative_repo}" config user.email "markus@barta.com"
printf 'token = "%s%s"\n' 'glpat-' '0123456789abcdefghij' >"${negative_repo}/fixture.txt"
git -C "${negative_repo}" add fixture.txt
git -C "${negative_repo}" commit -qm "synthetic negative fixture"

if "${gitleaks_bin}" git \
  --redact=100 \
  --no-banner \
  --no-color \
  --log-level error \
  "${negative_repo}" >/dev/null 2>&1; then
  echo "Gitleaks negative fixture was not rejected" >&2
  exit 1
fi

echo "ok: Gitleaks full history, tracked tree, and negative fixture"

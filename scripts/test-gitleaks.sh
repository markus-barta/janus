#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gitleaks_bin="${GITLEAKS_BIN:-gitleaks}"

if [[ ! -x "${gitleaks_bin}" ]] && ! command -v "${gitleaks_bin}" >/dev/null 2>&1; then
  echo "gitleaks binary unavailable" >&2
  exit 1
fi

ignore_count="$(awk '!/^#/ && NF { count++ } END { print count + 0 }' "${repo}/.gitleaksignore")"
if [[ "${ignore_count}" != "20" ]]; then
  echo "expected exactly twenty reviewed Gitleaks fingerprints, got ${ignore_count}" >&2
  exit 1
fi

cd "${repo}"
history_report="$(mktemp)"
tracked_tree="$(mktemp -d)"
tracked_report="$(mktemp)"
negative_repo="$(mktemp -d)"
cleanup() {
  rm -f -- "${history_report}" "${tracked_report}"
  rm -rf -- "${tracked_tree}" "${negative_repo}"
}
trap cleanup EXIT

report_findings() {
  local phase=$1
  local report=$2
  printf 'Gitleaks %s scan rejected reviewed input; value_returned=false\n' "${phase}" >&2
  jq -r \
    '.[] | [.RuleID, .File, (.StartLine | tostring), .Commit, .Fingerprint] | @tsv' \
    "${report}" >&2
}

if ! "${gitleaks_bin}" git \
  --gitleaks-ignore-path "${repo}/.gitleaksignore" \
  --redact=100 \
  --no-banner \
  --no-color \
  --log-level warn \
  --report-format json \
  --report-path "${history_report}" \
  --log-opts=--all; then
  report_findings history "${history_report}"
  exit 1
fi

git archive "$(git write-tree)" | tar -xf - -C "${tracked_tree}"
if ! (
  cd "${tracked_tree}"
  "${gitleaks_bin}" dir \
    --gitleaks-ignore-path .gitleaksignore \
    --redact=100 \
    --no-banner \
    --no-color \
    --log-level warn \
    --report-format json \
    --report-path "${tracked_report}" \
    .
); then
  report_findings tracked-tree "${tracked_report}"
  exit 1
fi

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

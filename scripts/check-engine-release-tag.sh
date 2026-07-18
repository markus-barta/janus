#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'usage: %s rust-engine-vX.Y.Z\n' "${0##*/}" >&2
  exit 2
fi

release_tag="$1"
workspace_version="$(
  awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    in_workspace_package && /^\[/ { exit }
    in_workspace_package && /^version[[:space:]]*=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*"/, "", value)
      sub(/"[[:space:]]*$/, "", value)
      print value
      exit
    }
  ' Cargo.toml
)"

[ -n "$workspace_version" ] || {
  printf 'could not resolve workspace.package.version from Cargo.toml\n' >&2
  exit 1
}

expected_tag="rust-engine-v${workspace_version}"
if [ "$release_tag" != "$expected_tag" ]; then
  printf 'release tag %s does not match Cargo workspace version %s (expected %s)\n' \
    "$release_tag" "$workspace_version" "$expected_tag" >&2
  exit 1
fi

printf 'ok: release tag %s matches Cargo workspace version %s\n' \
  "$release_tag" "$workspace_version"

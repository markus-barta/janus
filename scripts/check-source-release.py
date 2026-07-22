#!/usr/bin/env python3
"""Validate the released-source signature policy and exact release binding."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/assurance/source-release-signing-v1.json"
MANIFEST_KEYS = {"schema_version", "repository", "tag", "commit", "workflow", "image", "image_digest"}


class SourcePolicyError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourcePolicyError(message)


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy.get("schema_version") == 1, "unsupported source-signing schema")
    require(policy.get("owner") == "JANUS-324", "source-signing owner changed")
    require(policy.get("effective_on") == "2026-07-22", "effective date changed")
    require(policy.get("repository") == "markus-barta/janus", "repository changed")
    subset = policy.get("signed_subset")
    require(isinstance(subset, list) and len(subset) == 2, "released-source subset must be exact")
    require({item.get("tag_prefix") for item in subset} == {"go-envelope-v", "rust-engine-v"}, "released-source tag subset changed")
    require({item.get("workflow") for item in subset} == {".github/workflows/go-envelope.yml", ".github/workflows/rust.yml"}, "workflow subset changed")
    method = policy.get("method", {})
    require(method.get("tool") == "cosign" and method.get("mode") == "keyless_oidc", "source signatures must stay keyless Sigstore")
    require(method.get("issuer") == "https://token.actions.githubusercontent.com", "OIDC issuer changed")
    require(method.get("artifact") == "source-release.json", "source artifact name changed")
    require(method.get("bundle") == "source-release.sigstore.json", "source bundle name changed")
    require(bool(policy.get("recovery")) and bool(policy.get("history")), "recovery/history policy is incomplete")


def matching_rule(policy: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    matches = [item for item in policy["signed_subset"] if manifest["tag"].startswith(item["tag_prefix"])]
    require(len(matches) == 1, "tag is outside the released-source subset")
    return matches[0]


def validate_manifest(policy: dict[str, Any], manifest: dict[str, Any], bundle: pathlib.Path | None, check_git: bool) -> None:
    require(set(manifest) == MANIFEST_KEYS, "source release manifest fields changed")
    require(manifest.get("schema_version") == 1, "unsupported source manifest schema")
    require(manifest.get("repository") == policy["repository"], "source repository mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", "")) is not None, "source commit is invalid")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", manifest.get("image_digest", "")) is not None, "image digest is invalid")
    rule = matching_rule(policy, manifest)
    require(manifest.get("workflow") == rule["workflow"], "source workflow mismatch")
    require(manifest.get("image") == rule["image"], "source image mismatch")
    require(bundle is not None and bundle.is_file() and bundle.stat().st_size > 0, "released source is unsigned")
    json.loads(bundle.read_text())
    if check_git:
        resolved = subprocess.run(
            ["git", "rev-list", "-n", "1", manifest["tag"]],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        require(resolved == manifest["commit"], "release tag does not resolve to signed commit")


def self_test(policy: dict[str, Any]) -> None:
    validate_policy(copy.deepcopy(policy))
    manifest = {
        "schema_version": 1,
        "repository": "markus-barta/janus",
        "tag": "rust-engine-v0.0.0-fixture",
        "commit": "0" * 40,
        "workflow": ".github/workflows/rust.yml",
        "image": "ghcr.io/markus-barta/janus/janus-engine",
        "image_digest": "sha256:" + "0" * 64,
    }
    try:
        validate_manifest(policy, manifest, None, False)
    except SourcePolicyError:
        pass
    else:
        raise SourcePolicyError("unsigned release fixture passed")
    wrong = copy.deepcopy(manifest)
    wrong["workflow"] = ".github/workflows/unreviewed.yml"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as bundle:
        bundle.write("{}")
        bundle.flush()
        try:
            validate_manifest(policy, wrong, pathlib.Path(bundle.name), False)
        except SourcePolicyError:
            pass
        else:
            raise SourcePolicyError("wrong-identity fixture passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--bundle", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--skip-git", action="store_true")
    args = parser.parse_args()
    try:
        policy = json.loads(POLICY.read_text())
        validate_policy(policy)
        if args.self_test:
            self_test(policy)
        if args.manifest:
            manifest = json.loads(args.manifest.read_text())
            validate_manifest(policy, manifest, args.bundle, not args.skip_git)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, SourcePolicyError) as error:
        print(f"source release policy failed: {error}", file=sys.stderr)
        return 1
    print("source release policy passed: exact subset and signed source/tag/image binding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

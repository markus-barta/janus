#!/usr/bin/env python3
"""Validate the released-source signature policy and exact release binding."""

from __future__ import annotations

import argparse
import copy
import datetime
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
EFFECTIVE_FROM = "2026-07-22T14:00:17Z"
CANONICAL_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
EXPECTED_GRANDFATHERED_RELEASES = [
    {
        "tag": "go-envelope-v1.162",
        "commit": "d64b23933580c1e1541baec19dc7817c8464cf96",
        "published_at": "2026-07-22T12:48:31Z",
    }
]


class SourcePolicyError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourcePolicyError(message)


def parse_canonical_utc(value: Any, field: str) -> datetime.datetime:
    require(
        isinstance(value, str) and CANONICAL_UTC.fullmatch(value) is not None,
        f"{field} must use canonical UTC YYYY-MM-DDTHH:MM:SSZ",
    )
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SourcePolicyError(f"{field} is not a valid UTC timestamp") from error
    return parsed.replace(tzinfo=datetime.timezone.utc)


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy.get("schema_version") == 1, "unsupported source-signing schema")
    require(policy.get("owner") == "JANUS-324", "source-signing owner changed")
    require("effective_on" not in policy, "ambiguous date-only source-signing cutoff returned")
    effective_from_text = policy.get("effective_from")
    effective_from = parse_canonical_utc(effective_from_text, "effective_from")
    require(effective_from_text == EFFECTIVE_FROM, "source-signing cutoff changed")
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
    grandfathered = policy.get("grandfathered_releases")
    require(
        isinstance(grandfathered, list) and len(grandfathered) == 1,
        "released-source grandfather set must contain one exact release",
    )
    for release in grandfathered:
        require(
            isinstance(release, dict)
            and set(release) == {"tag", "commit", "published_at"},
            "grandfathered release fields changed",
        )
        published_at = parse_canonical_utc(
            release.get("published_at"), "grandfathered published_at"
        )
        require(published_at < effective_from, "grandfathered release is not before cutoff")
        require(
            re.fullmatch(r"[0-9a-f]{40}", release.get("commit", "")) is not None,
            "grandfathered release commit is invalid",
        )
        require(
            isinstance(release.get("tag"), str)
            and sum(release["tag"].startswith(item["tag_prefix"]) for item in subset) == 1,
            "grandfathered tag is outside the released-source subset",
        )
    require(
        grandfathered == EXPECTED_GRANDFATHERED_RELEASES,
        "released-source grandfather set changed",
    )
    require(
        policy.get("pre_policy_release_disposition") == "deny_unlisted",
        "unlisted pre-policy releases must remain inadmissible",
    )
    require(bool(policy.get("recovery")) and bool(policy.get("history")), "recovery/history policy is incomplete")


def verify_grandfathered_releases(policy: dict[str, Any]) -> None:
    repository = policy["repository"]
    for release in policy["grandfathered_releases"]:
        resolved = subprocess.run(
            ["git", "rev-list", "-n", "1", release["tag"]],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        require(
            resolved == release["commit"],
            "grandfathered release tag does not resolve to policy commit",
        )
        response = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repository}/releases/tags/{release['tag']}",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(response.stdout)
        require(metadata.get("tag_name") == release["tag"], "GitHub release tag mismatch")
        require(
            metadata.get("target_commitish") == release["commit"],
            "GitHub release target commit mismatch",
        )
        require(
            metadata.get("published_at") == release["published_at"],
            "GitHub release publication time mismatch",
        )
        require(
            metadata.get("draft") is False and metadata.get("prerelease") is False,
            "grandfathered GitHub release is not a final release",
        )
        asset_names = {
            asset.get("name")
            for asset in metadata.get("assets", [])
            if isinstance(asset, dict)
        }
        require(
            {"source-release.json", "source-release.sigstore.json"}.isdisjoint(
                asset_names
            ),
            "grandfathered release unexpectedly carries source-signing assets",
        )


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
    ambiguous = copy.deepcopy(policy)
    ambiguous.pop("effective_from")
    ambiguous["effective_on"] = "2026-07-22"
    try:
        validate_policy(ambiguous)
    except SourcePolicyError:
        pass
    else:
        raise SourcePolicyError("date-only cutoff fixture passed")
    noncanonical = copy.deepcopy(policy)
    noncanonical["effective_from"] = "2026-07-22T16:00:17+02:00"
    try:
        validate_policy(noncanonical)
    except SourcePolicyError:
        pass
    else:
        raise SourcePolicyError("noncanonical cutoff fixture passed")
    late_grandfather = copy.deepcopy(policy)
    late_grandfather["grandfathered_releases"][0]["published_at"] = policy["effective_from"]
    try:
        validate_policy(late_grandfather)
    except SourcePolicyError as error:
        require(
            str(error) == "grandfathered release is not before cutoff",
            "cutoff-equality fixture failed before the temporal boundary",
        )
    else:
        raise SourcePolicyError("post-cutoff grandfather fixture passed")
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
    parser.add_argument("--verify-grandfathered", action="store_true")
    parser.add_argument("--skip-git", action="store_true")
    args = parser.parse_args()
    try:
        policy = json.loads(POLICY.read_text())
        validate_policy(policy)
        if args.self_test:
            self_test(policy)
        if args.verify_grandfathered:
            verify_grandfathered_releases(policy)
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

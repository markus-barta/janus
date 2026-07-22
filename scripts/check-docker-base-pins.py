#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
INVENTORY = REPO / "config/release-channels/base-images-v1.json"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
TOP_LEVEL_KEYS = {"schema_version", "reviewed_at", "update_policy", "images"}
POLICY_KEYS = {"source", "trigger", "validation"}
IMAGE_KEYS = {
    "id",
    "dockerfile",
    "stage",
    "name",
    "tag",
    "digest",
    "required_platforms",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_inventory() -> dict:
    data = json.loads(INVENTORY.read_text())
    if set(data) != TOP_LEVEL_KEYS:
        fail("base-image inventory has unknown or missing top-level fields")
    if data["schema_version"] != 1:
        fail("unsupported base-image inventory schema")
    try:
        reviewed_at = dt.date.fromisoformat(data["reviewed_at"])
    except (TypeError, ValueError):
        fail("base-image inventory review date is invalid")
    if reviewed_at > dt.date.today():
        fail("base-image inventory review date is in the future")
    if set(data["update_policy"]) != POLICY_KEYS:
        fail("base-image update policy has unknown or missing fields")
    if not all(data["update_policy"].values()):
        fail("base-image update policy fields must be non-empty")
    if not isinstance(data["images"], list) or not data["images"]:
        fail("base-image inventory must contain images")
    return data


def expected_references(data: dict) -> dict[tuple[str, str], dict]:
    expected: dict[tuple[str, str], dict] = {}
    ids: set[str] = set()
    for image in data["images"]:
        if set(image) != IMAGE_KEYS:
            fail("base-image entry has unknown or missing fields")
        if image["id"] in ids:
            fail(f"duplicate base-image id: {image['id']}")
        ids.add(image["id"])
        key = (image["dockerfile"], image["stage"])
        if key in expected:
            fail(f"duplicate Dockerfile stage in inventory: {key}")
        if not DIGEST_RE.fullmatch(image["digest"]):
            fail(f"invalid digest for {image['id']}")
        if not image["tag"] or image["tag"] == "latest":
            fail(f"mutable or empty tag for {image['id']}")
        platforms = image["required_platforms"]
        if not platforms or len(platforms) != len(set(platforms)):
            fail(f"invalid platform list for {image['id']}")
        if any(not re.fullmatch(r"linux/(amd64|arm64)", item) for item in platforms):
            fail(f"unsupported platform in {image['id']}")
        expected[key] = image
    return expected


def dockerfile_references(files: set[str]) -> dict[tuple[str, str], str]:
    actual: dict[tuple[str, str], str] = {}
    for relative in sorted(files):
        for raw_line in (REPO / relative).read_text().splitlines():
            line = raw_line.strip()
            if not line.startswith("FROM "):
                continue
            parts = line.split()
            index = 1
            while index < len(parts) and parts[index].startswith("--"):
                index += 1
            if index >= len(parts):
                fail(f"malformed FROM line in {relative}")
            reference = parts[index]
            if reference == "scratch":
                continue
            stage = "runtime"
            if index + 2 < len(parts) and parts[index + 1].upper() == "AS":
                stage = parts[index + 2]
            key = (relative, stage)
            if key in actual:
                fail(f"duplicate Dockerfile stage: {key}")
            actual[key] = reference
    return actual


def repository_dockerfiles() -> set[str]:
    ignored_directories = {
        ".devenv",
        ".direnv",
        ".git",
        "node_modules",
        "result",
        "target",
    }
    discovered: set[str] = set()
    for root, directories, files in os.walk(REPO, followlinks=False):
        directories[:] = [
            item for item in directories if item not in ignored_directories
        ]
        for filename in files:
            if filename == "Dockerfile" or (
                filename.startswith("Dockerfile.")
                and not filename.endswith(".dockerignore")
            ):
                discovered.add(str((Path(root) / filename).relative_to(REPO)))
    return discovered


def verify_local(data: dict) -> list[dict]:
    expected = expected_references(data)
    inventoried_files = {item["dockerfile"] for item in data["images"]}
    discovered_files = repository_dockerfiles()
    if discovered_files != inventoried_files:
        missing = sorted(discovered_files - inventoried_files)
        stale = sorted(inventoried_files - discovered_files)
        fail(f"Dockerfile inventory drift missing={missing} stale={stale}")
    actual = dockerfile_references(discovered_files)
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        fail(f"Dockerfile/inventory stage drift missing={missing} extra={extra}")
    for key, image in expected.items():
        wanted = f"{image['name']}:{image['tag']}@{image['digest']}"
        if actual[key] != wanted:
            fail(f"base-image pin drift for {image['id']}: expected {wanted}")
    return list(expected.values())


def verify_remote(images: list[dict]) -> None:
    for image in images:
        tagged = f"{image['name']}:{image['tag']}"
        raw = subprocess.check_output(
            ["docker", "buildx", "imagetools", "inspect", "--raw", tagged]
        )
        resolved = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        if resolved != image["digest"]:
            fail(
                f"upstream tag movement for {image['id']}: "
                f"reviewed={image['digest']} resolved={resolved}"
            )
        manifest = json.loads(raw)
        available = {
            f"{item['platform']['os']}/{item['platform']['architecture']}"
            for item in manifest.get("manifests", [])
            if item.get("platform", {}).get("os") == "linux"
        }
        missing = sorted(set(image["required_platforms"]) - available)
        if missing:
            fail(f"missing platforms for {image['id']}: {missing}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args()
    data = load_inventory()
    images = verify_local(data)
    if args.verify_remote:
        verify_remote(images)
    print(
        "ok: immutable Docker base pins "
        f"images={len(images)} remote_verified={str(args.verify_remote).lower()}"
    )


if __name__ == "__main__":
    main()

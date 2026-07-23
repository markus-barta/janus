#!/usr/bin/env python3
"""Require immutable commit pins for every external GitHub Action."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
USES_LINE = re.compile(
    r"""^\s*(?:-\s*)?uses:\s*(?P<quote>["']?)(?P<value>[^"'#\s]+)(?P=quote)"""
    r"""(?:\s+#\s*(?P<comment>\S.*))?\s*$"""
)
USES_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])uses\s*:")
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACTION_PATH = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@+-]+)*$"
)
RELEASE_COMMENT = re.compile(r"^(?:v?\d+(?:[.A-Za-z0-9_-]*)?|stable)(?:\s|$)")


class PinError(RuntimeError):
    pass


def validate_text(source: str, text: str) -> tuple[int, int]:
    external = 0
    local_or_container = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = USES_LINE.match(line)
        if not match:
            if USES_TOKEN.search(line):
                raise PinError(f"{source}:{line_number}: malformed uses expression")
            continue
        value = match.group("value")
        if value.startswith("./") or value.startswith("docker://"):
            local_or_container += 1
            continue
        action, separator, ref = value.rpartition("@")
        if not separator or not ACTION_PATH.fullmatch(action):
            raise PinError(f"{source}:{line_number}: unsupported external action reference")
        if not FULL_COMMIT.fullmatch(ref):
            raise PinError(
                f"{source}:{line_number}: external action must use a full commit SHA"
            )
        comment = match.group("comment")
        if comment is None or not RELEASE_COMMENT.match(comment):
            raise PinError(
                f"{source}:{line_number}: commit pin needs a release or stable comment"
            )
        external += 1
    return external, local_or_container


def validate_repository() -> tuple[int, int]:
    workflows = sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in WORKFLOWS.glob(pattern)
    )
    if not workflows:
        raise PinError("no GitHub workflow files found")
    external = 0
    local_or_container = 0
    for workflow in workflows:
        workflow_external, workflow_local = validate_text(
            str(workflow.relative_to(ROOT)), workflow.read_text()
        )
        external += workflow_external
        local_or_container += workflow_local
    if external == 0:
        raise PinError("no external GitHub Actions found")
    return external, local_or_container


def self_test() -> None:
    pinned = (
        "steps:\n"
        "  - uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.2.3\n"
        "  - uses: owner/reusable/.github/workflows/check.yml@"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v4\n"
        "  - uses: 'owner/quoted@cccccccccccccccccccccccccccccccccccccccc' # v2\n"
        "  - uses: ./local-action\n"
        "  - uses: docker://alpine:3.23\n"
    )
    if validate_text("positive.yml", pinned) != (3, 2):
        raise PinError("positive fixture produced the wrong inventory")

    commented_mutable_ref = pinned + "  # - uses: attacker/action@latest\n"
    if validate_text("comment.yml", commented_mutable_ref) != (3, 2):
        raise PinError("commented fixture changed the inventory")

    negative_fixtures = {
        "mutable-tag": "steps:\n  - uses: owner/action@v1\n",
        "short-sha": "steps:\n  - uses: owner/action@abcdef1 # v1\n",
        "missing-comment": (
            "steps:\n"
            "  - uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        ),
        "dynamic-ref": "steps:\n  - uses: owner/action@${{ github.sha }} # stable\n",
        "malformed": "steps:\n  - uses: owner/action\n",
        "flow-style": (
            "steps:\n"
            "  - { uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }\n"
        ),
    }
    for name, fixture in negative_fixtures.items():
        try:
            validate_text(f"{name}.yml", fixture)
        except PinError:
            continue
        raise PinError(f"negative fixture passed: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        external, local_or_container = validate_repository()
    except (OSError, PinError) as error:
        print(f"GitHub Action pin gate failed: {error}", file=sys.stderr)
        return 1
    print(
        "GitHub Action pin gate passed: "
        f"{external} immutable external pins, "
        f"{local_or_container} local/container references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

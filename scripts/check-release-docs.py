#!/usr/bin/env python3
"""Keep release version, assurance claims, and local documentation links honest."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise RuntimeError(message)


def check_links(path: pathlib.Path) -> None:
    text = path.read_text()
    for raw in re.findall(r"(?<!!)\[[^]]+\]\(([^)]+)\)", text):
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            fail(f"broken local documentation link in {path.relative_to(ROOT)}: {raw}")


def main() -> int:
    try:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
        version = cargo["workspace"]["package"]["version"]
        tag = f"rust-engine-v{version}"
        readme = (ROOT / "README.md").read_text()
        normalized_readme = " ".join(readme.split())
        admission = (ROOT / "docs/release-admission.md").read_text()
        smoke = (ROOT / "scripts/smoke-published-engine.sh").read_text()
        rust_workflow = (ROOT / ".github/workflows/rust.yml").read_text()

        if readme.count(tag) != 3:
            fail(f"README must contain exactly three current release references: {tag}")
        if tag not in admission or tag not in smoke:
            fail("operator docs or published smoke default drifted from workspace version")
        for required in (
            "behavioral assurance script is intentionally not presented as the complete",
            "source/tag/commit/image-digest manifest",
            "scratch filesystem",
            "scripts/run-security-gates.sh",
        ):
            if required not in normalized_readme:
                fail(f"README assurance contract is missing: {required}")
        for asset in ("source-release.json", "source-release.sigstore.json", "rust-trivy-summary.json"):
            if asset not in rust_workflow:
                fail(f"Rust release workflow does not publish {asset}")
        dockerfile = (ROOT / "Dockerfile.engine").read_text()
        if "FROM scratch" not in dockerfile or "USER 65532:65532" not in dockerfile:
            fail("documented minimal runtime posture is not implemented")
        if re.search(r"^FROM debian", dockerfile, re.MULTILINE):
            fail("broad Debian runtime returned")

        for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
            check_links(path)
    except (OSError, KeyError, RuntimeError, tomllib.TOMLDecodeError) as error:
        print(f"release documentation check failed: {error}", file=sys.stderr)
        return 1
    print(f"release documentation check passed: {tag}, truthful assurance, local links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

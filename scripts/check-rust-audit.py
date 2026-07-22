#!/usr/bin/env python3
"""Fail closed around the narrowly time-bounded RustSec exceptions."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config/assurance/rust-advisory-exceptions-v1.json"
EXPECTED = {
    ("rsa", "0.9.10", "vulnerability", "RUSTSEC-2023-0071"),
    ("proc-macro-error2", "2.0.1", "unmaintained", "RUSTSEC-2026-0173"),
    ("spin", "0.9.8", "yanked", None),
}
EXPECTED_DIRECT_PARENTS = {
    "rsa": {"age", "ssh-key"},
    "proc-macro-error2": {"i18n-embed-fl"},
    "spin": {"lazy_static"},
}


class PolicyError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def parse_date(value: Any, field: str) -> dt.date:
    require(isinstance(value, str), f"{field} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise PolicyError(f"{field} must be an ISO date") from error


def validate_policy(policy: dict[str, Any], today: dt.date) -> None:
    require(policy.get("schema_version") == 1, "unsupported policy schema")
    require(policy.get("owner") == "JANUS-317", "exception owner must remain JANUS-317")
    created = parse_date(policy.get("created_on"), "created_on")
    reviewed = parse_date(policy.get("reviewed_on"), "reviewed_on")
    expires = parse_date(policy.get("expires_on"), "expires_on")
    require(created <= reviewed <= today, "review dates are invalid")
    require(today <= expires, "Rust advisory exception has expired")
    require((expires - created).days <= 90, "exception window exceeds 90 days")
    require(policy.get("review_cadence_days") == 30, "review cadence must be 30 days")
    restrictions = policy.get("runtime_restrictions")
    require(isinstance(restrictions, list) and len(restrictions) == 3, "runtime restrictions changed")

    exceptions = policy.get("exceptions")
    require(isinstance(exceptions, list), "exceptions must be a list")
    actual = {
        (item.get("package"), item.get("version"), item.get("kind"), item.get("advisory"))
        for item in exceptions
        if isinstance(item, dict)
    }
    require(actual == EXPECTED and len(exceptions) == len(EXPECTED), "exception set is not exact")
    for item in exceptions:
        require(item.get("rationale") and item.get("upstream"), "exception evidence is incomplete")
        paths = item.get("dependency_paths")
        require(isinstance(paths, list) and paths, "dependency paths are required")
        require(all(path and path[0] == item["package"] for path in paths), "dependency path is invalid")


def cargo_metadata() -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def validate_graph(policy: dict[str, Any], metadata: dict[str, Any]) -> None:
    packages = {package["id"]: package for package in metadata["packages"]}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in packages.values():
        by_name.setdefault(package["name"], []).append(package)
    require("secretspec" not in by_name, "unused secretspec/RSA generator dependency returned")
    for name, version, _, _ in EXPECTED:
        matches = [package for package in by_name.get(name, []) if package["version"] == version]
        require(len(matches) == 1, f"expected exact {name} {version} in Cargo.lock")

    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    reverse: dict[str, set[str]] = {package_id: set() for package_id in packages}
    for parent_id, node in nodes.items():
        for dependency in node["dependencies"]:
            reverse.setdefault(dependency, set()).add(parent_id)
    for child_name, expected_parents in EXPECTED_DIRECT_PARENTS.items():
        child = next(package for package in by_name[child_name] if package["version"] in {item[1] for item in EXPECTED if item[0] == child_name})
        parent_names = {packages[parent_id]["name"] for parent_id in reverse[child["id"]]}
        require(parent_names == expected_parents, f"unexpected direct parent for {child_name}: {sorted(parent_names)}")

    edges = {
        (packages[dependency]["name"], packages[parent_id]["name"])
        for parent_id, node in nodes.items()
        for dependency in node["dependencies"]
    }
    for item in policy["exceptions"]:
        for path in item["dependency_paths"]:
            require(all(edge in edges for edge in zip(path, path[1:])), f"dependency path no longer exists: {path}")


def run_audit(policy: dict[str, Any]) -> None:
    version = subprocess.run(
        ["cargo", "audit", "--version"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()
    require(version.split()[-1] == "0.22.2", "cargo-audit must be pinned to 0.22.2")
    ignored = [item["advisory"] for item in policy["exceptions"] if item["advisory"]]
    command = ["cargo", "audit", "--json"]
    for advisory in ignored:
        command.extend(["--ignore", advisory])
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    require(result.returncode == 0, "cargo audit did not produce the expected narrow report")
    report = json.loads(result.stdout)
    updated = dt.datetime.fromisoformat(report["database"]["last-updated"]).date()
    require((dt.date.today() - updated).days <= 7, "RustSec database is stale")
    require(report["vulnerabilities"]["count"] == 0, "unaccepted Rust vulnerability found")
    warnings = report.get("warnings", {})
    require(set(warnings) <= {"yanked"}, "unaccepted RustSec warning category found")
    yanked = {(entry["package"]["name"], entry["package"]["version"]) for entry in warnings.get("yanked", [])}
    require(yanked == {("spin", "0.9.8")}, "yanked dependency set changed")

    deny = ["cargo", "audit", "--deny", "warnings", "--no-yanked"]
    for advisory in ignored:
        deny.extend(["--ignore", advisory])
    subprocess.run(deny, cwd=ROOT, check=True)


def self_test(policy: dict[str, Any]) -> None:
    today = parse_date(policy["reviewed_on"], "reviewed_on")
    validate_policy(copy.deepcopy(policy), today)
    cases: list[tuple[str, dict[str, Any], dt.date]] = []
    expired = copy.deepcopy(policy)
    cases.append(("expired", expired, parse_date(policy["expires_on"], "expires_on") + dt.timedelta(days=1)))
    wrong_owner = copy.deepcopy(policy)
    wrong_owner["owner"] = "JANUS-000"
    cases.append(("wrong owner", wrong_owner, today))
    broad = copy.deepcopy(policy)
    broad["exceptions"].append(copy.deepcopy(broad["exceptions"][0]))
    cases.append(("broad exception", broad, today))
    for name, candidate, candidate_today in cases:
        try:
            validate_policy(candidate, candidate_today)
        except PolicyError:
            continue
        raise PolicyError(f"negative fixture passed: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=pathlib.Path, default=DEFAULT_POLICY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        policy = json.loads(args.policy.read_text())
        validate_policy(policy, dt.date.today())
        if args.self_test:
            self_test(policy)
        validate_graph(policy, cargo_metadata())
        run_audit(policy)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, PolicyError) as error:
        print(f"rust audit policy failed: {error}", file=sys.stderr)
        return 1
    print("rust audit policy passed: exact, current, and time-bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

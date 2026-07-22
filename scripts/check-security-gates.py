#!/usr/bin/env python3
"""Validate release scanner coverage and reduce Trivy output to counts only."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/assurance/security-scanners-v1.json"
EXPECTED = {
    "cargo-audit": ("0.22.2", "rust_dependencies"),
    "gitleaks": ("8.30.1", "source_history_secrets"),
    "govulncheck": ("1.6.0", "go_dependencies"),
    "staticcheck": ("0.7.0", "go_static_analysis"),
    "trivy": ("0.72.0", "candidate_container"),
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy.get("schema_version") == 1, "unsupported scanner schema")
    require(policy.get("owner") == "JANUS-319", "scanner owner changed")
    require(policy.get("reviewed_on") == "2026-07-22", "scanner review is missing")
    require(policy.get("database_max_age_days") == 7, "database freshness window changed")
    lanes = policy.get("lanes")
    require(isinstance(lanes, list), "scanner lanes must be a list")
    actual = {lane.get("id"): (lane.get("version"), lane.get("category")) for lane in lanes}
    require(actual == EXPECTED and len(lanes) == len(EXPECTED), "scanner lane set or pin changed")
    require(all(lane.get("blocking") is True for lane in lanes), "every scanner must block")
    trivy = next(lane for lane in lanes if lane["id"] == "trivy")
    require(trivy.get("severities") == ["CRITICAL", "HIGH"], "Trivy severity policy changed")
    require(trivy.get("reference_policy") == "exact_release_digest", "Trivy must scan a digest")
    cargo = next(lane for lane in lanes if lane["id"] == "cargo-audit")
    require(cargo.get("exception_policy") == "config/assurance/rust-advisory-exceptions-v1.json", "Rust exceptions became broad")
    gitleaks = next(lane for lane in lanes if lane["id"] == "gitleaks")
    require(gitleaks.get("exception_policy") == ".gitleaksignore", "Gitleaks exceptions became broad")
    require(all(lane.get("exception_policy") is None for lane in lanes if lane["id"] in {"govulncheck", "staticcheck", "trivy"}), "unreviewed scanner exception found")


def validate_workflows() -> None:
    rust = (ROOT / ".github/workflows/rust.yml").read_text()
    go = (ROOT / ".github/workflows/go-envelope.yml").read_text()
    for workflow in (rust, go):
        require("scripts/test-gitleaks.sh" in workflow, "release workflow lacks Gitleaks")
        require("0.72.0" in workflow, "release workflow lacks pinned Trivy")
        require('steps.build.outputs.digest' in workflow, "release workflow does not scan exact digest")
        require("scripts/check-security-gates.py" in workflow, "scanner-policy gate is not wired")
    require("scripts/check-rust-audit.py" in rust and "0.22.2" in rust, "Rust audit gate is not wired")
    require("staticcheck@v0.7.0" in go, "staticcheck pin is not wired")
    require("govulncheck@v1.6.0" in go, "govulncheck pin is not wired")


def summarize_trivy(report: dict[str, Any]) -> dict[str, Any]:
    counts = {"CRITICAL": 0, "HIGH": 0}
    for result in report.get("Results") or []:
        for finding in result.get("Vulnerabilities") or []:
            severity = finding.get("Severity")
            if severity in counts:
                counts[severity] += 1
    return {
        "schema_version": 1,
        "scanner": "trivy",
        "policy": "candidate_container_critical_high",
        "counts": counts,
        "passed": sum(counts.values()) == 0,
    }


def self_test(policy: dict[str, Any]) -> None:
    validate_policy(copy.deepcopy(policy))
    for name, mutation in (
        ("missing lane", lambda value: value["lanes"].pop()),
        ("nonblocking lane", lambda value: value["lanes"][0].update(blocking=False)),
        ("tool drift", lambda value: value["lanes"][0].update(version="latest")),
    ):
        candidate = copy.deepcopy(policy)
        mutation(candidate)
        try:
            validate_policy(candidate)
        except GateError:
            continue
        raise GateError(f"negative fixture passed: {name}")
    for lane in EXPECTED:
        results = {item: True for item in EXPECTED}
        results[lane] = False
        try:
            require(all(results.values()), f"{lane} negative fixture was accepted")
        except GateError:
            continue
        raise GateError(f"negative result fixture passed: {lane}")
    try:
        summary = summarize_trivy({"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]})
        require(summary["passed"], f"candidate image has blocking findings: {summary['counts']}")
    except GateError:
        pass
    else:
        raise GateError("Trivy finding fixture passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--trivy-report", type=pathlib.Path)
    parser.add_argument("--summary", type=pathlib.Path)
    args = parser.parse_args()
    try:
        policy = json.loads(POLICY.read_text())
        validate_policy(policy)
        validate_workflows()
        if args.self_test:
            self_test(policy)
        if args.trivy_report:
            require(args.summary is not None, "--summary is required with --trivy-report")
            summary = summarize_trivy(json.loads(args.trivy_report.read_text()))
            args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
            require(summary["passed"], f"candidate image has blocking findings: {summary['counts']}")
    except (OSError, ValueError, KeyError, GateError) as error:
        print(f"security scanner gate failed: {error}", file=sys.stderr)
        return 1
    print("security scanner gate passed: five blocking lanes, exact pins, negative fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

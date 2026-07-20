#!/usr/bin/env python3
"""Run the reviewed, bounded Rust security-property release gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = REPO / "config/assurance/security-properties-v1.json"
SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
SAFE_SELECTOR_CHARS = SAFE_ID_CHARS | frozenset("_")


class ContractError(ValueError):
    """The reviewed runner contract is invalid."""


@dataclass(frozen=True)
class Budget:
    cases: int
    max_input_bytes: int
    max_collection_items: int
    max_depth: int
    max_shrink_iterations: int
    max_flat_map_regenerations: int
    target_timeout_seconds: int


@dataclass(frozen=True)
class Target:
    id: str
    package: str
    test: str | None
    filter: str | None

    def command(self) -> list[str]:
        command = ["cargo", "test", "--locked", "-p", self.package]
        if self.test is not None:
            command.extend(["--test", self.test])
        if self.filter is not None:
            command.append(self.filter)
        command.extend(["--", "--test-threads=1"])
        return command


@dataclass(frozen=True)
class Contract:
    budget: Budget
    targets: tuple[Target, ...]


@dataclass(frozen=True)
class PublicFailure:
    target: str
    seed: str
    reason: str
    rerun: str

    def render(self) -> str:
        return (
            "error: security property target failed "
            f"target={self.target} seed={self.seed} reason={self.reason} "
            f"rerun={json.dumps(self.rerun)}"
        )


def _strict_object(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{context} has invalid fields")
    return value


def _positive_int(value: Any, context: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ContractError(f"{context} must be an integer in 1..={maximum}")
    return value


def _safe_id(value: Any, context: str, allowed: frozenset[str] = SAFE_ID_CHARS) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 80
        or value[0] == "-"
        or value[-1] == "-"
        or any(char not in allowed for char in value)
    ):
        raise ContractError(f"{context} must be a safe lowercase identifier")
    return value


def load_contract(path: Path) -> Contract:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("security property contract cannot be read") from error
    root = _strict_object(root, {"schema_version", "release", "targets"}, "contract")
    if root["schema_version"] != 1:
        raise ContractError("unsupported security property contract version")
    release = _strict_object(
        root["release"],
        {
            "cases",
            "max_input_bytes",
            "max_collection_items",
            "max_depth",
            "max_shrink_iterations",
            "max_flat_map_regenerations",
            "target_timeout_seconds",
        },
        "release budget",
    )
    budget = Budget(
        cases=_positive_int(release["cases"], "release cases", 1_000_000),
        max_input_bytes=_positive_int(
            release["max_input_bytes"], "maximum input bytes", 1_048_576
        ),
        max_collection_items=_positive_int(
            release["max_collection_items"], "maximum collection items", 4096
        ),
        max_depth=_positive_int(release["max_depth"], "maximum nesting depth", 128),
        max_shrink_iterations=_positive_int(
            release["max_shrink_iterations"], "maximum shrink iterations", 1_000_000
        ),
        max_flat_map_regenerations=_positive_int(
            release["max_flat_map_regenerations"],
            "maximum flat-map regenerations",
            10_000_000,
        ),
        target_timeout_seconds=_positive_int(
            release["target_timeout_seconds"], "target timeout", 3600
        ),
    )
    raw_targets = root["targets"]
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ContractError("contract targets must be a non-empty list")
    targets: list[Target] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_targets):
        if not isinstance(value, dict):
            raise ContractError(f"target {index} has invalid fields")
        selector_fields = {field for field in ("test", "filter") if field in value}
        if len(selector_fields) != 1:
            raise ContractError(f"target {index} must select one test or filter")
        value = _strict_object(
            value, {"id", "package"} | selector_fields, f"target {index}"
        )
        target_id = _safe_id(value["id"], f"target {index} id")
        package = _safe_id(value["package"], f"target {index} package")
        if target_id in seen:
            raise ContractError("target ids must be unique")
        seen.add(target_id)
        test = value.get("test")
        test_filter = value.get("filter")
        if (test is None) == (test_filter is None):
            raise ContractError(f"target {target_id} must select one test or filter")
        selected = test if test is not None else test_filter
        selected = _safe_id(
            selected, f"target {target_id} selector", SAFE_SELECTOR_CHARS
        )
        targets.append(
            Target(
                id=target_id,
                package=package,
                test=selected if test is not None else None,
                filter=selected if test_filter is not None else None,
            )
        )
    return Contract(budget=budget, targets=tuple(targets))


def property_environment(budget: Budget, cases: int) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "JANUS_PROPERTY_CASES": str(cases),
            "JANUS_PROPERTY_MAX_INPUT_BYTES": str(budget.max_input_bytes),
            "JANUS_PROPERTY_MAX_COLLECTION_ITEMS": str(budget.max_collection_items),
            "JANUS_PROPERTY_MAX_DEPTH": str(budget.max_depth),
            "JANUS_PROPERTY_MAX_SHRINK_ITERATIONS": str(budget.max_shrink_iterations),
            "PROPTEST_CASES": str(cases),
            "PROPTEST_MAX_SHRINK_ITERS": str(budget.max_shrink_iterations),
            "PROPTEST_MAX_FLAT_MAP_REGENS": str(budget.max_flat_map_regenerations),
            "PROPTEST_MAX_DEFAULT_SIZE_RANGE": str(budget.max_collection_items),
            "PROPTEST_RNG_ALGORITHM": "xs",
        }
    )
    return environment


def rerun_command(target: Target, cases: int, release: bool) -> str:
    command = ["python3", "scripts/run-security-properties.py", "--target", target.id]
    if release:
        command.append("--release")
    else:
        command.extend(["--cases", str(cases)])
    return " ".join(command)


def run_target(
    target: Target,
    budget: Budget,
    cases: int,
    release: bool,
    *,
    command_override: list[str] | None = None,
) -> PublicFailure | None:
    command = command_override if command_override is not None else target.command()
    try:
        completed = subprocess.run(
            command,
            cwd=REPO,
            env=property_environment(budget, cases),
            capture_output=True,
            text=False,
            timeout=budget.target_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        reason = "target_timeout"
    except OSError:
        reason = "target_unavailable"
    else:
        if completed.returncode == 0:
            return None
        reason = "property_failure"
    return PublicFailure(
        target=target.id,
        seed="source-persisted",
        reason=reason,
        rerun=rerun_command(target, cases, release),
    )


def self_test(contract: Contract) -> None:
    target = contract.targets[0]
    canary = "SENSITIVE_RUNNER_CANARY_MUST_NOT_ESCAPE"
    synthetic = [
        sys.executable,
        "-c",
        f"import sys; print({canary!r}); print({canary!r}, file=sys.stderr); sys.exit(7)",
    ]
    first = run_target(
        target,
        contract.budget,
        contract.budget.cases,
        True,
        command_override=synthetic,
    )
    second = run_target(
        target,
        contract.budget,
        contract.budget.cases,
        True,
        command_override=synthetic,
    )
    if first is None or first != second or canary in first.render():
        raise RuntimeError("runner output sanitization or determinism contract failed")
    lowered = max(1, contract.budget.cases - 1)
    effective = max(lowered, contract.budget.cases)
    if effective != contract.budget.cases:
        raise RuntimeError("release case budget was lowered")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--cases", type=int)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        contract = load_contract(args.contract)
        if args.self_test:
            self_test(contract)
            print("ok: security property runner self-test passed")
            return 0
        if args.release and args.cases is not None and args.cases < contract.budget.cases:
            raise ContractError("release mode cannot lower the reviewed case budget")
        cases = args.cases if args.cases is not None else contract.budget.cases
        cases = _positive_int(cases, "case budget", 1_000_000)
        if args.release:
            cases = max(cases, contract.budget.cases)
        selected = set(args.target)
        unknown = selected - {target.id for target in contract.targets}
        if unknown:
            raise ContractError("unknown security property target")
        targets = [target for target in contract.targets if not selected or target.id in selected]
        for target in targets:
            failure = run_target(target, contract.budget, cases, args.release)
            if failure is not None:
                print(failure.render(), file=sys.stderr)
                return 1
            print(f"ok: security property target={target.id} cases={cases}")
        return 0
    except (ContractError, RuntimeError) as error:
        print(f"error: security property runner reason={error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

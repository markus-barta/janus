#!/usr/bin/env python3
"""Run the closed, value-free managed-service UX assurance catalog."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG = REPO / "config/assurance/managed-service-ux-v1.json"
SAFE_ID = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
SAFE_GO_TEST = re.compile(r"^Test[A-Za-z0-9]+$")
SAFE_RUST_TEST = re.compile(r"^[a-z0-9_]+(?:::[a-z0-9_]+)*$")
SAFE_PACKAGE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ALLOWED_FAMILIES = frozenset(
    {
        "browser-lifecycle",
        "host-custody",
        "identity-authority",
        "intent-binding",
        "non-disclosure",
        "request-integrity",
        "workflow-recovery",
    }
)
ALLOWED_REVIEW_REQUIREMENTS = (
    "human-threat-model",
    "model-diverse-security",
)
ALLOWED_STACKS = frozenset({"browser", "go", "rust"})
ALLOWED_RUNNERS = frozenset({"cargo", "go", "npm", "shell"})
EXPECTED_FIELDS = {
    "id",
    "family",
    "stack",
    "runner",
    "working_directory",
    "target",
    "test_name",
    "value_returned",
}


class AssuranceError(ValueError):
    """The reviewed assurance catalog is invalid."""


@dataclass(frozen=True)
class Scenario:
    id: str
    family: str
    stack: str
    runner: str
    working_directory: str
    target: str
    test_name: str

    def command(self) -> list[str]:
        if self.runner == "cargo":
            return [
                "cargo",
                "test",
                "--locked",
                "-p",
                self.target,
                self.test_name,
                "--",
                "--exact",
                "--test-threads=1",
            ]
        if self.runner == "go":
            return [
                "go",
                "test",
                self.target,
                "-run",
                f"^{self.test_name}$",
                "-count=1",
            ]
        if self.runner == "npm":
            return ["npm", "run", self.target]
        return [str(REPO / self.target)]


@dataclass(frozen=True)
class Catalog:
    timeout_seconds: int
    scenarios: tuple[Scenario, ...]


def _strict_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AssuranceError(f"{context} has invalid fields")
    return value


def _safe_string(value: Any, pattern: re.Pattern[str], context: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AssuranceError(f"{context} is invalid")
    return value


def load_catalog(path: Path) -> Catalog:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssuranceError("catalog is unavailable") from error
    document = _strict_object(
        raw,
        {
            "schema",
            "schema_version",
            "reviewed_on",
            "review_valid_days",
            "timeout_seconds",
            "required_families",
            "review_requirements",
            "scenarios",
        },
        "catalog",
    )
    if (
        document["schema"] != "inspr.janus.managed-service-ux-assurance.v1"
        or document["schema_version"] != 1
    ):
        raise AssuranceError("catalog schema is unsupported")
    try:
        reviewed_on = date.fromisoformat(document["reviewed_on"])
    except (TypeError, ValueError) as error:
        raise AssuranceError("catalog review date is invalid") from error
    review_valid_days = document["review_valid_days"]
    if (
        not isinstance(review_valid_days, int)
        or isinstance(review_valid_days, bool)
        or not 1 <= review_valid_days <= 180
        or date.today() > reviewed_on + timedelta(days=review_valid_days)
        or reviewed_on > date.today()
    ):
        raise AssuranceError("catalog review is stale or invalid")
    timeout_seconds = document["timeout_seconds"]
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 10 <= timeout_seconds <= 600
    ):
        raise AssuranceError("catalog timeout is invalid")
    if document["required_families"] != sorted(ALLOWED_FAMILIES):
        raise AssuranceError("required assurance families changed")
    if document["review_requirements"] != list(ALLOWED_REVIEW_REQUIREMENTS):
        raise AssuranceError("review requirements changed")
    raw_scenarios = document["scenarios"]
    if not isinstance(raw_scenarios, list) or not 20 <= len(raw_scenarios) <= 64:
        raise AssuranceError("scenario count is invalid")

    scenarios: list[Scenario] = []
    identifiers: set[str] = set()
    covered_families: set[str] = set()
    covered_stacks: set[str] = set()
    for index, item in enumerate(raw_scenarios):
        scenario = _strict_object(item, EXPECTED_FIELDS, f"scenario {index}")
        identifier = _safe_string(scenario["id"], SAFE_ID, f"scenario {index} id")
        if identifier in identifiers:
            raise AssuranceError("scenario ids must be unique")
        identifiers.add(identifier)
        family = scenario["family"]
        stack = scenario["stack"]
        runner = scenario["runner"]
        if family not in ALLOWED_FAMILIES:
            raise AssuranceError(f"scenario {identifier} family is invalid")
        if stack not in ALLOWED_STACKS or runner not in ALLOWED_RUNNERS:
            raise AssuranceError(f"scenario {identifier} runner is invalid")
        if scenario["value_returned"] is not False:
            raise AssuranceError(f"scenario {identifier} permits a value return")
        working_directory = scenario["working_directory"]
        if working_directory not in {".", "go-envelope"}:
            raise AssuranceError(f"scenario {identifier} working directory is invalid")
        target = scenario["target"]
        test_name = scenario["test_name"]
        if runner == "cargo":
            _safe_string(target, SAFE_PACKAGE, f"scenario {identifier} package")
            _safe_string(test_name, SAFE_RUST_TEST, f"scenario {identifier} test")
            if stack != "rust" or working_directory != ".":
                raise AssuranceError(f"scenario {identifier} cargo binding is invalid")
        elif runner == "go":
            if target != "./..." or stack != "go" or working_directory != "go-envelope":
                raise AssuranceError(f"scenario {identifier} Go binding is invalid")
            _safe_string(test_name, SAFE_GO_TEST, f"scenario {identifier} test")
        elif runner == "npm":
            if (
                target != "test:managed-browser"
                or test_name != ""
                or stack != "browser"
                or working_directory != "."
            ):
                raise AssuranceError(f"scenario {identifier} npm binding is invalid")
        else:
            if (
                target != "scripts/smoke-janusd-lifecycle-entry.sh"
                or test_name != ""
                or stack != "rust"
                or working_directory != "."
            ):
                raise AssuranceError(f"scenario {identifier} shell binding is invalid")
        scenarios.append(
            Scenario(
                id=identifier,
                family=family,
                stack=stack,
                runner=runner,
                working_directory=working_directory,
                target=target,
                test_name=test_name,
            )
        )
        covered_families.add(family)
        covered_stacks.add(stack)
    if covered_families != ALLOWED_FAMILIES or covered_stacks != ALLOWED_STACKS:
        raise AssuranceError("catalog coverage is incomplete")
    return Catalog(timeout_seconds=timeout_seconds, scenarios=tuple(scenarios))


def self_test(path: Path) -> None:
    original = json.loads(path.read_text(encoding="utf-8"))
    mutations: list[dict[str, Any]] = []

    unknown = copy.deepcopy(original)
    unknown["unexpected"] = True
    mutations.append(unknown)

    missing_family = copy.deepcopy(original)
    missing_family["scenarios"] = [
        item
        for item in missing_family["scenarios"]
        if item["family"] != "request-integrity"
    ]
    mutations.append(missing_family)

    value_return = copy.deepcopy(original)
    value_return["scenarios"][0]["value_returned"] = True
    mutations.append(value_return)

    command_injection = copy.deepcopy(original)
    command_injection["scenarios"][0]["test_name"] = "TestSafe;uname"
    mutations.append(command_injection)

    wrong_review = copy.deepcopy(original)
    wrong_review["review_requirements"] = ["model-diverse-security"]
    mutations.append(wrong_review)

    import tempfile

    for mutation in mutations:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as fixture:
            json.dump(mutation, fixture)
            fixture.flush()
            try:
                load_catalog(Path(fixture.name))
            except AssuranceError:
                continue
            raise AssuranceError("self-test accepted an invalid catalog")
    print("ok: managed-service UX assurance self-test passed")


def run(catalog: Catalog, stack: str) -> None:
    selected = (
        catalog.scenarios
        if stack == "all"
        else tuple(item for item in catalog.scenarios if item.stack == stack)
    )
    if not selected:
        raise AssuranceError("selected assurance stack is empty")
    for scenario in selected:
        environment = os.environ.copy()
        if scenario.runner == "shell":
            # The isolated lifecycle fixture has no durable role registry.
            # Keep this conspicuous compatibility posture out of every other
            # security-boundary scenario.
            environment["JANUS_ROLE_AUTHORIZATION_MODE"] = "unsafe_disabled_dev"
            environment["JANUS_PRODUCT_MODE"] = "self_hosted"
        else:
            environment.pop("JANUS_ROLE_AUTHORIZATION_MODE", None)
            environment.pop("JANUS_PRODUCT_MODE", None)
        try:
            result = subprocess.run(
                scenario.command(),
                cwd=REPO / scenario.working_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=catalog.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AssuranceError(
                f"scenario failed id={scenario.id} family={scenario.family}"
            ) from error
        if result.returncode != 0:
            raise AssuranceError(
                f"scenario failed id={scenario.id} family={scenario.family}"
            )
        print(
            "ok: managed-service assurance "
            f"id={scenario.id} family={scenario.family} value_returned=false"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--stack",
        choices=("all", "browser", "go", "rust"),
        default="all",
    )
    args = parser.parse_args()
    try:
        catalog = load_catalog(args.catalog)
        if args.self_test:
            self_test(args.catalog)
        else:
            run(catalog, args.stack)
    except AssuranceError as error:
        print(f"error: managed-service UX assurance failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

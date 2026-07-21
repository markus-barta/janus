#!/usr/bin/env python3
"""Run the reviewed, deterministic Rust adversarial-scenario corpus."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = REPO / "config/assurance/adversarial-scenarios-v1.json"
SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
SAFE_CODE_CHARS = SAFE_ID_CHARS | frozenset("_")
SAFE_TEST_CHARS = SAFE_CODE_CHARS | frozenset(":")
ALLOWED_FAMILIES = (
    "approval-migration",
    "scope-recovery",
    "audit-integrity",
    "warden-abuse",
    "permit-execution",
    "rotation-failure",
    "sealed-recovery",
)
ALLOWED_TERMINAL_STATES = frozenset(
    {"blocked", "completed", "denied", "rolled-back"}
)
ALLOWED_AUDIT_EXPECTATIONS = frozenset({"required", "unavailable"})


class CorpusError(ValueError):
    """The reviewed adversarial corpus is invalid."""


@dataclass(frozen=True)
class Scenario:
    id: str
    family: str
    package: str
    test_binary: str | None
    test_name: str
    attack_phase: str
    expected_reason_code: str
    expected_terminal_state: str
    audit_expectation: str

    def command(self) -> list[str]:
        command = ["cargo", "test", "--locked", "-p", self.package]
        if self.test_binary is not None:
            command.extend(["--test", self.test_binary])
        command.extend(
            [self.test_name, "--", "--exact", "--test-threads=1"]
        )
        return command


@dataclass(frozen=True)
class Corpus:
    timeout_seconds: int
    scenarios: tuple[Scenario, ...]


@dataclass(frozen=True)
class PublicFailure:
    scenario: str
    family: str
    reason: str
    rerun: str

    def render(self) -> str:
        return (
            "error: adversarial scenario failed "
            f"scenario={self.scenario} family={self.family} reason={self.reason} "
            f"rerun={json.dumps(self.rerun)}"
        )


def _strict_object(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CorpusError(f"{context} has invalid fields")
    return value


def _safe_text(
    value: Any,
    context: str,
    allowed: frozenset[str] = SAFE_ID_CHARS,
    maximum: int = 100,
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value[0] in "-_"
        or value[-1] in "-_"
        or any(char not in allowed for char in value)
    ):
        raise CorpusError(f"{context} must be a safe lowercase identifier")
    return value


def _closed_string_list(
    value: Any,
    context: str,
    allowed: frozenset[str] = SAFE_CODE_CHARS,
) -> list[str]:
    if not isinstance(value, list) or not value:
        raise CorpusError(f"{context} must be a non-empty list")
    parsed = [_safe_text(item, context, allowed) for item in value]
    if len(parsed) != len(set(parsed)):
        raise CorpusError(f"{context} must not contain duplicates")
    return parsed


def _parse_corpus(root: Any) -> Corpus:
    root = _strict_object(
        root,
        {
            "schema_version",
            "corpus_id",
            "owner",
            "reviewed_on",
            "fixture_policy",
            "timeout_seconds",
            "required_families",
            "registered_reason_codes",
            "required_scenario_ids",
            "scenarios",
        },
        "corpus",
    )
    if root["schema_version"] != 1 or root["corpus_id"] != "janus-adversarial-v1":
        raise CorpusError("unsupported adversarial corpus identity")
    if _safe_text(root["owner"], "owner") != "janus-security":
        raise CorpusError("adversarial corpus owner is not reviewed")
    if root["fixture_policy"] != "synthetic-value-free":
        raise CorpusError("adversarial fixture policy is not reviewed")
    try:
        reviewed_on = date.fromisoformat(root["reviewed_on"])
    except (TypeError, ValueError) as error:
        raise CorpusError("review date must be an ISO calendar date") from error
    review_age = (date.today() - reviewed_on).days
    if review_age < 0 or review_age > 366:
        raise CorpusError("adversarial corpus review is invalid or stale")
    timeout = root["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise CorpusError("scenario timeout must be an integer in 1..=900")

    families = _closed_string_list(root["required_families"], "required families")
    if tuple(families) != ALLOWED_FAMILIES:
        raise CorpusError("required adversarial families do not match the v1 contract")
    registered_reasons = set(
        _closed_string_list(root["registered_reason_codes"], "registered reasons")
    )
    required_ids = set(
        _closed_string_list(root["required_scenario_ids"], "required scenario ids")
    )

    raw_scenarios = root["scenarios"]
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise CorpusError("scenarios must be a non-empty list")
    scenarios: list[Scenario] = []
    seen: set[str] = set()
    seen_families: set[str] = set()
    for index, raw in enumerate(raw_scenarios):
        raw = _strict_object(
            raw,
            {
                "id",
                "family",
                "package",
                "test_binary",
                "test_name",
                "attack_phase",
                "expected_reason_code",
                "expected_terminal_state",
                "audit_expectation",
                "value_returned",
            },
            f"scenario {index}",
        )
        scenario_id = _safe_text(raw["id"], f"scenario {index} id")
        if scenario_id in seen:
            raise CorpusError("scenario ids must be unique")
        seen.add(scenario_id)
        family = _safe_text(raw["family"], f"scenario {scenario_id} family")
        if family not in ALLOWED_FAMILIES:
            raise CorpusError("scenario uses an unknown family")
        seen_families.add(family)
        package = _safe_text(raw["package"], f"scenario {scenario_id} package")
        test_binary = raw["test_binary"]
        if test_binary is not None:
            test_binary = _safe_text(
                test_binary,
                f"scenario {scenario_id} test binary",
                SAFE_CODE_CHARS,
            )
        test_name = _safe_text(
            raw["test_name"],
            f"scenario {scenario_id} test name",
            SAFE_TEST_CHARS,
            180,
        )
        attack_phase = _safe_text(
            raw["attack_phase"], f"scenario {scenario_id} attack phase"
        )
        reason = _safe_text(
            raw["expected_reason_code"],
            f"scenario {scenario_id} expected reason",
            SAFE_CODE_CHARS,
        )
        if reason not in registered_reasons:
            raise CorpusError("scenario uses an unregistered reason code")
        terminal = raw["expected_terminal_state"]
        if terminal not in ALLOWED_TERMINAL_STATES:
            raise CorpusError("scenario uses an unknown terminal state")
        audit = raw["audit_expectation"]
        if audit not in ALLOWED_AUDIT_EXPECTATIONS:
            raise CorpusError("scenario uses an unknown audit expectation")
        if raw["value_returned"] is not False:
            raise CorpusError("every adversarial scenario must be value-free")
        scenarios.append(
            Scenario(
                id=scenario_id,
                family=family,
                package=package,
                test_binary=test_binary,
                test_name=test_name,
                attack_phase=attack_phase,
                expected_reason_code=reason,
                expected_terminal_state=terminal,
                audit_expectation=audit,
            )
        )
    if seen != required_ids:
        raise CorpusError("required adversarial scenario inventory is incomplete")
    if seen_families != set(ALLOWED_FAMILIES):
        raise CorpusError("one or more required adversarial families are empty")
    return Corpus(timeout_seconds=timeout, scenarios=tuple(scenarios))


def load_corpus(path: Path) -> Corpus:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusError("adversarial corpus cannot be read") from error
    return _parse_corpus(root)


def rerun_command(scenario: Scenario) -> str:
    return f"python3 scripts/run-adversarial-scenarios.py --scenario {scenario.id}"


def run_scenario(
    scenario: Scenario,
    timeout_seconds: int,
    *,
    command_override: list[str] | None = None,
) -> PublicFailure | None:
    command = command_override if command_override is not None else scenario.command()
    try:
        completed = subprocess.run(
            command,
            cwd=REPO,
            capture_output=True,
            text=False,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        runner_reason = "scenario_timeout"
    except OSError:
        runner_reason = "scenario_unavailable"
    else:
        output = completed.stdout + completed.stderr
        if completed.returncode == 0 and output.count(b"running 1 test") == 1:
            return None
        runner_reason = (
            "selector_unresolved" if completed.returncode == 0 else "scenario_failure"
        )
    return PublicFailure(
        scenario=scenario.id,
        family=scenario.family,
        reason=f"{runner_reason}_{scenario.expected_reason_code}",
        rerun=rerun_command(scenario),
    )


def _expect_invalid(root: Any) -> None:
    try:
        _parse_corpus(root)
    except CorpusError:
        return
    raise RuntimeError("invalid corpus mutation was accepted")


def self_test(corpus: Corpus, raw_root: Any) -> None:
    scenario = corpus.scenarios[0]
    canary = "SENSITIVE_ADVERSARIAL_RUNNER_CANARY_MUST_NOT_ESCAPE"
    synthetic_failure = [
        sys.executable,
        "-c",
        f"import sys; print({canary!r}); print({canary!r}, file=sys.stderr); sys.exit(7)",
    ]
    first = run_scenario(
        scenario, corpus.timeout_seconds, command_override=synthetic_failure
    )
    second = run_scenario(
        scenario, corpus.timeout_seconds, command_override=synthetic_failure
    )
    if first is None or first != second or canary in first.render():
        raise RuntimeError("runner sanitization contract failed")
    unresolved = run_scenario(
        scenario,
        corpus.timeout_seconds,
        command_override=[sys.executable, "-c", "print('running 0 tests')"],
    )
    if unresolved is None or not unresolved.reason.startswith("selector_unresolved_"):
        raise RuntimeError("unresolved selector contract failed")

    unknown_field = copy.deepcopy(raw_root)
    unknown_field["unexpected"] = True
    _expect_invalid(unknown_field)
    duplicate = copy.deepcopy(raw_root)
    duplicate["scenarios"].append(copy.deepcopy(duplicate["scenarios"][0]))
    _expect_invalid(duplicate)
    missing_scenario = copy.deepcopy(raw_root)
    missing_scenario["scenarios"].pop()
    _expect_invalid(missing_scenario)
    missing_family = copy.deepcopy(raw_root)
    missing_family["required_families"].pop()
    _expect_invalid(missing_family)
    unregistered_reason = copy.deepcopy(raw_root)
    unregistered_reason["scenarios"][0]["expected_reason_code"] = "unregistered_reason"
    _expect_invalid(unregistered_reason)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--family", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        raw_root = json.loads(args.corpus.read_text(encoding="utf-8"))
        corpus = _parse_corpus(raw_root)
        if args.self_test:
            self_test(corpus, raw_root)
            print("ok: adversarial scenario runner self-test passed")
            return 0
        selected_ids = set(args.scenario)
        selected_families = set(args.family)
        known_ids = {scenario.id for scenario in corpus.scenarios}
        if selected_ids - known_ids or selected_families - set(ALLOWED_FAMILIES):
            raise CorpusError("unknown adversarial scenario selection")
        scenarios = [
            scenario
            for scenario in corpus.scenarios
            if (not selected_ids or scenario.id in selected_ids)
            and (not selected_families or scenario.family in selected_families)
        ]
        if not scenarios:
            raise CorpusError("adversarial scenario selection is empty")
        for scenario in scenarios:
            failure = run_scenario(scenario, corpus.timeout_seconds)
            if failure is not None:
                print(failure.render(), file=sys.stderr)
                return 1
            print(
                "ok: adversarial scenario "
                f"scenario={scenario.id} family={scenario.family} "
                f"reason={scenario.expected_reason_code} "
                f"terminal={scenario.expected_terminal_state}"
            )
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, CorpusError):
        print("error: adversarial corpus reason=contract_invalid", file=sys.stderr)
        return 2
    except RuntimeError:
        print("error: adversarial corpus reason=self_test_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

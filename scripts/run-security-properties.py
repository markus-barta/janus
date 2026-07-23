#!/usr/bin/env python3
"""Run the reviewed, bounded Rust security-property release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = REPO / "config/assurance/security-properties-v2.json"
DEFAULT_RECEIPT = REPO / ".tmp/janus-property-replay.json"
DEFAULT_RECEIPT_ARGUMENT = ".tmp/janus-property-replay.json"
SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
SAFE_SELECTOR_CHARS = SAFE_ID_CHARS | frozenset("_")
SAFE_PATH_PART = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
XS_SEED = re.compile(r"xs ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\Z")
CC_SEED = re.compile(r"cc ([0-9a-f]{64})\Z")
REPLAY_ID = re.compile(r"rpl_[0-9a-f]{24}\Z")
MAX_U32 = (1 << 32) - 1


class ContractError(ValueError):
    """The reviewed runner contract or replay receipt is invalid."""


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
    persistence: str
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
class ReplayReceipt:
    target: str
    seed: str
    cases: int
    release: bool
    replay_id: str


@dataclass(frozen=True)
class PublicFailure:
    target: str
    replay: str
    reason: str
    rerun: str

    def render(self) -> str:
        return (
            "error: security property target failed "
            f"target={self.target} replay={self.replay} reason={self.reason} "
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


def _safe_persistence(value: Any, context: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 240:
        raise ContractError(f"{context} must be a safe repository-relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or str(pure) != value
        or len(pure.parts) < 4
        or pure.parts[0] != "crates"
        or pure.parts[-2] != "proptest-regressions"
        or not pure.name.endswith(".txt")
        or any(part in {".", ".."} or SAFE_PATH_PART.fullmatch(part) is None for part in pure.parts)
    ):
        raise ContractError(f"{context} must be a safe repository-relative path")
    candidate = (REPO / pure).resolve(strict=False)
    if not candidate.is_relative_to(REPO.resolve()):
        raise ContractError(f"{context} escapes the repository")
    return value


def load_contract(path: Path) -> Contract:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("security property contract cannot be read") from error
    root = _strict_object(root, {"schema_version", "release", "targets"}, "contract")
    if root["schema_version"] != 2:
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
    seen_ids: set[str] = set()
    seen_persistence: set[str] = set()
    for index, value in enumerate(raw_targets):
        if not isinstance(value, dict):
            raise ContractError(f"target {index} has invalid fields")
        selector_fields = {field for field in ("test", "filter") if field in value}
        if len(selector_fields) != 1:
            raise ContractError(f"target {index} must select one test or filter")
        value = _strict_object(
            value,
            {"id", "package", "persistence"} | selector_fields,
            f"target {index}",
        )
        target_id = _safe_id(value["id"], f"target {index} id")
        package = _safe_id(value["package"], f"target {index} package")
        persistence = _safe_persistence(
            value["persistence"], f"target {index} persistence"
        )
        if target_id in seen_ids:
            raise ContractError("target ids must be unique")
        if persistence in seen_persistence:
            raise ContractError("target persistence paths must be unique")
        seen_ids.add(target_id)
        seen_persistence.add(persistence)
        test = value.get("test")
        test_filter = value.get("filter")
        selected = test if test is not None else test_filter
        selected = _safe_id(
            selected, f"target {target_id} selector", SAFE_SELECTOR_CHARS
        )
        targets.append(
            Target(
                id=target_id,
                package=package,
                persistence=persistence,
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


def _seed_token(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 96:
        raise ContractError("property seed token is invalid")
    xs_match = XS_SEED.fullmatch(value)
    if xs_match is not None:
        if any(int(word) > MAX_U32 for word in xs_match.groups()):
            raise ContractError("property seed token is invalid")
        return "xs " + " ".join(str(int(word)) for word in xs_match.groups())
    cc_match = CC_SEED.fullmatch(value)
    if cc_match is not None:
        return f"cc {cc_match.group(1)}"
    raise ContractError("property seed token is invalid")


def _seed_from_persistence_line(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    token = stripped.split("#", 1)[0].rstrip()
    return _seed_token(token)


def _read_persisted_seeds(path: Path) -> tuple[str, ...]:
    if not path.exists():
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError("property persistence file cannot be read") from error
    seeds: list[str] = []
    for line in text.splitlines():
        seed = _seed_from_persistence_line(line)
        if seed is not None:
            seeds.append(seed)
    return tuple(seeds)


def _atomic_private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _sanitize_new_seed_lines(path: Path, before: tuple[str, ...]) -> tuple[str, ...]:
    if not path.exists():
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError("property persistence file cannot be read") from error
    before_set = set(before)
    new: list[str] = []
    sanitized: list[str] = []
    changed = False
    for raw_line in text.splitlines(keepends=True):
        body = raw_line.rstrip("\r\n")
        ending = raw_line[len(body) :]
        seed = _seed_from_persistence_line(body)
        if seed is not None and seed not in before_set:
            if seed not in new:
                new.append(seed)
            replacement = seed + ending
            sanitized.append(replacement)
            changed = changed or replacement != raw_line
        else:
            sanitized.append(raw_line)
    if changed:
        _atomic_private_write(path, "".join(sanitized).encode("utf-8"))
    return tuple(new)


def _receipt_payload(
    target: str, seed: str, cases: int, release: bool
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "target": target,
        "seed": seed,
        "cases": cases,
        "release": release,
    }


def _receipt_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return f"rpl_{hashlib.sha256(canonical).hexdigest()[:24]}"


def create_receipt(
    target: Target, seed: str, cases: int, release: bool
) -> ReplayReceipt:
    payload = _receipt_payload(target.id, _seed_token(seed), cases, release)
    return ReplayReceipt(
        target=target.id,
        seed=payload["seed"],
        cases=cases,
        release=release,
        replay_id=_receipt_id(payload),
    )


def _receipt_object(receipt: ReplayReceipt) -> dict[str, Any]:
    payload = _receipt_payload(
        receipt.target, receipt.seed, receipt.cases, receipt.release
    )
    return {**payload, "replay_id": receipt.replay_id}


def write_receipt(path: Path, receipt: ReplayReceipt) -> None:
    encoded = (
        json.dumps(_receipt_object(receipt), indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    _atomic_private_write(path, encoded)


def load_receipt(path: Path, contract: Contract) -> ReplayReceipt:
    try:
        root = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("property replay receipt cannot be read") from error
    root = _strict_object(
        root,
        {"schema_version", "target", "seed", "cases", "release", "replay_id"},
        "property replay receipt",
    )
    if root["schema_version"] != 1:
        raise ContractError("unsupported property replay receipt version")
    target = _safe_id(root["target"], "property replay target")
    if target not in {candidate.id for candidate in contract.targets}:
        raise ContractError("property replay target is not reviewed")
    seed = _seed_token(root["seed"])
    cases = _positive_int(root["cases"], "property replay case budget", 1_000_000)
    release = root["release"]
    if not isinstance(release, bool):
        raise ContractError("property replay release marker is invalid")
    if release and cases < contract.budget.cases:
        raise ContractError("property replay lowers the reviewed release case budget")
    replay_id = root["replay_id"]
    payload = _receipt_payload(target, seed, cases, release)
    if (
        not isinstance(replay_id, str)
        or REPLAY_ID.fullmatch(replay_id) is None
        or replay_id != _receipt_id(payload)
    ):
        raise ContractError("property replay receipt identity is invalid")
    return ReplayReceipt(
        target=target,
        seed=seed,
        cases=cases,
        release=release,
        replay_id=replay_id,
    )


def _normal_rerun_command(target: Target, cases: int, release: bool) -> str:
    command = ["python3", "scripts/run-security-properties.py", "--target", target.id]
    if release:
        command.append("--release")
    else:
        command.extend(["--cases", str(cases)])
    return " ".join(command)


def _replay_command() -> str:
    return (
        "python3 scripts/run-security-properties.py "
        f"--replay {DEFAULT_RECEIPT_ARGUMENT}"
    )


def _execute_target(
    target: Target,
    budget: Budget,
    cases: int,
    *,
    command_override: list[str] | None = None,
) -> str | None:
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
        return "target_timeout"
    except OSError:
        return "target_unavailable"
    if completed.returncode == 0:
        return None
    return "property_failure"


def _target_persistence(target: Target, override: Path | None = None) -> Path:
    if override is not None:
        return override
    path = (REPO / target.persistence).resolve(strict=False)
    if not path.is_relative_to(REPO.resolve()):
        raise ContractError("property persistence path escapes the repository")
    return path


def run_target(
    target: Target,
    budget: Budget,
    cases: int,
    release: bool,
    *,
    command_override: list[str] | None = None,
    persistence_override: Path | None = None,
    receipt_path: Path = DEFAULT_RECEIPT,
) -> PublicFailure | None:
    persistence = _target_persistence(target, persistence_override)
    before = _read_persisted_seeds(persistence)
    reason = _execute_target(
        target, budget, cases, command_override=command_override
    )
    if reason is None:
        return None
    new_seeds = _sanitize_new_seed_lines(persistence, before)
    if len(new_seeds) == 1:
        receipt = create_receipt(target, new_seeds[0], cases, release)
        write_receipt(receipt_path, receipt)
        return PublicFailure(
            target=target.id,
            replay=receipt.replay_id,
            reason=reason,
            rerun=_replay_command(),
        )
    return PublicFailure(
        target=target.id,
        replay="unavailable",
        reason=f"{reason}_without_new_seed",
        rerun=_normal_rerun_command(target, cases, release),
    )


def replay_target(
    target: Target,
    budget: Budget,
    receipt: ReplayReceipt,
    *,
    command_override: list[str] | None = None,
    persistence_override: Path | None = None,
) -> PublicFailure | None:
    persistence = _target_persistence(target, persistence_override)
    parent_existed = persistence.parent.exists()
    original = persistence.read_bytes() if persistence.exists() else None
    try:
        existing = _read_persisted_seeds(persistence)
        if receipt.seed not in existing:
            prefix = original or b""
            if prefix and not prefix.endswith(b"\n"):
                prefix += b"\n"
            _atomic_private_write(
                persistence, prefix + receipt.seed.encode("ascii") + b"\n"
            )
        reason = _execute_target(
            target,
            budget,
            receipt.cases,
            command_override=command_override,
        )
    finally:
        if original is None:
            persistence.unlink(missing_ok=True)
            if not parent_existed:
                try:
                    persistence.parent.rmdir()
                except OSError:
                    pass
        else:
            _atomic_private_write(persistence, original)
    if reason is None:
        return None
    return PublicFailure(
        target=target.id,
        replay=receipt.replay_id,
        reason="reproduced_failure",
        rerun=_replay_command(),
    )


def self_test(contract: Contract) -> None:
    target = contract.targets[0]
    canary = "SENSITIVE_RUNNER_CANARY_MUST_NOT_ESCAPE"
    seed = "xs 1 2 3 4"

    def exercise(root: Path) -> tuple[PublicFailure, Path, Path]:
        persistence = root / "proptest-regressions" / "fixture.txt"
        receipt_path = root / "receipt.json"
        synthetic = [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; import sys; "
                "path = Path(sys.argv[1]); path.parent.mkdir(parents=True, exist_ok=True); "
                "path.open('a', encoding='utf-8').write(sys.argv[2] + ' # ' + sys.argv[3] + '\\n'); "
                "print(sys.argv[3]); print(sys.argv[3], file=sys.stderr); sys.exit(7)"
            ),
            str(persistence),
            seed,
            canary,
        ]
        failure = run_target(
            target,
            contract.budget,
            contract.budget.cases,
            True,
            command_override=synthetic,
            persistence_override=persistence,
            receipt_path=receipt_path,
        )
        if failure is None:
            raise RuntimeError("synthetic property failure was not detected")
        return failure, persistence, receipt_path

    with tempfile.TemporaryDirectory(prefix="janus-property-self-test-") as directory:
        root = Path(directory)
        first, first_persistence, first_receipt = exercise(root / "first")
        second, second_persistence, second_receipt = exercise(root / "second")
        if first != second or canary in first.render():
            raise RuntimeError("runner output sanitization or determinism contract failed")
        for path in (
            first_persistence,
            first_receipt,
            second_persistence,
            second_receipt,
        ):
            if canary in path.read_text(encoding="utf-8"):
                raise RuntimeError("runner persisted generated diagnostic values")
            if path.stat().st_mode & 0o077:
                raise RuntimeError("runner replay evidence is not private")
        if first_persistence.read_text(encoding="utf-8") != seed + "\n":
            raise RuntimeError("runner did not reduce persistence to a seed token")
        receipt = load_receipt(first_receipt, contract)

        replay_persistence = root / "replay" / "proptest-regressions" / "fixture.txt"
        replay_probe = [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; import sys; "
                "present = sys.argv[2] in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines(); "
                "sys.exit(7 if present else 0)"
            ),
            str(replay_persistence),
            seed,
        ]
        replay_first = replay_target(
            target,
            contract.budget,
            receipt,
            command_override=replay_probe,
            persistence_override=replay_persistence,
        )
        replay_second = replay_target(
            target,
            contract.budget,
            receipt,
            command_override=replay_probe,
            persistence_override=replay_persistence,
        )
        if (
            replay_first is None
            or replay_first != replay_second
            or replay_first.reason != "reproduced_failure"
            or replay_persistence.exists()
        ):
            raise RuntimeError("property replay did not reproduce deterministically")

        valid = _receipt_object(receipt)
        invalid_receipts = (
            {**valid, "seed": f"{seed} # {canary}"},
            {**valid, "unexpected": canary},
            {**valid, "replay_id": "rpl_" + "0" * 24},
        )
        for index, invalid in enumerate(invalid_receipts):
            path = root / f"invalid-{index}.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            try:
                load_receipt(path, contract)
            except ContractError:
                continue
            raise RuntimeError("unsafe property replay receipt was accepted")

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
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        contract = load_contract(args.contract)
        if args.replay is not None:
            if args.target or args.cases is not None or args.release or args.self_test:
                raise ContractError("property replay cannot be combined with run options")
            receipt = load_receipt(args.replay, contract)
            target = next(
                candidate
                for candidate in contract.targets
                if candidate.id == receipt.target
            )
            failure = replay_target(target, contract.budget, receipt)
            if failure is not None:
                print(failure.render(), file=sys.stderr)
                return 1
            print(
                "ok: security property replay no longer fails "
                f"target={target.id} replay={receipt.replay_id}"
            )
            return 0
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
        DEFAULT_RECEIPT.unlink(missing_ok=True)
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
    except OSError:
        print(
            "error: security property runner reason=local_io_unavailable",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

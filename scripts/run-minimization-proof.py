#!/usr/bin/env python3
"""Run the closed, bounded cross-surface data-minimization release proof."""

from __future__ import annotations

import argparse
import copy
import json
import os
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = REPO / "config/assurance/minimization-proof-v1.json"
SAFE_ID = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
SAFE_RUST = SAFE_ID | frozenset("_:")
SAFE_GO = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
REQUIRED_STACKS = ("rust", "go")
REQUIRED_PROOF_IDS = (
    "rust-serialized-output",
    "rust-managed-output",
    "rust-env-file-sink",
    "rust-audit-admin",
    "rust-warden-transport",
    "rust-container-log",
    "rust-telemetry-absence",
    "go-closed-routes",
    "go-evidence-export",
    "go-diagnostic-sanitization",
    "go-telemetry-absence",
)
SURFACE_CLASSES = (
    "serialized-output",
    "process-output",
    "managed-execution",
    "env-file",
    "audit",
    "admin-state",
    "warden-transport",
    "container-log",
    "http-api",
    "http-ui",
    "evidence-export",
    "ci-diagnostic",
    "telemetry-absence",
)
FORBIDDEN_DATA_CLASSES = (
    "secret-value",
    "prompt-model-text",
    "command-stdout",
    "command-stderr",
    "environment-dump",
    "request-body",
    "backend-path",
    "auth-cookie",
    "identity-claim",
)
ALLOWED_SINKS = (
    {
        "id": "private-env-file-target",
        "condition": "reviewed-private-target",
        "data_classes": ["secret-value", "environment-dump"],
    },
    {
        "id": "reviewed-managed-child-input",
        "condition": "exact-reviewed-execution",
        "data_classes": ["secret-value", "environment-dump"],
    },
)
NO_EMITTERS = (
    {"id": "metrics", "state": "not_implemented/no_emitter"},
    {"id": "distributed-traces", "state": "not_implemented/no_emitter"},
)
ALLOWED_REPO_SCRIPTS = frozenset({"scripts/smoke-engine-container.sh"})
TELEMETRY_DEPENDENCIES = (
    "\nmetrics =",
    "\nmetrics=",
    "opentelemetry",
    "prometheus",
    "tracing-opentelemetry",
    "github.com/prometheus",
    "go.opentelemetry.io",
)
SYNTHETIC_CANARIES = (
    "JANUS_SECRET_CANARY_296",
    "JANUS_PROMPT_MODEL_CANARY_296",
    "JANUS_STDOUT_CANARY_296",
    "JANUS_STDERR_CANARY_296",
    "JANUS_ENV_DUMP_CANARY_296",
    "JANUS_REQUEST_BODY_CANARY_296",
    "JANUS_BACKEND_PATH_CANARY_296",
    "JANUS_AUTH_COOKIE_CANARY_296",
    "JANUS_IDENTITY_CLAIM_CANARY_296",
)


class ContractError(ValueError):
    """The reviewed minimization contract is malformed or incomplete."""


@dataclass(frozen=True)
class Limits:
    proof_timeout_seconds: int
    max_capture_bytes: int


@dataclass(frozen=True)
class Proof:
    id: str
    stack: str
    surface_classes: tuple[str, ...]
    kind: str
    package: str | None = None
    selector: str | None = None
    script: str | None = None

    def command(self) -> tuple[list[str], Path] | None:
        if self.kind == "rust-test":
            assert self.package is not None and self.selector is not None
            return (
                [
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    self.package,
                    self.selector,
                    "--",
                    "--exact",
                    "--test-threads=1",
                ],
                REPO,
            )
        if self.kind == "go-test":
            assert self.selector is not None
            return (
                [
                    "go",
                    "test",
                    "./...",
                    "-run",
                    f"^{self.selector}$",
                    "-count=1",
                    "-v",
                ],
                REPO / "go-envelope",
            )
        if self.kind == "repo-script":
            assert self.script is not None
            return ([str(REPO / self.script)], REPO)
        return None


@dataclass(frozen=True)
class Contract:
    limits: Limits
    proofs: tuple[Proof, ...]


@dataclass(frozen=True)
class PublicFailure:
    proof: str
    reason: str
    rerun: str

    def render(self) -> str:
        return (
            "error: minimization proof failed "
            f"proof={self.proof} reason={self.reason} rerun={json.dumps(self.rerun)}"
        )


def _strict_object(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{context} has invalid fields")
    return value


def _safe_string(value: Any, context: str, allowed: frozenset[str]) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 160
        or value[0] in "-:"
        or value[-1] in "-:"
        or any(character not in allowed for character in value)
    ):
        raise ContractError(f"{context} is not a safe identifier")
    return value


def _positive_int(value: Any, context: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ContractError(f"{context} is outside the reviewed bound")
    return value


def _exact_list(value: Any, expected: tuple[Any, ...], context: str) -> None:
    if value != list(expected):
        raise ContractError(f"{context} is not the closed reviewed list")


def _parse_proof(raw: Any, index: int) -> Proof:
    item = _strict_object(
        raw, {"id", "stack", "surface_classes", "command"}, f"proof {index}"
    )
    proof_id = _safe_string(item["id"], f"proof {index} id", SAFE_ID)
    if item["stack"] not in REQUIRED_STACKS:
        raise ContractError(f"proof {proof_id} has an unknown stack")
    surfaces = item["surface_classes"]
    if (
        not isinstance(surfaces, list)
        or not surfaces
        or len(set(surfaces)) != len(surfaces)
        or any(surface not in SURFACE_CLASSES for surface in surfaces)
    ):
        raise ContractError(f"proof {proof_id} has invalid surface coverage")
    command = item["command"]
    if not isinstance(command, dict) or "kind" not in command:
        raise ContractError(f"proof {proof_id} has an invalid command")
    kind = command["kind"]
    package = selector = script = None
    if kind == "rust-test":
        command = _strict_object(command, {"kind", "package", "selector"}, "rust command")
        package = _safe_string(command["package"], "rust package", SAFE_ID)
        selector = _safe_string(command["selector"], "rust selector", SAFE_RUST)
    elif kind == "go-test":
        command = _strict_object(command, {"kind", "selector"}, "go command")
        selector = _safe_string(command["selector"], "go selector", SAFE_GO)
        if not selector.startswith("Test"):
            raise ContractError("go selector must name one test")
    elif kind == "repo-script":
        command = _strict_object(command, {"kind", "script"}, "script command")
        if command["script"] not in ALLOWED_REPO_SCRIPTS:
            raise ContractError("repo script is not on the closed allowlist")
        script = command["script"]
    elif kind == "static-telemetry-absence":
        _strict_object(command, {"kind"}, "telemetry command")
    else:
        raise ContractError(f"proof {proof_id} has an arbitrary command kind")
    if item["stack"] == "rust" and kind not in {
        "rust-test",
        "repo-script",
        "static-telemetry-absence",
    }:
        raise ContractError(f"proof {proof_id} crosses the reviewed stack boundary")
    if item["stack"] == "go" and kind not in {
        "go-test",
        "static-telemetry-absence",
    }:
        raise ContractError(f"proof {proof_id} crosses the reviewed stack boundary")
    return Proof(
        id=proof_id,
        stack=item["stack"],
        surface_classes=tuple(surfaces),
        kind=kind,
        package=package,
        selector=selector,
        script=script,
    )


def parse_contract(root: Any, *, today: date | None = None) -> Contract:
    root = _strict_object(
        root,
        {
            "schema_version",
            "contract_id",
            "owner",
            "reviewed_on",
            "limits",
            "required_stacks",
            "surface_classes",
            "forbidden_data_classes",
            "allowed_sinks",
            "no_emitters",
            "required_proof_ids",
            "proofs",
        },
        "contract",
    )
    if root["schema_version"] != 1:
        raise ContractError("unsupported minimization contract version")
    if root["contract_id"] != "janus-minimization-proof-v1":
        raise ContractError("unknown minimization contract id")
    if root["owner"] != "janus-security":
        raise ContractError("minimization contract owner changed")
    try:
        reviewed_on = date.fromisoformat(root["reviewed_on"])
    except (TypeError, ValueError) as error:
        raise ContractError("review date is invalid") from error
    current = today or date.today()
    age = (current - reviewed_on).days
    if age < 0 or age > 366:
        raise ContractError("minimization contract review is stale")
    limits = _strict_object(
        root["limits"], {"proof_timeout_seconds", "max_capture_bytes"}, "limits"
    )
    parsed_limits = Limits(
        proof_timeout_seconds=_positive_int(
            limits["proof_timeout_seconds"], "proof timeout", 3600
        ),
        max_capture_bytes=_positive_int(
            limits["max_capture_bytes"], "capture limit", 8 * 1024 * 1024
        ),
    )
    _exact_list(root["required_stacks"], REQUIRED_STACKS, "required stacks")
    _exact_list(root["surface_classes"], SURFACE_CLASSES, "surface classes")
    _exact_list(
        root["forbidden_data_classes"], FORBIDDEN_DATA_CLASSES, "forbidden data classes"
    )
    _exact_list(root["allowed_sinks"], ALLOWED_SINKS, "allowed sinks")
    _exact_list(root["no_emitters"], NO_EMITTERS, "no-emitter declarations")
    raw_proofs = root["proofs"]
    if not isinstance(raw_proofs, list) or not raw_proofs:
        raise ContractError("proofs must be a non-empty list")
    proofs = tuple(_parse_proof(raw, index) for index, raw in enumerate(raw_proofs))
    ids = [proof.id for proof in proofs]
    if len(ids) != len(set(ids)):
        raise ContractError("proof ids must be unique")
    _exact_list(root["required_proof_ids"], REQUIRED_PROOF_IDS, "required proof ids")
    if root["required_proof_ids"] != ids:
        raise ContractError("required proof ids do not exactly match proofs")
    if {proof.stack for proof in proofs} != set(REQUIRED_STACKS):
        raise ContractError("one or more required stacks have no proof")
    covered = {surface for proof in proofs for surface in proof.surface_classes}
    if covered != set(SURFACE_CLASSES):
        raise ContractError("one or more surface classes have no proof")
    for proof in proofs:
        if proof.kind == "static-telemetry-absence" and proof.surface_classes != (
            "telemetry-absence",
        ):
            raise ContractError("telemetry proof has unrelated surface coverage")
    return Contract(limits=parsed_limits, proofs=proofs)


def load_contract(path: Path) -> tuple[Contract, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("minimization contract cannot be read") from error
    return parse_contract(raw), raw


def _bounded_command(
    command: list[str], cwd: Path, limits: Limits
) -> tuple[str, bytes]:
    environment = os.environ.copy()
    environment.update({"NO_COLOR": "1", "CLICOLOR": "0"})
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError:
        return "proof_unavailable", b""
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + limits.proof_timeout_seconds
    reason = ""
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reason = "proof_timeout"
            process.kill()
            break
        events = selector.select(min(remaining, 0.25))
        if not events and process.poll() is not None:
            events = selector.select(0)
        for key, _ in events:
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            if len(output) + len(chunk) > limits.max_capture_bytes:
                reason = "capture_limit"
                process.kill()
                selector.close()
                break
            output.extend(chunk)
        if reason:
            break
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    selector.close()
    if reason:
        return reason, bytes(output)
    if process.returncode != 0:
        return "proof_failure", bytes(output)
    return "ok", bytes(output)


def _telemetry_absent(stack: str) -> bool:
    paths = (
        list((REPO / "crates").glob("*/Cargo.toml"))
        if stack == "rust"
        else [REPO / "go-envelope/go.mod"]
    )
    for path in paths:
        try:
            content = path.read_text(encoding="utf-8").lower()
        except (OSError, UnicodeError):
            return False
        if any(dependency in content for dependency in TELEMETRY_DEPENDENCIES):
            return False
    return True


def _rerun(proof: Proof) -> str:
    return f"python3 scripts/run-minimization-proof.py --proof {proof.id}"


def run_proof(
    proof: Proof,
    limits: Limits,
    *,
    command_override: list[str] | None = None,
) -> PublicFailure | None:
    if proof.kind == "static-telemetry-absence" and command_override is None:
        if _telemetry_absent(proof.stack):
            return None
        reason = "unexpected_emitter_dependency"
    else:
        command_and_cwd = proof.command()
        if command_override is not None:
            command_and_cwd = (command_override, REPO)
        assert command_and_cwd is not None
        reason, output = _bounded_command(*command_and_cwd, limits)
        if reason == "ok" and any(
            canary.encode("utf-8") in output for canary in SYNTHETIC_CANARIES
        ):
            reason = "forbidden_literal"
        if reason == "ok" and proof.kind == "rust-test":
            if output.splitlines().count(b"running 1 test") != 1:
                reason = "selector_unresolved"
        if reason == "ok" and proof.kind == "go-test":
            marker = f"=== RUN   {proof.selector}".encode("utf-8")
            if output.splitlines().count(marker) != 1:
                reason = "selector_unresolved"
        if reason == "ok":
            return None
    return PublicFailure(proof=proof.id, reason=reason, rerun=_rerun(proof))


def _expect_contract_failure(raw: Any) -> None:
    try:
        parse_contract(raw, today=date(2026, 7, 21))
    except ContractError:
        return
    raise RuntimeError("contract mutation was accepted")


def self_test(contract: Contract, raw: Any) -> None:
    first = contract.proofs[0]
    canary = SYNTHETIC_CANARIES[0]
    synthetic = [
        sys.executable,
        "-c",
        f"import sys; print({canary!r}); print({canary!r}, file=sys.stderr); sys.exit(7)",
    ]
    failure_a = run_proof(first, contract.limits, command_override=synthetic)
    failure_b = run_proof(first, contract.limits, command_override=synthetic)
    if failure_a is None or failure_b is None:
        raise RuntimeError("synthetic failure did not fail closed")
    if failure_a.render() != failure_b.render() or canary in failure_a.render():
        raise RuntimeError("public failures are not deterministic and value-free")

    tight_limits = Limits(proof_timeout_seconds=1, max_capture_bytes=64)
    oversized = run_proof(
        first,
        tight_limits,
        command_override=[sys.executable, "-c", "print('x' * 4096)"],
    )
    if oversized is None or oversized.reason != "capture_limit":
        raise RuntimeError("capture limit did not fail closed")
    timed_out = run_proof(
        first,
        tight_limits,
        command_override=[sys.executable, "-c", "import time; time.sleep(5)"],
    )
    if timed_out is None or timed_out.reason != "proof_timeout":
        raise RuntimeError("proof timeout did not fail closed")
    unresolved = run_proof(
        first,
        contract.limits,
        command_override=[sys.executable, "-c", "print('running 0 tests')"],
    )
    if unresolved is None or unresolved.reason != "selector_unresolved":
        raise RuntimeError("unresolved selector did not fail closed")

    mutations: list[Any] = []
    unknown = copy.deepcopy(raw)
    unknown["unexpected"] = True
    mutations.append(unknown)
    missing = copy.deepcopy(raw)
    missing["proofs"].pop()
    mutations.append(missing)
    broad_sink = copy.deepcopy(raw)
    broad_sink["allowed_sinks"][0]["condition"] = "any-target"
    mutations.append(broad_sink)
    missing_surface = copy.deepcopy(raw)
    missing_surface["proofs"][0]["surface_classes"] = []
    mutations.append(missing_surface)
    arbitrary = copy.deepcopy(raw)
    arbitrary["proofs"][0]["command"] = {"kind": "shell", "command": "true"}
    mutations.append(arbitrary)
    stale = copy.deepcopy(raw)
    stale["reviewed_on"] = "2020-01-01"
    mutations.append(stale)
    duplicate = copy.deepcopy(raw)
    duplicate["proofs"][1]["id"] = duplicate["proofs"][0]["id"]
    duplicate["required_proof_ids"][1] = duplicate["required_proof_ids"][0]
    mutations.append(duplicate)
    for mutation in mutations:
        _expect_contract_failure(mutation)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--stack", choices=("all", "rust", "go"), default="all")
    parser.add_argument("--proof")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        contract, raw = load_contract(args.contract)
        if args.self_test:
            self_test(contract, raw)
            print("ok: minimization proof runner self-test passed")
            return 0
        proofs = list(contract.proofs)
        if args.proof is not None:
            proofs = [proof for proof in proofs if proof.id == args.proof]
            if not proofs:
                raise ContractError("requested proof id is not declared")
        elif args.stack != "all":
            proofs = [proof for proof in proofs if proof.stack == args.stack]
        for proof in proofs:
            failure = run_proof(proof, contract.limits)
            if failure is not None:
                print(failure.render(), file=sys.stderr)
                return 1
    except (ContractError, RuntimeError) as error:
        print(f"error: minimization proof unavailable reason={json.dumps(str(error))}", file=sys.stderr)
        return 2
    print(f"ok: minimization proof passed proofs={len(proofs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

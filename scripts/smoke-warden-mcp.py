#!/usr/bin/env python3
"""Launch janus-warden over MCP stdio and verify a local value-free instance."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = "2024-11-05"
REQUEST_TIMEOUT_SECONDS = 15
CANARY_VALUE = "expected-canary"
REQUEST_BODY_CANARY = "SENSITIVE_CANARY_REQUEST_BODY"
CONTAINER_FIXTURE_DIR = "/tmp/janus-warden-smoke"


def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    temp_parent = None
    if args.image:
        temp_parent = repo / ".tmp"
        temp_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="janus-warden-smoke-", dir=temp_parent) as tmp:
        fixture = Path(tmp)
        manifest = fixture / "secretspec.toml"
        env_file = fixture / ".env"
        metadata = fixture / "metadata.toml"
        permit_dir = fixture / "permits"
        permit_dir.mkdir()

        manifest.write_text(
            """[project]
name = "janus"
revision = "1.0"

[profiles.default]
CANARY = { description = "Canary token", required = true }
""",
            encoding="utf-8",
        )
        env_file.write_text(f"CANARY={CANARY_VALUE}\n", encoding="utf-8")
        metadata.write_text(
            """[defaults]
owner = "infra"
classification = "normal"
""",
            encoding="utf-8",
        )
        if args.image:
            prepare_container_mount(fixture, permit_dir)

        child_env = os.environ.copy()
        child_env.update(smoke_env(fixture))

        command = warden_command(repo, fixture, args)
        proc = subprocess.Popen(
            command,
            cwd=repo,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        smoke = McpSmoke(proc)
        try:
            run_smoke(smoke)
        finally:
            smoke.close()

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke-test janus-warden over MCP stdio without exposing values."
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("JANUS_WARDEN_IMAGE"),
        help="Run janus-warden from this engine container image instead of cargo.",
    )
    parser.add_argument(
        "--platform",
        default=os.environ.get("JANUS_WARDEN_IMAGE_PLATFORM"),
        help="Docker platform to use with --image, for example linux/amd64.",
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("JANUS_WARDEN_BIN"),
        help="Run this janus-warden binary instead of cargo.",
    )
    return parser.parse_args()


def smoke_env(fixture: Path, *, container: bool = False) -> dict[str, str]:
    root = Path(CONTAINER_FIXTURE_DIR) if container else fixture
    env = {
        "JANUS_WARDEN_BACKEND": "secretspec",
        "JANUS_WARDEN_SECRETSPEC_FILE": str(root / "secretspec.toml"),
        "JANUS_WARDEN_SECRETSPEC_PROVIDER_URI": f"dotenv:{root / '.env'}",
        "JANUS_WARDEN_SECRETSPEC_METADATA_FILE": str(root / "metadata.toml"),
        "JANUS_WARDEN_DESTINATION": "dev-smoke",
        "JANUS_WARDEN_EXECUTOR": "warden-stdio",
        "JANUS_WARDEN_SCOPE_ORGANIZATION": "fixture-org",
        "JANUS_WARDEN_SCOPE_PROJECT": "janus",
        "JANUS_WARDEN_SCOPE_REPOSITORY": "janus",
        "JANUS_WARDEN_SCOPE_ENVIRONMENT": "dev",
    }
    if not container:
        env["JANUS_WARDEN_PERMIT_DIR"] = str(root / "permits")
    return env


def prepare_container_mount(fixture: Path, permit_dir: Path) -> None:
    # The engine image runs as the unprivileged `janus` user. The smoke fixture
    # is temporary test data, so make it readable and the permit directory
    # writable across host/container uid boundaries.
    fixture.chmod(0o755)
    permit_dir.chmod(0o777)
    for path in [fixture / "secretspec.toml", fixture / ".env", fixture / "metadata.toml"]:
        path.chmod(0o644)


def warden_command(repo: Path, fixture: Path, args: argparse.Namespace) -> list[str]:
    if args.image:
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--entrypoint",
            "janus-warden",
            "--mount",
            f"type=bind,source={fixture.resolve()},target={CONTAINER_FIXTURE_DIR}",
        ]
        if args.platform:
            command.extend(["--platform", args.platform])
        for key, value in smoke_env(fixture, container=True).items():
            command.extend(["-e", f"{key}={value}"])
        command.append(args.image)
        return command

    if args.bin:
        return [args.bin]
    return ["cargo", "run", "--quiet", "-p", "janus-warden"]


class McpSmoke:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            raise RuntimeError("janus-warden stdio pipes were not created")
        self.proc = proc
        self.stdin = proc.stdin
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.stdout, selectors.EVENT_READ)
        self.next_id = 1
        self.transcript: list[str] = []

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self.write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            line = self.read_line(deadline)
            response = json.loads(line)
            if response.get("id") == request_id:
                if "error" in response:
                    raise AssertionError(f"{method} returned MCP error: {response['error']}")
                return response["result"]
        raise TimeoutError(f"timed out waiting for MCP response to {method}")

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.write({"jsonrpc": "2.0", "method": method, "params": params})

    def write(self, message: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.stdin.flush()

    def read_line(self, deadline: float) -> str:
        timeout = max(0.0, deadline - time.monotonic())
        events = self.selector.select(timeout)
        if not events:
            raise TimeoutError(self.diagnostic_tail("no MCP stdout received"))
        line = self.stdout.readline()
        if not line:
            raise RuntimeError(self.diagnostic_tail("janus-warden exited before responding"))
        line = line.strip()
        self.transcript.append(line)
        return line

    def diagnostic_tail(self, message: str) -> str:
        stderr = self.stderr.read() if self.proc.poll() is not None else ""
        tail = stderr[-2000:] if stderr else "<still running>"
        return f"{message}; stderr tail: {tail}"

    def close(self) -> None:
        try:
            self.selector.unregister(self.stdout)
        except Exception:
            pass
        try:
            self.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)


def run_smoke(smoke: McpSmoke) -> None:
    initialized = smoke.request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "janus-warden-smoke", "version": "0"},
        },
    )
    assert_equal(initialized["serverInfo"]["name"], "janus-warden", "server name")
    smoke.notify("notifications/initialized", {})

    tools = smoke.request("tools/list", {})
    tool_names = {tool["name"] for tool in tools["tools"]}
    assert_equal(
        tool_names,
        {"list_secrets", "describe_secret", "request_use", "health"},
        "tool catalog",
    )

    unknown = structured_denial(
        smoke.request("tools/call", {"name": "resolve_secret", "arguments": {}})
    )
    assert_equal(
        unknown["error"]["reason_code"], "denied_unknown_tool", "unknown tool denial"
    )
    assert_false(unknown["value_returned"], "unknown tool value_returned")

    malformed = structured_denial(
        smoke.request(
            "tools/call",
            {
                "name": "describe_secret",
                "arguments": {
                    "secret_ref": "sec_fixture",
                    "request_body": REQUEST_BODY_CANARY,
                },
            },
        )
    )
    assert_equal(
        malformed["error"]["reason_code"], "denied_invalid_args", "invalid args denial"
    )
    assert_false(malformed["value_returned"], "invalid args value_returned")

    oversized = structured_denial(
        smoke.request(
            "tools/call",
            {
                "name": "describe_secret",
                "arguments": {
                    "secret_ref": REQUEST_BODY_CANARY + ("x" * 8192),
                },
            },
        )
    )
    assert_equal(
        oversized["error"]["reason_code"],
        "denied_arguments_too_large",
        "oversized args denial",
    )
    assert_false(oversized["value_returned"], "oversized args value_returned")

    health = structured(smoke.request("tools/call", {"name": "health", "arguments": {}}))
    assert_false(health["value_returned"], "health top-level value_returned")
    assert_true(health["ok"], "health call ok")
    assert_true(health["result"]["ok"], "backend health ok")
    assert_false(health["result"]["value_returned"], "health result value_returned")
    assert_equal(health["result"]["backend"], "dotenv", "health backend")

    listed = structured(smoke.request("tools/call", {"name": "list_secrets", "arguments": {}}))
    assert_false(listed["value_returned"], "list top-level value_returned")
    assert_true(listed["ok"], "list call ok")
    assert_false(listed["result"]["value_returned"], "list result value_returned")
    secrets = listed["result"]["secrets"]
    assert_equal(len(secrets), 1, "listed secret count")
    secret = secrets[0]
    assert_true(secret["secret_ref"].startswith("sec_"), "secret_ref shape")
    assert_equal(secret["label"], "Canary token", "secret label")
    assert_true(secret["present"], "secret presence")
    assert_equal(secret["metadata_state"], "complete", "metadata state")
    assert_true(secret["normal_use_allowed"], "normal use allowed")
    assert_false(secret["value_returned"], "descriptor value_returned")

    described = structured(
        smoke.request(
            "tools/call",
            {
                "name": "describe_secret",
                "arguments": {"secret_ref": secret["secret_ref"]},
            },
        )
    )
    assert_true(described["ok"], "describe call ok")
    assert_false(described["value_returned"], "describe top-level value_returned")
    assert_equal(
        described["result"]["secret"]["secret_ref"],
        secret["secret_ref"],
        "describe secret_ref",
    )
    assert_false(
        described["result"]["secret"]["value_returned"],
        "describe descriptor value_returned",
    )

    permit = structured(
        smoke.request(
            "tools/call",
            {
                "name": "request_use",
                "arguments": {
                    "secret_ref": secret["secret_ref"],
                    "profile_id": secret["allowed_uses"][0],
                    "purpose": "dev smoke",
                },
            },
        )
    )
    assert_true(permit["ok"], "request_use call ok")
    assert_false(permit["value_returned"], "request_use top-level value_returned")
    assert_false(permit["result"]["value_returned"], "request_use result value_returned")
    assert_equal(permit["result"]["secret_ref"], secret["secret_ref"], "permit secret_ref")
    assert_true(permit["result"]["permit_id"].startswith("use_"), "permit id shape")

    rendered = "\n".join(smoke.transcript)
    for canary in [CANARY_VALUE, REQUEST_BODY_CANARY]:
        if canary in rendered:
            raise AssertionError(f"MCP transcript leaked canary material: {canary}")

    print(
        "janus-warden MCP smoke ok "
        f"backend={health['result']['backend']} "
        f"tools={len(tool_names)} "
        f"secret_ref={secret['secret_ref']} "
        "value_returned=false"
    )


def structured(call_result: dict[str, Any]) -> dict[str, Any]:
    if call_result.get("isError"):
        raise AssertionError(f"tool call returned isError=true: {call_result}")
    content = call_result.get("structuredContent")
    if not isinstance(content, dict):
        raise AssertionError(f"tool call did not include structuredContent: {call_result}")
    return content


def structured_denial(call_result: dict[str, Any]) -> dict[str, Any]:
    if call_result.get("isError") is not True:
        raise AssertionError(f"tool denial did not set isError=true: {call_result}")
    content = call_result.get("structuredContent")
    if not isinstance(content, dict):
        raise AssertionError(f"tool denial did not include structuredContent: {call_result}")
    if content.get("ok") is not False:
        raise AssertionError(f"tool denial did not set ok=false: {content}")
    return content


def assert_true(value: Any, label: str) -> None:
    if value is not True:
        raise AssertionError(f"{label}: expected true, got {value!r}")


def assert_false(value: Any, label: str) -> None:
    if value is not False:
        raise AssertionError(f"{label}: expected false, got {value!r}")


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as err:
        print(f"janus-warden MCP smoke failed: {err}", file=sys.stderr)
        raise

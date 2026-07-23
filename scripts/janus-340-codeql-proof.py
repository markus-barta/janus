#!/usr/bin/env python3
"""Temporary remote-command-injection fixture for the JANUS-340 ruleset proof."""

from __future__ import annotations

import subprocess

from flask import Flask, request


app = Flask(__name__)


@app.get("/proof")
def proof() -> str:
    command = request.args.get("command", "")
    return subprocess.check_output(command, shell=True, text=True)

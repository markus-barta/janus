#!/usr/bin/env python3
"""Temporary command-injection fixture for the JANUS-340 ruleset proof."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: janus-340-codeql-proof.py COMMAND")
    subprocess.run(sys.argv[1], check=True, shell=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

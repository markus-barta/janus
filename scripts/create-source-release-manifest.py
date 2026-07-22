#!/usr/bin/env python3
"""Create the deterministic source/tag/image binding that receives a keyless signature."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        print("source release commit must be a full lowercase Git SHA", file=sys.stderr)
        return 1
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest):
        print("source release image digest is invalid", file=sys.stderr)
        return 1
    manifest = {
        "schema_version": 1,
        "repository": args.repository,
        "tag": args.tag,
        "commit": args.commit,
        "workflow": args.workflow,
        "image": args.image,
        "image_digest": args.image_digest,
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

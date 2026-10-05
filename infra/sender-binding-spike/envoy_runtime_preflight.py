#!/usr/bin/env python3
"""Bind the runtime gate to the current schema evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

IMAGE_INDEX = "sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66"
ARM64 = "sha256:5edd669228659835ac243e3ffa5c08a65e92bb267d56da5c28317dbcf5a70292"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("schema_result", type=Path)
    parser.add_argument("checker", type=Path)
    parser.add_argument("verifier", type=Path)
    args = parser.parse_args()
    evidence = json.loads(args.schema_result.read_text())
    config_sha = hashlib.sha256(args.config.read_bytes()).hexdigest()
    if evidence.get("status") != "pass":
        raise ValueError("schema evidence is not green")
    if evidence.get("config_sha256") != config_sha:
        raise ValueError("schema evidence does not bind the current config")
    for field, path in (
        ("checker_sha256", args.checker), ("verifier_sha256", args.verifier)
    ):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if evidence.get(field) != digest:
            raise ValueError(f"schema evidence does not bind the current {field}")
    if evidence.get("image_index") != IMAGE_INDEX:
        raise ValueError("schema evidence uses another image index")
    if evidence.get("linux_arm64_manifest") != ARM64:
        raise ValueError("schema evidence uses another arm64 manifest")
    if evidence.get("executed_platform") != "linux/arm64":
        raise ValueError("schema evidence did not execute linux/arm64")
    if "/1.39.0/Clean/RELEASE/BoringSSL" not in evidence.get("envoy_version", ""):
        raise ValueError("schema evidence uses another Envoy build")
    print(json.dumps({"status": "pass", "config_sha256": config_sha}, sort_keys=True))


if __name__ == "__main__":
    main()

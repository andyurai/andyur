#!/usr/bin/env python3
"""Run one verification command under a total process-group deadline."""

from __future__ import annotations

import os
import signal
import subprocess
import sys


def run(argv: list[str], timeout: float, grace: float = 5.0) -> int:
    process = subprocess.Popen(argv, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return 124


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: bounded_exec.py SECONDS COMMAND [ARG ...]")
    raise SystemExit(run(sys.argv[2:], float(sys.argv[1])))

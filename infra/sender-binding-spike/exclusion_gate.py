#!/usr/bin/env python3
"""Current-tree guard against packaging the disposable sender-binding spike."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


SPIKE_MARKERS = ("sender-binding-spike", "phase1_gate.py")


def docker_sources(line: str) -> list[str]:
    stripped = line.strip()
    match = re.match(r"(?i)^(COPY|ADD)\s+(.*)$", stripped)
    if not match:
        return []
    rest = re.sub(r"^(--[^\s]+\s+)+", "", match.group(2)).strip()
    if rest.startswith("["):
        values = json.loads(rest)
        return [str(value) for value in values[:-1]]
    values = rest.split()
    return values[:-1]


def docker_instructions(text: str) -> list[tuple[int, str]]:
    """Join Dockerfile continuations before parsing COPY/ADD instructions."""
    result: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not pending:
            start = number
        pending += line[:-1] + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            result.append((start, pending))
            pending = ""
    if pending:
        raise ValueError(f"unterminated Dockerfile continuation at line {start}")
    return result


def source_includes_spike(source: str) -> bool:
    normalized = source.strip('"\'').rstrip("/") or "."
    return (normalized in {".", "./", "/", "infra", "./infra"}
            or "$" in normalized or "sender-binding-spike" in normalized)


def scan(root: Path) -> list[str]:
    failures = []
    for dockerfile in root.rglob("Dockerfile*"):
        if "sender-binding-spike" in dockerfile.parts:
            continue
        try:
            instructions = docker_instructions(dockerfile.read_text())
        except (UnicodeDecodeError, OSError, ValueError) as exc:
            failures.append(f"{dockerfile}: cannot parse safely: {type(exc).__name__}")
            continue
        for number, line in instructions:
            for source in docker_sources(line):
                if source_includes_spike(source):
                    failures.append(f"{dockerfile}:{number}: broad {source!r}")
    for relative in ("andyur", "infra/kubernetes"):
        base = root / relative
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in {
                    ".py", ".sh", ".yaml", ".yml", ".toml", ".md", ".json"}:
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError) as exc:
                failures.append(f"{path}: cannot scan safely: {type(exc).__name__}")
                continue
            if any(marker in text for marker in SPIKE_MARKERS):
                failures.append(f"{path}: production reference to spike")
    return failures


def self_test() -> None:
    accepted = ["COPY andyur ./andyur", "COPY infra/tool.sh /usr/bin/tool"]
    rejected = [
        "COPY . /app",
        "COPY ./ /app",
        "COPY --chown=1:1 . /app",
        'COPY [".", "/app"]',
        "ADD . /app",
        "COPY infra /app/infra",
        "COPY infra/sender-binding-spike /app/spike",
        "COPY --from=builder / /app",
        "COPY $SOURCE /app",
    ]
    if any(any(source_includes_spike(src) for src in docker_sources(line)) for line in accepted):
        raise AssertionError("exclusion self-test rejected an allowlisted narrow copy")
    for line in rejected:
        if not any(source_includes_spike(src) for src in docker_sources(line)):
            raise AssertionError(f"exclusion mutation stayed green: {line}")
    multiline = "COPY --chown=1:1 \\\n+      infra/sender-binding-spike \\\n+      /app/spike"
    [(number, instruction)] = docker_instructions(multiline)
    if number != 1 or not any(source_includes_spike(src)
                              for src in docker_sources(instruction)):
        raise AssertionError("multiline exclusion mutation stayed green")


if __name__ == "__main__":
    self_test()
    failures = scan(Path(sys.argv[1]).resolve())
    if failures:
        raise SystemExit("\n".join(failures))
    print("PASS: current-tree spike exclusion guard")

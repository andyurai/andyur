"""No gate may read a container log through an early-exiting pipeline.

`docker logs X | grep -q PAT` looks correct and is not. grep -q exits at the
FIRST match, which closes the pipe while docker is still writing; docker dies
of SIGPIPE (141); and in a script with `set -o pipefail` the PIPELINE then
reports failure even though the pattern WAS found.

The failure is size-dependent -- it only appears once the log is big enough
that docker has not already finished writing -- so a gate written this way
passes early in its life and starts lying as the system it watches gets
chattier. That is indistinguishable from a flake, and it cost this project a
wrong root cause (recorded as host memory pressure) before it was found.

Both directions were observed live against a real container: the pre-fix
helper reported a healthy, running Keycloak as not ready; the capture-then-
match form found it. Read the log into a variable and match it with `case`.
"""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

# `docker logs ...` feeding a grep that stops at the first hit. -c/-o/tail all
# drain the producer, so only the early-exiting readers are the hazard.
# A single `|` (not `||`, which is an OR and drains nothing) carrying `docker
# logs` into a grep that stops early. Bounded to one command: `;` ends the
# match, so a later unrelated pipeline on a joined line is not a false hit.
PIPED_READ = re.compile(r"docker\s+logs\b[^|;\n]*\|(?!\|)[^;\n]*grep\s+-[A-Za-z]*q")


def _logical_lines(text):
    """Yield (lineno, logical line), joining shell continuations.

    A pipeline may be split across lines -- ending a line with `|` or `\\` and
    continuing on the next is idiomatic and readable. Scanning line by line
    misses those entirely, which is a false negative in exactly the shape this
    module exists to catch: the first version of this guard scanned single
    lines and walked straight past verify-opa-hardening.sh's two-line
    `docker logs ... |` / `grep -Eqi ...` in wait_for_bundle_refusal_signal.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        merged = lines[i]
        while merged.rstrip().endswith(("|", "\\")) and i + 1 < len(lines):
            i += 1
            merged = merged.rstrip().rstrip("\\") + " " + lines[i].strip()
        yield start + 1, merged
        i += 1


def _shell_scripts():
    files = sorted(ROOT.glob("infra/**/*.sh")) + [ROOT / "run.sh"]
    return [f for f in files if f.is_file()]


def test_no_gate_reads_docker_logs_through_an_early_exiting_pipe():
    offenders = []
    for path in _shell_scripts():
        text = path.read_text(errors="replace")
        if "pipefail" not in text:
            continue
        for n, line in _logical_lines(text):
            if line.lstrip().startswith("#"):
                continue  # the warning comments name the idiom on purpose
            if PIPED_READ.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not offenders, (
        "these read a container log through a pipeline that exits at the first "
        "match; under pipefail that reports NOT FOUND for a pattern that IS "
        "present (SIGPIPE 141). Capture into a variable and match with case:\n  "
        + "\n  ".join(offenders))

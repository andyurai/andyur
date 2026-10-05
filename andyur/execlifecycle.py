"""exec/v1 run completion: mapping a stock process's exit to run state, and
bounding the output captured from it (ADR-011 D3).

A runtime-v1 agent reports its own completion: it streams a ``done`` sentinel
the runner turns into a finished run. A stock ``exec/v1`` workload reports
nothing -- it starts, does its work, writes to stdout, and exits. So the
platform reads completion at the one boundary it owns, the process's exit, and
that is what this module encodes.

D3 IS THE DECISION THIS ENFORCES: ``exit 0`` means the PROCESS COMPLETED, never
that the work succeeded. The audit is the proof -- OpenSRE exited 0 having
concluded "unable to determine root cause". So exit status maps to a LIFECYCLE
state, and the captured output is DIAGNOSTIC: stored, shown to the operator,
never read by an authorization decision and never treated as evidence that
anything happened. Two functions, one for each half, kept pure so the daemon
that owns exec/v1 completion has no lifecycle rule of its own to drift.
"""

from __future__ import annotations

from .redact import redact

# The marker left where captured output was cut. Distinct and unambiguous so an
# operator reading a truncated bundle knows the cut was the platform's, not the
# workload's.
TRUNCATION_MARKER = "\n[andyur: output truncated at the retention bound]\n"


def exit_error(exit_code: int | None) -> str | None:
    """A process exit to the run's error, or None for a clean completion (D3).

        exit 0            -> None                     the process COMPLETED
        exit non-zero     -> "...code N"              it exited unsuccessfully
        exit None         -> "...vanished"            no exit status at all

    RETURNS ONLY THE ERROR, never a run state, ON PURPOSE. `done` vs `failed`
    is derived from the presence of an error in exactly one place -- the server's
    finish_run (`state = "failed" if error else "done"`) -- and a second decider
    here would be a rule kept in two places that will disagree. The daemon hands
    the server this error and the server decides the state, exactly as the
    runner does for a runtime-v1 run.

    The None (vanished) case is a container that reached a terminal phase with no
    readable exit code -- evicted, OOM-killed, or gone before its status was
    read. That is an error, not a clean exit: absence of an exit status is not
    exit 0. TTL, operator halt and revocation do not arrive here -- they
    terminate through the platform's kill path, which finalizes the run before
    this observation, and finish_run's state guard makes a late report a no-op.
    """
    if exit_code == 0:
        return None
    if exit_code is None:
        return ("the workload process vanished before reporting an exit status "
                "(evicted, OOM-killed, or gone before its status was read)")
    return f"the workload process exited with code {exit_code}"


def capture_output(stdout: str | None, stderr: str | None, *,
                   emission_max_bytes: int, retention_max_bytes: int) -> str:
    """The workload's captured output, redacted and bounded, for the run record.

    Two bounds, and the EFFECTIVE one is the smaller (ADR-011 D3 / D's decision
    #4): ``emission_max_bytes`` is what the manifest asked to emit
    (``process.output.max_bytes``), ``retention_max_bytes`` is what the platform
    will store regardless (an operator constant), and neither may be exceeded.
    Redaction runs FIRST, before truncation, so a secret split across the cut
    cannot survive by being half-included; then the redacted text is truncated
    on a UTF-8 boundary with a marker.

    Diagnostic only. This value lands in the run's summary, which is shown to
    the operator and is never an input to an authorization decision.
    """
    parts = []
    if stdout:
        parts.append(redact(stdout))
    if stderr:
        # Labelled, because a stock tool's diagnostics and its result share no
        # stream discipline and an operator needs to tell them apart.
        parts.append("[stderr]\n" + redact(stderr))
    combined = "\n".join(parts)
    bound = min(emission_max_bytes, retention_max_bytes)
    return _truncate_utf8(combined, bound)


def _truncate_utf8(text: str, max_bytes: int) -> str:
    """Truncate `text` so its UTF-8 encoding is at most `max_bytes`, appending
    the marker when it cut. Never splits a multi-byte character."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    marker_bytes = len(TRUNCATION_MARKER.encode("utf-8"))
    if max_bytes <= marker_bytes:
        # The bound is smaller than the marker itself (a pathological
        # process.output.max_bytes). Truncate hard on a character boundary and
        # do not append a marker that would push the result back over the bound
        # -- the result must never exceed max_bytes.
        return encoded[:max_bytes].decode("utf-8", errors="ignore")
    keep = max_bytes - marker_bytes
    # Back off to a character boundary: decode ignoring a trailing partial
    # sequence, which errors="ignore" drops.
    head = encoded[:keep].decode("utf-8", errors="ignore")
    return head + TRUNCATION_MARKER

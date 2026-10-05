"""Reporting a run's terminal state to the control plane, in one place.

A run ends by POSTing its ``summary`` and ``error`` to ``/runs/{id}/finish``;
the server derives the run STATE from whether an error is present (one decider,
in coordinator.finish_run). The HTTP contract around that call -- how many times
to retry, which status codes are terminal, and what a failure to confirm means
-- was copied inline at four runner call sites and would have been a fifth in
the daemon's exec/v1 completion path. It lives here instead, so the rule that a
5xx is retried while a run left unconfirmed is lost to the reaper is written
once.
"""

from __future__ import annotations

import asyncio

from .redact import redact

FINISH_ATTEMPTS = 3


async def post_finish(api, run_id: str, *, summary: str | None,
                      error: str | None, attempts: int = FINISH_ATTEMPTS,
                      path: str | None = None, extra: dict | None = None,
                      ) -> tuple[bool, str]:
    """POST a run's terminal state, retrying transient failures.

    Returns ``(confirmed, reason)``. ``confirmed`` is True when the server
    reports a terminal state -- ``2xx`` (we finalized it), ``409`` (already
    finalized), ``404`` (the run is gone), or ``403`` (worker-finish: the run is
    not ours to finish -- reassigned to another worker -- so its outcome is that
    worker's to report); ``reason`` is a short redacted string for the caller's
    log when it is not.

    ONLY those four are terminal-confirmed; EVERYTHING ELSE is retried, and that
    breadth is deliberate. httpx does not raise on a 5xx and a run left
    ``running`` is reaped ~17 minutes later with its result lost, so a 5xx is
    retried -- but so is a ``401``: a finish landing during an SVID/token
    rotation fails auth transiently and succeeds on the next attempt, and giving
    up on it would strand the run exactly as a 5xx would. A genuinely bad
    request is retried a bounded few times and then reported unconfirmed, which
    costs two extra calls and never a lost run. The caller supplies a client
    already authenticated for the endpoint; this function is auth-agnostic, so
    the runner (its run-token client -> /runs/{id}/finish) and the daemon (its
    worker client -> /runs/{id}/worker-finish, via ``path``/``extra``) share the
    retry-and-terminal rule unchanged. A 409 is CONFIRMED for either: a run the
    proxy runner already finished is not a run the worker lost.
    """
    url = path or f"/runs/{run_id}/finish"
    body = {"summary": summary, "error": error}
    if extra:
        body.update(extra)
    reason = "no attempt made"
    for attempt in range(attempts):
        try:
            resp = await api.post(url, json=body)
            # Terminal, stop retrying: 2xx (we finalized it), 404 (gone), 409
            # (already finalized), AND 403 -- worker-finish 403s when the run has
            # been reassigned to another worker; it is not ours to finish, so a
            # 403 is a decision, not a transient auth blip to hammer. (The runner
            # /finish path never 403s -- it carries the run's own token.)
            if resp.status_code < 300 or resp.status_code in (403, 404, 409):
                return True, ""
            reason = f"finish returned {resp.status_code}"
        except Exception as exc:  # network error mid-call: retry
            reason = redact(f"{type(exc).__name__}: {exc}")
        if attempt < attempts - 1:
            await asyncio.sleep(1)
    return False, reason

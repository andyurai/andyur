"""HTTP calls to things we do not control, with a bound that actually binds.

Andyur composes other people's infrastructure on purpose: the PDP is theirs, the
IdP is theirs, and both sit on the request path where an authorization decision
is being made. We cannot make those services well behaved. The client is the only
place we control, so the bound has to live here.

WHY THE OBVIOUS SPELLING IS WRONG. Both `httpx`'s `timeout=5.0` and urllib's
`urlopen(..., timeout=30)` are PER-OPERATION. They bound how long one read may
block, not how long the call may take. A peer that sends one byte every four
seconds resets the clock on every read and the call never returns. Measured, not
theorised: against a PDP dripping a chunk every 2s, `httpx.Client(timeout=5.0)`
was still waiting at 45 seconds, and at three minutes when left alone. The same
shape applies to PyJWKClient, which is urllib underneath.

WHAT THAT COSTS. `server/pdp.py` calls the PDP with a SYNCHRONOUS client, so each
stalled call holds a thread. A degraded PDP -- not an attack, just a bad
afternoon behind a load balancer -- exhausts the pool, and because the PDP fails
closed the platform's degraded mode becomes "deny everything, slowly". The IdP
path is the same: a slow JWKS refresh stalls every request needing user auth.

So: a TOTAL wall-clock deadline, and a size cap, on every call to a component an
adopter supplies. Per-operation timeouts stay as well -- they fail faster in the
ordinary stall -- but they are no longer the only thing standing between us and
an unbounded wait.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

log = logging.getLogger("andyur.http")

# Enough for a JWKS with many keys or a batched PDP response, small enough that a
# hostile or broken peer cannot stream us out of memory. The cap is enforced
# while streaming, so an oversized body is abandoned rather than buffered first.
MAX_BYTES = 1 << 20        # 1 MiB
DEFAULT_BUDGET = 5.0       # seconds, TOTAL


class Unbounded(Exception):
    """The peer exceeded its total time or size budget.

    A distinct type because callers on the authorization path must be able to log
    WHY they are denying. `pdp.py` already fails closed on any exception; this
    just makes the reason legible in the operator's log rather than appearing as
    a generic transport error.
    """


def _read_bounded(response: httpx.Response, deadline: float, max_bytes: int,
                  what: str) -> bytes:
    """Stream a body, giving up on the TOTAL clock or the size cap.

    The deadline is checked between chunks, which is the only place it can be
    checked -- and is exactly the place the per-operation timeout does not look.
    """
    body = bytearray()
    for chunk in response.iter_raw():
        # iter_raw, not iter_bytes. `iter_bytes` yields DECODED bytes, and httpx
        # decompresses with no output limit, so one small gzip chunk expands
        # without bound before this check ever runs -- measured at 33-50 MB
        # buffered against a 1 MiB cap, from a peer sending a few hundred KB.
        # A cap that is checked after the allocation is not a cap.
        body += chunk
        if len(body) > max_bytes:
            raise Unbounded(
                f"{what} sent more than {max_bytes} bytes; abandoned")
        if time.monotonic() > deadline:
            raise Unbounded(
                f"{what} did not finish within its total budget; abandoned after "
                f"{len(body)} bytes")
    return bytes(body)


def _call(method: str, url: str, *, what: str, budget: float, max_bytes: int,
          json_body: Any = None, form_body: dict[str, str] | None = None,
          headers: dict[str, str] | None = None,
          raise_for_status: bool = True) -> tuple[int, bytes]:
    deadline = time.monotonic() + budget
    # Per-operation limits stay, and are derived from the total rather than set
    # independently: a connect that alone outlasts the whole budget is already a
    # failure, and two numbers that can disagree eventually do.
    per_op = httpx.Timeout(budget, connect=min(2.0, budget))
    # Identity encoding, so the bytes counted are the bytes allocated. Asking
    # for compression would reintroduce the decompression bomb above by the back
    # door: httpx sets Accept-Encoding: gzip, deflate by default.
    hdrs = {"Accept-Encoding": "identity", **(headers or {})}
    with httpx.Client(timeout=per_op) as client:
        with client.stream(method, url, json=json_body, data=form_body,
                           headers=hdrs) as resp:
            if raise_for_status:
                resp.raise_for_status()
            # The body is read under the SAME budget whether or not the status
            # was an error. An error body is attacker-influenced too -- an AS
            # that 400s and then dribbles a gigabyte is the identical hazard as
            # one that 200s and does it.
            return resp.status_code, _read_bounded(resp, deadline, max_bytes, what)


def post_json(url: str, payload: Any, *, what: str,
              budget: float = DEFAULT_BUDGET, max_bytes: int = MAX_BYTES,
              headers: dict[str, str] | None = None) -> Any:
    """POST JSON and parse the reply, within a total wall-clock budget."""
    _status, body = _call("POST", url, what=what, budget=budget,
                          max_bytes=max_bytes, json_body=payload, headers=headers)
    return json.loads(body)


def post_json_response(url: str, payload: Any, *, what: str,
                       budget: float = DEFAULT_BUDGET,
                       max_bytes: int = MAX_BYTES,
                       headers: dict[str, str] | None = None) -> tuple[int, Any]:
    """POST JSON and preserve an OAuth-style error status and body."""
    status, body = _call("POST", url, what=what, budget=budget,
                         max_bytes=max_bytes, json_body=payload,
                         headers=headers, raise_for_status=False)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def post_form(url: str, form: dict[str, str], *, what: str,
              budget: float = DEFAULT_BUDGET, max_bytes: int = MAX_BYTES,
              headers: dict[str, str] | None = None) -> tuple[int, Any]:
    """POST `application/x-www-form-urlencoded` and parse the reply.

    Returns `(status, parsed)` and does NOT raise on 4xx, because an OAuth error
    IS a 400 with a JSON body naming the cause (RFC 6749 sec 5.2). Raising here
    would discard `error` and `error_description` and leave the caller reporting
    "the exchange failed" when the AS said exactly which control refused -- and
    an error naming the wrong cause costs more than one naming none.

    A body that is not JSON yields `(status, None)` rather than raising: an AS
    behind a proxy can return an HTML error page, and that is a failure to report
    rather than a traceback to propagate.
    """
    status, body = _call("POST", url, what=what, budget=budget,
                         max_bytes=max_bytes, form_body=form, headers=headers,
                         raise_for_status=False)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def get_bytes(url: str, *, what: str, budget: float = DEFAULT_BUDGET,
              max_bytes: int = MAX_BYTES,
              headers: dict[str, str] | None = None) -> bytes:
    """GET a body within a total wall-clock budget.

    Returns bytes rather than parsed JSON because its caller is PyJWKClient's
    `fetch_data`, which wants to do its own decoding.
    """
    _status, body = _call("GET", url, what=what, budget=budget,
                          max_bytes=max_bytes, headers=headers)
    return body

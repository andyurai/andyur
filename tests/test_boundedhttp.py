"""Calls to an adopter's components must be bounded in TOTAL, not per read.

The bug these guard against is not a hang under attack -- it is a hang under a
component behaving slightly badly, which is the ordinary condition of anything
behind a load balancer. `httpx.Client(timeout=5.0)` and `urlopen(timeout=30)`
both bound one read, so a peer that sends a byte every few seconds is never timed
out. Measured against the server below: the unfixed client was still waiting at
three minutes.

Every test here runs against a real socket rather than a mocked transport,
because the defect lives in how the transport handles a slow peer and a mock
would have none of that behaviour to get wrong.
"""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from andyur import boundedhttp

BUDGET = 1.0            # keep the suite fast; the defect is scale-free


def _serve(handler) -> tuple[str, threading.Event]:
    """Start a one-shot HTTP server on a free port; return its base URL."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handler, args=(conn, stop), daemon=True).start()
        srv.close()

    threading.Thread(target=loop, daemon=True).start()
    return f"http://127.0.0.1:{port}", stop


def _drip(conn, stop):
    """Answers, forever. Every individual read lands well inside any per-read
    timeout; the response as a whole never ends."""
    conn.recv(65536)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n")
    while not stop.is_set():
        try:
            conn.sendall(b"1\r\n \r\n")
        except OSError:
            return
        time.sleep(0.1)


def _flood(conn, stop):
    """Answers as fast as it can, and never stops. Bounded by SIZE, not time."""
    conn.recv(65536)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n")
    chunk = b"1000\r\n" + b"x" * 0x1000 + b"\r\n"
    while not stop.is_set():
        try:
            conn.sendall(chunk)
        except OSError:
            return


def _healthy(payload):
    def handler(conn, stop):
        conn.recv(65536)
        body = json.dumps(payload).encode()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        conn.close()
    return handler


def _within(seconds, fn):
    """Run fn, and report if it is still going after `seconds`.

    A plain call would hang the whole suite on regression rather than failing it,
    which is the difference between a red build and an abandoned one.
    """
    box: dict = {}

    def go():
        try:
            box["ok"] = fn()
        except BaseException as exc:            # noqa: BLE001 - reported, not swallowed
            box["exc"] = exc

    th = threading.Thread(target=go, daemon=True)
    started = time.monotonic()
    th.start()
    th.join(seconds)
    if th.is_alive():
        pytest.fail(f"still running after {seconds}s -- the call is UNBOUNDED")
    return box, time.monotonic() - started


def test_a_dripping_peer_is_abandoned_within_the_total_budget():
    base, stop = _serve(_drip)
    try:
        box, elapsed = _within(BUDGET * 15,
                               lambda: boundedhttp.post_json(f"{base}/x", {"a": 1},
                                                             what="peer", budget=BUDGET))
        assert isinstance(box.get("exc"), boundedhttp.Unbounded), box
        assert elapsed < BUDGET * 6, (
            f"took {elapsed:.1f}s for a {BUDGET}s budget; bounded, but not by the budget")
    finally:
        stop.set()


def test_a_dripping_peer_is_abandoned_on_a_GET_too():
    """Both verbs, because the two call sites use different ones: the PDP POSTs
    its evaluation, the IdP's JWKS is fetched with GET. A fix on one only would
    read as done."""
    base, stop = _serve(_drip)
    try:
        box, _ = _within(BUDGET * 15,
                         lambda: boundedhttp.get_bytes(f"{base}/jwks",
                                                       what="peer", budget=BUDGET))
        assert isinstance(box.get("exc"), boundedhttp.Unbounded), box
    finally:
        stop.set()


def test_a_flooding_peer_is_abandoned_on_size_before_the_clock_runs_out():
    """Time is not the only unbounded axis. A peer answering at full speed stays
    inside every deadline while streaming us out of memory."""
    base, stop = _serve(_flood)
    try:
        box, _ = _within(30, lambda: boundedhttp.get_bytes(
            f"{base}/jwks", what="peer", budget=60, max_bytes=1 << 16))
        assert isinstance(box.get("exc"), boundedhttp.Unbounded), box
        assert "bytes" in str(box["exc"]), (
            f"abandoned for the wrong reason: {box['exc']}")
    finally:
        stop.set()


def test_a_healthy_peer_still_gets_through():
    """The positive control. Every assertion above is satisfied by a client that
    refuses everything, so on its own the suite would pass with the feature
    broken in the most useless possible way."""
    base, stop = _serve(_healthy({"decision": True}))
    try:
        assert boundedhttp.post_json(f"{base}/x", {"a": 1},
                                     what="peer", budget=BUDGET) == {"decision": True}
    finally:
        stop.set()


def test_the_pdp_denies_rather_than_hanging_when_its_peer_drips():
    """The property, at the call site that matters.

    Testing boundedhttp alone would leave the PDP free to stop using it. This
    asserts what an operator actually cares about: a degraded PDP produces a
    prompt denial, not a stalled request path.
    """
    from andyur import config
    from andyur.server import pdp

    base, stop = _serve(_drip)
    was_url, was_pdp = config.PDP_URL, config.PDP
    config.PDP_URL, config.PDP = base, "authzen"
    try:
        subject = pdp.Subject(type="run", id="r1", is_operator=False)
        box, elapsed = _within(30, lambda: pdp._authzen(subject, ["files:read"]))
        assert box.get("ok") == [False], f"expected a closed failure, got {box}"
        assert elapsed < 30, "the decision was reached, but not promptly"
    finally:
        config.PDP_URL, config.PDP = was_url, was_pdp
        stop.set()


def test_the_jwks_fetch_is_bounded_and_keeps_pyjwts_error_contract():
    """PyJWT's callers key off PyJWKClientConnectionError. Bounding the fetch must
    change WHEN it fails, never HOW -- otherwise the exception escapes as a 500
    where a 401 belongs."""
    import jwt

    from andyur.server import oidc

    base, stop = _serve(_drip)
    try:
        client = oidc._bounded_jwk_client_class()(f"{base}/.well-known/jwks.json")
        box, _ = _within(30, client.fetch_data)
        assert isinstance(box.get("exc"), jwt.exceptions.PyJWKClientConnectionError), box
    finally:
        stop.set()


def test_no_call_to_an_adopters_component_builds_its_own_http_client():
    """The CLASS, so the next one is caught before it ships.

    This defect was found in the gateway, fixed there, and then sat unnoticed in
    the PDP and IdP clients -- the same mistake, in the same shape, on the more
    security-critical path. A per-site test would have caught none of that.
    """
    import ast
    import pathlib

    # Parsed, not grepped. The first cut of this test matched the string
    # `urlopen(` inside a COMMENT explaining the bug, and failed on the file that
    # had just been fixed. A test that cannot tell code from prose will be
    # silenced rather than trusted.
    banned = {("httpx", "Client"), ("urllib", "urlopen"), ("request", "urlopen")}
    root = pathlib.Path(__file__).resolve().parent.parent / "andyur"
    offenders = []
    for path in (root / "server" / "pdp.py", root / "server" / "oidc.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if (f.value.id, f.attr) in banned:
                    offenders.append(f"{path.name}:{node.lineno} {f.value.id}.{f.attr}")
            elif isinstance(f, ast.Attribute) and f.attr == "urlopen":
                offenders.append(f"{path.name}:{node.lineno} ...urlopen")
    assert not offenders, (
        f"{offenders} build their own HTTP client to reach an adopter-supplied "
        "component. A bare timeout= is per-operation and does not bound the call; "
        "use andyur.boundedhttp.")

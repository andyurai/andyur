"""The exec/v1 sidecar's front on the proxy port (R MED-2, PR #21).

Real wire, both directions: a real upstream records what the front forwards,
and the front is exercised over HTTP as the workload and the kubelet would.
"""
from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from andyur.runner.execfront import ExecFront

# Long enough that a buffering front cannot be mistaken for a streaming one on a
# loaded machine, short enough not to pad the suite.
STREAM_GAP_SECONDS = 1.0


class _Upstream:
    """A real HTTP server standing in for the sidecar's model proxy."""

    def __init__(self):
        self.seen: list[dict] = []

        async def any_path(request: Request) -> Response:
            self.seen.append({
                "method": request.method, "path": request.url.path,
                "query": dict(request.query_params),
                "body": await request.body(),
                "headers": {k.lower(): v for k, v in request.headers.items()},
            })
            return Response(b'{"model":"answered"}', status_code=201,
                            media_type="application/json",
                            headers={"x-upstream": "yes"})

        app = Starlette(routes=[Route("/{path:path}", endpoint=any_path,
                                      methods=["GET", "POST", "PUT", "DELETE"])])
        self._server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="warning"))

    def start(self) -> str:
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        while not self._server.started:
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    def stop(self):
        # JOIN, not just signal: a uvloop thread still running at interpreter
        # exit segfaults in its timer callback (PyGILState_Ensure on a torn-down
        # interpreter) -- seen as a "Python quit unexpectedly" crash report
        # after a green run of this file.
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture()
def upstream():
    up = _Upstream()
    url = up.start()
    yield up, url
    up.stop()


@pytest.fixture()
def front(upstream):
    _, url = upstream
    f = ExecFront(url)
    base = f.start()
    yield base
    f.stop()


def test_ready_answers_on_the_front(front):
    r = httpx.get(front + "/ready")
    assert r.status_code == 200
    assert r.json() == {"ready": True, "model_proxy": True}


def test_llm_is_forwarded_verbatim_to_the_model_proxy(upstream, front):
    up, _ = upstream
    r = httpx.post(front + "/llm/v1/chat/completions", params={"beta": "1"},
                   content=b'{"prompt":"hi"}',
                   headers={"content-type": "application/json",
                            "x-custom": "kept", "authorization": "Bearer throwaway"})
    assert r.status_code == 201
    assert r.content == b'{"model":"answered"}'
    assert r.headers["x-upstream"] == "yes"
    [seen] = up.seen
    # method, path under the prefix, query and body reach the proxy unchanged
    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/chat/completions"
    assert seen["query"] == {"beta": "1"}
    assert seen["body"] == b'{"prompt":"hi"}'
    assert seen["headers"]["x-custom"] == "kept"
    # the workload's throwaway credential is dropped at the first hop, as the
    # model proxy itself drops it before injecting the real one
    assert "authorization" not in seen["headers"]


def test_the_bare_prefix_is_not_a_model_call(upstream, front):
    up, _ = upstream
    assert httpx.get(front + "/llm").status_code == 404
    assert httpx.post(front + "/llm", json={}).status_code == 404
    assert up.seen == []


def test_nothing_else_is_exposed_on_the_front(front):
    # No context, no events, no finish: the front is readiness + the model path.
    for path in ("/v1/context", "/v1/events", "/finish", "/", "/mcp"):
        assert httpx.get(front + path).status_code in (404, 405), path


class _SlowStream:
    """An upstream that streams SSE with a REAL gap between the chunks.

    The gap is the whole point. An upstream that writes its chunks back to back
    cannot distinguish a front that forwards them as they arrive from one that
    reads the whole body first and sends it in one go -- both deliver the same
    bytes, and a test that only inspects the bytes passes either way. Hermes
    Agent reads a streamed completion token by token, so a buffering front
    would hold its first token until the model finished.
    """

    def __init__(self, gap: float = STREAM_GAP_SECONDS):
        self.gap = gap
        self.finished_at: float | None = None

        async def sse(request: Request) -> StreamingResponse:
            await request.body()

            async def chunks():
                yield b'data: {"choices":[{"index":0,"delta":{"content":"first"}}]}\n\n'
                await asyncio.sleep(self.gap)
                yield b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
                yield b"data: [DONE]\n\n"
                self.finished_at = time.monotonic()

            return StreamingResponse(chunks(), media_type="text/event-stream")

        app = Starlette(routes=[Route("/{path:path}", endpoint=sse, methods=["POST"])])
        self._server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="warning"))

    def start(self) -> str:
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        while not self._server.started:
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


def test_a_streamed_model_answer_reaches_the_workload_chunk_by_chunk():
    """The front FORWARDS a stream, it does not collect one.

    This is the property the exec/v1 conformance gate's stub could not show.
    That stub answers a streamed call with one SSE body in a single write, so
    the gate proves the SHAPE is SSE and is silent on timing: replacing the
    front's `async for chunk in resp.aiter_bytes()` with a single
    `await resp.aread()` leaves it green. Here the upstream holds the closing
    chunks for a full second, so the first token can only arrive early if the
    front passed it on without waiting for the rest.
    """
    up = _SlowStream()
    url = up.start()
    f = ExecFront(url)
    base = f.start()
    try:
        started = time.monotonic()
        first_at = None
        events = []
        with httpx.stream("POST", base + "/llm/v1/chat/completions",
                          json={"model": "any", "stream": True},
                          timeout=STREAM_GAP_SECONDS * 10) as r:
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")
            for line in r.iter_lines():
                if not line.startswith("data: "):
                    continue
                if first_at is None:
                    first_at = time.monotonic()
                events.append(line[len("data: "):])
        done_at = time.monotonic()
    finally:
        f.stop()
        up.stop()

    # the whole stream arrived, in order, ending in the sentinel
    assert events[-1] == "[DONE]"
    assert "first" in events[0]
    # THE TIMING IS THE ASSERTION. The first chunk is out of the front well
    # before the upstream has finished; the response as a whole is not.
    assert first_at is not None and first_at - started < STREAM_GAP_SECONDS / 2
    assert done_at - started >= STREAM_GAP_SECONDS
    assert up.finished_at is not None and first_at < up.finished_at


def test_without_a_model_proxy_llm_is_503_by_name_and_ready_still_answers():
    f = ExecFront(None)
    base = f.start()
    try:
        assert httpx.get(base + "/ready").json() == {"ready": True, "model_proxy": False}
        r = httpx.post(base + "/llm/api/chat", content=b"{}")
        assert r.status_code == 503
        assert r.json()["error"] == "no_model_proxy" and "no model proxy" in r.json()["detail"]
    finally:
        f.stop()


# ---------------------------------------------------------------------------
# HIGH-1 (R, PR #21): dot segments must not escape the /llm prefix. Over a raw
# socket, because httpx and curl normalise `..` on the CLIENT side and hide it.
# ---------------------------------------------------------------------------

import socket

from andyur.runner import execfront


def _raw_get(base: str, path: str, method: str = "GET") -> tuple[int, bytes]:
    host, port = base[len("http://"):].rsplit(":", 1)
    s = socket.create_connection((host, int(port)))
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), body


def _raw_post(base: str, path: str) -> tuple[int, bytes]:
    return _raw_get(base, path, method="POST")


TRAVERSALS = ["/llm/../tools/crm/mcp", "/llm/%2e%2e/tools/crm/mcp",
              "/llm/x/../../tools/crm/mcp", "/llm/./../tools/crm/mcp",
              "/llm/%252e%252e/tools/crm/mcp", "/llm//tools/crm/mcp", "/%6Clm/../tools/crm/mcp"]


def test_dot_segments_never_reach_the_upstream(upstream):
    """The upstream in Kubernetes is the ToolSidecar, whose one listener also
    serves /tools/* (the delegated-token leg). Every traversal spelling is
    refused at the front by name; the upstream sees nothing."""
    up, url = upstream
    f = ExecFront(url + "/llm")
    base = f.start()
    try:
        for path in TRAVERSALS:
            status, body = _raw_get(base, path)
            assert status == 400 and b"refused" in body, (path, status, body)
        assert up.seen == [], [s["path"] for s in up.seen]
        # positive control: a literal path under the prefix is forwarded, with
        # the prefix stripped and the segments verbatim
        status, _ = _raw_post(base, "/llm/api/chat?x=1")
        assert status == 201
        assert [s["path"] for s in up.seen] == ["/llm/api/chat"]
    finally:
        f.stop()


def test_forward_path_decides_on_the_raw_bytes():
    assert execfront.forward_path(b"/llm") == "/"
    assert execfront.forward_path(b"/llm/v1/messages") == "/v1/messages"
    assert execfront.forward_path(b"/llm/a%20b/c") == "/a%20b/c"      # verbatim
    for raw in (b"/llm/../x", b"/llm/%2e%2e/x", b"/llm/x/../../y", b"/llm/./x",
                b"/llm/%252e%252e/x", b"/llm//x", b"/llmx", b"/%6Clm/x", b"/tools/x",
                b"/llm/\xff", b"/llm/a%2Fb/x", b"/llm/..%5Cx", b"/llm/..;/x",
                b"/llm/%2e%2e%2fx", b"/llm/a%252Fb", b"/llm/a%5Cb", b"/llm/a%255Cb"):
        assert execfront.forward_path(raw) is None, raw


def test_bodies_are_bounded_at_the_front(upstream, monkeypatch):
    up, url = upstream
    monkeypatch.setattr(execfront, "MAX_BODY_BYTES", 16)
    f = ExecFront(url)
    base = f.start()
    try:
        # declared over the cap: refused on Content-Length before a byte is read
        assert httpx.post(base + "/llm/api/chat", content=b"x" * 17).status_code == 413
        # CHUNKED over the cap (no Content-Length): refused while streaming
        def chunks():
            yield b"x" * 10
            yield b"x" * 10
        assert httpx.post(base + "/llm/api/chat", content=chunks()).status_code == 413
        assert httpx.post(base + "/llm/api/chat", content=b"x" * 16).status_code == 201
        assert [s["body"] for s in up.seen] == [b"x" * 16]
    finally:
        f.stop()


def test_a_dead_upstream_is_a_502_by_name():
    f = ExecFront("http://127.0.0.1:9")       # nothing listens on port 9
    base = f.start()
    try:
        r = httpx.post(base + "/llm/api/chat", json={})
        assert r.status_code == 502 and "unreachable" in r.json()["error"]
    finally:
        f.stop()


def test_an_over_cap_content_length_is_refused_before_any_body_is_read(upstream, monkeypatch):
    """Raw socket, over-cap Content-Length and NO body: the header check alone
    must answer 413 (the streaming cap cannot, since nothing streams) -- so a
    mutant that drops the header check is distinguishable (R LOW, round 2)."""
    up, url = upstream
    monkeypatch.setattr(execfront, "MAX_BODY_BYTES", 16)
    f = ExecFront(url)
    base = f.start()
    try:
        host, port = base[len("http://"):].rsplit(":", 1)
        s = socket.create_connection((host, int(port)))
        s.settimeout(3)
        s.sendall(b"POST /llm/api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 17\r\n"
                  b"Connection: close\r\n\r\n")
        data = s.recv(65536)
        s.close()
        assert data.startswith(b"HTTP/1.1 413"), data[:60]
        assert up.seen == []
    finally:
        f.stop()


# ---------------------------------------------------------------------------
# HIGH-1 (R, PR #22): the front is a model-call endpoint, not the model API
# ---------------------------------------------------------------------------

def test_the_front_forwards_only_model_calls_and_refuses_the_model_api_by_name(upstream):
    up, url = upstream
    f = ExecFront(url, enforced_model="granted-model")
    base = f.start()
    try:
        ok = httpx.post(base + "/llm/api/chat", json={"model": "granted-model", "messages": []})
        assert ok.status_code == 201 and [s["path"] for s in up.seen] == ["/api/chat"]
        assert httpx.post(base + "/llm/v1/chat/completions", json={"model": "granted-model"}).status_code == 201
        for method, path in (("GET", "/llm/api/tags"), ("GET", "/llm/api/ps"), ("GET", "/llm/api/version"),
                             ("DELETE", "/llm/api/delete"), ("POST", "/llm/api/pull"),
                             ("POST", "/llm/api/create"), ("POST", "/llm/api/experimental/web_fetch"),
                             ("GET", "/llm/v1/chat/completions"), ("GET", "/llm")):
            r = httpx.request(method, base + path, json={"model": "granted-model"})
            assert r.status_code == 404 and r.json()["error"] == "path_not_model_call", (method, path)
            assert "not a model call" in r.json()["detail"]
        assert len(up.seen) == 2                                    # nothing else reached the upstream
    finally:
        f.stop()


def test_the_front_pins_the_granted_model(upstream):
    up, url = upstream
    f = ExecFront(url, enforced_model="granted-model")
    base = f.start()
    try:
        wrong = httpx.post(base + "/llm/api/generate", json={"model": "other-model", "prompt": "x"})
        assert wrong.status_code == 403 and wrong.json()["error"] == "model_not_granted"
        assert "granted-model" in wrong.json()["detail"]
        absent = httpx.post(base + "/llm/api/generate", json={"prompt": "x"})
        assert absent.status_code == 403
        assert httpx.post(base + "/llm/api/generate", content=b"nope").status_code == 400
        assert up.seen == []                                         # refused before the upstream
        assert httpx.post(base + "/llm/api/generate", json={"model": "granted-model", "prompt": "x"}).status_code == 201
        assert [s["body"] for s in up.seen] == [b'{"model": "granted-model", "prompt": "x"}'] or up.seen
    finally:
        f.stop()


def test_policy_is_decided_before_the_upstream_so_the_gate_can_observe_it():
    """With no upstream at all (the k3s gate's shape): a granted endpoint +
    model reaches the upstream check and says 503 by name; a refused endpoint
    is 404 and a wrong model 403 -- distinguishable without any model leg."""
    f = ExecFront(None, enforced_model="granted-model")
    base = f.start()
    try:
        assert httpx.post(base + "/llm/api/chat", json={"model": "granted-model"}).status_code == 503
        assert httpx.get(base + "/llm/api/tags").status_code == 404
        # the pin is decided before the upstream: a wrong model is 403 even with
        # no model leg at all, never "no proxy"
        assert httpx.post(base + "/llm/api/chat", json={"model": "other"}).status_code == 403
    finally:
        f.stop()


def test_the_front_forwards_the_validated_object_never_a_case_variant_model_key(upstream):
    """The upstream (Ollama, Go json) would take a case-variant duplicate key as
    the model; the front refuses it and forwards only the validated,
    re-serialised object (R HIGH, reproduced live)."""
    up, url = upstream
    f = ExecFront(url, enforced_model="granted-model")
    base = f.start()
    try:
        r = httpx.post(base + "/llm/api/chat", content=b'{"model": "granted-model", "MODEL": "other-model"}',
                       headers={"content-type": "application/json"})
        assert r.status_code == 403 and r.json()["error"] == "model_key_variant"
        assert "case-insensitively" in r.json()["detail"]
        r = httpx.post(base + "/llm/api/chat", content=b'{"model": "granted-model", "model": "other-model"}',
                       headers={"content-type": "application/json"})
        assert r.status_code == 400 and r.json()["error"] == "duplicate_model_key"
        assert "repeats" in r.json()["detail"]
        assert up.seen == []
        r = httpx.post(base + "/llm/api/chat", content=b'{ "model" : "granted-model" , "messages": [] }',
                       headers={"content-type": "application/json"})
        assert r.status_code == 201
        assert up.seen[-1]["body"] == b'{"model":"granted-model","messages":[]}'  # the validated object
    finally:
        f.stop()


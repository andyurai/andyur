"""The forwarder that holds the agent's model credential for it.

The property being tested is a negative one: after this exists, there is no
model credential in the agent's environment. Everything else here supports that
claim -- the credential is added by the proxy, the agent's own headers cannot
override it, and the proxy dies with the process, which is what makes "the run
was killed" and "the run can no longer spend" the same event.
"""

import threading
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request

from andyur.runner.modelproxy import ModelProxy
from andyur.runner.driver import MODEL_PROXY_AUTH_MARKER


@pytest.fixture
def upstream():
    """A stand-in broker that records what reached it."""
    seen = {"auth": None, "path": None, "body": None, "count": 0}
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def catch(path: str, request: Request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = "/" + path
        seen["body"] = (await request.body()).decode()
        seen["count"] += 1
        return {"ok": True}

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                           log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        threading.Event().wait(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", seen
    server.should_exit = True
    t.join(timeout=5)


@pytest.fixture
def proxy(upstream):
    url, seen = upstream
    p = ModelProxy(url, credential="the-secret-credential")
    base = p.start()
    yield base, seen, p
    p.stop()


def test_the_proxy_supplies_the_credential(proxy):
    """The agent sends none and the upstream still sees one: that is the whole
    point. The credential lives in the runner's memory, under a uid the agent
    cannot read from /proc."""
    base, seen, _ = proxy
    r = httpx.post(f"{base}/v1/messages", json={"hello": "world"}, timeout=10)
    assert r.status_code == 200
    assert seen["auth"] == "Bearer the-secret-credential"
    assert seen["path"] == "/v1/messages"
    import json
    assert json.loads(seen["body"]) == {"hello": "world"}   # bytes, not whitespace


def test_an_agent_supplied_credential_cannot_override_it(proxy):
    """A compromised agent must not be able to make the runner forward someone
    else's credential, or its own choice of one."""
    base, seen, _ = proxy
    httpx.post(f"{base}/v1/messages", json={},
               headers={"Authorization": "Bearer attacker-token",
                        "x-api-key": "sk-attacker"}, timeout=10)
    assert seen["auth"] == "Bearer the-secret-credential"


def test_installed_claude_cli_accepts_proxy_marker_without_receiving_a_credential():
    """Exercise an installed real CLI auth preflight against a fake stream.

    Empty auth exits with "Not logged in" before making a request. The public
    marker gets past that client-local check, while ModelProxy must replace it
    with the runner-held credential on every upstream request. The runner image
    pins its CLI independently; coupling this behavioral test to whichever
    development CLI happens to be first on PATH made an otherwise compatible
    patch release fail the suite before this behavior was even exercised.
    """
    cli = shutil.which("claude")
    assert cli, "Claude Code CLI is a required development prerequisite"
    seen = []
    app = FastAPI()

    @app.post("/v1/messages")
    async def messages(request: Request):
        seen.append((request.headers.get("authorization"), await request.body()))

        async def stream():
            events = [
                ("message_start", {"type": "message_start", "message": {
                    "id": "msg_test", "type": "message", "role": "assistant",
                    "content": [], "model": "claude-haiku-4-5",
                    "stop_reason": None, "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 0}}}),
                ("content_block_start", {"type": "content_block_start", "index": 0,
                    "content_block": {"type": "text", "text": ""}}),
                ("content_block_delta", {"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": "ok"}}),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                ("message_delta", {"type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 1}}),
                ("message_stop", {"type": "message_stop"}),
            ]
            for event, data in events:
                yield f"event: {event}\ndata: {json.dumps(data)}\n\n"

        from fastapi.responses import StreamingResponse
        return StreamingResponse(stream(), media_type="text/event-stream")

    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    proxy = None
    try:
        deadline = time.monotonic() + 5
        while not server.started:
            assert thread.is_alive(), "fake Anthropic server exited during startup"
            assert time.monotonic() < deadline, "fake Anthropic server did not start"
            threading.Event().wait(0.02)
        upstream = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
        proxy = ModelProxy(upstream, credential="broker-purpose-token")
        base = proxy.start()
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "ANTHROPIC_BASE_URL": base,
                   "ANTHROPIC_AUTH_TOKEN": MODEL_PROXY_AUTH_MARKER,
                   "ANTHROPIC_API_KEY": ""}
            result = subprocess.run(
                [cli, "-p", "reply ok", "--model", "claude-haiku-4-5",
                 "--output-format", "json"],
                env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr or result.stdout
        assert json.loads(result.stdout)["result"] == "ok"
        assert seen
        assert {auth for auth, _ in seen} == {"Bearer broker-purpose-token"}
        assert MODEL_PROXY_AUTH_MARKER.encode() not in b"".join(body for _, body in seen)
    finally:
        if proxy is not None:
            proxy.stop()
        server.should_exit = True
        thread.join(timeout=5)
        assert not thread.is_alive(), "fake Anthropic server did not stop"


def test_spending_stops_when_the_proxy_stops(proxy):
    """Liveness becomes structural. The proxy dies with the runner, and the
    runner dies with the container, so 'the run was destroyed' and 'the run can
    no longer spend' are the same event -- no check, no cache, no grace window,
    no endpoint on the control plane to answer one."""
    base, seen, p = proxy
    assert httpx.post(f"{base}/v1/messages", json={}, timeout=10).status_code == 200
    before = seen["count"]
    p.stop()
    with pytest.raises(httpx.HTTPError):
        httpx.post(f"{base}/v1/messages", json={}, timeout=3)
    assert seen["count"] == before, "a call reached the upstream after shutdown"


def test_the_response_is_streamed_not_buffered(upstream):
    """Model output arrives incrementally and the CLI renders it as it lands.
    A proxy that buffers would break that, and would also hold the whole reply
    in memory."""
    url, _ = upstream
    chunks_seen = []

    app = FastAPI()

    @app.get("/stream")
    async def stream():
        from fastapi.responses import StreamingResponse

        async def gen():
            for i in range(5):
                yield f"chunk{i}\n".encode()

        return StreamingResponse(gen(), media_type="text/plain")

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                           log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        threading.Event().wait(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]

    p = ModelProxy(f"http://127.0.0.1:{port}", credential="c")
    base = p.start()
    try:
        with httpx.stream("GET", f"{base}/stream", timeout=10) as r:
            for line in r.iter_lines():
                if line:
                    chunks_seen.append(line)
    finally:
        p.stop()
        server.should_exit = True
        t.join(timeout=5)

    assert chunks_seen == [f"chunk{i}" for i in range(5)]


def test_the_proxy_binds_loopback_only(proxy):
    """It carries a credential, so it must not be reachable from outside the
    container even if the run network were misconfigured."""
    base, _, _ = proxy
    assert base.startswith("http://127.0.0.1:")


def test_a_compressed_upstream_response_arrives_readable():
    """The proxy must hand the client a body it can actually parse.

    The first version streamed aiter_raw (bytes exactly as they arrived, still
    gzipped) while stripping the content-encoding header that told the client to
    decompress. Every response became unparseable -- "API Error: Failed to parse
    JSON" -- and no test caught it because the local model used in testing never
    compressed, while api.anthropic.com always does. This test compresses.
    """
    import gzip
    import json as _json

    app = FastAPI()

    @app.get("/v1/thing")
    async def thing():
        from fastapi.responses import Response as RawResponse

        payload = gzip.compress(_json.dumps({"deep": "value"}).encode())
        return RawResponse(
            content=payload, media_type="application/json",
            headers={"content-encoding": "gzip"},
        )

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                           log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        threading.Event().wait(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]

    p = ModelProxy(f"http://127.0.0.1:{port}", credential="c")
    base = p.start()
    try:
        r = httpx.get(f"{base}/v1/thing", timeout=10)
        assert r.json() == {"deep": "value"}, f"unparseable body: {r.content[:40]!r}"
    finally:
        p.stop()
        server.should_exit = True
        t.join(timeout=5)


# --- the runner must not describe a failure as a success ----------------------

# Built from the REAL SDK class, never a hand-rolled stub. The first version of
# these tests defined a three-attribute `class _Msg`, which meant the test
# supplied the very fields it was checking: a cause living in any OTHER field
# could not be represented, so the test could not see the failure mode it was
# written to prevent. That is the same stand-in blind spot as the bug -- the
# broker "worked" for four reviews because it was only ever tested against a
# local model that does not gzip. Using the dataclass means a field the SDK adds
# or renames shows up here as a TypeError instead of a silent pass.
def _result(**kw):
    from claude_agent_sdk import ResultMessage
    base = dict(subtype="success", duration_ms=1, duration_api_ms=1,
                is_error=True, num_turns=1, session_id="s1")
    return ResultMessage(**{**base, **kw})


def test_a_failed_run_reports_the_actual_failure_not_the_subtype():
    """A run that failed reported: `error: agent run ended with success`.

    The SDK sets is_error independently of subtype, so a failing run can carry
    subtype="success" -- the message both contradicted itself and discarded the
    only diagnostic there was. Here the real cause ("API Error: Failed to parse
    JSON") sat in `result`, which was thrown away.
    """
    from andyur.runner.runner import describe_failure

    error = describe_failure(_result(result="API Error: Failed to parse JSON"))
    assert "subtype=success" not in error, f"still reports the subtype: {error!r}"
    assert "Failed to parse JSON" in error


def test_a_provider_http_error_is_reported_not_swallowed():
    """The SDK's own docstring: api_error_status is set when is_error is True
    and subtype is "success" -- exactly this function's case. Reading `result`
    alone still produced `(subtype=success)` for every 429 and 529, which are
    the failures most likely to reach it."""
    from andyur.runner.runner import describe_failure

    error = describe_failure(_result(api_error_status=529, result=None))
    assert "529" in error
    assert "subtype=success" not in error


def test_a_cause_in_the_errors_list_is_reported():
    from andyur.runner.runner import describe_failure

    error = describe_failure(_result(errors=["upstream connection reset"]))
    assert "upstream connection reset" in error


def test_a_failure_with_no_detail_at_all_does_not_contradict_itself():
    """When the SDK gives us nothing, say that, rather than printing a word
    that reads as the opposite of what happened."""
    from andyur.runner.runner import describe_failure

    error = describe_failure(_result())
    assert "no cause attached" in error
    assert not error.startswith("agent run failed (subtype=success)")


def test_a_real_subtype_is_still_reported_when_it_is_all_there_is():
    from andyur.runner.runner import describe_failure

    assert describe_failure(_result(subtype="error_max_turns")) == \
        "agent run failed (subtype=error_max_turns)"


# --- the sandbox image must be able to start the runner ----------------------

def test_the_runner_image_declares_what_the_runner_imports():
    """runner.py imports the model proxy at top level, and the proxy needs
    fastapi and uvicorn to serve. The image installed neither, so the runner
    could not start AT ALL under ANDYUR_SANDBOX=on -- the configuration
    production requires -- and that shipped, because no test ran an agent inside
    a container.

    A host venv has everything, so this gap is invisible outside the image.
    Checked here rather than only in the container harness so it fails in the
    unit suite, where it is cheap to notice.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile.runner").read_text()
    declared = set(re.findall(r'"([A-Za-z0-9_.\-]+)[><=]', dockerfile))

    # What the runner's own import graph needs from third parties.
    needed = {"fastapi", "uvicorn", "httpx", "claude-agent-sdk"}
    missing = needed - declared
    assert not missing, f"Dockerfile.runner does not install: {sorted(missing)}"

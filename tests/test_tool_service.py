"""The andyur platform tools served over loopback HTTP (the container split).

The property: the SAME tools the in-process path exposes are reachable over HTTP,
they perform the SAME audited control-plane calls (carrying the run token the
sidecar holds, never the agent), and an optional per-run token gates the port.
"""

import asyncio
from unittest.mock import patch

import httpx
import pytest

from andyur.runner import toolservice

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _connect(url, headers):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    async with streamablehttp_client(url, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            return s, sorted(t.name for t in tools.tools)


async def test_all_platform_tools_are_served_and_call_the_control_plane():
    calls = []

    async def fake_server_call(method, path, **kw):
        calls.append((method, path, kw.get("json")))
        return {"id": "t7", "assignee": "bob", "content": "prev"}

    with patch("andyur.runner.driver._server_call", fake_server_call):
        svc = toolservice.ToolService("alice", run_id="r1", token="tok")
        url = await asyncio.to_thread(svc.start)
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(url, headers={"Authorization": "Bearer tok"}) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    names = sorted(t.name for t in (await s.list_tools()).tools)
                    assert names == [
                        "append_long_term_memory", "create_task", "handle_message",
                        "request_rollback", "search_memory_graph", "send_message",
                        "update_short_term_memory", "update_task",
                    ]
                    out = await s.call_tool(
                        "create_task", {"assignee": "bob", "title": "x", "detail": "d"})
                    assert "created task t7" in out.content[0].text
        finally:
            await asyncio.to_thread(svc.stop)

    # the tool made the audited call as this agent/run
    assert ("POST", "/tasks", {
        "assignee": "bob", "title": "x", "detail": "d", "creator": "alice",
        "trace_ctx": None, "parent_run_id": "r1"}) in calls


async def test_the_token_gates_the_port():
    async def fake_server_call(method, path, **kw):
        return {}

    with patch("andyur.runner.driver._server_call", fake_server_call):
        svc = toolservice.ToolService("alice", run_id="r1", token="right")
        url = await asyncio.to_thread(svc.start)
        try:
            with pytest.raises(Exception):
                await _connect(url, {"Authorization": "Bearer wrong"})
            with pytest.raises(Exception):
                await _connect(url, {})
            _, names = await _connect(url, {"Authorization": "Bearer right"})
            assert "create_task" in names
        finally:
            await asyncio.to_thread(svc.stop)


async def test_no_token_configured_is_open_on_loopback():
    async def fake_server_call(method, path, **kw):
        return {}

    with patch("andyur.runner.driver._server_call", fake_server_call):
        svc = toolservice.ToolService("alice", run_id="r1", token=None)
        url = await asyncio.to_thread(svc.start)
        try:
            _, names = await _connect(url, {})
            assert "send_message" in names
        finally:
            await asyncio.to_thread(svc.stop)


async def test_bind_and_advertised_hosts_are_independent():
    """Separate Kubernetes Pods bind all interfaces but receive the proxy IP."""
    with patch("andyur.runner.driver._server_call"):
        svc = toolservice.ToolService(
            "alice", run_id="r1", token=None,
            host="0.0.0.0", advertise_host="10.42.0.19", port=18766)
        url = await asyncio.to_thread(svc.start)
        try:
            assert url == "http://10.42.0.19:18766/mcp"
        finally:
            await asyncio.to_thread(svc.stop)


def test_a_tool_call_sends_no_trace_header_because_the_server_would_not_read_it():
    """WHERE THE RUN'S TRACE IS JOINED, and where it deliberately is not.

    `action.decide` was landing in a trace of its own, so an operator reading a
    run's trace saw the agent's `mcp.tool` call and then nothing. The obvious
    fix -- inject `traceparent` here -- does not work and is worse than doing
    nothing: the control plane's `ObservedASGI` does not read caller-supplied
    trace headers anywhere in this codebase, because a span parent taken from a
    request is a parent the caller chose, and the caller of THIS request is a
    process executing an agent's instructions.

    So the link is made server-side from the run's own stored traceparent
    (`actionrequests._run_traceparent`), and this asserts the client stays out
    of it -- a header nothing honours reads like a link that exists."""
    import andyur.runner.driver as driver

    captured = {}

    class FakeResponse:
        content = b"{}"
        def raise_for_status(self): pass
        def json(self): return {}

    class FakeClient:
        def __init__(self, **kw):
            captured["headers"] = dict(kw.get("headers") or {})
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, path, **kw): return FakeResponse()

    with patch.object(driver.httpx, "AsyncClient", FakeClient), \
         patch.object(driver.identity, "client_tls", lambda who: (None, True)), \
         patch.object(driver.identity, "httpx_auth", lambda: None), \
         patch.object(driver.identity, "run_token_header",
                      lambda: {"X-Andyur-Run-Token": "t"}):
        asyncio.run(driver._server_call("POST", "/runs/r1/actions", json={}))

    assert "traceparent" not in captured["headers"]
    assert captured["headers"].get("X-Andyur-Run-Token") == "t"


def test_the_decision_is_parented_on_the_runs_own_stored_trace():
    """The trusted source: the traceparent the control plane wrote when it
    anchored the run, read from the row -- not from anything the requester
    sends. Every span the action produces hangs off it, `action.perform`
    included, because that is the one that says whether the cluster moved."""
    import inspect

    from andyur.server import actionrequests

    source = inspect.getsource(actionrequests)
    assert "SELECT trace_ctx FROM runs WHERE id = ?" in source
    for span in ("action.decide", "action.perform"):
        start = source.index(f'start_as_current_span("{span}"')
        assert "context=" in source[start:start + 200], (
            f"{span} has no parent, so it is an orphan root the run cannot reach")


def test_a_run_with_no_stored_trace_still_gets_a_decision():
    """Telemetry must never be able to fail a decision. A run anchored before
    tracing was on has no traceparent, and a None parent is simply a root span
    -- which is what these were before."""
    from andyur.server import actionrequests

    with patch.object(actionrequests.db, "connect", side_effect=RuntimeError("no db")):
        assert actionrequests._run_traceparent("whatever") is None

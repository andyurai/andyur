"""Per-tool MCP authority on the DEFAULT sidecar path.

The defect this closes: `mcp_tools` grants were compiled, narrowed and sealed
into the signed registry artifact, and enforced ONLY in the Envoy dataplane --
which is off by default. The sidecar tool leg had zero JSON-RPC awareness, so an
enumerated binding granted every tool its upstream happened to expose, while
`docs/agent-runtime-protocol-v1.md` promised third-party agent authors that
"the list is never wider than the law".

Both answers come from mcpwire.permitted_tools, the same function the dataplane
uses, so the menu an agent sees and the calls it may make cannot drift apart.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from andyur import mcpwire
from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar

UPSTREAM_TOOLS = [
    {"name": "error_rate", "description": "granted"},
    {"name": "last_deploy", "description": "granted"},
    {"name": "delete_everything", "description": "NOT granted"},
]


def _harness(permitted, upstream_body=None, upstream_status=200,
             content_type="application/json"):
    """A sidecar in front of a stub MCP upstream.

    `permitted` is THE SERVER'S per-run decision, already narrowed: None means
    the binding enumerates nothing and stays audience-level; a list -- even an
    empty one -- means it enumerates and this is the whole set this run may
    call. The sidecar computes none of it."""
    seen = {}

    def upstream(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        payload = upstream_body
        if payload is None:
            payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                                  "result": {"tools": UPSTREAM_TOOLS}}).encode()

        async def stream():
            # An async-generator body keeps the response STREAMING, which is
            # what the sidecar actually receives from a real client. A
            # materialized body would exercise a path production never takes.
            yield payload

        return httpx.Response(upstream_status, content=stream(),
                              headers={"content-type": content_type})

    entry = {"url": "https://obs.example/mcp", "audience": "resource:obs",
             "scheme": "https", "host": "obs.example", "port": 443,
             "path": "/mcp"}
    if permitted is not None:
        entry["permitted_tools"] = list(permitted)
    else:
        entry["permitted_tools"] = None
    router = sidecar.Router({"obs": sidecar.ToolRoute.from_managed("obs", entry)})
    app = proxy_app.build_app(
        router=router,
        identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=[], pin=None, gateway_url="http://unused",
        exchange_fn=lambda **_: {"access_token": "delegated-token",
                                 "expires_in": 300},
        tool_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(upstream)))
    return app, seen


GRANT = ["error_rate", "last_deploy"]


def _call(app, payload):
    with TestClient(app) as c:
        return c.post("/tools/obs/mcp", content=json.dumps(payload).encode())


# --------------------------------------------------------------------------
# tools/call: the calls it may make
# --------------------------------------------------------------------------

def test_a_granted_tool_call_reaches_the_upstream():
    """Positive control. Without it a sidecar that refused everything would
    pass every negative test below."""
    app, seen = _harness(GRANT)
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "error_rate", "arguments": {}}})
    assert r.status_code == 200
    assert b"error_rate" in seen["body"]


def test_an_ungranted_tool_call_is_refused_and_never_reaches_the_upstream():
    """THE defect. Before this the call was forwarded and the upstream ran it."""
    app, seen = _harness(GRANT)
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "delete_everything", "arguments": {}}})
    assert r.status_code == 403
    assert seen == {}, "the refused call must not be forwarded"


def test_an_audience_level_binding_is_unchanged():
    """A binding that enumerates nothing has nothing to filter against, so the
    leg stays audience-authorized exactly as before."""
    app, seen = _harness(None)
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "anything_at_all"}})
    assert r.status_code == 200
    assert b"anything_at_all" in seen["body"]


def test_an_enumerated_empty_grant_permits_no_tool_call():
    """`{}` and `None` are different answers. Empty means the reviewer
    enumerated and granted nothing; it must not read as audience-level."""
    app, seen = _harness([])
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "error_rate"}})
    assert r.status_code == 403
    assert seen == {}


@pytest.mark.parametrize("body", [b"[]", b'[{"method":"tools/call"}]'])
def test_a_batch_body_is_refused_on_an_enumerated_binding(body):
    """A batch can carry a tools/call single-message parsing cannot surface, so
    authorizing it per-tool is impossible and it fails closed. MCP 2025-06-18
    removed batching, so this is protocol-correct, not merely defensive."""
    app, seen = _harness(GRANT)
    with TestClient(app) as c:
        r = c.post("/tools/obs/mcp", content=body)
    assert r.status_code == 403
    assert seen == {}


def test_an_unparseable_body_is_refused_on_an_enumerated_binding():
    app, seen = _harness(GRANT)
    with TestClient(app) as c:
        r = c.post("/tools/obs/mcp", content=b"not json at all")
    assert r.status_code == 403
    assert seen == {}


@pytest.mark.parametrize("method", sorted(mcpwire.MCP_TOOL_SESSION_METHODS))
def test_every_session_method_still_passes(method):
    """Positive control over the WHOLE vocabulary. The previous version of this
    test checked only `initialize`, which passed while resources/read and
    prompts/get rode through ungated -- it locked the gap in rather than
    guarding against it. Two independent reviews found that; this is the fix."""
    app, _ = _harness(GRANT)
    payload = {"jsonrpc": "2.0", "method": method, "params": {}}
    if not method.startswith("notifications/"):
        payload["id"] = 1
    if method == "tools/call":
        payload["params"] = {"name": "error_rate"}
    with TestClient(app) as c:
        assert c.post("/tools/obs/mcp",
                      content=json.dumps(payload).encode()).status_code == 200


@pytest.mark.parametrize("method", [
    "resources/read", "resources/list", "resources/subscribe",
    "prompts/get", "prompts/list",
    "completion/complete", "logging/setLevel", "sampling/createMessage",
    "roots/list", "some/future/method",
])
def test_a_method_outside_the_vocabulary_is_refused(method):
    """An enumerated binding says "this server is used for THESE tools". Every
    other method reaches the same upstream over the same credential, so an open
    vocabulary is a side door around the reviewed grant: resources/read reads
    server state and prompts/get runs server-side templates that no tool grant
    ever mentioned."""
    app, seen = _harness(GRANT)
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": method, "params": {}})
    assert r.status_code == 403
    assert seen == {}, "the refused method must not reach the upstream"


def test_an_audience_level_binding_keeps_the_open_vocabulary():
    """A binding that enumerates nothing was never constrained by the method
    set, and closing it there would be a behaviour change nobody asked for."""
    app, seen = _harness(None)
    r = _call(app, {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                    "params": {}})
    assert r.status_code == 200


def test_the_resumable_event_stream_is_refused_on_an_enumerated_binding():
    """A body-less GET is the standalone SSE stream. It can carry a REPLAYED
    tools/list result when a client resumes with Last-Event-ID, and there is no
    request body to classify -- so the reply would reach the agent unfiltered.
    Refused rather than served as a menu that cannot be filtered."""
    app, seen = _harness(GRANT)
    with TestClient(app) as c:
        r = c.get("/tools/obs/mcp")
    assert r.status_code == 403
    assert seen == {}


def test_the_event_stream_is_untouched_on_an_audience_level_binding():
    app, seen = _harness(None)
    with TestClient(app) as c:
        assert c.get("/tools/obs/mcp").status_code == 200


# --------------------------------------------------------------------------
# tools/list: the menu it sees
# --------------------------------------------------------------------------

def _list(app):
    return _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                       "params": {}})


def test_the_menu_is_no_wider_than_the_law():
    """The protocol document's own promise, now true on this path."""
    app, _ = _harness(GRANT)
    r = _list(app)
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == {"error_rate", "last_deploy"}
    assert "delete_everything" not in r.text


def test_the_menu_and_the_law_come_from_one_decision():
    """Anything the listing shows must be callable, and anything it hides must
    not be. Asserted together because drift between them is the failure mode
    permitted_tools exists to prevent."""
    app, _ = _harness(GRANT)
    shown = {t["name"] for t in _list(app).json()["result"]["tools"]}
    for name in shown:
        app2, _ = _harness(GRANT)
        assert _call(app2, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": name}}).status_code == 200
    app3, _ = _harness(GRANT)
    assert _call(app3, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "delete_everything"}}
                 ).status_code == 403


def test_an_audience_level_binding_does_not_filter_its_menu():
    app, _ = _harness(None)
    names = {t["name"] for t in _list(app).json()["result"]["tools"]}
    assert names == {"error_rate", "last_deploy", "delete_everything"}


def test_an_sse_listing_is_filtered_too():
    """Streamable HTTP may answer tools/list as SSE. An unfiltered SSE menu
    would be the same defect wearing a different content type."""
    sse = ("event: message\r\n"
           "data: " + json.dumps({"jsonrpc": "2.0", "id": 1,
                                  "result": {"tools": UPSTREAM_TOOLS}}) + "\r\n"
           "\r\n").encode()
    app, _ = _harness(GRANT, upstream_body=sse,
                      content_type="text/event-stream")
    r = _list(app)
    assert r.status_code == 200
    assert "error_rate" in r.text
    assert "delete_everything" not in r.text


def test_an_unreadable_listing_is_withheld_not_passed_through():
    """Passing it through IS the unfiltered menu."""
    app, _ = _harness(GRANT, upstream_body=b"\xff\xfe not json not sse")
    assert _list(app).status_code == 502


def test_an_oversized_listing_is_refused_not_truncated(monkeypatch):
    """A truncated JSON document is not a smaller menu, it is an unparseable
    one."""
    monkeypatch.setattr(proxy_app, "_TOOLS_LIST_MAX_BYTES", 64)
    big = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
        "tools": [{"name": f"t{i}", "description": "x" * 50}
                  for i in range(50)]}}).encode()
    app, _ = _harness(GRANT, upstream_body=big)
    assert _list(app).status_code == 502


def test_an_upstream_error_passes_through_with_its_status():
    """A non-2xx names no tools; filtering an error document is not this
    function's job."""
    app, _ = _harness(GRANT, upstream_body=b'{"error":"upstream down"}',
                      upstream_status=503)
    assert _list(app).status_code == 503


def test_the_sidecar_and_the_dataplane_share_one_decision():
    """Two implementations would drift silently. This asserts they are the same
    object, not merely that they agree today."""
    from andyur import mcpwire
    from andyur.dataplane import extauthz
    assert extauthz.permitted_tools is mcpwire.permitted_tools
    assert extauthz.filter_tools_payload is mcpwire.filter_tools_payload
    assert extauthz.parse_mcp is mcpwire.parse_mcp
    assert extauthz.mcp_body_kind is mcpwire.mcp_body_kind


# --------------------------------------------------------------------------
# The narrowing itself. Two independent reviews called this P0: the sidecar
# used to call permitted_tools({"actions": None}, ...), whose literal None
# short-circuits to "every enumerated tool", so the run's narrowed authority
# never entered the decision. For a BROKERED binding the sidecar is the only
# Andyur enforcement point, so that was a real widening.
# --------------------------------------------------------------------------

STATIC_GRANTS = {"error_rate": "obs:read", "purge": "obs:admin"}


def test_the_server_narrows_the_static_grant_by_the_runs_authority():
    """The decision the server now seals. A run scoped to obs:read may call
    error_rate and not purge, even though the binding statically grants both."""
    from andyur import mcpwire
    from andyur.server import registry as registry_authority

    decision = registry_authority.narrow(
        entitlement=["obs:read"], pin=None,
        ceiling={"actions": ["obs:read", "obs:admin"], "audiences": None},
        audience="resource:obs")
    assert sorted(mcpwire.permitted_tools(decision, STATIC_GRANTS)) == ["error_rate"]


def test_the_old_hardcoded_decision_would_have_permitted_both():
    """The defect, pinned so it cannot come back unnoticed. This is what the
    sidecar used to compute."""
    from andyur import mcpwire
    assert sorted(mcpwire.permitted_tools({"actions": None}, STATIC_GRANTS)) \
        == ["error_rate", "purge"]


def test_a_narrowed_run_cannot_call_the_tool_it_lost():
    """End to end at the sidecar, with the narrowed set the server would seal."""
    app, seen = _harness(["error_rate"])
    assert _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "purge"}}).status_code == 403
    assert seen == {}
    app2, seen2 = _harness(["error_rate"])
    assert _call(app2, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "error_rate"}}).status_code == 200


def test_a_narrowed_run_does_not_see_the_tool_it_lost_in_the_menu():
    app, _ = _harness(["error_rate"])
    names = {t["name"] for t in _list(app).json()["result"]["tools"]}
    assert names == {"error_rate"}


def test_a_run_narrowed_to_nothing_can_call_nothing_and_sees_nothing():
    app, seen = _harness([])
    assert _call(app, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "error_rate"}}).status_code == 403
    assert seen == {}
    app2, _ = _harness([])
    assert _list(app2).json()["result"]["tools"] == []


def test_the_sidecar_holds_no_way_to_widen_what_the_server_sealed():
    """The structural property. ToolRoute carries a set of NAMES, not the
    binding's grants plus an authority model, so there is nothing in the
    sidecar from which a wider answer could be derived."""
    import dataclasses

    from andyur.proxy import sidecar as sc
    fields = {f.name for f in dataclasses.fields(sc.ToolRoute)}
    assert "permitted_tools" in fields
    assert "mcp_tools" not in fields, (
        "the sidecar must not hold the raw grants; holding them is how it came "
        "to recompute the decision with the narrowing discarded")


def test_a_client_response_is_admitted_because_it_names_no_method():
    """A JSON-RPC RESPONSE from the client -- what a conforming MCP client
    sends back when the SERVER made a request of it -- carries no `method`.
    The dataplane admits it; the sidecar refused it, so the two components
    disagreed about the same protocol. It invokes nothing, so it is admitted."""
    app, seen = _harness(GRANT)
    r = _call(app, {"jsonrpc": "2.0", "id": 7, "result": {"model": "x"}})
    assert r.status_code == 200


def test_both_paths_agree_on_a_method_less_body():
    """Asserted as AGREEMENT, not as shared code: the two now reach the same
    answer for the same input."""
    from andyur import mcpwire
    from andyur.dataplane import extauthz
    method, _ = mcpwire.parse_mcp(b'{"jsonrpc":"2.0","id":1,"result":{}}')
    assert method is None
    dataplane_admits = not (
        method is not None and method not in extauthz.MCP_TOOL_SESSION_METHODS)
    assert dataplane_admits is True

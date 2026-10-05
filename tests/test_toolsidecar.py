"""The per-run tool sidecar's runner-facing helpers.

The uvicorn lifecycle mirrors ToolService and the proxy behaviour it hosts is
covered by the proxy tests; what is new here is the mapping the runner relies on:
the managed dict -> the sidecar Router (audience by tool name, not URL), and the
agent's mcp.json rewrite (loopback /tools/<name>, NO credential handed to the
agent)."""

import pytest

from andyur.runner import toolsidecar as ts
from andyur.proxy import sidecar as sc
from andyur import config as _config


def test_the_gateway_advertises_the_reachable_host_not_the_bind_host():
    """O1 regression: under a separate-netns/Pod shape the sidecar binds all
    interfaces but the agent addresses it by a routable name. The base_url given
    to the agent must be that advertised name, not the bind host -- otherwise the
    api+LiteLLM path handed the agent an unreachable loopback /llm."""
    ident = sc.RunIdentity("", lambda: "", lambda: {})
    srv = ts.ToolSidecar(
        router=ts.router_from_managed({}), identity=ident, scope=None, pin=None,
        gateway_url="http://litellm:4000", host="0.0.0.0", advertise_host="sidecar")
    try:
        base = srv.start()
        assert base.startswith("http://sidecar:")   # advertised, not 0.0.0.0
        assert "0.0.0.0" not in base
    finally:
        srv.stop()


def test_the_gateway_defaults_to_loopback_when_not_advertising():
    ident = sc.RunIdentity("", lambda: "", lambda: {})
    srv = ts.ToolSidecar(router=ts.router_from_managed({}), identity=ident,
                         scope=None, pin=None, gateway_url="http://litellm:4000")
    try:
        assert srv.start().startswith("http://127.0.0.1:")
    finally:
        srv.stop()


_MANAGED = {
    "obs": {"url": "http://127.0.0.1:8797/mcp", "audience": "resource:telemetry",
            "scheme": "http", "host": "127.0.0.1", "port": 8797, "path": "/mcp"},
    "tix": {"url": "http://127.0.0.1:8798/mcp", "audience": "resource:tickets",
            "scheme": "http", "host": "127.0.0.1", "port": 8798, "path": "/mcp"},
}


def test_router_keys_audience_by_tool_name_not_url():
    router = ts.router_from_managed(_MANAGED)
    obs = router.classify("/tools/obs/mcp")
    assert obs.kind == "tool"
    # the audience is the manifest resource_id, decoupled from the reach URL
    assert obs.tool.audience == "resource:telemetry"
    assert obs.tool.audience != obs.tool.reach_url
    assert (obs.tool.host, obs.tool.port, obs.tool.path) == ("127.0.0.1", 8797, "/mcp")
    assert router.classify("/tools/tix/mcp").tool.audience == "resource:tickets"
    # an undeclared tool is not routable
    assert router.classify("/tools/ghost/mcp").kind == "unknown"


def test_agent_config_points_at_the_sidecar_with_no_credential():
    cfg = ts.agent_tool_config("http://127.0.0.1:5000/", _MANAGED,
                               {"notes": {"type": "http", "url": "http://n/mcp"}})
    # each managed tool -> the sidecar's loopback /tools/<name>/mcp
    assert cfg["obs"] == {"type": "http", "url": "http://127.0.0.1:5000/tools/obs/mcp"}
    assert cfg["tix"] == {"type": "http", "url": "http://127.0.0.1:5000/tools/tix/mcp"}
    # the agent is handed NO credential for a managed tool -- the sidecar attaches
    # the real one; whatever the agent holds, the agent can leak.
    assert "headers" not in cfg["obs"] and "headers" not in cfg["tix"]
    # passthrough tools are untouched
    assert cfg["notes"] == {"type": "http", "url": "http://n/mcp"}


def test_agent_config_with_no_managed_tools_is_just_passthrough():
    assert ts.agent_tool_config("http://x:1", {}, {"n": {"type": "http"}}) == \
        {"n": {"type": "http"}}


def test_agent_config_uses_the_tools_declared_path_not_a_hardcoded_one():
    managed = {"deep": {"url": "http://tools.internal:9812/api/v2/mcp",
                        "audience": "resource:deep", "scheme": "http",
                        "host": "tools.internal",
                        "port": 9812, "path": "/api/v2/mcp"}}
    cfg = ts.agent_tool_config("http://127.0.0.1:5000", managed, {})
    # the proxy forwards only to the declared path, so the agent must be
    # addressed there -- a hardcoded /mcp would 404 this tool on every call
    assert cfg["deep"]["url"] == "http://127.0.0.1:5000/tools/deep/api/v2/mcp"


def test_start_gives_up_when_uvicorn_never_reports_ready(monkeypatch):
    # a wedged startup (thread alive, `started` never set) must fail the tool
    # path closed, not hang the runner's event loop forever
    monkeypatch.setattr(ts.proxy_app, "build_app", lambda **kw: object())
    monkeypatch.setattr(ts, "START_TIMEOUT", 0.1)
    srv = ts.ToolSidecar(router=ts.router_from_managed(_MANAGED), identity=None,
                         scope=None, pin=None, gateway_url="")

    class Wedged:
        started = False
        should_exit = False

        def run(self):
            import time
            while not self.should_exit:
                time.sleep(0.01)
    srv._server = Wedged()
    with pytest.raises(RuntimeError, match="did not come up"):
        srv.start()
    # and the wedged thread was told to exit rather than being abandoned
    assert srv._server.should_exit


def test_shutdown_drain_is_bounded(monkeypatch):
    # unbounded graceful shutdown lets an agent pinning a long SSE stream keep
    # the run's credentials serviceable after stop()'s join times out
    monkeypatch.setattr(ts.proxy_app, "build_app", lambda **kw: object())
    srv = ts.ToolSidecar(router=ts.router_from_managed(_MANAGED), identity=None,
                         scope=None, pin=None, gateway_url="")
    assert srv._server.config.timeout_graceful_shutdown == _config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS == 1


def test_sidecar_hands_the_injected_exchange_fn_to_the_app(monkeypatch):
    # the runner's choice of mint (local vs external AS) must reach build_app;
    # a dropped kwarg would silently fall back to the external-AS default
    got = {}

    def fake_build_app(**kwargs):
        got.update(kwargs)
        return object()
    monkeypatch.setattr(ts.proxy_app, "build_app", fake_build_app)
    sentinel = lambda **kw: {"access_token": "T"}      # noqa: E731
    ts.ToolSidecar(router=ts.router_from_managed(_MANAGED), identity=None,
                   scope=None, pin=None, gateway_url="",
                   exchange_fn=sentinel)
    assert got["exchange_fn"] is sentinel

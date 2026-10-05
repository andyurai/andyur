"""The runner consumes the run-bound tool endpoint without a legacy fallback."""

import asyncio

import pytest

from andyur.runner import registry_consumption as rc
from andyur.runner import runner


class Response:
    def __init__(self, body=None, status=200):
        self.body = body if body is not None else {}
        self.status_code = status

    def json(self):
        return self.body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class Api:
    def __init__(self, response, finish_statuses=None):
        self.response = response
        self.finish_statuses = list(finish_statuses or [200])
        self.paths = []
        self.posts = []

    async def get(self, path, params=None):
        self.paths.append(path)
        if path.endswith("/registry-tools"):
            return self.response
        if path.endswith("/files/mcp.json"):
            return Response(status=404)
        raise AssertionError(path)

    async def post(self, path, json=None):
        self.posts.append((path, json))
        status = self.finish_statuses.pop(0) if self.finish_statuses else 200
        return Response({}, status=status)


def descriptor():
    return {"name": "obs", "reach_url": "http://tools:8797/mcp",
            "resource_id": "https://resources.andyur.local/telemetry",
            "authority": "managed", "permitted_tools": None}


def test_bound_run_fetches_own_descriptor_and_never_reads_workspace_mcp():
    api = Api(Response({"registry_agent_id": "agt_bound",
                        "tools": [descriptor()]}))
    legacy, partitioned = asyncio.run(
        runner._tool_inputs(api, "runtime-name", "r1",
                            {"registry_agent_id": "agt_bound"}))
    assert legacy == {}
    assert api.paths == ["/runs/r1/registry-tools"]
    assert partitioned[0]["obs"]["audience"] == (
        "https://resources.andyur.local/telemetry")


def test_unbound_run_uses_legacy_mcp_and_never_calls_registry_tools():
    api = Api(Response({"should": "not be read"}))
    legacy, partitioned = asyncio.run(
        runner._tool_inputs(api, "legacy", "r1", {}))
    assert legacy == {} and partitioned is None
    assert api.paths == ["/agents/legacy/files/mcp.json"]


@pytest.mark.parametrize("body", [
    {"registry_agent_id": "agt_other", "tools": []},
    {"registry_agent_id": "agt_bound"},
    [],
])
def test_bound_descriptor_mismatch_or_shape_drift_aborts_launch(body):
    api = Api(Response(body))
    with pytest.raises(rc.UnlaunchableResolution):
        asyncio.run(runner._tool_inputs(
            api, "runtime", "r1", {"registry_agent_id": "agt_bound"}))


def test_bound_endpoint_failure_aborts_instead_of_falling_back_to_workspace():
    api = Api(Response({"detail": "registry unavailable"}, status=503))
    with pytest.raises(RuntimeError, match="503"):
        asyncio.run(runner._tool_inputs(
            api, "runtime", "r1", {"registry_agent_id": "agt_bound"}))
    assert api.paths == ["/runs/r1/registry-tools"]


def test_bound_endpoint_failure_terminally_finishes_the_assigned_run():
    api = Api(Response({"detail": "registry unavailable"}, status=503))
    result = asyncio.run(runner._tool_inputs_or_finish(
        api, "runtime", "r1", {"registry_agent_id": "agt_bound"}))
    assert result is None
    assert api.posts == [("/runs/r1/finish", {
        "summary": None,
        "error": "registry tool preparation failed: HTTP 503",
    })]


def test_finish_auth_failure_is_retried_until_terminal_state_is_confirmed(
        monkeypatch):
    async def no_sleep(_): pass
    monkeypatch.setattr(runner.asyncio, "sleep", no_sleep)
    api = Api(Response({}, status=503), finish_statuses=[401, 200])
    assert asyncio.run(runner._tool_inputs_or_finish(
        api, "runtime", "r1", {"registry_agent_id": "agt_bound"})) is None
    assert len(api.posts) == 2


def test_unconfirmed_finish_is_named_for_the_reaper(monkeypatch, capsys):
    async def no_sleep(_): pass
    monkeypatch.setattr(runner.asyncio, "sleep", no_sleep)
    api = Api(Response({}, status=503), finish_statuses=[401, 401, 401])
    asyncio.run(runner._tool_inputs_or_finish(
        api, "runtime", "r1", {"registry_agent_id": "agt_bound"}))
    assert len(api.posts) == 3
    assert "leaving it for the reaper" in capsys.readouterr().out

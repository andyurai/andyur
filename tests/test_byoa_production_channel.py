"""Production acceptance pins for the public BYOA runtime protocol."""

from starlette.testclient import TestClient

from andyur.runner.agentchannel import AgentChannel
from andyur.runner.runner import _runtime_v1_context


def _channel(token="run-channel-secret"):
    return AgentChannel({
        "protocol_version": "andyur-agent-runtime/v1",
        "run_id": "run_test",
        "agent_id": "agt_test",
        "model": "approved-model",
        "input": {"prompt": "hello"},
        "services": {},
        "limits": {},
        "trace": {},
    }, token=token)


def test_production_runner_builds_the_frozen_v1_context_shape():
    context = _runtime_v1_context(
        agent_id="agt_bound", run_id="run_test", prompt="hello",
        run_input=None,   # a plain wakeup: `input.data` must then be ABSENT
        selected_model="approved-model", model_base_url="http://model",
        mcp_url="http://tools/mcp",
        mcp_headers={"Authorization": "Bearer tool-only"},
        extra_mcp_servers={}, traceparent="00-trusted")

    assert set(context) == {
        "protocol_version", "run_id", "agent_id", "model", "input",
        "services", "limits", "trace",
    }
    assert context["protocol_version"] == "andyur-agent-runtime/v1"
    assert context["agent_id"] == "agt_bound"
    assert context["input"] == {"prompt": "hello"}
    assert context["services"] == {
        "model_base_url": "http://model",
        "mcp_url": "http://tools/mcp",
        "mcp_headers": {"Authorization": "Bearer tool-only"},
        "extra_mcp_servers": {},
    }
    assert context["limits"]["max_line_bytes"] > 0
    assert context["limits"]["max_stream_bytes"] >= context["limits"]["max_line_bytes"]
    assert context["trace"] == {"traceparent": "00-trusted"}
    serialized = str(context)
    for forbidden in ("run_token", "broker", "spiffe", "database"):
        assert forbidden not in serialized.lower()


def test_public_v1_context_is_served_by_production_channel():
    channel = _channel()
    client = TestClient(channel._build_app())
    response = client.get(
        "/v1/context", headers={"Authorization": "Bearer run-channel-secret"})
    assert response.status_code == 200
    assert response.json()["protocol_version"] == "andyur-agent-runtime/v1"
    assert response.json()["model"] == "approved-model"


def test_public_v1_context_uses_same_run_bound_authentication():
    channel = _channel()
    client = TestClient(channel._build_app())
    assert client.get("/v1/context").status_code == 401
    assert client.get(
        "/v1/context", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_legacy_context_alias_is_identical_during_migration():
    channel = _channel()
    client = TestClient(channel._build_app())
    headers = {"Authorization": "Bearer run-channel-secret"}
    assert client.get("/inputs", headers=headers).json() == \
        client.get("/v1/context", headers=headers).json()


def test_public_v1_events_refuses_second_stream():
    channel = _channel()
    client = TestClient(channel._build_app())
    headers = {"Authorization": "Bearer run-channel-secret"}
    first = client.post("/v1/events", headers=headers,
                        content=b'{"kind":"done","exit":0,"error":null}\n')
    assert first.status_code == 200
    second = client.post("/v1/events", headers=headers,
                         content=b'{"kind":"done","exit":0,"error":null}\n')
    assert second.status_code == 409


def test_legacy_stream_and_v1_stream_share_single_stream_guard():
    channel = _channel()
    client = TestClient(channel._build_app())
    headers = {"Authorization": "Bearer run-channel-secret"}
    assert client.post("/stream", headers=headers,
                       content=b'{"kind":"done","exit":0,"error":null}\n').status_code == 200
    assert client.post("/v1/events", headers=headers,
                       content=b'{"kind":"done","exit":0,"error":null}\n').status_code == 409

"""The registry model reaches the SDK on every production handoff.

The overlay is worthless if a run silently uses the default model, so each
handoff is captured with an EXACT non-default model and the mutation contract is
explicit: deleting the model wiring at that handoff reddens its named test.

Chain: model_from_ctx(ctx) (tested in test_registry_consumption) -> the run
path passes it to run_agent / open_conversation / the split inputs -> those pass
it to driver._build_options -> ClaudeAgentOptions.model. These tests cover the
last two links for all three paths; the driver default is the None fallback.
"""

import pytest

from andyur.agent import agent as agent_mod
from andyur.runner import driver, runner

NONDEFAULT = "claude-fable-5"   # deliberately not driver.DEFAULT_MODEL


def _assert_nondefault():
    assert NONDEFAULT != driver.DEFAULT_MODEL, "test model must differ from default"


# --- the driver applies the model it is given (execute + conversation rely on this)

def test_build_options_applies_the_given_model():
    _assert_nondefault()
    opts = driver._build_options(
        "a", "/tmp", "sys", None, "r1", {}, andyur_mcp_url="http://x/mcp",
        model=NONDEFAULT)
    assert opts.model == NONDEFAULT


def test_build_options_falls_back_to_default_when_model_is_none():
    opts = driver._build_options(
        "a", "/tmp", "sys", None, "r1", {}, andyur_mcp_url="http://x/mcp",
        model=None)
    assert opts.model == driver.DEFAULT_MODEL


# --- the in-process paths pass their model through to the driver ---------------

class _DummyClient:
    def __init__(self, options=None):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def query(self, *a, **k):
        return None

    async def receive_response(self):
        if False:
            yield None            # empty async generator


def _capture_model(monkeypatch):
    """Capture the model kwarg run_agent/open_conversation pass to _build_options,
    without invoking the real options builder (which would reach the platform MCP
    server). The returned sentinel is fine: _DummyClient ignores its options."""
    captured = {}

    def spy(*a, **k):
        captured["model"] = k.get("model")
        return object()

    monkeypatch.setattr(driver, "_build_options", spy)
    monkeypatch.setattr(driver, "ClaudeSDKClient", _DummyClient)
    monkeypatch.setattr(driver, "_open_scratch", lambda *a, **k: None)
    return captured


async def _drain(gen):
    async for _ in gen:
        pass


def test_run_agent_passes_the_model_to_the_driver(monkeypatch):
    """execute()'s handoff: run_agent(model=...) must reach _build_options."""
    import asyncio
    captured = _capture_model(monkeypatch)
    asyncio.run(_drain(driver.run_agent(
        "a", "prompt", "/tmp", None, "r1", model=NONDEFAULT)))
    assert captured["model"] == NONDEFAULT


def test_open_conversation_passes_the_model_to_the_driver(monkeypatch):
    """_run_conversation()'s handoff: open_conversation(model=...) must reach it."""
    captured = _capture_model(monkeypatch)
    driver.open_conversation("a", "/tmp", None, "r1", model=NONDEFAULT)
    assert captured["model"] == NONDEFAULT


# --- the split path threads the model through the channel inputs ---------------

def test_split_options_thread_the_inputs_model():
    """_run_split sets context['model']; andyur.agent._options_for must pass it to
    the driver so the container agent has model parity."""
    _assert_nondefault()
    inputs = {"agent_id": "agt_a", "run_id": "r1", "model": NONDEFAULT,
              "services": {"model_base_url": None, "mcp_url": "http://x/mcp",
                           "mcp_headers": {}, "extra_mcp_servers": {}},
              "trace": {"traceparent": None}}
    opts = agent_mod._options_for(inputs, "/tmp")
    assert opts.model == NONDEFAULT


def test_split_options_default_when_inputs_have_no_model():
    inputs = {"agent_id": "agt_a", "run_id": "r1",
              "services": {"model_base_url": None, "mcp_url": "http://x/mcp",
                           "mcp_headers": {}, "extra_mcp_servers": {}},
              "trace": {"traceparent": None}}
    opts = agent_mod._options_for(inputs, "/tmp")
    assert opts.model == driver.DEFAULT_MODEL


# --- actual runner.py handoffs ------------------------------------------------

class _Resp:
    def __init__(self, data=None, status=200):
        self._data, self.status_code = data if data is not None else {}, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


_CTX = {
    "profile": {"name": "bound", "description": "d", "personality": "p",
                "spiffe_id": None},
    "knowledge": "k", "instructions": "REGISTRY INSTRUCTION",
    "short_term": "s", "long_term": "l", "graph_enabled": False,
    "registry_agent_id": "agt_bound", "registry_model": NONDEFAULT,
}


class _Span:
    def __init__(self, seen): self.seen = seen
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def set_attribute(self, key, value): self.seen[key] = value
    def end(self): return None


class _Tracer:
    def __init__(self, seen): self.seen = seen
    def start_as_current_span(self, *args, **kwargs):
        self.seen.setdefault("span_names", []).append(args[0])
        return _Span(self.seen)
    def start_span(self, *args, **kwargs): return _Span(self.seen)


def test_framework_records_a_gateway_neutral_llm_response_span(monkeypatch):
    seen = {}
    monkeypatch.setattr(runner, "_tracer", _Tracer(seen))
    monkeypatch.setattr(runner, "LLM_MODE", "api")
    runner._record_llm_response(NONDEFAULT, blocks=2)
    assert seen["span_names"] == ["llm.response"]
    assert seen["gen_ai.operation.name"] == "chat"
    assert seen["gen_ai.request.model"] == NONDEFAULT
    assert seen["gen_ai.response.model"] == NONDEFAULT
    assert seen["andyur.llm_mode"] == "api"
    assert seen["andyur.llm.response_blocks"] == 2


class _HeadlessApi:
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return False

    async def get(self, path, params=None):
        if path == "/runs/r1":
            return _Resp({"id": "r1", "run_type": "headless",
                          "reason": "test", "workflow_id": "wf"})
        if path.endswith("/context"): return _Resp(dict(_CTX))
        if path == "/runs/r1/registry-tools":
            return _Resp({"registry_agent_id": "agt_bound", "tools": [{
                "name": "obs", "reach_url": "http://tools:8797/mcp",
                "resource_id": "https://resources.andyur.local/telemetry",
                "authority": "managed", "permitted_tools": None,
            }]})
        if path in ("/tasks", "/messages"): return _Resp([])
        if path.endswith("/files/mcp.json"): return _Resp(status=404)
        return _Resp({})

    async def post(self, path, json=None): return _Resp({})
    async def put(self, path, json=None): return _Resp({})


def test_execute_path_passes_context_model_to_run_agent(monkeypatch):
    """This invokes runner.execute itself. Deleting its `model=...` handoff must
    red this test; downstream driver tests alone cannot establish that property."""
    import asyncio
    seen = {}

    async def fake_run_agent(*args, **kwargs):
        seen["model"] = kwargs.get("model")
        seen["prompt"] = args[1]
        if False:
            yield None

    monkeypatch.setattr(runner.httpx, "AsyncClient", lambda **kw: _HeadlessApi())
    monkeypatch.setattr(runner.identity, "client_tls", lambda role: (None, True))
    monkeypatch.setattr(runner.identity, "httpx_auth", lambda: None)
    monkeypatch.setattr(runner.identity, "run_token_header", lambda: {})
    monkeypatch.setattr(runner.config, "AGENT_SPLIT", False)
    monkeypatch.setattr(runner, "run_agent", fake_run_agent)
    monkeypatch.setattr(runner, "_start_model_proxy", lambda: (None, None))
    def fake_gateway(agent, servers, *, partitioned=None, selected_model=None):
        seen["registry_tools"] = partitioned
        seen["sidecar_model"] = selected_model
        return {}, None
    monkeypatch.setattr(runner, "_start_tool_egress", fake_gateway)
    monkeypatch.setattr(runner, "_tracer", _Tracer(seen))
    monkeypatch.setattr(runner.otel, "flush", lambda: None)

    assert asyncio.run(runner.execute("bound", "r1")) == 1  # no ResultMessage
    assert seen["model"] == NONDEFAULT
    assert "REGISTRY INSTRUCTION" in seen["prompt"]
    assert seen["andyur.model"] == NONDEFAULT
    assert seen["registry_tools"][0]["obs"]["audience"] == (
        "https://resources.andyur.local/telemetry")


def test_conversation_path_passes_context_model_to_open_conversation(monkeypatch):
    """Invoke one real conversation turn, assert its registry prompt/model, then
    halt. Deleting the prompt preamble or model handoff must red this test."""
    import asyncio
    from contextlib import asynccontextmanager
    seen = {}

    class Api(_HeadlessApi):
        def __init__(self): self.turns = 0

        async def get(self, path, params=None):
            if path.endswith("/context"): return _Resp(dict(_CTX))
            if path == "/runs/r1/registry-tools":
                return await super().get(path, params=params)
            if path.endswith("/files/mcp.json"): return _Resp(status=404)
            if path.endswith("/next-turn"):
                self.turns += 1
                return _Resp({"turn": {"seq": 1, "kind": "message",
                                        "body": "hello"}})
            return _Resp({})

    class Client:
        async def query(self, value): seen["query"] = value
        async def receive_response(self):
            if False: yield None

    @asynccontextmanager
    async def fake_open(*args, **kwargs):
        seen["model"] = kwargs.get("model")
        yield Client()

    halt_calls = 0
    async def halted(*args, **kwargs):
        nonlocal halt_calls
        halt_calls += 1
        return halt_calls > 1
    async def no_reply(*args, **kwargs): return None
    async def no_write(*args, **kwargs): return None

    monkeypatch.setattr(runner, "open_conversation", fake_open)
    monkeypatch.setattr(runner, "_halted", halted)
    monkeypatch.setattr(runner, "_post_reply", no_reply)
    monkeypatch.setattr(runner, "_put_file", no_write)
    monkeypatch.setattr(runner, "_start_model_proxy", lambda: (None, None))
    def fake_gateway(agent, servers, *, partitioned=None, selected_model=None):
        seen["registry_tools"] = partitioned
        seen["sidecar_model"] = selected_model
        return {}, None
    monkeypatch.setattr(runner, "_start_tool_egress", fake_gateway)
    monkeypatch.setattr(runner, "_tracer", _Tracer(seen))
    monkeypatch.setattr(runner.otel, "flush", lambda: None)
    run = {"id": "r1", "run_type": "conversation", "workflow_id": "wf"}
    assert asyncio.run(runner._run_conversation(Api(), "bound", "r1", run, None)) == 1
    assert seen["model"] == NONDEFAULT
    assert seen["andyur.model"] == NONDEFAULT
    assert "REGISTRY INSTRUCTION" in seen["query"]
    assert seen["registry_tools"][0]["obs"]["audience"] == (
        "https://resources.andyur.local/telemetry")


class _ToolOutageApi(_HeadlessApi):
    def __init__(self): self.finished = []

    async def get(self, path, params=None):
        if path == "/runs/r1/registry-tools": return _Resp(status=503)
        return await super().get(path, params=params)

    async def post(self, path, json=None):
        if path == "/runs/r1/finish": self.finished.append(json)
        return _Resp({})


def _must_not_launch(*args, **kwargs):
    raise AssertionError("execution service launched after registry outage")


def test_execute_tool_outage_finishes_before_launch(monkeypatch):
    import asyncio
    api = _ToolOutageApi()
    monkeypatch.setattr(runner.httpx, "AsyncClient", lambda **kw: api)
    monkeypatch.setattr(runner.identity, "client_tls", lambda role: (None, True))
    monkeypatch.setattr(runner.identity, "httpx_auth", lambda: None)
    monkeypatch.setattr(runner.identity, "run_token_header", lambda: {})
    monkeypatch.setattr(runner.config, "AGENT_SPLIT", False)
    monkeypatch.setattr(runner, "_start_model_proxy", _must_not_launch)
    assert asyncio.run(runner.execute("bound", "r1")) == 1
    assert api.finished and "registry tool preparation failed" in api.finished[0]["error"]


def test_conversation_tool_outage_finishes_before_launch(monkeypatch):
    import asyncio
    api = _ToolOutageApi()
    monkeypatch.setattr(runner, "_start_model_proxy", _must_not_launch)
    run = {"id": "r1", "run_type": "conversation", "workflow_id": "wf"}
    assert asyncio.run(
        runner._run_conversation(api, "bound", "r1", run, None)) == 1
    assert api.finished and "registry tool preparation failed" in api.finished[0]["error"]


def test_runner_main_flushes_prepare_failure_span_before_process_exit(monkeypatch):
    import asyncio
    flushed = []
    async def failed_execute(*args, **kwargs): return 1
    monkeypatch.setattr(runner, "execute", failed_execute)
    monkeypatch.setattr(runner.identity, "seal_run_token", lambda: None)
    monkeypatch.setattr(runner.otel, "flush", lambda: flushed.append(True))
    monkeypatch.setattr(runner.sys, "argv",
                        ["andyur-runner", "--agent", "bound", "--run-id", "r1"])
    with pytest.raises(SystemExit) as stopped:
        runner.main()
    assert stopped.value.code == 1
    assert flushed == [True]

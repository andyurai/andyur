"""O1 call-site wiring: under an isolated-pod shape the runner must bind the
sidecar's services on all interfaces AND advertise the routable name, at the
ACTUAL construction sites. These pin what stubbed/kubernetes/ollama tests missed:
reverting the docker-pod bind/advertise wiring reddens here.
"""
import importlib

import pytest


@pytest.fixture
def r(monkeypatch):
    from andyur.runner import runner as mod
    importlib.reload(mod)
    # docker-pod isolated shape: advertise the per-run alias
    monkeypatch.setattr(mod.config, "DEPLOYMENT", "docker")
    monkeypatch.setenv("ANDYUR_ADVERTISE_HOST", "acme-side")
    return mod


def test_model_proxy_call_site_binds_all_interfaces_and_advertises_the_alias(r, monkeypatch):
    captured = {}

    class FakeProxy:
        def __init__(self, upstream, credential, host="127.0.0.1", advertise_host=None):
            captured["host"] = host
            captured["advertise_host"] = advertise_host
        def start(self): return "http://acme-side:9/"
    monkeypatch.setattr(r, "ModelProxy", FakeProxy)
    monkeypatch.setattr(r, "LLM_MODE", "api")
    monkeypatch.setattr(r, "BROKER_URL", "http://broker")
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "btok")

    url, proxy = r._start_model_proxy()
    assert proxy is not None
    assert captured["host"] == "0.0.0.0"            # not loopback
    assert captured["advertise_host"] == "acme-side"


def test_tool_gateway_call_site_binds_all_interfaces_and_advertises_the_alias(r, monkeypatch):
    """The literal /llm fix site: the api+LiteLLM tool gateway must advertise the
    alias so the agent's ANTHROPIC_BASE_URL resolves from its own netns."""
    captured = {}

    class FakeSidecar:
        def __init__(self, **kw):
            captured["host"] = kw.get("host")
            captured["advertise_host"] = kw.get("advertise_host")
        def start(self): return "http://acme-side:9"
        def stop(self): pass
    monkeypatch.setattr(r.toolsidecar, "ToolSidecar", FakeSidecar)
    monkeypatch.setattr(r.toolsidecar, "router_from_managed", lambda m: object())
    monkeypatch.setattr(r.toolsidecar, "agent_tool_config", lambda *a, **k: {})
    monkeypatch.setattr(r, "LLM_MODE", "api")
    monkeypatch.setattr(r.config, "LITELLM_URL", "http://litellm:4000")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "k")

    # non-managed (llm-only) path: no tools, just the /llm gateway
    r._start_tool_sidecar("alice", managed={}, passthrough={}, selected_model="claude-x")
    assert captured["host"] == "0.0.0.0"
    assert captured["advertise_host"] == "acme-side"


class _Resp:
    status_code = 200
    def json(self): return []
    def raise_for_status(self): pass


class _Api:
    async def get(self, *a, **k): return _Resp()
    async def post(self, *a, **k): return _Resp()


def _drive_run_split(r, monkeypatch, captured):
    """Drive _run_split up to the AgentChannel construction (docker pod mode),
    faking every network/service seam; the fake channel's start() raises so the
    guarded teardown finalizes the run. What matters is the captured ctor
    kwargs of the REAL call-site."""
    import asyncio

    async def fetch_ctx(api, agent): return {"graph_enabled": False}
    async def tool_inputs(api, agent, run_id, ctx): return ({}, {})
    async def put_file(*a, **k): pass

    class FakeToolService:
        def __init__(self, agent, origin_trace, run_id, token=None, **net):
            captured["tool_service_net"] = net
        def start(self): return "http://ts"
        def stop(self): pass

    class FakeChannel:
        def __init__(self, inputs, token=None, host="127.0.0.1", port=0):
            captured["channel_host"] = host
            captured["channel_port"] = port
            captured["channel_token"] = token
            self.done = {}
        async def start(self): raise RuntimeError("bail: call-site captured")
        async def stop(self): pass

    monkeypatch.setattr(r, "_fetch_context", fetch_ctx)
    monkeypatch.setattr(r, "_tool_inputs_or_finish", tool_inputs)
    monkeypatch.setattr(r, "_put_file", put_file)
    monkeypatch.setattr(r, "build_prompt", lambda ctx, run: "p")
    monkeypatch.setattr(r, "_start_tool_egress",
                        lambda *a, **k: ({}, None))
    monkeypatch.setattr(r, "_start_model_proxy", lambda: ("http://prox", None))
    monkeypatch.setattr(r, "LLM_MODE", "subscription")
    monkeypatch.setattr(r, "ToolService", FakeToolService)
    monkeypatch.setattr(r, "AgentChannel", FakeChannel)
    monkeypatch.setattr(r.config, "AGENT_SPLIT_POD", True)
    monkeypatch.setenv("ANDYUR_CHANNEL_TOKEN", "chtok")

    rc = asyncio.run(r._run_split(_Api(), "alice", "runX", {}, None))
    assert rc != 0  # the bail finalized the run as failed, proving we got there


def test_channel_call_site_binds_all_interfaces_in_docker_pod_mode(r, monkeypatch):
    """The channel construction site itself: under the O1 docker-pod shape the
    A<->B channel must bind all interfaces (the agent connects from its OWN
    netns over the per-run network) on the fixed pod port. Reverting the
    channel_host ternary to a kubernetes-only test reddens here."""
    captured = {}
    _drive_run_split(r, monkeypatch, captured)
    assert captured["channel_host"] == "0.0.0.0"
    assert captured["channel_port"] == r.config.CHANNEL_PORT
    assert captured["channel_token"] == "chtok"
    # the one advertise decision drove the tool service too (no disagreement)
    assert captured["tool_service_net"]["host"] == "0.0.0.0"
    assert captured["tool_service_net"]["advertise_host"] == "acme-side"


def test_channel_call_site_stays_on_loopback_without_advertise(r, monkeypatch):
    """Positive-control twin: with no advertise decision (shared-netns shapes)
    the same call-site stays on loopback, proving the assertion above keys on
    the advertise decision, not on pod mode incidentally."""
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    captured = {}
    _drive_run_split(r, monkeypatch, captured)
    assert captured["channel_host"] == "127.0.0.1"
    assert captured["tool_service_net"] == {}


def test_run_split_threads_the_run_input_into_the_v1_context_data(r, monkeypatch):
    """WIRING, not the helper: _run_split must pass the RUN ROW's input into
    _runtime_v1_context as input.data. A typo (run.get('inpt')) or a run-loading
    SELECT that dropped the column would silently strip input.data for every
    runtime-v1 workload; the helper-level tests would not catch it."""
    import asyncio
    captured = {}

    async def fetch_ctx(api, agent): return {"graph_enabled": False}
    async def tool_inputs(api, agent, run_id, ctx): return ({}, {})
    async def put_file(*a, **k): pass

    class FakeToolService:
        def __init__(self, *a, **k): pass
        def start(self): return "http://ts"
        def stop(self): pass

    class FakeChannel:
        def __init__(self, inputs, token=None, host="127.0.0.1", port=0):
            captured["inputs"] = inputs
            self.done = {}
        async def start(self): raise RuntimeError("bail: inputs captured")
        async def stop(self): pass

    monkeypatch.setattr(r, "_fetch_context", fetch_ctx)
    monkeypatch.setattr(r, "_tool_inputs_or_finish", tool_inputs)
    monkeypatch.setattr(r, "_put_file", put_file)
    monkeypatch.setattr(r, "build_prompt", lambda ctx, run: "p")
    monkeypatch.setattr(r, "_start_tool_egress", lambda *a, **k: ({}, None))
    monkeypatch.setattr(r, "_start_model_proxy", lambda: ("http://prox", None))
    monkeypatch.setattr(r, "LLM_MODE", "subscription")
    monkeypatch.setattr(r, "ToolService", FakeToolService)
    monkeypatch.setattr(r, "AgentChannel", FakeChannel)
    monkeypatch.setattr(r.config, "AGENT_SPLIT_POD", True)
    monkeypatch.setenv("ANDYUR_CHANNEL_TOKEN", "chtok")

    # the run row as execute() fetched it from GET /runs/{id}, carrying input
    run = {"input": '{"incident":"INC-4471"}'}
    asyncio.run(r._run_split(_Api(), "alice", "runX", run, None))
    assert captured["inputs"]["input"]["data"] == {"incident": "INC-4471"}

    # and a plain wakeup (no input) omits data entirely
    captured.clear()
    asyncio.run(r._run_split(_Api(), "alice", "runY", {}, None))
    assert captured["inputs"]["input"] == {"prompt": "p"}


def test_serve_only_call_sites_bind_all_interfaces_on_the_fixed_ports_in_pod_mode(r, monkeypatch):
    """exec/v1 serve-only under the isolated-pod shape (R MED-2, PR #21): the
    front binds 0.0.0.0 on CHANNEL_PORT (the readiness probe and the workload's
    resolved model URL name that port) and the ToolService takes the SAME
    advertise decision as every other service. Mutants this kills: front port
    CHANNEL_PORT+1, front bound 127.0.0.1 while advertising, ToolService
    constructed without _tool_service_network()."""
    import asyncio
    captured = {}

    async def fetch_ctx(api, agent): return {"graph_enabled": False, "registry_model": "context-model"}
    async def tool_inputs(api, agent, run_id, ctx): return ({}, {})
    async def put_file(*a, **k): pass

    class FakeToolService:
        def __init__(self, agent, origin_trace, run_id, token=None, **net):
            captured["tool_service_net"] = net
            captured["token"] = token
        def start(self): return "http://ts/mcp"
        def stop(self): pass

    class FakeFront:
        def __init__(self, upstream, host="127.0.0.1", port=0, enforced_model=None,
                     require_model=False, run_id=None, agent=None, origin_trace=None):
            captured["front"] = {"upstream": upstream, "host": host, "port": port,
                                 "enforced_model": enforced_model, "require_model": require_model,
                                 "run_id": run_id, "agent": agent, "origin_trace": origin_trace}
        def start(self): return "http://front"
        def stop(self): pass

    monkeypatch.setattr(r, "_fetch_context", fetch_ctx)
    monkeypatch.setattr(r, "_tool_inputs_or_finish", tool_inputs)
    monkeypatch.setattr(r, "_put_file", put_file)
    monkeypatch.setattr(r, "build_prompt", lambda ctx, run: "p")
    monkeypatch.setattr(r, "_start_tool_egress", lambda *a, **k: ({}, None))
    monkeypatch.setattr(r, "_start_model_proxy", lambda: ("http://acme-side:9", None))
    monkeypatch.setattr(r, "LLM_MODE", "subscription")
    monkeypatch.setattr(r, "ToolService", FakeToolService)
    monkeypatch.setattr(r, "ExecFront", FakeFront)
    monkeypatch.setattr(r, "RUN_TTL_SECONDS", 0.2)
    monkeypatch.setattr(r.config, "AGENT_SPLIT_POD", True)
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    monkeypatch.setenv("ANDYUR_EXEC_MODEL", "granted-model")   # the grant != the context

    rc = asyncio.run(r._run_split(_Api(), "alice", "runX", {}, None, serve_only=True))
    assert rc == 0
    assert captured["front"] == {"upstream": "http://acme-side:9",
                                 "host": "0.0.0.0", "port": r.config.CHANNEL_PORT,
                                 # pinned to the ASSIGNMENT's grant, and only that
                                 # (HIGH-1, MED-1): no grant refuses every call
                                 "enforced_model": "granted-model", "require_model": True,
                                 "run_id": "runX", "agent": "alice", "origin_trace": None}
    assert captured["tool_service_net"]["host"] == "0.0.0.0"
    assert captured["tool_service_net"]["advertise_host"] == "acme-side"
    assert captured["token"] == "declared"

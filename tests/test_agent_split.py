"""The container split, end to end at the sidecar.

These drive the REAL sidecar lifecycle (_run_split): prepare, prompt, the real
tool service + channel, the consume loop with redaction / tool spans / summary
extraction / halt kill-switch / TTL, and finalize. The agent process (B) is
faked IN-PROCESS -- it fetches inputs from the real channel and forwards a real
NDJSON event stream -- so the whole A<->B protocol runs without a model or a
container. The real subprocess B is exercised separately in test_agent_process.
"""

import asyncio
import json

import httpx
import pytest

from andyur.runner import runner
from andyur.runner.protocol import done_event, encode

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --- a stand-in control plane ----------------------------------------------

class FakeResp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data if data is not None else {}
        self.content = b"x"

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)


CTX = {
    "profile": {"name": "alice", "description": "d", "personality": "p", "spiffe_id": None},
    "knowledge": "k", "instructions": "i", "short_term": "s", "long_term": "l",
    "graph_enabled": False,
}


class FakeApi:
    def __init__(self):
        self.finish = None
        self.puts = []

    async def get(self, path, params=None):
        if path.endswith("/context"):
            return FakeResp(200, dict(CTX))
        if path.endswith("/registry-tools"):
            return FakeResp(200, {
                "registry_agent_id": CTX.get("registry_agent_id"),
                "tools": [{"name": "obs",
                           "reach_url": "http://tools:8797/mcp",
                           "resource_id":
                               "https://resources.andyur.local/telemetry",
                           "authority": "managed", "permitted_tools": None}],
            })
        if path == "/tasks" or path == "/messages":
            return FakeResp(200, [])
        if path.startswith("/runs/"):
            return FakeResp(200, {"id": "r1", "run_type": "headless", "reason": "test"})
        return FakeResp(200, {})

    async def put(self, path, json=None):
        self.puts.append((path, json))
        return FakeResp(200, {})

    async def post(self, path, json=None):
        if path.endswith("/start"):
            return FakeResp(200, {})
        if path.endswith("/finish"):
            self.finish = json
            return FakeResp(200, {})
        return FakeResp(200, {})


RUN = {"id": "r1", "run_type": "headless", "reason": "test", "workflow_id": "wf1"}


# --- an in-process fake B ---------------------------------------------------

class FakeProc:
    def __init__(self):
        self.returncode = None
        self.pid = -1        # never a real pid; kill is patched out

    def poll(self):
        return self.returncode


def install_fake_b(monkeypatch, events_fn):
    """Replace process launch/kill with an in-process B that forwards events_fn.
    Returns a record dict capturing the inputs B saw and whether it was killed."""
    rec = {"inputs": None, "killed": False, "task": None, "proc": None}

    def fake_launch(channel_url, channel_token):
        proc = FakeProc()
        rec["proc"] = proc
        headers = {"Authorization": f"Bearer {channel_token}"} if channel_token else {}

        async def run_b():
            try:
                async with httpx.AsyncClient(headers=headers,
                                             timeout=httpx.Timeout(10, read=None, write=None)) as c:
                    rec["inputs"] = (await c.get(f"{channel_url}/v1/context")).json()

                    async def body():
                        async for ev in events_fn(rec["inputs"]):
                            yield encode(ev)
                    await c.post(f"{channel_url}/v1/events", content=body())
            finally:
                proc.returncode = 0
        rec["task"] = asyncio.create_task(run_b())
        return proc

    def fake_kill(proc):
        rec["killed"] = True
        if rec["task"] and not rec["task"].done():
            rec["task"].cancel()
        if proc is not None:
            proc.returncode = -9

    monkeypatch.setattr(runner, "_launch_agent_process", fake_launch)
    monkeypatch.setattr(runner, "_kill_agent_process", fake_kill)
    return rec


def _msg(**kw):
    ev = {"kind": "msg", "record": kw.get("record", {}), "texts": kw.get("texts", []),
          "tools": kw.get("tools", []), "results": kw.get("results", []),
          "result": kw.get("result")}
    return ev


# --- tests ------------------------------------------------------------------

async def test_happy_path_forwards_summary_and_finalizes(monkeypatch):
    async def events(inputs):
        yield _msg(record={"type": "AssistantMessage"}, texts=["working"],
                   tools=[{"id": "t1", "name": "mcp__andyur__create_task", "input": {}}])
        yield _msg(record={"type": "UserMessage"},
                   results=[{"tool_use_id": "t1", "content": "ok", "is_error": False}])
        yield _msg(record={"type": "ResultMessage"},
                   result={"result": "all done", "num_turns": 2, "total_cost_usd": 0.01,
                           "session_id": "s", "is_error": False, "usage": {}})
        yield done_event(0, None)

    seen = {}
    class Span:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def set_attribute(self, key, value): seen[key] = value
        def end(self): return None
    class Tracer:
        def start_as_current_span(self, *args, **kwargs): return Span()
        def start_span(self, *args, **kwargs): return Span()

    monkeypatch.setattr(runner, "_tracer", Tracer())
    monkeypatch.setitem(CTX, "registry_model", "registry-split-model")
    monkeypatch.setitem(CTX, "registry_agent_id", "agt_split")
    monkeypatch.setitem(CTX, "instructions", "REGISTRY SPLIT INSTRUCTION")
    def fake_gateway(agent, servers, *, partitioned=None, selected_model=None):
        seen["registry_tools"] = partitioned
        seen["sidecar_model"] = selected_model
        return {}, None
    monkeypatch.setattr(runner, "_start_tool_egress", fake_gateway)
    rec = install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None)
    assert rc == 0
    assert api.finish["summary"] == "all done" and api.finish["error"] is None
    # a transcript and a summary.json were written
    paths = [p for p, _ in api.puts]
    assert any(p.endswith("transcript.jsonl") for p in paths)
    assert any(p.endswith("summary.json") for p in paths)
    # B never received the run token or a broker credential in its inputs
    assert "run_token" not in json.dumps(rec["inputs"])
    assert "broker_token" not in json.dumps(rec["inputs"])
    assert rec["inputs"]["services"]["mcp_url"].startswith("http://127.0.0.1:")
    assert rec["inputs"]["input"]["prompt"]
    # This is the actual _run_split -> channel handoff. Deleting the model entry
    # from runner.py must make this assertion red.
    assert rec["inputs"]["model"] == "registry-split-model"
    assert "REGISTRY SPLIT INSTRUCTION" in rec["inputs"]["input"]["prompt"]
    assert seen["andyur.model"] == "registry-split-model"
    assert seen["registry_tools"][0]["obs"]["audience"] == (
        "https://resources.andyur.local/telemetry")


async def test_a_failed_result_is_named(monkeypatch):
    async def events(inputs):
        yield _msg(record={}, result={"is_error": True, "result": "",
                                       "api_error_status": 529, "subtype": "success",
                                       "num_turns": 1, "total_cost_usd": 0.0,
                                       "session_id": "s", "usage": {}})
        yield done_event(0, None)

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None)
    assert rc == 1
    assert "HTTP 529" in api.finish["error"]


async def test_registry_tool_outage_finishes_before_split_services_start(
        monkeypatch):
    monkeypatch.setitem(CTX, "registry_agent_id", "agt_split")

    class OutageApi(FakeApi):
        async def get(self, path, params=None):
            if path.endswith("/registry-tools"):
                return FakeResp(503, {"detail": "registry unavailable"})
            return await super().get(path, params=params)

    monkeypatch.setattr(
        runner, "_start_model_proxy",
        lambda: (_ for _ in ()).throw(
            AssertionError("split services started after registry outage")),
    )
    api = OutageApi()
    assert await runner._run_split(api, "alice", "r1", RUN, None) == 1
    assert api.finish and "registry tool preparation failed" in api.finish["error"]


async def test_halt_mid_run_kills_b_and_fails(monkeypatch):
    async def _always_halted(api, wf_id):
        return True
    monkeypatch.setattr(runner, "_halted", _always_halted)

    async def events(inputs):
        # emit enough messages to trip the message-burst halt poll, then hang
        for i in range(6):
            yield _msg(record={"i": i})
        await asyncio.sleep(30)   # would hang without the kill
        yield done_event(0, None)

    rec = install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=10)
    assert rc == 1
    assert "halted" in api.finish["error"]
    assert rec["killed"] is True


async def test_ttl_kills_b_and_fails(monkeypatch):
    monkeypatch.setattr(runner, "RUN_TTL_SECONDS", 1)

    async def _never_halted(api, wf_id):
        return False
    monkeypatch.setattr(runner, "_halted", _never_halted)

    async def events(inputs):
        yield _msg(record={})
        await asyncio.sleep(30)   # never completes; TTL must fire
        yield done_event(0, None)

    rec = install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=10)
    assert rc == 1
    assert "TTL" in api.finish["error"]
    assert rec["killed"] is True


async def test_b_dropping_the_stream_is_a_failure_not_a_success(monkeypatch):
    async def events(inputs):
        yield _msg(record={})
        # ends without a done sentinel: B "died" mid-forward

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None)
    assert rc == 1
    assert api.finish["error"] and "without completion" in api.finish["error"]


async def test_a_service_startup_failure_finalizes_the_run_as_failed(monkeypatch):
    """A port collision or a broken tool-service image must not crash the sidecar
    or strand the run 'running': the failure is caught and the run is finalized
    with a reason, and the agent process is never launched."""
    class BoomToolService:
        def __init__(self, *a, **kw):
            pass
        def start(self):
            raise RuntimeError("tool service could not bind")
        def stop(self):
            pass

    launched = {"count": 0}
    monkeypatch.setattr(runner, "ToolService", BoomToolService)
    monkeypatch.setattr(runner, "_launch_agent_process",
                        lambda *a: launched.__setitem__("count", launched["count"] + 1))
    api = FakeApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None)
    assert rc == 1
    assert "tool service could not bind" in api.finish["error"]
    assert launched["count"] == 0


async def test_pod_mode_waits_for_the_agent_container_and_spawns_nothing(monkeypatch):
    """In a pod the agent is a CONTAINER the daemon launched, so the sidecar must
    not also spawn an agent process -- that would give the run two agents -- and
    it must take the channel credential the daemon minted rather than minting one
    the agent could never present."""
    monkeypatch.setattr(runner.config, "AGENT_SPLIT_POD", True)
    monkeypatch.setattr(runner.config, "CHANNEL_PORT", 0)   # ephemeral for the test
    monkeypatch.setattr(runner, "LLM_MODE", "ollama")
    monkeypatch.setattr(runner, "_start_tool_egress",
                        lambda *a, **kw: ({}, None))
    monkeypatch.setattr(runner, "_start_model_proxy", lambda: (None, None))
    monkeypatch.setenv("ANDYUR_CHANNEL_TOKEN", "from-the-daemon")
    monkeypatch.setattr(runner.config, "DEPLOYMENT", "kubernetes")
    monkeypatch.setenv("ANDYUR_POD_IP", "10.42.0.19")
    monkeypatch.setenv("ANDYUR_MCP_PORT", "8766")
    spawned = []
    monkeypatch.setattr(runner, "_launch_agent_process",
                        lambda *a: spawned.append(a))

    captured = {}
    real_tool_service = runner.ToolService
    def spy_tool_service(*args, **kwargs):
        captured["tool_service"] = kwargs
        return real_tool_service(*args, **kwargs)
    monkeypatch.setattr(runner, "ToolService", spy_tool_service)
    real_channel = runner.AgentChannel

    def spy_channel(inputs, token=None, host="127.0.0.1", port=0):
        captured["token"] = token
        ch = real_channel(inputs, token=token, host=host, port=port)
        captured["ch"] = ch
        return ch

    monkeypatch.setattr(runner, "AgentChannel", spy_channel)

    async def be_the_agent_container():
        # stand in for the agent container connecting on its own
        await asyncio.sleep(0.1)
        ch = captured["ch"]
        await ch.inject_done(0, None)

    asyncio.create_task(be_the_agent_container())
    api = FakeApi()
    await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=15)
    assert spawned == [], "the sidecar spawned an agent process inside a pod"
    assert captured["token"] == "from-the-daemon"
    assert captured["tool_service"]["host"] == "0.0.0.0"
    assert captured["tool_service"]["advertise_host"] == "10.42.0.19"
    assert captured["tool_service"]["port"] == 8766
    assert captured["tool_service"]["token"]


async def test_an_agent_container_that_never_connects_fails_the_run(monkeypatch):
    """The pod's equivalent of a dead B. There is no process to poll, so the
    sidecar bounds the wait -- otherwise a broken agent image holds the run, and
    its worker slot, until the run TTL."""
    monkeypatch.setattr(runner.config, "AGENT_SPLIT_POD", True)
    monkeypatch.setattr(runner.config, "CHANNEL_PORT", 0)
    monkeypatch.setattr(runner.config, "AGENT_CONNECT_TIMEOUT", 0.3)
    monkeypatch.setattr(runner, "_launch_agent_process", lambda *a: None)
    api = FakeApi()
    rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=15)
    assert rc == 1
    assert "never connected" in api.finish["error"]


async def test_a_secret_in_the_transcript_is_redacted(monkeypatch):
    leak = "sk-ant-api03-" + "A" * 40

    async def events(inputs):
        yield _msg(record={"type": "AssistantMessage", "leak": leak}, texts=[leak])
        yield _msg(record={}, result={"result": f"my key is {leak}", "is_error": False,
                                      "num_turns": 1, "total_cost_usd": 0.0,
                                      "session_id": "s", "usage": {}})
        yield done_event(0, None)

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    await runner._run_split(api, "alice", "r1", RUN, None)
    # the leak must appear NOWHERE the sidecar persisted it
    assert leak not in json.dumps(api.finish)
    for _, body in api.puts:
        assert leak not in json.dumps(body)


async def test_a_forged_cost_field_cannot_strand_the_run(monkeypatch):
    """The untrusted half chooses every value in the result object, and two of
    them were used OUTSIDE the guarded block. A total_cost_usd of "free" raised
    ValueError out of _run_split, execute and asyncio.run -- past the transcript,
    past summary.json, past /runs/{id}/finish -- so one JSON field left the run
    'running' and its worker slot pinned until the reaper ~17 minutes later.
    Repeatable on every run."""
    for forged in ("free", {"a": 1}, [1], True):
        async def events(inputs, forged=forged):
            yield _msg(record={}, result={"result": "ok", "num_turns": 1,
                                          "total_cost_usd": forged, "session_id": "s",
                                          "is_error": False, "usage": {}})
            yield done_event(0, None)

        install_fake_b(monkeypatch, events)
        api = FakeApi()
        rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None),
                                    timeout=15)
        assert api.finish is not None, f"run was never finalized with {forged!r}"
        assert api.finish["summary"] == "ok"
        assert any(p.endswith("summary.json") for p, _ in api.puts), forged
        assert rc == 0


async def test_forged_scalar_fields_do_not_reach_the_run_record(monkeypatch):
    """num_turns/session_id/summary are stored and later read back. A forged type
    must be dropped, not coerced with str(), so an object cannot smuggle its repr
    into the record."""
    async def events(inputs):
        yield _msg(record={}, result={"result": {"not": "a string"}, "num_turns": "many",
                                      "session_id": ["x"], "total_cost_usd": 0.5,
                                      "is_error": False, "usage": {}})
        yield done_event(0, None)

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=15)
    assert api.finish is not None
    assert api.finish["summary"] is None          # not the dict's repr
    summary_json = [b for p, b in api.puts if p.endswith("summary.json")][0]
    body = json.loads(summary_json["content"])
    assert body["num_turns"] is None and body["session_id"] is None
    assert body["total_cost_usd"] == 0.5          # the well-typed one survives


async def test_a_forged_done_error_cannot_crash_the_redactor(monkeypatch):
    """The done sentinel is the agent's too. A non-string error reached _redact,
    which runs re.sub over it and raises TypeError on a dict."""
    async def events(inputs):
        yield {"kind": "done", "exit": 0, "error": {"x": 1}}

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=15)
    assert rc == 1
    assert api.finish is not None and api.finish["error"]


async def test_unmatched_tool_spans_cannot_exhaust_the_sidecar(monkeypatch):
    """The byte budget bounds what the agent SENDS; this bounds what the sidecar
    RETAINS. A tool_use with no matching tool_result is never popped, and both
    the id and the pairing are the agent's choice -- so 86-byte events convert to
    ~3.5 KB of open span each, and the 64 MiB the channel permits becomes
    multiple GB of sidecar memory: an OOM of the half holding every credential,
    past the container's own 2g limit."""
    monkeypatch.setattr(runner, "_MAX_OPEN_TOOL_SPANS", 32)
    seen = {}

    async def events(inputs):
        for i in range(2000):
            yield _msg(record={}, tools=[{"id": f"t{i}", "name": "B", "input": 0}])
        seen["peak"] = None
        yield _msg(record={}, result={"result": "done", "num_turns": 1,
                                      "total_cost_usd": 0.0, "session_id": "s",
                                      "is_error": False, "usage": {}})
        yield done_event(0, None)

    real_open = runner._open_tool_span
    peak = {"n": 0}

    def spy(tool_spans, sid, sp):
        real_open(tool_spans, sid, sp)
        peak["n"] = max(peak["n"], len(tool_spans))

    monkeypatch.setattr(runner, "_open_tool_span", spy)
    install_fake_b(monkeypatch, events)
    api = FakeApi()
    rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=60)
    assert rc == 0
    assert peak["n"] <= 32, f"held {peak['n']} open spans for 2000 unmatched tool uses"


async def test_a_failed_run_that_still_has_a_summary_keeps_its_proxy_for_capture(monkeypatch):
    """The proxy is stopped early to stop a condemned run spending. Keying that
    on `error is not None` was wrong: a ResultMessage can carry BOTH a summary
    and is_error, so it killed the proxy for every failed-with-a-message run and
    silently disabled its graph capture -- which swallows its own errors, so
    nothing would have said so. The condition is `summary is None`."""
    stopped = {"n": 0}

    class FakeProxy:
        def stop(self):
            stopped["n"] += 1

    monkeypatch.setattr(runner, "_start_model_proxy",
                        lambda: ("http://127.0.0.1:1", FakeProxy()))

    # The graph must be ON, or capture never runs and nothing distinguishes the
    # two conditions -- an assertion that cannot fail.
    monkeypatch.setitem(CTX, "graph_enabled", True)
    seen = {}

    async def fake_capture(api, agent, run_id, ctx, summary, proxy_url=None):
        # what capture actually needs: a proxy that is still alive when it runs
        seen["stopped_before_capture"] = stopped["n"]
        seen["proxy_url"] = proxy_url

    monkeypatch.setattr(runner, "_capture", fake_capture)

    async def events(inputs):
        # a run that FAILED but still produced a summary
        yield _msg(record={}, result={"result": "partial work done", "is_error": True,
                                      "num_turns": 1, "total_cost_usd": 0.0,
                                      "session_id": "s", "usage": {}})
        yield done_event(0, None)

    install_fake_b(monkeypatch, events)
    api = FakeApi()
    try:
        rc = await asyncio.wait_for(runner._run_split(api, "alice", "r1", RUN, None), timeout=20)
    finally:
        CTX["graph_enabled"] = False
    assert rc == 1
    assert api.finish["summary"] == "partial work done"
    assert seen.get("proxy_url"), "capture never ran for a failed-with-summary run"
    assert seen["stopped_before_capture"] == 0, (
        "the proxy was stopped before graph capture, so capture's model call "
        "would fail -- silently, since capture swallows its own errors")


async def test_serve_only_posts_start_but_never_finishes_or_connects(monkeypatch):
    """H2 runner half: an exec/v1 serve-only sidecar posts /start, serves the
    model proxy + MCP, and NEVER constructs a channel, arms the connect
    watchdog, or posts /finish -- the daemon owns completion via worker-finish.

    With RUN_TTL tiny the serve-wait returns fast; with AGENT_CONNECT_TIMEOUT
    tiny, a mutant that RESTORED the watchdog would fire "never connected" and
    post a /finish here. Skipping /start leaves started False; restoring /finish
    sets api.finish; either reddens."""
    import andyur.config as _config
    monkeypatch.setattr(runner, "RUN_TTL_SECONDS", 0.3)
    monkeypatch.setattr(_config, "AGENT_CONNECT_TIMEOUT", 0.3, raising=False)

    class Span:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def set_attribute(self, *a): pass
        def end(self): return None

    class Tracer:
        def start_as_current_span(self, *a, **k): return Span()
        def start_span(self, *a, **k): return Span()

    monkeypatch.setattr(runner, "_tracer", Tracer())
    monkeypatch.setitem(CTX, "registry_model", "m")
    monkeypatch.setitem(CTX, "registry_agent_id", "agt_split")
    monkeypatch.setattr(
        runner, "_start_tool_egress",
        lambda a, s, *, partitioned=None, selected_model=None: ({}, None))
    # M1: the serve-only tool service takes the DECLARED bearer or refuses.
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer")

    class RecordingApi(FakeApi):
        def __init__(self):
            super().__init__()
            self.started = False

        async def post(self, path, json=None):
            if path.endswith("/start"):
                self.started = True
            return await super().post(path, json)

    api = RecordingApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None, serve_only=True)
    assert rc == 0
    assert api.started is True            # /start posted -> started_at is set
    assert api.finish is None             # the sidecar NEVER finishes an exec/v1 run
    # The COMPLETION write path -- summary.json / transcript.jsonl / graph -- is
    # what a channel done() would drive under the run token; serve-only never
    # constructs the channel, so none of it is reachable. (prompt.md is written
    # during prepare, before serve-only, and is not that path.)
    paths = [p for p, _ in api.puts]
    assert not any(p.endswith("summary.json") or p.endswith("transcript.jsonl")
                   for p in paths)


# ---------------------------------------------------------------------------
# exec/v1 serve-only: the declared bearer or a refusal; a front on the proxy
# port (R, PR #21: fail-open ANDYUR_MCP_TOKEN; MED-2 nothing listened on 8765)
# ---------------------------------------------------------------------------

class _Recorder:
    """Stands in for ToolService / ExecFront and records construction, start
    and stop in ONE shared order, so start ordering is checkable."""
    calls: list = []

    def __init__(self, kind, *args, **kwargs):
        self.kind = kind
        _Recorder.calls.append((kind, "init", args, kwargs))

    def start(self):
        _Recorder.calls.append((self.kind, "start"))
        return f"http://127.0.0.1:1/{self.kind}"

    def stop(self):
        _Recorder.calls.append((self.kind, "stop"))


class _RecordingApi(FakeApi):
    def __init__(self):
        super().__init__()
        self.started = False

    async def post(self, path, json=None):
        if path.endswith("/start"):
            self.started = True
        return await super().post(path, json)


def _serve_only_env(monkeypatch):
    import andyur.config as _config
    monkeypatch.setattr(runner, "RUN_TTL_SECONDS", 0.3)
    monkeypatch.setattr(_config, "AGENT_CONNECT_TIMEOUT", 0.3, raising=False)

    class Span:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def set_attribute(self, *a): pass
        def end(self): return None

    class Tracer:
        def start_as_current_span(self, *a, **k): return Span()
        def start_span(self, *a, **k): return Span()

    monkeypatch.setattr(runner, "_tracer", Tracer())
    # The CONTEXT model is deliberately NOT the grant the serve-only test sets:
    # a front pinned to the context (R mutant m4b) must not pass by coincidence.
    monkeypatch.setitem(CTX, "registry_model", "context-model")
    monkeypatch.setitem(CTX, "registry_agent_id", "agt_split")
    monkeypatch.setattr(
        runner, "_start_tool_egress",
        lambda a, s, *, partitioned=None, selected_model=None: ({}, None))
    _Recorder.calls.clear()
    monkeypatch.setattr(runner, "ToolService",
                        lambda *a, **kw: _Recorder("tool", *a, **kw))
    monkeypatch.setattr(runner, "ExecFront",
                        lambda *a, **kw: _Recorder("front", *a, **kw))


async def test_serve_only_refuses_to_serve_without_the_declared_bearer(monkeypatch):
    """ANDYUR_MCP_TOKEN absent is a REFUSAL, not ToolService(token=None) on the
    Pod IP (which would accept every bearer from anything the NetworkPolicy
    admits). And the failed sidecar still never takes the completion path:
    nothing served, no summary/transcript written, no /finish -- the daemon is
    the sole completer even when the sidecar dies at start."""
    _serve_only_env(monkeypatch)
    monkeypatch.delenv("ANDYUR_MCP_TOKEN", raising=False)
    api = _RecordingApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None, serve_only=True)
    assert rc == 1
    assert api.started is True                      # /start was posted in prepare
    assert not [c for c in _Recorder.calls if c[1] == "init"], (
        "a service was constructed without the declared bearer")
    assert api.finish is None
    assert not any(p.endswith("summary.json") or p.endswith("transcript.jsonl")
                   for p, _ in api.puts)


async def test_serve_only_serves_the_declared_bearer_behind_a_ready_front(monkeypatch):
    """With the bearer present: the tool service is keyed on EXACTLY the
    declared value (never minted here), the front on the proxy port is started
    AFTER it (readiness cannot answer before /mcp is up) and forwards to this
    sidecar's model proxy, and both are torn down with the run."""
    _serve_only_env(monkeypatch)
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer")
    monkeypatch.setenv("ANDYUR_EXEC_MODEL", "granted-model")     # != the context model
    monkeypatch.setattr(runner, "LLM_MODE", "subscription")   # no model leg at all
    api = _RecordingApi()
    rc = await runner._run_split(api, "alice", "r1", RUN, None, serve_only=True)
    assert rc == 0
    calls = _Recorder.calls
    tool_init = next(c for c in calls if c[0] == "tool" and c[1] == "init")
    assert tool_init[3]["token"] == "declared-bearer"
    front_init = next(c for c in calls if c[0] == "front" and c[1] == "init")
    # process mode here: loopback, dynamic port; upstream is this run's model
    # proxy URL (none configured in this test -> None, and the front says so)
    assert front_init[2] == (None,)
    assert front_init[3] == {"host": "127.0.0.1", "port": 0, "enforced_model": "granted-model",
                             "require_model": True,
                             # the front joins the RUN's trace and names the run (PR B)
                             "run_id": "r1", "agent": "alice", "origin_trace": None}
    assert "ANDYUR_EXEC_MODEL" not in __import__("os").environ      # popped
    order = [(k, e) for k, e, *_ in calls]
    assert order.index(("tool", "start")) < order.index(("front", "start"))
    assert ("tool", "stop") in order and ("front", "stop") in order
    assert api.finish is None


def test_serve_only_token_helper_refuses_blank_and_returns_the_declared_value(monkeypatch):
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "   ")
    with pytest.raises(RuntimeError, match="ANDYUR_MCP_TOKEN"):
        runner._serve_only_mcp_token()
    monkeypatch.delenv("ANDYUR_MCP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="ANDYUR_MCP_TOKEN"):
        runner._serve_only_mcp_token()
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    assert runner._serve_only_mcp_token() == "declared"
    assert "ANDYUR_MCP_TOKEN" not in __import__("os").environ   # popped: no subprocess inherits it


def test_serve_only_services_stop_the_tool_service_when_the_front_fails(monkeypatch):
    """A front that cannot bind must not leave the tool service (a credential
    holder on the Pod IP) running behind a raised exception."""
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    _Recorder.calls.clear()
    monkeypatch.setattr(runner, "ToolService",
                        lambda *a, **kw: _Recorder("tool", *a, **kw))

    class FailingFront(_Recorder):
        def start(self):
            raise RuntimeError("the exec/v1 front failed to start")

    monkeypatch.setattr(runner, "ExecFront",
                        lambda *a, **kw: FailingFront("front", *a, **kw))
    with pytest.raises(RuntimeError, match="front failed"):
        runner._start_serve_only_services("alice", "r1", None, None)
    assert ("tool", "stop") in [(c[0], c[1]) for c in _Recorder.calls]


def test_serve_only_park_ends_on_sigterm_even_as_an_init_process():
    """R MED-0 test A: the runner is the container's PID 1 and init gets no
    default signal disposition, so without a handler a SIGTERM is not delivered
    and the proxy Pod delete pays the whole grace period. Spawn the park with
    SIGTERM IGNORED by inheritance (SIG_IGN survives exec and Python does not
    reset it) -- the same situation as PID 1 -- and it must still exit within
    2s of SIGTERM because the park installs its own handler. Drop the handler
    and this hangs to the timeout."""
    import os as _os
    import signal
    import subprocess
    import sys
    import time
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import asyncio\nfrom andyur.runner import runner\n"
         "print(asyncio.run(runner._serve_only_park(120)), flush=True)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        preexec_fn=lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN))
    try:
        deadline = time.monotonic() + 20
        while "parked" not in (line := proc.stdout.readline()):
            assert time.monotonic() < deadline and line != "", proc.stderr.read()
        proc.send_signal(signal.SIGTERM)
        # The BOUND is the property: wait first (a blocking read here would
        # hide a handler that honours SIGTERM late -- R, round 2), then read.
        assert proc.wait(timeout=2) == 0, proc.stderr.read()
        assert "sigterm" in proc.stdout.read()
    finally:
        if proc.poll() is None:
            proc.kill()

def test_serve_only_front_forwards_to_ollama_in_local_model_mode(monkeypatch):
    """ANDYUR_LLM=ollama: no credential means no model proxy, but the workload
    was handed services.model.base_url on the proxy port, so the front's
    upstream is the platform's Ollama -- the model leg stays observed at the
    proxy and the workload never learns the model address. In api mode with no
    proxy the front has no upstream (503 by name)."""
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    _Recorder.calls.clear()
    monkeypatch.setattr(runner, "ToolService", lambda *a, **kw: _Recorder("tool", *a, **kw))
    monkeypatch.setattr(runner, "ExecFront", lambda *a, **kw: _Recorder("front", *a, **kw))
    monkeypatch.setattr(runner, "LLM_MODE", "ollama")
    monkeypatch.setattr(runner, "OLLAMA_URL", "http://10.43.147.32:11434")
    runner._start_serve_only_services("alice", "r1", None, None)
    front = next(c for c in _Recorder.calls if c[0] == "front" and c[1] == "init")
    assert front[2] == ("http://10.43.147.32:11434",)
    # an explicit model proxy always wins, whatever the mode
    _Recorder.calls.clear()
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    runner._start_serve_only_services("alice", "r1", None, "http://10.0.0.5:4321")
    front = next(c for c in _Recorder.calls if c[0] == "front" and c[1] == "init")
    assert front[2] == ("http://10.0.0.5:4321",)
    # api mode with nothing to hold: no upstream
    _Recorder.calls.clear()
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    monkeypatch.setattr(runner, "LLM_MODE", "api")
    runner._start_serve_only_services("alice", "r1", None, None)
    front = next(c for c in _Recorder.calls if c[0] == "front" and c[1] == "init")
    assert front[2] == (None,)


def test_a_sigterm_before_the_park_is_remembered(monkeypatch):
    """The stop handler is installed at execute() level, so a SIGTERM that
    lands while services are still starting ends the park at once instead of
    being dropped (R LOW, round 2)."""
    import os as _os
    import signal as _signal

    async def go():
        stop = runner._install_stop_handler(asyncio.get_running_loop())
        _os.kill(_os.getpid(), _signal.SIGTERM)          # before anything parks
        await asyncio.sleep(0.05)
        assert stop.is_set()
        return await runner._serve_only_park(30)

    assert asyncio.run(go()) == "sigterm"


async def test_execute_installs_the_stop_handler_before_anything_else(monkeypatch):
    """The handler is execute()'s first act, before the control-plane client
    exists: the runner is PID 1 and a SIGTERM during startup must land
    somewhere (R LOW, round 2). Drives the real execute() up to its first
    control-plane call, which is made to answer 404 (run gone -> return 0)."""
    order = []
    monkeypatch.setattr(runner, "_install_stop_handler", lambda loop: order.append("handler"))
    monkeypatch.setattr(runner.identity, "httpx_auth", lambda: None)
    monkeypatch.setattr(runner.identity, "client_tls", lambda role: (None, True))

    class Gone:
        status_code = 404

    class FakeClient:
        def __init__(self, **kw):
            order.append("client")
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def get(self, path, **kw):
            return Gone()

    monkeypatch.setattr(runner.httpx, "AsyncClient", FakeClient)
    assert await runner.execute("alice", "r-gone", serve_only=True) == 0
    assert order == ["handler", "client"]
    # the other shapes keep their default dispositions (R LOW, round 2)
    order.clear()
    assert await runner.execute("alice", "r-gone", serve_only=False) == 0
    assert order == ["client"]


def test_the_front_pins_the_assignments_grant_never_the_context_or_the_default(monkeypatch):
    """R MED-1: the front used to pin `selected_model` (the run's context, else
    DEFAULT_MODEL) while the workload's services.model.name came from the
    assignment -- two sources, and a model-less grant pinned the platform
    default. One source now: ANDYUR_EXEC_MODEL from the controller; absent =
    no grant = refuse every model call (require_model)."""
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared")
    monkeypatch.delenv("ANDYUR_EXEC_MODEL", raising=False)
    assert runner._exec_granted_model() is None
    monkeypatch.setenv("ANDYUR_EXEC_MODEL", "  ")
    assert runner._exec_granted_model() is None
    monkeypatch.setenv("ANDYUR_EXEC_MODEL", "qwen3-andyur:latest")
    assert runner._exec_granted_model() == "qwen3-andyur:latest"
    assert "ANDYUR_EXEC_MODEL" not in __import__("os").environ


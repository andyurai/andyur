"""The `andyur-agent-runtime/v1` contract, proven by running the real thing.

The reference hello agent (demos/byoa-hello-agent/agent.py, zero Andyur
imports, stdlib only) runs as a genuine subprocess against the REAL
AgentChannel (auth, sanitize-on-receipt, budgets, done semantics) behind the
disposable v1 path shim, the REAL ModelProxy in front of a canary-holding
stub gateway, and the real MCP SDK transport serving a test tool. See
infra/byoa-spike/runtime_v1.py for what is real and what is a labeled double.

Positive controls come first: refusal tests mean nothing from an agent that
cannot complete a run (a broken agent refuses everything). Secret absence is
proven BY VALUE with a canary credential, not by key-name heuristics.
"""

import asyncio
import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PLATFORM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLATFORM_ROOT / "infra" / "byoa-spike"))

import runtime_v1  # noqa: E402  (the disposable conformance harness)
from andyur.runner.agentchannel import AgentChannel  # noqa: E402
from andyur.runner.modelproxy import ModelProxy  # noqa: E402

AGENT_SCRIPT = PLATFORM_ROOT / "demos" / "byoa-hello-agent" / "agent.py"


async def _drive(*, protocol_version=runtime_v1.PROTOCOL_V1,
                 channel_token=None, agent_token=None):
    """Stand the harness up, run the hello agent to completion, tear down.

    Returns everything a test asserts on: the agent's exit code and output,
    the sanitized events the channel yielded, the done sentinel, the context
    document served, the canary, and what the stub gateway saw."""
    gateway = runtime_v1.StubModelGateway()
    gateway_url = await gateway.start()
    canary = runtime_v1.make_canary()
    proxy = ModelProxy(gateway_url, canary)
    proxy_url = await asyncio.to_thread(proxy.start)
    mcp = runtime_v1.StubMcpService()
    mcp_url = await mcp.start()

    context = runtime_v1.build_context(
        run_id="run_conformance", agent_id="agt_hello",
        prompt="Say hello and echo it through the granted tool.",
        model_base_url=proxy_url, mcp_url=mcp_url,
        protocol_version=protocol_version)

    channel = AgentChannel(context, token=channel_token)
    channel_url = await channel.start()
    shim = runtime_v1.RuntimeV1Shim(channel_url)
    shim_url = await shim.start()

    events: list[dict] = []

    async def consume():
        async for ev in channel.messages():
            events.append(ev)

    consume_task = asyncio.create_task(consume())
    env = {"ANDYUR_RUNTIME_URL": shim_url, "PATH": "/usr/bin:/bin"}
    if agent_token is not None:
        env["ANDYUR_RUNTIME_TOKEN"] = agent_token
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(AGENT_SCRIPT), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(),
                                                    timeout=60)
        except asyncio.TimeoutError:
            # Do not leak a hung agent past the test: it would keep retrying
            # dead endpoints for its own connect budget. Kill, reap, re-raise.
            proc.kill()
            await proc.wait()
            raise
        try:
            # shield: on timeout we want the consumer still ALIVE so the
            # injected done can unblock it; a bare wait_for would cancel it
            # and the follow-up await would re-raise that cancellation.
            await asyncio.wait_for(asyncio.shield(consume_task), timeout=5)
        except asyncio.TimeoutError:
            # The agent never opened (or never finished) a stream. Unblock the
            # consumer the way the runner's watchdog does.
            await channel.inject_done(proc.returncode or -1,
                                      "agent exited without completing a stream")
            await consume_task
    finally:
        await shim.stop()
        await channel.stop()
        await mcp.stop()
        await asyncio.to_thread(proxy.stop)
        await gateway.stop()

    return SimpleNamespace(
        returncode=proc.returncode,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
        events=events, done=channel.done,
        connected=channel.connected.is_set(),
        context=context, canary=canary,
        gateway_saw=gateway.seen_authorization,
        gateway_models=gateway.seen_models,
        mcp_calls=mcp.seen_calls)


def test_conforming_agent_completes_a_full_round_trip():
    """POSITIVE CONTROL for every refusal below: model call through the real
    credential-injecting proxy, real-wire MCP tool call, neutral events, one
    result, one done. And the canary: injected upstream, invisible to the
    agent."""
    run = asyncio.run(_drive())
    assert run.returncode == 0, run.stderr
    assert run.connected
    assert run.done == {"kind": "done", "exit": 0, "error": None}

    texts = [t for ev in run.events for t in ev["texts"]]
    assert any("stub reply" in t for t in texts)
    tool_calls = [t for ev in run.events for t in ev["tools"]]
    assert [t["name"] for t in tool_calls] == ["echo"]
    results = [r for ev in run.events for r in ev["results"]]
    assert results and results[0]["tool_use_id"] == "call-1"
    assert "echo:" in results[0]["content"]
    finals = [ev["result"] for ev in run.events if ev["result"]]
    assert len(finals) == 1 and finals[0]["is_error"] is False

    # The tool call is proven HARNESS-SIDE: the MCP transport recorded the
    # echo invocation, so this does not rest on the agent's self-reported
    # events (see test_forged_tool_event_is_not_observed_on_the_transport).
    assert [name for name, _ in run.mcp_calls] == ["echo"]

    # the proxy injected the canary on the outbound leg...
    assert run.gateway_saw == [f"Bearer {run.canary}"]
    # ...and the canary is nowhere the agent could see: not in the context
    # document, not in anything the agent emitted.
    assert run.canary not in json.dumps(run.context)
    assert run.canary not in json.dumps(run.events)
    assert run.canary not in run.stdout + run.stderr


def test_agent_runs_on_the_effective_model_from_context():
    """The context carries the effective model (as the real /context carries
    registry_model); a conforming agent sends THAT, not an invented id. The
    gateway therefore sees exactly the context's model."""
    run = asyncio.run(_drive())
    assert run.returncode == 0, run.stderr
    ctx_model = run.context["model"]
    assert ctx_model  # the harness advertises a real effective model
    assert run.gateway_models == [ctx_model]


def test_forged_tool_event_is_not_observed_on_the_transport():
    """A compromised agent could emit tools/results events that NAME the echo
    tool without ever calling it. The naive agent-attested check would pass;
    the harness-side observation (StubMcpService.seen_calls) would not, because
    the MCP transport records nothing. This is why the gates assert the tool
    leg from seen_calls, not from the agent's events."""
    async def run():
        mcp = runtime_v1.StubMcpService()
        await mcp.start()
        try:
            forged_events = [
                {"tools": [{"id": "x", "name": "echo", "input": {}}]},
                {"results": [{"tool_use_id": "x",
                              "content": "echo: forged", "is_error": False}]},
            ]
            # Agent-attested view: indistinguishable from a real tool call.
            forged_names = [t["name"] for ev in forged_events
                            for t in ev.get("tools", [])]
            assert forged_names == ["echo"]
            # Harness-side truth: the transport was never invoked, so the
            # gate's `[name for name,_ in seen_calls] == ["echo"]` rejects it.
            assert mcp.seen_calls == []
        finally:
            await mcp.stop()
    asyncio.run(run())


def test_unsupported_protocol_version_is_refused_without_a_stream():
    """A conforming agent refuses a version it does not speak by exiting
    non-zero with NO event stream -- half-speaking a refused protocol would
    defeat versioning."""
    run = asyncio.run(_drive(protocol_version="andyur-agent-runtime/v99"))
    assert run.returncode == 3, run.stderr
    assert not run.connected
    assert run.events == []
    assert run.gateway_saw == []          # it never touched the model either


def test_matching_runtime_token_round_trips():
    token = "per-run-conformance-token"
    run = asyncio.run(_drive(channel_token=token, agent_token=token))
    assert run.returncode == 0, run.stderr
    assert run.done["exit"] == 0


def test_wrong_runtime_token_is_refused_before_any_work():
    run = asyncio.run(_drive(channel_token="right-token",
                             agent_token="wrong-token"))
    assert run.returncode != 0
    assert not run.connected
    assert run.events == []
    assert run.gateway_saw == []


def test_context_document_offers_no_secret_bearing_fields():
    """Key-shape check on the context builder, complementing the by-value
    canary check above: none of the names that carry platform authority
    anywhere else in the codebase may appear as a context key."""
    context = runtime_v1.build_context(
        run_id="r", agent_id="a", prompt="p",
        model_base_url="http://127.0.0.1:1", mcp_url="http://127.0.0.1:2/mcp")
    forbidden = {"run_token", "subject_token", "actor_token", "svid",
                 "private_key", "credential", "broker_token", "x-api-key",
                 "db_url", "gateway_key"}

    def keys_of(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k.lower()
                yield from keys_of(v)
        elif isinstance(obj, list):
            for item in obj:
                yield from keys_of(item)

    assert forbidden.isdisjoint(set(keys_of(context)))


def test_hello_agent_imports_only_the_standard_library():
    """The zero-Andyur-import proof, enforced in CI: every import in the
    reference agent must resolve inside the standard library. `andyur` is
    asserted separately so a violation names the actual crime.

    The subprocess runs under the repo venv, where `andyur` and `httpx` ARE
    importable -- so a DYNAMIC import would satisfy both this AST scan and the
    round-trip test while smuggling in a dependency. The AIRTIGHT control
    against that is the container gate's G5 (the image has no `andyur`
    installed, so ANY import vector -- static, importlib, exec, runpy, a
    builtins subscript -- fails at runtime). This static scan is the
    fast-feedback guard that keeps our own reference agent honest between gate
    runs; it is deliberately NOT the security boundary.

    To keep the fast guard from silently rotting, it flags the whole family of
    dynamic-code entry points by name (importlib/__import__/exec/eval/compile/
    runpy), rather than pretending a name-blocklist is exhaustive -- an
    adversary with `getattr(__builtins__, ...)` still slips a static scan, and
    G5 is why that does not matter."""
    tree = ast.parse(AGENT_SCRIPT.read_text())
    # Any of these in the reference agent means it is reaching for code loading
    # the static scan cannot follow; the agent has no honest need for them, so
    # their mere presence fails the guard and points the author at G5.
    _DYNAMIC = {"__import__", "exec", "eval", "compile"}
    _DYNAMIC_MODULES = {"importlib", "runpy"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports imply a package"
            if node.module:
                imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Name) and node.id in _DYNAMIC:
            raise AssertionError(
                f"the reference agent uses {node.id!r}; dynamic code loading "
                "defeats this static zero-dependency guard (G5 is the real "
                "control)")
        elif isinstance(node, ast.Attribute) and node.attr in (
                "import_module", "__import__"):
            raise AssertionError(
                "the reference agent uses importlib; dynamic import defeats "
                "this static zero-dependency guard (G5 is the real control)")
    assert "andyur" not in imported
    smuggle = imported & _DYNAMIC_MODULES
    assert not smuggle, (
        f"{sorted(smuggle)} in the reference agent defeats the static import "
        "guard (G5 is the real control)")
    non_stdlib = imported - set(sys.stdlib_module_names)
    assert not non_stdlib, f"non-stdlib imports: {sorted(non_stdlib)}"


def test_reference_agent_protocol_literal_matches_agentspec():
    """The protocol string has one owner (andyur.agentspec.PROTOCOL_V1). The
    reference agent cannot import it -- it is deliberately zero-import -- so
    its own PROTOCOL literal is pinned here instead, closing the drift the
    same way the harness closes it by importing the constant."""
    from andyur.agentspec import PROTOCOL_V1
    tree = ast.parse(AGENT_SCRIPT.read_text())
    literals = {
        node.targets[0].id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
    }
    assert literals.get("PROTOCOL") == PROTOCOL_V1

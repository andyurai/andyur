"""DISPOSABLE multi-framework proof for the BYOA runtime contract (ADR-008
acceptance gate #7: "at least two independent agent frameworks pass the same
conformance/security suite").

Builds and runs each REAL third-party framework agent -- LangGraph and the
OpenAI Agents SDK, each its own container with its own dependency tree and
zero `andyur` -- against the SAME real platform components the stdlib gate
uses (AgentChannel, ModelProxy, real MCP transport), and asserts per agent:

  F-a  round trip: the framework agent completes context -> model (through the
       credential-injecting proxy) -> granted MCP tool -> events -> result ->
       done, driven by its OWN model client and OWN MCP client;
  F-b  canary: the gateway credential was injected by the proxy and never
       appears in the context, the container env, or anything the agent
       emitted (secret absence, by value);
  F-c  the image cannot import `andyur` (its dependency tree is framework
       code, not Andyur).

This complements byoa_gate.py, which proves the contract's controls (limits,
refusal, kill) with the minimal stdlib agent. Here the point is different:
that unmodified, real frameworks work under the identical controls.

Run:  ./verify-frameworks.sh   (from infra/byoa-spike)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PLATFORM_ROOT))

import runtime_v1  # noqa: E402
from byoa_gate import (  # noqa: E402  (reuse the real-component harness)
    Harness, record, run_agent_container, sh, file_sha, CHECKS,
)

DEMOS = PLATFORM_ROOT / "demos"
FRAMEWORKS = [
    {"name": "langgraph", "dir": DEMOS / "byoa-langgraph-agent",
     "image": "byoa-langgraph-agent:gate", "container": "byoa-fw-langgraph",
     "import": "langgraph"},
    {"name": "openai-agents", "dir": DEMOS / "byoa-openai-agent",
     "image": "byoa-openai-agent:gate", "container": "byoa-fw-openai",
     "import": "agents"},
]


def build(fw: dict) -> str:
    out = sh("docker", "build", "-q", str(fw["dir"]), "-t", fw["image"],
             timeout=900)
    if out.returncode != 0:
        raise RuntimeError(f"{fw['name']} build failed: {out.stderr[-500:]}")
    return out.stdout.strip()


async def run_framework(fw: dict) -> None:
    async with Harness() as h:
        proc = await asyncio.to_thread(
            run_agent_container, h.shim_url, h.token, 180,
            fw["image"], fw["container"])
        await h.finish_stream(timeout=15)
        done = h.channel.done or {}
        texts = [t for ev in h.events for t in ev["texts"]]
        tools = [t["name"] for ev in h.events for t in ev["tools"]]
        results = [r for ev in h.events for r in ev["results"]]
        finals = [ev["result"] for ev in h.events if ev["result"]]
        ok = (proc.returncode == 0 and done.get("exit") == 0
              and tools and "echo" in tools
              and results and finals and finals[-1]["is_error"] is False)
        record(f"F[{fw['name']}] round trip via its own model+MCP client", ok,
               f"exit={proc.returncode} done={done} tools={tools} "
               f"results={len(results)} finals={len(finals)} "
               f"stderr={proc.stderr[-300:]!r}")
        injected = h.gateway.seen_authorization and all(
            a == f"Bearer {h.canary}" for a in h.gateway.seen_authorization)
        record(f"F[{fw['name']}] canary injected by the proxy, never held", injected,
               f"gateway saw {len(h.gateway.seen_authorization)} model call(s)")
        # The granted tool call, proven HARNESS-SIDE (the MCP transport
        # recorded it) -- so the framework really routed a call through its
        # MCP client, not just emitted a tools event.
        tool_calls = [name for name, _ in h.mcp.seen_calls]
        record(f"F[{fw['name']}] MCP tool invoked (observed on the transport)",
               "echo" in tool_calls,
               f"mcp transport saw calls: {h.mcp.seen_calls}")
        # The framework agent read the effective model from context and SENT
        # it -- proving model selection flows through the contract, not a
        # hardcoded id (enforcement is server-side). A claude-* id sent through
        # the OpenAI surface also shows the id is vendor-neutral to the agent.
        ctx_model = h.context["model"]
        used = (bool(h.gateway.seen_models)
                and all(m == ctx_model for m in h.gateway.seen_models))
        record(f"F[{fw['name']}] sent the context's effective model", used,
               f"context model={ctx_model!r}, gateway saw {h.gateway.seen_models}")
        leaked = (h.canary in json.dumps(h.context)
                  or h.canary in json.dumps(h.events)
                  or h.canary in proc.stdout + proc.stderr)
        record(f"F[{fw['name']}] canary invisible to the agent", not leaked,
               "canary absent from context, events, agent output")


def zero_andyur(fw: dict) -> None:
    bad = sh("docker", "run", "--rm", "--entrypoint", "python", fw["image"],
             "-c", "import andyur")
    # Positive control: the same image CAN import its own framework, so a
    # refusal means "andyur absent", not "python broken / image empty".
    good = sh("docker", "run", "--rm", "--entrypoint", "python", fw["image"],
              "-c", f"import {fw['import']}")
    ok = (bad.returncode != 0 and "ModuleNotFoundError" in bad.stderr
          and good.returncode == 0)
    record(f"F[{fw['name']}] image has no andyur ({fw['import']} imports)", ok,
           f"import andyur exit={bad.returncode}, "
           f"import {fw['import']} exit={good.returncode}")


async def main() -> int:
    started = time.time()
    for fw in FRAMEWORKS:
        sh("docker", "rm", "-f", fw["container"])
    built = {}
    try:
        for fw in FRAMEWORKS:
            try:
                built[fw["name"]] = build(fw)
            except RuntimeError as exc:
                record(f"F[{fw['name']}] image build", False, str(exc))
                continue
            zero_andyur(fw)
            try:
                await run_framework(fw)
            except Exception as exc:
                record(f"F[{fw['name']}] run crashed", False,
                       f"{type(exc).__name__}: {exc}")
    finally:
        for fw in FRAMEWORKS:
            sh("docker", "rm", "-f", fw["container"])
    ok = all(c["ok"] for c in CHECKS)
    stamp = time.strftime("%Y-%m-%d", time.gmtime(started))
    out = HERE / f"result-frameworks-{stamp}.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps({
        "gate": "byoa-frameworks", "adr": "adr-008",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "duration_s": round(time.time() - started, 1),
        "frameworks": [{"name": fw["name"], "image": fw["image"],
                        "image_id": built.get(fw["name"]),
                        "agent_sha256": file_sha(fw["dir"] / "agent.py")}
                       for fw in FRAMEWORKS],
        "checks": CHECKS, "ok": ok,
    }, indent=2) + "\n")
    tmp.rename(out)
    print(f"[frameworks] {'GREEN' if ok else 'RED'}: "
          f"{sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks; {out.name}",
          flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

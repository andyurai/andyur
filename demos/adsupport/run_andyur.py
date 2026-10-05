"""Dual-control episode where the SYSTEM UNDER TEST is a real Andyur conversational
agent.

Correct eval shape:
  - the simulated app is a standalone SERVICE (the shared world)         [app_server]
  - the simulated customer is a standalone LLM harness                   [this file]
  - the support agent is a REAL Andyur conversation (the SUT), with its   [Andyur +
    support tools as an MCP server acting on the app service              mcp_support]

The customer drives the Andyur agent through the /turn + /events API (the
conversational-agents feature) and acts on the app service through its own
advertiser tools. Success is read from the app service's goal state.

Prereqs: an app service on :8650, and the Andyur stack (server + daemon) up in
api mode with ANTHROPIC_API_KEY. See run_demo.sh.
"""

import argparse
import json
import os
import time

import httpx

from .agent import LLMAgent
from .app import ADVERTISER_TOOLS
from .provision import AGENT_NAME, provision_agent   # the SUT's definition lives here
from .scenarios import SCENARIOS, customer_system

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642")
APP = os.environ.get("ADSUPPORT_APP_URL", "http://127.0.0.1:8650")
MODEL = os.environ.get("ADSUPPORT_MODEL", "claude-haiku-4-5-20251001")


def app_snapshot() -> dict:
    return httpx.get(f"{APP}/snapshot", timeout=15).json()


def app_goal() -> bool:
    return bool(httpx.get(f"{APP}/goal", timeout=15).json().get("resolved"))


def advertiser_dispatch(actor: str, name: str, args: dict) -> dict:
    r = httpx.post(f"{APP}/call",
                   json={"actor": "advertiser", "tool": name, "args": args}, timeout=30)
    return r.json()


def drain(c: httpx.Client, run_id: str, cursor: int, deadline: float):
    """Collect the agent's streamed reply until turn_end / session_end."""
    reply = []
    while time.time() < deadline:
        r = c.get(f"/runs/{run_id}/events", params={"after": cursor})
        if r.status_code != 200:
            return cursor, "".join(reply), True
        data = r.json()
        for ev in data.get("events", []):
            cursor = ev["seq"]
            if ev["kind"] == "chunk":
                reply.append(ev["body"])
            elif ev["kind"] == "turn_end":
                return cursor, "".join(reply), False
            elif ev["kind"] in ("session_end", "error"):
                return cursor, "".join(reply), ev["kind"] == "session_end"
        if data.get("state") in ("done", "failed", "cancelled"):
            return cursor, "".join(reply), True
        time.sleep(0.5)
    return cursor, "".join(reply), False


def run_episode(scenario_key: str, max_rounds: int = 10) -> dict:
    scenario = SCENARIOS[scenario_key]
    seed = httpx.post(f"{APP}/seed", json={"scenario": scenario_key}, timeout=15).json()
    ctx = seed["ctx"]
    print(f"\n{'='*78}\nSCENARIO: {scenario_key}  (SUT = Andyur agent '{AGENT_NAME}')\n"
          f"{scenario.summary}\n{'='*78}")

    c = httpx.Client(base_url=ANDYUR, timeout=30)
    provision_agent(c)   # stand up the SUT from its definition (provision.py)
    r = c.post(f"/agents/{AGENT_NAME}/trigger",
               json={"run_type": "conversation", "reason": "adsupport eval"})
    if r.status_code != 201:
        print(f"trigger failed: {r.status_code} {r.text}")
        return {"scenario": scenario_key, "resolved": False, "error": "trigger"}
    run_id = r.json()["run_id"]

    # wait for the daemon to launch the conversation session
    for _ in range(30):
        st = c.get(f"/runs/{run_id}").json().get("state")
        if st == "running":
            break
        time.sleep(1)

    customer = LLMAgent("advertiser", customer_system(scenario, ctx),
                        ADVERTISER_TOOLS, advertiser_dispatch, MODEL, temperature=0.8)
    cursor, prev, resolved, rounds, stall, started = 0, app_snapshot(), app_goal(), 0, 0, False

    turn, _ = customer.respond(
        "Begin the conversation. In one short message, tell support your problem "
        "in your own words AND include your account id (and ad id if you have one) "
        "so they can look you up.")
    print(f"\n[customer] {turn}")

    while not resolved and rounds < max_rounds:
        rounds += 1
        c.post(f"/runs/{run_id}/turn", json={"body": turn})
        cursor, reply, ended = drain(c, run_id, cursor, time.time() + 180)
        print(f"\n[agent (Andyur SUT)] {reply}")
        snap = app_snapshot(); changed = snap != prev; prev = snap
        started = started or changed
        stall = 0 if changed else (stall + 1 if started else 0)
        resolved = app_goal()
        if resolved or ended or stall >= 4:
            break
        turn, _ = customer.respond(reply)   # customer acts on the app + replies
        print(f"\n[customer] {turn}")
        snap = app_snapshot(); changed = snap != prev; prev = snap
        started = started or changed
        stall = 0 if changed else (stall + 1 if started else 0)
        resolved = app_goal()
        if resolved or stall >= 4:
            break

    c.post(f"/runs/{run_id}/close")
    outcome = "RESOLVED ✓" if resolved else "UNRESOLVED ✗"
    print(f"\n{'-'*78}\nRESULT: {outcome}   rounds={rounds}   "
          f"SUT=Andyur conversation {run_id}")
    if SHOW_TRANSCRIPT:
        _show_full_transcript(c, run_id)
    return {"scenario": scenario_key, "resolved": resolved, "rounds": rounds}


SHOW_TRANSCRIPT = False


def _blocks(data: dict):
    return data.get("content") if isinstance(data.get("content"), list) else []


def _show_full_transcript(c: httpx.Client, run_id: str) -> None:
    """Fetch and pretty-print the FULL session transcript the runner saved: every
    human turn, every agent text reply, AND every tool call the agent made against
    the app (with results). Waits for the run to finalize first (the transcript is
    written on finalize)."""
    for _ in range(30):
        if c.get(f"/runs/{run_id}").json().get("state") in ("done", "failed", "cancelled"):
            break
        time.sleep(1)
    r = c.get(f"/agents/{AGENT_NAME}/files/runs/{run_id}/transcript.jsonl")
    if r.status_code != 200:
        print("(transcript not available)")
        return
    print(f"\n{'='*78}\nFULL TRANSCRIPT (Andyur run {run_id})\n{'='*78}")
    for line in r.json()["content"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if "human" in rec:
            print(f"\nCUSTOMER: {rec['human']}")
            continue
        typ, data = rec.get("type"), rec.get("data", {})
        if typ == "AssistantMessage":
            for b in _blocks(data):
                if b.get("text"):
                    print(f"\nAGENT: {b['text'].strip()}")
                elif b.get("name") and "input" in b:
                    # skip Claude Code's ToolSearch (it just loads MCP tool schemas
                    # on demand); show the real ad-platform tool calls
                    if b["name"] == "ToolSearch":
                        continue
                    args = ", ".join(f"{k}={v}" for k, v in (b.get("input") or {}).items())
                    print(f"   >> tool call: {b['name'].replace('mcp__adsupport__','')}({args})")
        elif typ == "UserMessage":
            for b in _blocks(data):
                if "tool_use_id" in b or b.get("type") == "tool_result":
                    content = b.get("content")
                    if isinstance(content, list):
                        content = " ".join(x.get("text", "") for x in content
                                           if isinstance(x, dict))
                    print(f"      << result: {str(content)[:160]}")
    print(f"{'='*78}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="payment_limit",
                    choices=list(SCENARIOS) + ["all"])
    ap.add_argument("--max-rounds", type=int, default=10)
    ap.add_argument("--transcript", action="store_true",
                    help="print the full session transcript incl. the agent's tool calls")
    args = ap.parse_args()
    global SHOW_TRANSCRIPT
    SHOW_TRANSCRIPT = args.transcript
    keys = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    reports = [run_episode(k, args.max_rounds) for k in keys]
    print(f"\n{'='*78}\nSUMMARY (SUT = Andyur agent)")
    for r in reports:
        print(f"  {r['scenario']:<16} "
              f"{'RESOLVED ✓' if r['resolved'] else 'UNRESOLVED ✗':<14} "
              f"rounds={r.get('rounds','-')}")
    print(f"\n  resolved {sum(r['resolved'] for r in reports)}/{len(reports)}")


if __name__ == "__main__":
    main()

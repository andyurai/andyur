"""Run a dual-control support episode: a τ²-style customer simulator and a support
agent converse, BOTH acting on the shared simulated app, until the customer's
issue is resolved (the app reaches the goal state) or the round budget runs out.

Usage:
    python -m demos.adsupport.run --scenario payment_limit
    python -m demos.adsupport.run --scenario all --model claude-haiku-4-5-20251001
"""

import argparse
import os
import sys

from .agent import LLMAgent
from .app import (ADVERTISER_MUTATING_TOOLS, ADVERTISER_TOOLS, AGENT_MUTATING_TOOLS,
                  AGENT_TOOLS, dispatch)
from .provision import support_system_prompt
from .scenarios import SCENARIOS, customer_system

DEFAULT_MODEL = os.environ.get("ADSUPPORT_MODEL", "claude-haiku-4-5-20251001")


def _fmt_calls(calls) -> str:
    if not calls:
        return ""
    bits = []
    for name, args, ok in calls:
        a = ", ".join(f"{k}={v}" for k, v in args.items())
        bits.append(f"{name}({a}) {'✓' if ok else '✗'}")
    return "      · " + "\n      · ".join(bits)


def run_episode(key: str, model: str, max_rounds: int, verbose: bool = True) -> dict:
    scenario = SCENARIOS[key]
    app, ctx = scenario.build()
    # both sides act on the SAME in-process app for this standalone variant
    disp = lambda actor, name, args: dispatch(app, actor, name, args)  # noqa: E731
    # the support agent runs cooler (follow policy reliably); the customer runs
    # warmer (human-like variability in how they phrase and react)
    agent = LLMAgent("agent", support_system_prompt(ctx), AGENT_TOOLS, disp, model,
                     temperature=0.2)
    customer = LLMAgent("advertiser", customer_system(scenario, ctx),
                        ADVERTISER_TOOLS, disp, model, temperature=0.8)

    if verbose:
        print(f"\n{'='*78}\nSCENARIO: {scenario.name}\n{scenario.summary}\n{'='*78}")

    def emit(who, msg, calls):
        if verbose:
            tag = "customer" if who == "advertiser" else "agent   "
            print(f"\n[{tag}] {msg}")
            fc = _fmt_calls(calls)
            if fc:
                print(fc)

    def muts(actor, calls):
        s = AGENT_MUTATING_TOOLS if actor == "agent" else ADVERTISER_MUTATING_TOOLS
        return sum(1 for (n, a, ok) in calls if ok and n in s)

    msg, calls = customer.respond(
        "Begin the conversation. In one short message, tell support your problem "
        "in your own words.")
    emit("advertiser", msg, calls)
    all_calls = [("advertiser", *c) for c in calls]   # uniform (actor, name, args, ok)
    resolved = scenario.goal(app, ctx)
    rounds = 0
    stall = 0          # consecutive turns with no successful mutating action
    started = False    # has real work begun yet? (set by step() below)
    stalled = False

    def step(actor, calls_):
        # stall only counts AFTER work has started, so early diagnosis/clarification
        # turns (no mutation yet) never trip it; it only guards a post-work chit-chat
        # loop. Threshold 4 tolerates a normal back-and-forth.
        nonlocal stall, started
        if muts(actor, calls_):
            stall, started = 0, True
        elif started:
            stall += 1

    step("advertiser", calls)
    while not resolved and rounds < max_rounds:
        rounds += 1
        amsg, acalls = agent.respond(msg)
        emit("agent", amsg, acalls)
        all_calls += [("agent", *c) for c in acalls]
        step("agent", acalls)
        if scenario.goal(app, ctx):
            resolved = True
            break
        if stall >= 4:
            stalled = True
            break
        cmsg, ccalls = customer.respond(amsg)
        emit("advertiser", cmsg, ccalls)
        all_calls += [("advertiser", *c) for c in ccalls]
        msg = cmsg
        step("advertiser", ccalls)
        if scenario.goal(app, ctx):
            resolved = True
            break
        if stall >= 4:
            stalled = True
            break

    # coordination metric: did BOTH parties make a successful mutating call?
    agent_mut = any(actor == "agent" and n in AGENT_MUTATING_TOOLS and ok
                    for (actor, n, a, ok) in all_calls)
    adv_mut = any(actor == "advertiser" and n in ADVERTISER_MUTATING_TOOLS and ok
                  for (actor, n, a, ok) in all_calls)

    report = {
        "scenario": scenario.name, "resolved": resolved, "rounds": rounds,
        "coordinated": agent_mut and adv_mut, "stalled": stalled,
        "agent_acted": agent_mut, "advertiser_acted": adv_mut,
    }
    if verbose:
        outcome = ("RESOLVED ✓" if resolved
                   else "STALLED ✗" if stalled else "UNRESOLVED ✗")
        print(f"\n{'-'*78}")
        print(f"RESULT: {outcome}   rounds={rounds}   "
              f"coordination={'both acted ✓' if report['coordinated'] else 'one-sided ✗'}")
        print(f"        agent-acted={agent_mut}  advertiser-acted={adv_mut}")
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="all",
                    choices=list(SCENARIOS) + ["all"])
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-rounds", type=int, default=10)
    args = ap.parse_args()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(2)

    keys = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    reports = [run_episode(k, args.model, args.max_rounds) for k in keys]
    print(f"\n{'='*78}\nSUMMARY ({args.model})")
    for r in reports:
        print(f"  {r['scenario']:<16} "
              f"{'RESOLVED ✓' if r['resolved'] else 'UNRESOLVED ✗':<14} "
              f"rounds={r['rounds']:<3} "
              f"coordination={'both ✓' if r['coordinated'] else 'one-sided ✗'}")
    n_res = sum(r["resolved"] for r in reports)
    # coordination is only meaningful for scenarios that REQUIRE both parties
    dc = [r for r in reports if SCENARIOS[r["scenario"]].dual_control]
    n_coord = sum(r["coordinated"] for r in dc)
    print(f"\n  resolved {n_res}/{len(reports)}   dual-control coordination "
          f"{n_coord}/{len(dc)} (of the {len(dc)} dual-control scenarios)")


if __name__ == "__main__":
    main()

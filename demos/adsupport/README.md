# adsupport: a dual-control support demo

A reusable demo app + harness for testing conversational support agents, in the
style of **τ²-bench** (Barres et al., arXiv 2506.07982): a *dual-control*
environment where **both** the support agent and the customer take actions on one
shared, simulated system, and a ticket only closes if they coordinate.

It exists to be built on. The simulated app is generic (a mock ad platform, not
any real product), so we reuse it across our conversation-agent tests and grow it
as we go.

## The eval shape (who is the System Under Test)

The **support agent is the SUT** and is a **real Andyur conversational agent**.
The app and the customer are the standalone harness around it:

```
   standalone customer sim ──/turn,/events──►  ANDYUR CONVERSATION  (the SUT)
     │ (LLM + advertiser tools)                   │ support tools = an MCP server
     └────────────►  APP SERVICE (:8650)  ◄───────┘  (mcp_support.py)
                     the shared world; both sides call it; success is read here
```

There are two run modes:

- **`run_andyur.py`**: the real eval: the SUT is a live Andyur conversation.
  Use `run_demo.sh` to bring up everything and run it.
- **`run.py`**: a standalone fallback where BOTH sides are local LLMs sharing an
  in-process app. Handy for iterating on scenarios/app without the Andyur stack.

## The pieces

| File | What it is |
|---|---|
| `app.py` | The **simulated application**: a mock ad-platform backend (accounts, campaigns, ads, charges) with state, business rules, and two **asymmetric API surfaces** (`AGENT_TOOLS`, `ADVERTISER_TOOLS`). The dual control lives here: some ops are support-only (lift a limit, issue a credit, expedite a review), some are advertiser-only (update payment, edit creative, resubmit). `dispatch()` enforces the boundary. |
| `scenarios.py` | Seeded broken states + a **persona**, a **hidden goal**, and a **goal predicate** per scenario. Each dual-control scenario is unsolvable by one party alone (a unit test asserts this). |
| `agent.py` | A minimal tool-using LLM agent, used for **both** sides. It differs only in system prompt + tool surface. |
| `app_server.py` | The app as a standalone **HTTP service** (the shared world both processes reach). Seed / call / snapshot / goal. |
| `mcp_support.py` | The support agent's tools as an **MCP server**. Andyur loads this via the agent's `mcp.json`, so the SUT calls these tools during a conversation and they act on the app service. This is the agent surface only, so the SUT structurally cannot do the advertiser's part. |
| `agent/instructions.md` | The SUT's **definition**: its standing policy, authored as a file (not code). This is who the agent *is*, kept separate from the harness that tests it. |
| `provision.py` | Stands the SUT up in Andyur from its definition: writes `instructions.md` and generates its `mcp.json` (deployment binding). Any harness (or a human) provisions the agent the same way, then just drives it by name. |
| `run_andyur.py` | The **eval harness** (only): drives a live Andyur conversation (the SUT) with the standalone customer sim; both act on the app service; success read from `/goal`. It references the agent by name; it does not define it. |
| `run.py` | Standalone fallback orchestrator (both sides local LLMs, in-process app). |
| `run_demo.sh` | Brings up the app service + Andyur control plane + a worker and runs `run_andyur`. Tears down on exit. |
| `test_app.py` | Pure-Python tests (no LLM): the state machine, the authority boundary, and that each scenario needs coordination. Fast, CI-friendly. |

## Run it

The real thing (SUT = a live Andyur agent), one command:

```bash
./demos/adsupport/run_demo.sh payment_limit     # or: disapproved_ad | combined_hard | billing_dispute | all
```

The standalone fallback (no Andyur stack, both sides local LLMs):

```bash
PYTHONPATH=$PWD .venv/bin/python -m demos.adsupport.run --scenario all
```

Unit tests (no API cost):

```bash
PYTHONPATH=$PWD .venv/bin/python -m pytest demos/adsupport/test_app.py -q
```

## What a good episode looks like

The customer opens with their problem in-character; the agent diagnoses with read
tools, does its admin part, and tells the customer to do THEIR part; the customer
simulator **actually calls** its own tools (update payment, edit the ad) and
reports back; the agent finishes (lift the limit, expedite the review). `RESOLVED`
only if the app's final state meets the goal, and `coordination = both acted` only
if both parties made a successful mutating call.

## Metrics emitted

- **resolved**: did the shared app reach the goal state (the τ²-style success signal).
- **rounds**: turns to resolution (friction).
- **coordination**: did both parties act (the dual-control signal); reported only
  for scenarios that require it.
- **stalled**: the conversation stopped making progress (guards against a
  degenerate chit-chat loop).

## Extending it (this is the point)

- **A new scenario** = a `build()` (seed the app), a persona, a goal_text, and a
  `goal` predicate. No harness changes.
- **A new domain** = a new `app.py` with its own two tool surfaces. The harness
  (`agent.py` + `run.py`) is domain-agnostic and unchanged.
- **The support agent is already a real Andyur conversational agent** in
  `run_andyur.py` (its tools are `mcp_support.py`). To evaluate a DIFFERENT agent,
  point the harness at a different Andyur agent name, or reuse the customer sim +
  app service against any agent that speaks the same conversation API.

## Honest framing

This is a τ²-**inspired** harness we built, not the official τ²-bench. It
demonstrates the dual-control idea and is a reusable test bed for our own agents.
Running the *real* τ²-bench against an agent is a separate, more rigorous step.

"""The support agent's DEFINITION, and how to provision it into Andyur.

This is who the System Under Test IS -- kept separate from the eval harness that
tests it (run_andyur.py). An Andyur agent is just its mind + its tools:

  - agent/instructions.md : the standing policy (its identity; authored, static)
  - mcp.json              : the tool wiring to the adsupport MCP server (a
                            DEPLOYMENT binding -- paths/urls -- so it is generated
                            here from the environment rather than hard-coded)

`provision_agent(client)` creates the agent and writes both, so any harness (or a
human) can stand up the SUT the same way and then just drive it by name.
"""

import json
import os

AGENT_NAME = "adsupport-bot"

_HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))           # repo root
VENV_PY = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
APP_URL = os.environ.get("ADSUPPORT_APP_URL", "http://127.0.0.1:8650")


def instructions() -> str:
    """The agent's standing policy, authored as a file (not code)."""
    with open(os.path.join(_HERE, "agent", "instructions.md")) as f:
        return f.read()


def support_system_prompt(ctx: dict) -> str:
    """The standalone support agent's system prompt: the SAME policy the Andyur SUT
    is provisioned with (instructions.md), plus the ids it has for this episode. So
    the policy is authored ONCE and both runners test the same behavior."""
    from .scenarios import ids_line
    return (instructions()
            + f"\n\nContext you already have: the advertiser is on {ids_line(ctx)}.")


def mcp_json() -> str:
    """The tool wiring. The command/paths/url are deployment bindings, so this is
    generated from the environment; the tool SURFACE (the adsupport server) is the
    identity part and is fixed."""
    return json.dumps({"mcpServers": {"adsupport": {
        "command": VENV_PY,
        "args": ["-m", "demos.adsupport.mcp_support"],
        "env": {"PYTHONPATH": PROJECT_ROOT, "ADSUPPORT_APP_URL": APP_URL},
    }}})


def provision_agent(client) -> str:
    """Create the SUT in Andyur (idempotent) and (re)write its policy + tools.
    Returns the agent name. `client` is an httpx.Client bound to the Andyur server."""
    client.post("/agents", json={"name": AGENT_NAME,
                                 "description": "ad-platform support agent",
                                 "personality": "concise, warm, concrete"})
    client.put(f"/agents/{AGENT_NAME}/files/instructions.md",
               json={"content": instructions(), "actor": "operator"})
    client.put(f"/agents/{AGENT_NAME}/files/mcp.json",
               json={"content": mcp_json(), "actor": "operator"})
    return AGENT_NAME

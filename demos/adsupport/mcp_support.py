"""The support agent's tools, as an MCP server.

This is what makes the Andyur conversational agent a real support agent: Andyur
loads this via the agent's mcp.json, so the agent (the SUT) calls these tools
during a conversation, and each one acts on the shared app SERVICE. The tools are
exactly the AGENT surface of the dual control -- there is no advertiser tool here,
so the agent structurally cannot do the advertiser's part.

Run (Andyur spawns this): python -m demos.adsupport.mcp_support
Needs ADSUPPORT_APP_URL in the environment.
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

APP_URL = os.environ.get("ADSUPPORT_APP_URL", "http://127.0.0.1:8650")
mcp = FastMCP("adsupport")


def _call(tool: str, args: dict) -> dict:
    try:
        r = httpx.post(f"{APP_URL}/call",
                       json={"actor": "agent", "tool": tool, "args": args},
                       timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"ok": False, "error": f"tool backend unreachable: {e}"}


# -- read tools ------------------------------------------------------------
@mcp.tool()
def get_account(account_id: str) -> dict:
    """Look up an advertiser account's full status."""
    return _call("get_account", {"account_id": account_id})


@mcp.tool()
def list_campaigns(account_id: str) -> dict:
    """List an account's campaigns."""
    return _call("list_campaigns", {"account_id": account_id})


@mcp.tool()
def get_ad_review(ad_id: str) -> dict:
    """Get an ad's review status and any policy violation."""
    return _call("get_ad_review", {"ad_id": ad_id})


@mcp.tool()
def list_charges(account_id: str) -> dict:
    """List an account's charges."""
    return _call("list_charges", {"account_id": account_id})


# -- agent-only actions ----------------------------------------------------
@mcp.tool()
def issue_credit(account_id: str, amount_cents: int, reason: str) -> dict:
    """Credit an account (support authority)."""
    return _call("issue_credit", {"account_id": account_id,
                                  "amount_cents": amount_cents, "reason": reason})


@mcp.tool()
def waive_charge(charge_id: str, reason: str) -> dict:
    """Waive a specific charge (support authority)."""
    return _call("waive_charge", {"charge_id": charge_id, "reason": reason})


@mcp.tool()
def lift_account_limit(account_id: str) -> dict:
    """Lift an account limit. Only succeeds once the underlying cause (e.g. the
    advertiser's payment method) is resolved."""
    return _call("lift_account_limit", {"account_id": account_id})


@mcp.tool()
def expedite_ad_review(ad_id: str) -> dict:
    """Push an in-review ad to an immediate decision (support authority)."""
    return _call("expedite_ad_review", {"ad_id": ad_id})


@mcp.tool()
def clear_policy_review(account_id: str) -> dict:
    """Clear an account's policy-review hold (support authority)."""
    return _call("clear_policy_review", {"account_id": account_id})


if __name__ == "__main__":
    mcp.run()

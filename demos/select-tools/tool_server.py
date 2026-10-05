#!/usr/bin/env python3
"""Ten tools (all canned) for testing tool SELECTION.

The point: give an agent all ten with GENERIC instructions (see
instructions.md, which does NOT name any tool) and check that it picks the right
one for a request based only on the tools' names, descriptions, and input
schemas, which is all the MCP protocol gives the model.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def ci_status(service: str) -> str:
    """Get the latest CI build and test status for a service."""
    return {"checkout-service": "FAILING (build #412)"}.get(service, f"{service}: passing")


@mcp.tool()
def list_deploys(service: str) -> str:
    """List the recent deployments of a service, newest first."""
    return f"{service}: deploy-31 (2h ago), deploy-30 (1d ago), deploy-29 (3d ago)"


@mcp.tool()
def rollback_deploy(deploy_id: str) -> str:
    """Roll back a specific deployment by its id."""
    return f"rollback of {deploy_id} started; ETA 4 minutes"


@mcp.tool()
def restart_service(service: str) -> str:
    """Restart a running service."""
    return f"{service} restart requested"


@mcp.tool()
def query_metric(service: str, metric: str) -> str:
    """Query a live metric for a service (metric: cpu, memory, latency_p99, error_rate)."""
    return f"{service}.{metric} = 0.42 (last 5m avg)"


@mcp.tool()
def search_logs(service: str, query: str) -> str:
    """Search a service's recent logs for a string."""
    return f"3 matches for '{query}' in {service} logs (most recent 12s ago)"


@mcp.tool()
def get_oncall(team: str) -> str:
    """Get the current on-call engineer for a team."""
    return {"payments": "Dana Lee (pager: +1-555-0142)"}.get(team, f"{team}: nobody on call")


@mcp.tool()
def page_oncall(team: str, message: str) -> str:
    """Page the on-call engineer for a team with a message."""
    return f"paged {team} on-call: {message!r}"


@mcp.tool()
def open_ticket(title: str, body: str) -> str:
    """Open a tracking ticket for follow-up work."""
    return f"opened ticket OPS-778: {title!r}"


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return f"{city}: 18C, cloudy"


if __name__ == "__main__":
    mcp.run()

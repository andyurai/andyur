#!/usr/bin/env python3
"""The ci_status tool for this demo agent (a stub returning canned data).

Real tool servers would call a real CI/metrics/paging API here instead.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ci")


@mcp.tool()
def ci_status(service: str) -> str:
    """Get the latest CI build status for a service."""
    return {
        "checkout-service": "FAILING (build #412: redis connection pool config error)",
        "payments-api": "passing (build #987)",
        "search-service": "passing (build #1023)",
    }.get(service, f"no CI data for service '{service}'")


if __name__ == "__main__":
    mcp.run()

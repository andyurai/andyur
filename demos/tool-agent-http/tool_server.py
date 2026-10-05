#!/usr/bin/env python3
"""HTTP (Streamable HTTP) MCP tool server for the demo.

Unlike the stdio server in demos/tool-agent/, this runs as a standalone HTTP
service that the agent connects to by URL. So its mcp.json is just a URL with
no absolute paths, which means the mcp.json can be a tracked file.

Run it (it must be running while the agent runs):
    python3 demos/tool-agent-http/tool_server.py     # serves on 127.0.0.1:8790/mcp
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ci-http", host="127.0.0.1",
              port=int(os.environ.get("CI_HTTP_PORT", "8790")))


@mcp.tool()
def ci_status(service: str) -> str:
    """Get the latest CI build status for a service."""
    return {
        "checkout-service": "FAILING (build #412: redis connection pool config error)",
        "payments-api": "passing (build #987)",
        "search-service": "passing (build #1023)",
    }.get(service, f"no CI data for service '{service}'")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

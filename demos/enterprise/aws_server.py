#!/usr/bin/env python3
"""AWS Auto Scaling + CloudWatch, as an Andyur MANAGED tool.

API-SHAPED ON PURPOSE. The three tools mirror boto3 -- DescribeAutoScalingGroups,
DescribeAlarms, SetDesiredCapacity -- so replacing the dicts with
`boto3.client("autoscaling").set_desired_capacity(...)` under an assumed role is
a change to THIS FILE ONLY.

NOTE WHICH ONE IS THE WRITE. `set_desired_capacity` changes production capacity
and costs money. It is the tool that would move to the CONSEQUENTIAL ACTION path
(andyur/actions.py) before anyone pointed it at a real account -- a closed
decision vocabulary with deny/allow/approve and an operator in the loop, not a
scope an agent simply holds. It is here as a scoped tool to show the shape; that
is not the same as saying it is ready for a real account.

WHAT IS REAL RIGHT NOW: the authorization. Every call is refused unless the
caller presents an Andyur-minted token that is audience-bound to THIS server,
carries the scope the tool requires, and is pinned to the incident it names.
The data is simulated; the governance is not.
"""
from __future__ import annotations

import logging, os, sys

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [aws] %(message)s")
log = logging.getLogger("aws")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("AWS_PORT", "8803"))
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"

# The simulated project. PLAT-1183 is the standing bug the deploy regressed,
# so a search finds prior art rather than an empty backlog.
_ASGS = {
    "checkout-service-asg": {"name": "checkout-service-asg", "desired": 6,
                             "min": 4, "max": 20, "healthy": 6},
}
_ALARMS = [
    {"name": "checkout-5xx-rate", "state": "ALARM",
     "reason": "5xx rate 68% > threshold 2% for 3 datapoints"},
    {"name": "checkout-redis-pool-saturation", "state": "ALARM",
     "reason": "connection pool in use 200/200 for 5 datapoints"},
    {"name": "checkout-cpu", "state": "OK", "reason": "within threshold"},
]

verifier = AndyurTokenVerifier(
    jwks_url=f"{ANDYUR}/.well-known/jwks.json",
    issuer=os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur"),
    audience=RESOURCE)

mcp = FastMCP("aws", host="127.0.0.1", port=PORT, token_verifier=verifier,
              auth=AuthSettings(issuer_url=AnyHttpUrl(ANDYUR),
                                resource_server_url=AnyHttpUrl(RESOURCE),
                                required_scopes=[]))


def _guard(scope: str, resource: str, tool: str):
    """Authority first, and PINNED to the resource named in the call."""
    try:
        require(get_access_token(), scope, {"resource": resource})
    except Refused as why:
        log.warning("REFUSED %s(%s): %s", tool, resource, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s(%s)", tool, resource)


@mcp.tool()
def describe_auto_scaling_group(name: str) -> str:
    """Read one ASG's capacity. Requires `cloud:read`."""
    _guard("cloud:read", name, "describe_auto_scaling_group")
    g = _ASGS.get(name)
    if not g:
        return f"no auto scaling group {name}"
    return (f"{g['name']}: desired={g['desired']} min={g['min']} max={g['max']} "
            f"healthy={g['healthy']}")


@mcp.tool()
def describe_alarms(prefix: str) -> str:
    """CloudWatch alarms whose name starts with a prefix. Requires `cloud:read`."""
    _guard("cloud:read", prefix, "describe_alarms")
    hits = [a for a in _ALARMS if a["name"].startswith(prefix)]
    if not hits:
        return f"no alarms matching {prefix!r}"
    return "\n".join(f"{a['name']}: {a['state']} -- {a['reason']}" for a in hits)


@mcp.tool()
def set_desired_capacity(name: str, desired: int) -> str:
    """Change an ASG's desired capacity. Requires `cloud:write`.

    THE WRITE. In a real account this belongs on the consequential-action path,
    not on a scope an agent holds -- see this module's docstring.
    """
    _guard("cloud:write", name, "set_desired_capacity")
    g = _ASGS.get(name)
    if not g:
        return f"no auto scaling group {name}"
    was, g["desired"] = g["desired"], int(desired)
    return f"{name}: desired {was} -> {g['desired']}"


if __name__ == "__main__":
    log.info("aws tool on %s (audience enforced)", RESOURCE)
    mcp.run(transport="streamable-http")

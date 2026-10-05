#!/usr/bin/env python3
"""The capacity manager. The CAPACITY agent may read and scale; nobody else may.

The third resource of the message-relay demo, and the one that exists to be
UNREACHABLE from the on-call agent. The on-call agent's ceiling has no capacity
actions, so when triage concludes "the pool is too small" its only lawful move
is to message the capacity agent, whose own ceiling allows nothing but capacity
work. Least privilege is what makes the delegation happen at all: a demo where
one agent could do everything would never produce a second identity to attest.

Two bounds are enforced HERE rather than in any agent's prompt:

- the pin: a token pinned to one service cannot read or scale another, and the
  service each allocation belongs to is this server's own record, never the
  caller's claim
- the hard ceiling: an entitled, correctly-pinned caller still cannot raise a
  limit past the allocation's stated maximum, because a remediation bounded
  only by the model asking for it is not bounded

    ANDYUR_SERVER_URL=http://127.0.0.1:8642 \\
    ANDYUR_CAPACITY_PORT=8799 python3 demos/sre-triage/capacity.py
"""

import logging
import os
import sys

# These demos are launched by absolute path from the verifier. Put the project
# root on sys.path before importing Andyur's framework telemetry.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from andyur import otel

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [capacity] %(message)s")
log = logging.getLogger("capacity")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("ANDYUR_CAPACITY_PORT", "8799"))
LISTEN_HOST = os.environ.get("ANDYUR_TOOL_HOST", "127.0.0.1")
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"
AUDIENCE = os.environ.get("ANDYUR_CAPACITY_AUDIENCE", "resource:capacity")
# WHOSE TOKENS THIS SERVER ACCEPTS. Same discovery rule as tickets.py: with an
# external AS configured the issuer's own discovery document names the JWKS URL;
# guessing a path is gap G3.
_AS_ISSUER = os.environ.get("ANDYUR_AS_ISSUER", "")
if _AS_ISSUER:
    import json as _json
    import urllib.request as _url
    with _url.urlopen(_AS_ISSUER.rstrip("/") + "/.well-known/openid-configuration",
                      timeout=5) as _r:
        _doc = _json.loads(_r.read())
    ISSUER, JWKS_URL = _doc["issuer"], _doc["jwks_uri"]
    log.info("validating against the EXTERNAL authorization server: %s", JWKS_URL)
else:
    ISSUER = os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur")
    JWKS_URL = f"{ANDYUR}/.well-known/jwks.json"

# One allocation for the incident's service, and one belonging to another team,
# so the pin has something to refuse rather than only something to permit. The
# hard ceiling is the allocation's own bound: this server refuses to exceed it
# no matter whose token asks.
ALLOCATIONS = {
    "checkout-service": {"redis_pool_max": 8, "hard_ceiling": 64},
    "payments-api": {"redis_pool_max": 32, "hard_ceiling": 64},
}

mcp = FastMCP(
    "capacity", host=LISTEN_HOST, port=PORT,
    token_verifier=AndyurTokenVerifier(
        jwks_url=JWKS_URL,
        issuer=ISSUER, audience=AUDIENCE),
    auth=AuthSettings(issuer_url=AnyHttpUrl(ANDYUR),
                      resource_server_url=AnyHttpUrl(RESOURCE),
                      required_scopes=[]),
    transport_security=TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*", "host.docker.internal",
                       "host.docker.internal:*"],
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*",
                         "http://host.docker.internal:*"],
    ),
)


def _gate(service: str, action: str):
    """The allocation's OWN service is what the pin is checked against.

    Same direction as tickets.py: the server looks up which service the
    allocation belongs to and checks the token against that, so an agent pinned
    to checkout-service cannot scale payments-api by naming it in an argument.
    """
    alloc = ALLOCATIONS.get(service)
    if alloc is None:
        raise ToolError(f"no allocation for service {service!r}")
    try:
        require(get_access_token(), action, {"service": service})
    except Refused as why:
        log.warning("REFUSED %s on %s: %s", action, service, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s on %s", action, service)
    return alloc


@mcp.tool()
def get_allocation(service: str) -> str:
    """Read one service's current allocation and its hard ceiling."""
    alloc = _gate(service, "capacity:read")
    return (f"{service}: redis_pool_max={alloc['redis_pool_max']} "
            f"(hard ceiling {alloc['hard_ceiling']})")


@mcp.tool()
def scale_pool(service: str, redis_pool_max: int) -> str:
    """Set a service's Redis connection pool limit. This is what the capacity
    agent is FOR, and the hard ceiling is why an entitled caller is still
    bounded: authority to scale is not authority to scale without limit."""
    alloc = _gate(service, "capacity:scale")
    if redis_pool_max <= 0:
        raise ToolError(f"refused: redis_pool_max must be positive, "
                        f"got {redis_pool_max}")
    if redis_pool_max > alloc["hard_ceiling"]:
        log.warning("REFUSED scale on %s: %d exceeds hard ceiling %d",
                    service, redis_pool_max, alloc["hard_ceiling"])
        raise ToolError(f"refused: {redis_pool_max} exceeds the hard ceiling "
                        f"of {alloc['hard_ceiling']} for {service}")
    old = alloc["redis_pool_max"]
    alloc["redis_pool_max"] = redis_pool_max
    log.info("SCALED %s redis_pool_max %d -> %d", service, old, redis_pool_max)
    return f"{service} redis_pool_max scaled from {old} to {redis_pool_max}"


if __name__ == "__main__":
    log.info("endpoint=%r audience=%r (published AND enforced), issuer=%r",
             RESOURCE, AUDIENCE, ISSUER)
    import uvicorn
    try:
        uvicorn.run(
            otel.TracedASGI(
                mcp.streamable_http_app(), service_name="sre-capacity"),
            host=LISTEN_HOST, port=PORT, log_level="info")
    finally:
        otel.flush()

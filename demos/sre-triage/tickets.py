#!/usr/bin/env python3
"""The ticket tracker. The agent may COMMENT; it may not CLOSE.

The other half of the SRE triage demo, and the half that shows why an action
ceiling is a different control from an audience. The on-call agent holds a token
for this resource -- it is allowed to be here at all -- and is still refused when
it reaches for `tickets:close`, because being admitted to a service is not the
same as being permitted every operation in it.

That distinction is the one an operator most needs to see. "The agent can file
what it found, and cannot declare the incident over" is a sentence a human can
sign off on, and it is enforced by the token rather than by the agent's prompt.

    ANDYUR_SERVER_URL=http://127.0.0.1:8642 \\
    ANDYUR_TICKETS_PORT=8798 python3 demos/sre-triage/tickets.py
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
                    format="%(asctime)s %(levelname)s [tickets] %(message)s")
log = logging.getLogger("tickets")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("ANDYUR_TICKETS_PORT", "8798"))
LISTEN_HOST = os.environ.get("ANDYUR_TOOL_HOST", "127.0.0.1")
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"
AUDIENCE = os.environ.get("ANDYUR_TICKETS_AUDIENCE", "resource:tickets")
# When an EXTERNAL AS governs this resource, its tokens carry the AS's own scope
# vocabulary (tickets:read/write/delete), not Andyur's logical
# tickets:read/comment/close. The deployment supplies this logical->AS map so
# enforcement speaks the AS's vocabulary; empty (dev default) is identity.
import json as _sjson  # noqa: E402
_SCOPE_MAP = _sjson.loads(os.environ.get("ANDYUR_TOOL_SCOPE_MAP", "{}"))
def _enforced(action: str) -> str:  # noqa: E302
    return _SCOPE_MAP.get(action, action)
# WHOSE TOKENS THIS SERVER ACCEPTS.
#
# With an external authorization server configured, the tokens are signed by THEM
# and this server validates against THEIR JWKS and THEIR issuer. Andyur does not
# sign access tokens (docs/decisions.md #1), so validating against Andyur's JWKS
# in that deployment would validate nothing that ever arrives.
#
# DISCOVERED, never constructed: `<issuer>/.well-known/jwks.json` 404s on
# Keycloak, whose document advertises a different path, and guessing is gap G3.
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

# One open incident, and one belonging to another team, so the pin has something
# to refuse rather than only something to permit.
TICKETS = {
    "INC-4471": {"service": "checkout-service", "state": "open",
                 "title": "checkout 5xx spike since 14:02Z", "comments": []},
    "INC-4472": {"service": "payments-api", "state": "open",
                 "title": "latency alert, investigating", "comments": []},
}

mcp = FastMCP(
    "tickets", host=LISTEN_HOST, port=PORT,
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


def _gate(issue: str, action: str):
    """The ticket's OWN service is what the pin is checked against.

    Note the direction: the caller does not get to say which service this ticket
    belongs to. The server looks it up and checks the token against that, so an
    agent pinned to checkout-service cannot comment on payments-api's incident by
    asserting otherwise in its arguments.
    """
    ticket = TICKETS.get(issue)
    if ticket is None:
        raise ToolError(f"no ticket {issue!r}")
    try:
        require(get_access_token(), _enforced(action), {"service": ticket["service"]})
    except Refused as why:
        log.warning("REFUSED %s on %s: %s", action, issue, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s on %s", action, issue)
    return ticket


@mcp.tool()
def get_ticket(issue: str) -> str:
    """Read one incident."""
    ticket = _gate(issue, "tickets:read")
    return (f"{issue} [{ticket['state']}] {ticket['title']} "
            f"(service: {ticket['service']}, {len(ticket['comments'])} comments)")


@mcp.tool()
def comment(issue: str, text: str) -> str:
    """Add a triage note. This is what the on-call agent is FOR."""
    ticket = _gate(issue, "tickets:comment")
    ticket["comments"].append(text)
    log.info("COMMENT on %s: %s", issue, text[:120])
    return f"commented on {issue}"


@mcp.tool()
def close(issue: str) -> str:
    """Declare the incident over.

    Present so the demo has something the agent is NOT allowed to do at a
    resource it IS allowed to reach. A demo where every call succeeds shows only
    that a token was accepted, not that anything was bounded.
    """
    ticket = _gate(issue, "tickets:close")
    ticket["state"] = "closed"
    return f"closed {issue}"


if __name__ == "__main__":
    log.info("endpoint=%r audience=%r (published AND enforced), issuer=%r",
             RESOURCE, AUDIENCE, ISSUER)
    import uvicorn
    try:
        uvicorn.run(
            otel.TracedASGI(
                mcp.streamable_http_app(), service_name="sre-tickets"),
            host=LISTEN_HOST, port=PORT, log_level="info")
    finally:
        otel.flush()

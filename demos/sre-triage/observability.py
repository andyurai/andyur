#!/usr/bin/env python3
"""Telemetry for one service. READ-ONLY, and pinned to the service under incident.

Half of the SRE triage demo. The on-call agent reads error rates here and writes
its findings to the ticket server next door -- two resources, two audiences, two
tokens, which is the shape a real triage tool chain has and the reason the
gateway runs one listener per tool server rather than one for all of them.

The pin is what makes this interesting. A run opened for `checkout-service` gets
a token pinned to `checkout-service`, so the same agent with the same code cannot
read another team's telemetry during that incident. That is not a filter this
server applies out of politeness; it is a bound the token carries, minted by a
party the agent cannot influence.

    ANDYUR_SERVER_URL=http://127.0.0.1:8642 \\
    ANDYUR_OBS_PORT=8797 python3 demos/sre-triage/observability.py
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

# The SAME PEP the bank demo uses, imported rather than copied, because a policy
# enforcement point that only works for one server is not the thing this is
# trying to show. A real adopter copies pep.py into their own service; here two
# services share it to prove it is not shaped around either.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [observability] %(message)s")
log = logging.getLogger("observability")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("ANDYUR_OBS_PORT", "8797"))
LISTEN_HOST = os.environ.get("ANDYUR_TOOL_HOST", "127.0.0.1")
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"
AUDIENCE = os.environ.get("ANDYUR_OBS_AUDIENCE", "resource:telemetry")
# When an EXTERNAL AS governs this resource, the token it issues carries the AS's
# own scope vocabulary (e.g. telemetry:read), not Andyur's logical obs:read. The
# deployment supplies this logical->AS map so enforcement speaks the AS's
# vocabulary; empty (the dev default) leaves the logical action unchanged.
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

# Canned telemetry. The incident is real enough to triage: checkout-service
# started failing after a deploy, and the errors name the cause.
TELEMETRY = {
    "checkout-service": {
        "error_rate": "14.2% (baseline 0.3%) since 14:02Z",
        "errors": ["redis: connection pool exhausted (max=8)",
                   "redis: connection pool exhausted (max=8)",
                   "upstream timeout calling payments-api after 30s"],
        "deploy": "v2.31.0 at 13:58Z by @dana, changed REDIS_POOL_MAX 64 -> 8",
    },
    "payments-api": {
        "error_rate": "0.2% (baseline 0.2%)",
        "errors": [],
        "deploy": "v9.4.1 at 09:12Z",
    },
}

mcp = FastMCP(
    "observability", host=LISTEN_HOST, port=PORT,
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


def _read(service: str, what: str):
    """Every read goes through the same gate: the token must permit `obs:read`
    AND be pinned to the service being asked about."""
    try:
        claims = require(get_access_token(), _enforced("obs:read"), {"service": service})
    except Refused as why:
        log.warning("REFUSED %s(%s): %s", what, service, why)
        raise ToolError(f"refused: {why}") from why
    # Log the VALIDATED issuer of the token we just ACCEPTED (not the configured
    # one echoed at startup): this line only appears after AndyurTokenVerifier
    # enforced iss+JWKS, so a harness that greps it is proving real acceptance.
    log.info("ALLOWED %s(%s) validated_iss=%r", what, service, claims.get("iss"))
    return TELEMETRY.get(service)


@mcp.tool()
def error_rate(service: str) -> str:
    """The current error rate for a service, against its baseline."""
    data = _read(service, "error_rate")
    return data["error_rate"] if data else f"no telemetry for {service!r}"


@mcp.tool()
def recent_errors(service: str) -> str:
    """The most recent distinct error messages for a service."""
    data = _read(service, "recent_errors")
    if not data:
        return f"no telemetry for {service!r}"
    return "\n".join(data["errors"]) or "no errors in the window"


@mcp.tool()
def last_deploy(service: str) -> str:
    """What shipped most recently, and what it changed."""
    data = _read(service, "last_deploy")
    return data["deploy"] if data else f"no deploy history for {service!r}"


if __name__ == "__main__":
    log.info("endpoint=%r audience=%r (published AND enforced), issuer=%r",
             RESOURCE, AUDIENCE, ISSUER)
    import uvicorn
    try:
        uvicorn.run(
            otel.TracedASGI(
                mcp.streamable_http_app(), service_name="sre-observability"),
            host=LISTEN_HOST, port=PORT, log_level="info")
    finally:
        otel.flush()

#!/usr/bin/env python3
"""An MCP tool server that REFUSES a token that was not minted for it.

The other side of the loop. `demos/tool-agent-http/` shows an agent reaching a
tool through the gateway; this one shows the tool checking what arrives, which
until now nothing did.

Run it:

    ANDYUR_TOOL_AUDIENCE=tool:bank \\
    ANDYUR_SERVER_URL=http://127.0.0.1:8642 \\
    python3 demos/authority-tool/tool_server.py

Then watch its log while `./run.sh authority-demo` drives calls at it. A token
minted for `tool:ci` presented here is refused, and the refusal is the point:
every constraint Andyur mints was self-asserted until something on this side
checked it.
"""

import logging
import os
import sys

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [tool-server] %(message)s")
log = logging.getLogger("authority-tool")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("ANDYUR_TOOL_PORT", "8795"))
# ONE identifier, published and enforced.
#
# This used to be an opaque `tool:bank` while the RFC 9728 metadata published the
# URL -- so the server contradicted itself, and only Andyur's own probe worked,
# because it skipped discovery. A spec-following MCP client sends the canonical
# URL as its `resource` and would have been refused. See ADR 002.
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"
AUDIENCE = os.environ.get("ANDYUR_TOOL_AUDIENCE", RESOURCE)
# WHOSE TOKENS THIS SERVER ACCEPTS.
#
# With an external authorization server configured, tokens are signed by THEM and
# this server validates against THEIR JWKS and THEIR issuer. Andyur does not sign
# access tokens (`docs/decisions.md` #1), so pointing at Andyur's JWKS in that
# deployment would validate nothing that will ever arrive.
#
# The endpoints are DISCOVERED, never constructed: `<issuer>/.well-known/jwks.json`
# 404s on Keycloak, whose document advertises a different path entirely, and
# guessing it is gap G3.
AS_ISSUER = os.environ.get("ANDYUR_AS_ISSUER", "")
if AS_ISSUER:
    import json as _json
    import urllib.request as _url
    with _url.urlopen(
            AS_ISSUER.rstrip("/") + "/.well-known/openid-configuration",
            timeout=5) as _r:
        _doc = _json.loads(_r.read())
    ISSUER = _doc["issuer"]
    JWKS_URL = _doc["jwks_uri"]
else:
    # Andyur's own mint, which retires with the AS work.
    ISSUER = os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur")
    JWKS_URL = f"{ANDYUR}/.well-known/jwks.json"

verifier = AndyurTokenVerifier(
    jwks_url=JWKS_URL,
    issuer=ISSUER,
    audience=AUDIENCE,
)

mcp = FastMCP(
    "authority-bank",
    host="127.0.0.1",
    port=PORT,
    token_verifier=verifier,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ANDYUR),
        # The SAME value the verifier enforces. If these two ever disagree the
        # server is telling clients to ask for a token it will not accept.
        resource_server_url=AnyHttpUrl(AUDIENCE),
        # Deliberately empty. The SDK would enforce these across EVERY tool, and
        # the actions Andyur grants differ per tool -- `require()` inside each
        # tool is where that belongs, because only there is the resource known.
        required_scopes=[],
    ),
)


@mcp.tool()
def balance(account: str) -> str:
    """Read an account balance. Requires `files:read` for THIS account."""
    try:
        require(get_access_token(), "files:read", {"account": account})
    except Refused as why:
        log.warning("REFUSED balance(%s): %s", account, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED balance(%s)", account)
    return f"account {account}: 4,182.55 USD"


@mcp.tool()
def transfer(account: str, amount: str) -> str:
    """Move money. Requires `payments:transfer` for THIS account.

    Present so the demo can show a token that is valid, correctly audienced, and
    still refused -- because the action is above what it was granted. That is a
    different refusal from a wrong audience, and an operator needs to tell them
    apart.

    A refusal is RAISED, not returned. Returning "refused: ..." as a successful
    tool result hands the model a string it cannot distinguish from data -- and
    the model is the party that decides what to do next. An error is the only
    shape that says "this did not happen".
    """
    try:
        require(get_access_token(), "payments:transfer", {"account": account})
    except Refused as why:
        log.warning("REFUSED transfer(%s, %s): %s", account, amount, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED transfer(%s, %s)", account, amount)
    return f"moved {amount} from {account}"


@mcp.tool()
def whoami() -> str:
    """What this server believes about the caller, from the token alone."""
    access: AccessToken | None = get_access_token()
    if access is None:
        return "no verified token"
    claims = access.claims or {}
    return (f"sub={claims.get('sub')} act={(claims.get('act') or {}).get('sub')} "
            f"aud={claims.get('aud')} scope={access.scopes}")


if __name__ == "__main__":
    if AUDIENCE != RESOURCE:
        log.warning("audience %r is not this server's canonical resource id %r; "
                    "a client following RFC 9728 will ask for the latter and be "
                    "refused", AUDIENCE, RESOURCE)
    log.info("audience=%r (published AND enforced) issuer=%r jwks=%s andyur=%s",
             AUDIENCE, ISSUER, JWKS_URL, ANDYUR)
    log.info("bearer only: cnf is not minted yet, so possession is sufficient")
    mcp.run(transport="streamable-http")

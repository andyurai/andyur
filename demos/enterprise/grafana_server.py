#!/usr/bin/env python3
"""Grafana, as an Andyur MANAGED tool -- against a REAL, FEDERATED Grafana.

WHAT IS DIFFERENT ABOUT THIS ONE. The other demo tool servers hold a service
credential and act as a robot. This one holds NOTHING. It receives the token the
runner minted for the run, checks it, and PASSES IT ON to Grafana, which
validates the signature itself against a key set containing Andyur's exchange
key. So Grafana resolves the call to the HUMAN in `sub` -- and the agents that
acted for her are in the `act` chain, on the record.

  Sarah logs in ONCE, at Keycloak.
  |
  +- run token: sub=sarah.miller, act={platform-engineer, act:{incident-responder}}
     |
     +- THIS SERVER: is the audience right? is the scope enough? is it pinned?
        |
        +- GRAFANA: is the signature ours? was the subject a REAL login
           (andyur_sub_src=idp)? -> acts as sarah.miller

TWO INDEPENDENT CHECKS, on purpose. This server is a policy enforcement point;
Grafana is the resource server. Neither trusts the other's answer, and neither
trusts the agent. The audience is GRAFANA's URL, not this server's, because the
token really is minted for Grafana -- this process is a gate in front of it, not
a separate destination that then acts on its own behalf.

NO PLATFORM CODE IS INVOLVED. This is a demo tool server, like every other file
in demos/. It uses the same `pep.py` the other managed tools use.
"""
from __future__ import annotations

import logging, os, sys, time

import requests
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [grafana] %(message)s")
log = logging.getLogger("grafana")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
GRAFANA = os.environ.get("ANDYUR_GRAFANA_URL", "http://127.0.0.1:3000").rstrip("/")
PORT = int(os.environ.get("GRAFANA_TOOL_PORT", "8804"))

# ADR 002: an MCP tool's audience IS its canonical resource id, derived from
# its own url. Naming Grafana's url here instead made the runner's audience
# ceiling refuse the tool outright -- it withheld it rather than call it
# unauthenticated, which is the right failure, but it means the agent silently
# had no tools. The token forwarded to Grafana therefore carries THIS audience,
# and Grafana is configured to require exactly it.
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"

verifier = AndyurTokenVerifier(
    jwks_url=f"{ANDYUR}/.well-known/jwks.json",
    issuer=os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur"),
    audience=RESOURCE)

mcp = FastMCP("grafana", host="127.0.0.1", port=PORT, token_verifier=verifier,
              auth=AuthSettings(issuer_url=AnyHttpUrl(ANDYUR),
                                resource_server_url=AnyHttpUrl(RESOURCE),
                                required_scopes=[]))


def _guard(scope: str, resource: str | None, tool: str):
    """Authority first, PINNED to the resource named in the call.

    `resource=None` for a call that touches nothing -- `whoami` asks who the
    token speaks for, not permission to reach a service. Naming a resource that
    the call does not actually touch would demand a pin for no reason.
    """
    tok = get_access_token()
    try:
        if resource is None:
            require(tok, scope, allow_unpinned=True)
        else:
            require(tok, scope, {"service": resource})
    except Refused as why:
        cl = getattr(tok, "claims", None) or {}
        log.warning("REFUSED %s(%s): %s", tool, resource, why)
        log.warning("   token claims: sub=%r scope=%r authorization_details=%r",
                    cl.get("sub"), cl.get("scope"), cl.get("authorization_details"))
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s(%s)", tool, resource)
    return tok


def _raw(tok) -> str:
    """The token exactly as it arrived, to hand on to Grafana.

    Deliberately NOT re-minted here: re-signing would replace Sarah's chain with
    this process's word for it, and a resource server cannot tell those apart.
    """
    for attr in ("token", "raw", "access_token", "jwt"):
        v = getattr(tok, attr, None)
        if isinstance(v, str) and v.count(".") == 2:
            return v
    raise ToolError("the presented token could not be read back for forwarding")


def _gf(method: str, path: str, tok, **kw):
    r = requests.request(method, f"{GRAFANA}{path}",
                         headers={"X-Andyur-Auth": _raw(tok),
                                  "Accept": "application/json",
                                  "Content-Type": "application/json"},
                         timeout=20, **kw)
    if r.status_code == 401:
        import base64 as _b64, json as _json
        try:
            _c = _raw(tok).split(".")[1]
            _cl = _json.loads(_b64.urlsafe_b64decode(_c + "=" * (-len(_c) % 4)))
            log.error("grafana 401. forwarded claims: iss=%r sub=%r aud=%r "
                      "andyur_sub_src=%r exp=%r act=%r",
                      _cl.get("iss"), _cl.get("sub"), _cl.get("aud"),
                      _cl.get("andyur_sub_src"), _cl.get("exp"), _cl.get("act"))
        except Exception as _e:
            log.error("grafana 401 and the token could not be decoded: %s", _e)
        log.error("grafana body: %s", r.text[:200])
        # Grafana's OWN refusal, not ours. The most likely cause is a subject
        # that was asserted rather than authenticated.
        raise ToolError("grafana refused the token (401): it validates the "
                        "signature and requires andyur_sub_src=idp -- a subject "
                        "nobody actually logged in as is rejected here")
    return r


@mcp.tool()
def whoami() -> str:
    """Report who GRAFANA thinks is making this call. Requires `telemetry:read`."""
    tok = _guard("telemetry:read", None, "whoami")
    r = _gf("GET", "/api/user", tok)
    if r.status_code >= 400:
        raise ToolError(f"grafana /api/user failed ({r.status_code}): {r.text[:200]}")
    u = r.json()
    return (f"grafana resolved this call to: login={u.get('login')} "
            f"email={u.get('email')} external={u.get('isExternal')} "
            f"via={u.get('authLabels')}")


@mcp.tool()
def list_dashboards(service: str) -> str:
    """Find dashboards for a service. Requires `telemetry:read`."""
    tok = _guard("telemetry:read", service, "list_dashboards")
    r = _gf("GET", "/api/search", tok, params={"query": service, "limit": 10})
    if r.status_code >= 400:
        raise ToolError(f"grafana search failed ({r.status_code}): {r.text[:200]}")
    hits = r.json()
    if not hits:
        return f"no dashboards match {service!r}"
    return "\n".join(f"{h.get('title')}  (uid={h.get('uid')}, type={h.get('type')})"
                     for h in hits)


@mcp.tool()
def read_incident_annotations(service: str) -> str:
    """Read recent incident annotations for a service. Requires `telemetry:read`."""
    tok = _guard("telemetry:read", service, "read_incident_annotations")
    r = _gf("GET", "/api/annotations", tok,
            params={"tags": service, "limit": 10, "type": "annotation"})
    if r.status_code >= 400:
        raise ToolError(f"grafana annotations failed ({r.status_code}): {r.text[:200]}")
    rows = r.json()
    if not rows:
        return f"no annotations tagged {service!r}"
    return "\n".join(
        f"[{time.strftime('%Y-%m-%d %H:%M', time.gmtime(a['time']/1000))}] "
        f"{a.get('text')}  (by {a.get('login') or a.get('email') or '?'})"
        for a in rows)


@mcp.tool()
def annotate_incident(service: str, text: str) -> str:
    """Record a finding against a service's timeline. Requires `incidents:write`.

    THIS IS A WRITE, and it is the point of the demo: the row Grafana stores
    names the human the agent acted for, not the agent and not a service account.
    """
    tok = _guard("incidents:write", service, "annotate_incident")
    r = _gf("POST", "/api/annotations", tok,
            json={"text": text, "tags": [service, "andyur"],
                  "time": int(time.time() * 1000)})
    if r.status_code >= 400:
        raise ToolError(f"grafana annotate failed ({r.status_code}): {r.text[:250]}")
    aid = r.json().get("id")
    who = _gf("GET", "/api/user", tok)
    login = who.json().get("login") if who.status_code == 200 else "?"
    return f"annotation {aid} recorded on {service}, attributed by grafana to {login!r}"


if __name__ == "__main__":
    log.info("grafana tool on %s -- forwarding to %s", RESOURCE, GRAFANA)
    log.info("this server holds NO grafana credential; it passes the run's token on")
    mcp.run(transport="streamable-http")

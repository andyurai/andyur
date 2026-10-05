#!/usr/bin/env python3
"""ServiceNow incident management, as an Andyur MANAGED tool.

API-SHAPED ON PURPOSE. The three tools mirror the ServiceNow Table API for
`incident` -- get by number, add a work note, set state -- so replacing the
`_INCIDENTS` dict with `requests.get(f"{instance}/api/now/table/incident", ...)`
and a real credential is a change to THIS FILE ONLY. Nothing about the agent,
the manifest, the delegation or the audit trail changes when the data becomes
real, which is the point of putting the boundary here.

WHAT IS REAL RIGHT NOW: the authorization. Every call is refused unless the
caller presents an Andyur-minted token that is audience-bound to THIS server,
carries the scope the tool requires, and is pinned to the incident it names.
The data is simulated; the governance is not.
"""
from __future__ import annotations

import logging, os, pathlib, sys

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [servicenow] %(message)s")
log = logging.getLogger("servicenow")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("SN_PORT", "8801"))
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"

# ---------------------------------------------------------------- the backend
#
# ONE SWITCH, AND IT SAYS WHICH SIDE IT IS ON. With SN_INSTANCE/SN_USER/
# SN_PASSWORD set AND a credential that authenticates, every tool below calls
# the real ServiceNow Table API. Without them it serves the simulated record.
#
# The mode is logged at startup and named in every tool's return value, because
# a demo that cannot tell you whether it touched a real system is worse than one
# that is obviously simulated.
# READ THE CREDENTIAL FILE OURSELVES, never through the shell.
#
# `set -a; . servicenow.env` looks harmless until a password contains `&`, `(`,
# `}` or `^` -- which a good one will -- and bash reports `parse error near &`
# while the server starts with NO credential and quietly serves simulated data.
# A secrets file that cannot hold shell metacharacters is a trap, so the file is
# parsed here: split on the FIRST `=` only, and take the rest of the line
# verbatim. The environment still wins, for a deployment that injects it.
def _load_secrets(path: str = "") -> None:
    candidate = pathlib.Path(path or os.environ.get(
        "SN_SECRETS_FILE",
        pathlib.Path(__file__).resolve().parents[2] / "data/secrets/servicenow.env"))
    if not candidate.is_file():
        return
    for line in candidate.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value)


_load_secrets()

SN_INSTANCE = os.environ.get("SN_INSTANCE", "").rstrip("/")
SN_USER = os.environ.get("SN_USER", "")
SN_PASSWORD = os.environ.get("SN_PASSWORD", "")
# OAuth, which is what a current instance actually wants. ServiceNow is
# actively eliminating Basic Auth on inbound surfaces, and an instance can
# refuse it while the very same credentials log in fine on the web -- which is
# exactly what dev408600 does: the password authenticates (the login sets
# `glide_returning_auth_user` and redirects to login_redirect.do) and every
# Basic-Auth REST call still returns 401.
#
# Register one client ONCE in the instance: System OAuth > Application Registry
# > New > "Create an OAuth API endpoint for external clients". Put its id and
# secret here and this server uses the password grant against /oauth_token.do.
SN_CLIENT_ID = os.environ.get("SN_CLIENT_ID", "")
SN_CLIENT_SECRET = os.environ.get("SN_CLIENT_SECRET", "")
LIVE = bool(SN_INSTANCE and SN_USER and SN_PASSWORD)
AUTH_MODE = "basic"   # settled by the startup preflight below
_TOKEN: dict = {"value": "", "expires": 0.0}
_IN_PREFLIGHT = [False]


def _oauth_token() -> str:
    """A cached OAuth access token, refreshed a minute before it expires."""
    import time as _t
    import requests
    if _TOKEN["value"] and _t.time() < _TOKEN["expires"]:
        return _TOKEN["value"]
    r = requests.post(f"{SN_INSTANCE}/oauth_token.do", timeout=30, data={
        "grant_type": "password", "client_id": SN_CLIENT_ID,
        "client_secret": SN_CLIENT_SECRET, "username": SN_USER,
        "password": SN_PASSWORD})
    r.raise_for_status()
    doc = r.json()
    _TOKEN["value"] = doc["access_token"]
    _TOKEN["expires"] = _t.time() + int(doc.get("expires_in", 1800)) - 60
    return _TOKEN["value"]


# THE SESSION FALLBACK, and why it exists.
#
# dev408600 refuses Basic Auth on the REST API -- 401 "User is not
# authenticated" -- while the SAME credential logs in perfectly on the web and
# the same account reads the same table happily over a session. That is the
# instance exercising its right to say which inbound auth methods it accepts
# (ServiceNow is actively eliminating Basic Auth on inbound surfaces), not a
# broken credential and not a missing role.
#
# So this client speaks the three methods in the order an operator would want:
# OAuth if a client is registered, then Basic, then a browser-shaped session
# with the CSRF token ServiceNow requires on session-authenticated API calls.
# The session is genuinely a fallback -- it holds a password and a cookie
# rather than a scoped token, so OAuth remains the right answer for anything
# beyond a demo, and the startup line always says which one is in use.
_SESSION: dict = {"s": None, "token": ""}


def _session_call(method: str, path: str, **kw):
    import re
    import requests
    if _SESSION["s"] is None:
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0"
        s.post(f"{SN_INSTANCE}/login.do", timeout=30,
               data={"user_name": SN_USER, "user_password": SN_PASSWORD,
                     "sys_action": "sysverb_login"})
        # g_ck is only rendered by a real UI page, not by the REST surface.
        page = s.get(f"{SN_INSTANCE}/incident.do?sysparm_query=", timeout=30).text
        found = re.search(r"g_ck\s*=\s*['\"]([0-9a-zA-Z+/=_-]{24,})['\"]", page)
        if not found:
            raise RuntimeError("logged in but no CSRF token on the page; "
                               "the session cannot call the API")
        _SESSION["s"], _SESSION["token"] = s, found.group(1)
    s, token = _SESSION["s"], _SESSION["token"]
    r = s.request(method, f"{SN_INSTANCE}{path}", timeout=30,
                  headers={"Accept": "application/json",
                           "Content-Type": "application/json",
                           "X-UserToken": token}, **kw)
    if r.status_code == 401:                       # the session aged out; re-login once
        _SESSION["s"] = None
        return _session_call(method, path, **kw)
    r.raise_for_status()
    return r.json().get("result")


PREFLIGHT_TIMEOUT = float(os.environ.get("SN_PREFLIGHT_TIMEOUT", "8"))


def _api(method: str, path: str, **kw):
    """One authenticated call to the ServiceNow Table API, by whichever method
    this instance actually accepts."""
    import requests
    kw.setdefault("timeout", PREFLIGHT_TIMEOUT if _IN_PREFLIGHT[0] else 30)
    if AUTH_MODE == "session":
        return _session_call(method, path, **kw)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = None
    if AUTH_MODE == "oauth":
        headers["Authorization"] = f"Bearer {_oauth_token()}"
    else:
        auth = (SN_USER, SN_PASSWORD)
    r = requests.request(method, f"{SN_INSTANCE}{path}", auth=auth,
                         headers=headers, **kw)
    r.raise_for_status()
    return r.json().get("result")


def _preflight() -> str:
    """Prove the credential works BEFORE the first agent asks, so a bad one is a
    named startup line rather than a tool failure inside a run."""
    global AUTH_MODE
    _IN_PREFLIGHT[0] = True
    if not LIVE:
        return "SIMULATED (no SN_INSTANCE/SN_USER/SN_PASSWORD)"
    # TRIED IN ORDER, AND THE ONE THAT WORKS IS THE ONE USED. Which methods an
    # instance accepts is the instance's decision; discovering it once at
    # startup beats every tool call failing the same way inside a run.
    # BOUNDED, AND SESSION ONLY WHEN ASKED FOR. The first version tried three
    # methods at import time, one of them a full browser-shaped login, with a
    # 30s timeout each -- so an instance that is merely slow to refuse left the
    # tool server hanging before it ever bound its port, and the whole demo
    # went with it. A backend that will not answer must cost this server a
    # startup line, not its life.
    tried = []
    modes = (("oauth",) if SN_CLIENT_ID and SN_CLIENT_SECRET else ()) + ("basic",)
    if os.environ.get("SN_ALLOW_SESSION_AUTH", "").lower() in ("1", "on", "true"):
        # Opt-in: it holds a password and a cookie rather than a scoped token,
        # so it is a diagnostic convenience, never the default.
        modes += ("session",)
    for mode in modes:
        AUTH_MODE = mode
        try:
            _api("GET", "/api/now/table/incident?sysparm_limit=1")
            _IN_PREFLIGHT[0] = False
            return f"LIVE against {SN_INSTANCE} (auth: {mode})"
        except Exception as exc:                               # noqa: BLE001
            tried.append(f"{mode}: {str(exc)[:80]}")
    _IN_PREFLIGHT[0] = False
    AUTH_MODE = "basic"
    return (f"SIMULATED -- no auth method reached {SN_INSTANCE} [{'; '.join(tried)}]; "
            "refusing to pretend a real instance is behind these tools")


# The simulated instance, used when the live preflight does not pass. One
# incident, matching tonight's cluster incident, so the ServiceNow record and
# the Kubernetes rollback are about the same outage.
_INCIDENTS = {
    "INC0042701": {
        "number": "INC0042701", "state": "In Progress", "priority": "1 - Critical",
        "short_description": "checkout-service returning 5xx after deploy",
        "cmdb_ci": "checkout-service",
        "description": ("Error rate on checkout-service went from 0.1% to 68% at 02:10 UTC. "
                        "A new revision was rolled out at 02:04 UTC. Payment completion "
                        "is failing for all regions."),
        "work_notes": [],
    },
}

verifier = AndyurTokenVerifier(
    jwks_url=f"{ANDYUR}/.well-known/jwks.json",
    issuer=os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur"),
    audience=RESOURCE)

mcp = FastMCP("servicenow", host="127.0.0.1", port=PORT, token_verifier=verifier,
              auth=AuthSettings(issuer_url=AnyHttpUrl(ANDYUR),
                                resource_server_url=AnyHttpUrl(RESOURCE),
                                required_scopes=[]))


def _guard(scope: str, incident: str, tool: str):
    """Authority first, and PINNED to the incident named in the call.

    The pin is what stops a run authorized for one incident from reading or
    writing another -- the same property the Kubernetes rollback gets from
    `subject_context`, enforced here by the resource server rather than
    self-asserted by the caller.
    """
    try:
        require(get_access_token(), scope, {"incident": incident})
    except Refused as why:
        log.warning("REFUSED %s(%s): %s", tool, incident, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s(%s)", tool, incident)


@mcp.tool()
def get_incident(incident: str) -> str:
    """Read one ServiceNow incident by number. Requires `incidents:read`."""
    _guard("incidents:read", incident, "get_incident")
    if MODE.startswith("LIVE"):
        rows = _api("GET", f"/api/now/table/incident?sysparm_query=number={incident}"
                           "&sysparm_display_value=true&sysparm_limit=1")
        if not rows:
            return f"[live] no incident {incident}"
        r = rows[0]
        return (f"[live] {r.get('number')} [{r.get('state')}, {r.get('priority')}] "
                f"{r.get('short_description')}\nCI: {r.get('cmdb_ci')}\n"
                f"{r.get('description')}")
    rec = _INCIDENTS.get(incident)
    if not rec:
        return f"no incident {incident}"
    return (f"{rec['number']} [{rec['state']}, {rec['priority']}] {rec['short_description']}\n"
            f"CI: {rec['cmdb_ci']}\n{rec['description']}\n"
            f"work notes: {len(rec['work_notes'])}")


@mcp.tool()
def add_work_note(incident: str, note: str) -> str:
    """Append a work note to an incident. Requires `incidents:write`."""
    _guard("incidents:write", incident, "add_work_note")
    if MODE.startswith("LIVE"):
        rows = _api("GET", f"/api/now/table/incident?sysparm_query=number={incident}"
                           "&sysparm_fields=sys_id&sysparm_limit=1")
        if not rows:
            return f"[live] no incident {incident}"
        _api("PATCH", f"/api/now/table/incident/{rows[0]['sys_id']}",
             json={"work_notes": note})
        return f"[live] work note added to {incident}"
    rec = _INCIDENTS.get(incident)
    if not rec:
        return f"no incident {incident}"
    rec["work_notes"].append(note)
    return f"work note added to {incident} (now {len(rec['work_notes'])})"


@mcp.tool()
def set_state(incident: str, state: str) -> str:
    """Move an incident's state. Requires `incidents:write`."""
    _guard("incidents:write", incident, "set_state")
    if MODE.startswith("LIVE"):
        rows = _api("GET", f"/api/now/table/incident?sysparm_query=number={incident}"
                           "&sysparm_fields=sys_id&sysparm_limit=1")
        if not rows:
            return f"[live] no incident {incident}"
        _api("PATCH", f"/api/now/table/incident/{rows[0]['sys_id']}",
             json={"state": state})
        return f"[live] {incident} state set to {state}"
    rec = _INCIDENTS.get(incident)
    if not rec:
        return f"no incident {incident}"
    rec["state"] = state
    return f"{incident} is now {state}"


MODE = _preflight()

if __name__ == "__main__":
    log.info("BACKEND: %s", MODE)
    log.info("servicenow tool on %s (audience enforced)", RESOURCE)
    mcp.run(transport="streamable-http")

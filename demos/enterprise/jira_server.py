#!/usr/bin/env python3
"""Jira issue tracking, as an Andyur MANAGED tool.

ONE SWITCH, AND IT SAYS WHICH SIDE IT IS ON. With JIRA_SITE/JIRA_USER/
JIRA_TOKEN set AND a credential that authenticates, every tool below calls the
real Jira Cloud REST v3 API. Without them it serves a simulated project. The
mode is logged at startup and named in every tool's return value, because a
demo that cannot tell you whether it touched a real system is worse than one
that is obviously simulated.

WHAT IS REAL IN BOTH MODES: the authorization. Every call is refused unless the
caller presents an Andyur-minted token that is audience-bound to THIS server,
carries the scope the tool requires, and is pinned to the project it names.
Going live changes the DATA, never the governance.
"""
from __future__ import annotations

import json, logging, os, pathlib, sys

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "authority-tool"))
from pep import AndyurTokenVerifier, Refused, require   # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [jira] %(message)s")
log = logging.getLogger("jira")

ANDYUR = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642").rstrip("/")
PORT = int(os.environ.get("JIRA_PORT", "8802"))
RESOURCE = f"http://127.0.0.1:{PORT}/mcp"


def _load_secrets(path: str = "") -> None:
    """READ THE CREDENTIAL FILE OURSELVES, never through the shell.

    `set -a; . jira.env` looks harmless until a token contains `&`, `(`, `}`
    or `^` -- and an Atlassian API token is base64-ish, so it will -- and bash
    reports `parse error near &` while the server starts with NO credential and
    quietly serves simulated data. Same lesson as the ServiceNow server.
    """
    here = pathlib.Path(__file__).resolve()
    candidate = pathlib.Path(path) if path else here.parents[2] / "data" / "secrets" / "jira.env"
    if not candidate.is_file():
        return
    for line in candidate.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value)


_load_secrets()

JIRA_SITE = os.environ.get("JIRA_SITE", "").rstrip("/")
JIRA_USER = os.environ.get("JIRA_USER", "")          # the Atlassian account email
JIRA_TOKEN = os.environ.get("JIRA_TOKEN", "")        # an API token, NOT a password
PROJECT = os.environ.get("JIRA_PROJECT", "PLAT")
ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")
LIVE = bool(JIRA_SITE and JIRA_USER and JIRA_TOKEN)


def _mode() -> str:
    return f"LIVE ({JIRA_SITE})" if LIVE else "SIMULATED (no JIRA_SITE/JIRA_USER/JIRA_TOKEN)"


def _api(method: str, path: str, **kw):
    """One call to Jira Cloud, Basic auth over the account email + API token."""
    import requests
    r = requests.request(method, f"{JIRA_SITE}{path}", auth=(JIRA_USER, JIRA_TOKEN),
                         headers={"Accept": "application/json",
                                  "Content-Type": "application/json"},
                         timeout=20, **kw)
    if r.status_code == 401:
        raise ToolError("jira refused the credential (401): the API token is wrong, "
                        "revoked, or does not belong to JIRA_USER")
    if r.status_code == 403:
        raise ToolError(f"jira refused the operation (403): {JIRA_USER} lacks permission "
                        f"on {PROJECT}. This is JIRA's own check, not Andyur's.")
    return r


def _adf(text: str) -> dict:
    """REST v3 takes Atlassian Document Format, not a string."""
    return {"type": "doc", "version": 1,
            "content": [{"type": "paragraph",
                         "content": [{"type": "text", "text": text}]}]}


# The simulated project, used only when LIVE is false. PLAT-1183 is the
# standing bug the deploy regressed, so a search finds prior art rather than an
# empty backlog.
_ISSUES = {
    "PLAT-1183": {"key": "PLAT-1183", "status": "Done", "summary":
                  "checkout-service: redis connection pool exhausted under retry storm",
                  "resolution": "raised pool max to 200; added backoff"},
}
_NEXT = [1400]

verifier = AndyurTokenVerifier(
    jwks_url=f"{ANDYUR}/.well-known/jwks.json",
    issuer=os.environ.get("ANDYUR_EXCHANGE_ISSUER", "andyur"),
    audience=RESOURCE)

mcp = FastMCP("jira", host="127.0.0.1", port=PORT, token_verifier=verifier,
              auth=AuthSettings(issuer_url=AnyHttpUrl(ANDYUR),
                                resource_server_url=AnyHttpUrl(RESOURCE),
                                required_scopes=[]))


def _guard(scope: str, project: str, tool: str):
    """Authority first, and PINNED to the project named in the call."""
    try:
        require(get_access_token(), scope, {"project": project})
    except Refused as why:
        log.warning("REFUSED %s(%s): %s", tool, project, why)
        raise ToolError(f"refused: {why}") from why
    log.info("ALLOWED %s(%s)", tool, project)


@mcp.tool()
def search_issues(jql: str) -> str:
    """Search issues with a JQL query. Requires `issues:read`."""
    _guard("issues:read", PROJECT, "search_issues")
    if not LIVE:
        hits = [i for i in _ISSUES.values()
                if any(w.lower() in (i["summary"] + i.get("resolution", "")).lower()
                       for w in jql.replace('"', " ").split() if len(w) > 4)]
        if not hits:
            return f"[simulated] no issues match {jql!r}"
        return "[simulated]\n" + "\n".join(
            f"{i['key']} [{i['status']}] {i['summary']}"
            + (f"\n  resolution: {i['resolution']}" if i.get("resolution") else "")
            for i in hits)

    # Atlassian replaced GET /rest/api/3/search with POST /rest/api/3/search/jql.
    # Try the current endpoint, fall back for older sites rather than guessing.
    body = {"jql": jql, "maxResults": 10, "fields": ["summary", "status", "resolution"]}
    r = _api("POST", "/rest/api/3/search/jql", json=body)
    if r.status_code == 404:
        r = _api("POST", "/rest/api/3/search", json=body)
    if r.status_code >= 400:
        raise ToolError(f"jira search failed ({r.status_code}): {r.text[:300]}")
    issues = r.json().get("issues", [])
    if not issues:
        return f"[live] no issues match {jql!r}"
    out = []
    for i in issues:
        f = i.get("fields", {})
        status = (f.get("status") or {}).get("name", "?")
        line = f"{i['key']} [{status}] {f.get('summary', '')}"
        res = (f.get("resolution") or {}).get("name")
        if res:
            line += f"\n  resolution: {res}"
        out.append(line)
    return "[live]\n" + "\n".join(out)


@mcp.tool()
def create_issue(summary: str, description: str) -> str:
    """Create an issue in the configured project. Requires `issues:write`."""
    _guard("issues:write", PROJECT, "create_issue")
    if not LIVE:
        _NEXT[0] += 1
        key = f"{PROJECT}-{_NEXT[0]}"
        _ISSUES[key] = {"key": key, "status": "To Do", "summary": summary,
                        "description": description}
        return f"[simulated] created {key}: {summary}"

    body = {"fields": {"project": {"key": PROJECT},
                       "summary": summary,
                       "description": _adf(description),
                       "issuetype": {"name": ISSUE_TYPE}}}
    r = _api("POST", "/rest/api/3/issue", json=body)
    if r.status_code >= 400:
        raise ToolError(f"jira create failed ({r.status_code}): {r.text[:300]}")
    key = r.json().get("key", "?")
    return f"[live] created {key}: {summary}  ({JIRA_SITE}/browse/{key})"


@mcp.tool()
def transition_issue(key: str, status: str) -> str:
    """Move an issue to a new status. Requires `issues:write`."""
    _guard("issues:write", PROJECT, "transition_issue")
    if not LIVE:
        issue = _ISSUES.get(key)
        if not issue:
            return f"[simulated] no issue {key}"
        issue["status"] = status
        return f"[simulated] {key} -> {status}"

    # A transition is BY ID and the ids are per-workflow: ask the issue what it
    # will accept rather than assuming a global "Done" exists.
    r = _api("GET", f"/rest/api/3/issue/{key}/transitions")
    if r.status_code >= 400:
        raise ToolError(f"jira could not read transitions for {key} "
                        f"({r.status_code}): {r.text[:200]}")
    available = r.json().get("transitions", [])
    match = next((t for t in available if t["name"].lower() == status.lower()), None)
    if match is None:
        offered = ", ".join(t["name"] for t in available) or "(none)"
        return (f"[live] {key} cannot move to {status!r} from its current status; "
                f"this workflow offers: {offered}")
    r = _api("POST", f"/rest/api/3/issue/{key}/transitions",
             json={"transition": {"id": match["id"]}})
    if r.status_code >= 400:
        raise ToolError(f"jira transition failed ({r.status_code}): {r.text[:300]}")
    return f"[live] {key} -> {match['name']}"


@mcp.tool()
def whoami() -> str:
    """Report which Jira account this tool server acts as. Requires `issues:read`."""
    _guard("issues:read", PROJECT, "whoami")
    if not LIVE:
        return "[simulated] no Jira account is in use"
    r = _api("GET", "/rest/api/3/myself")
    if r.status_code >= 400:
        raise ToolError(f"jira /myself failed ({r.status_code}): {r.text[:200]}")
    me = r.json()
    return (f"[live] {me.get('displayName')} <{me.get('emailAddress')}> "
            f"accountId={me.get('accountId')} on {JIRA_SITE}")


if __name__ == "__main__":
    log.info("jira tool on %s (audience enforced) -- backend: %s", RESOURCE, _mode())
    if LIVE:
        log.info("acting as %s in project %s", JIRA_USER, PROJECT)
    mcp.run(transport="streamable-http")

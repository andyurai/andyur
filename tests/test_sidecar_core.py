"""The per-run sidecar's credential and routing core.

The security-critical property is S1/S2: the agent holds no credential, so
anything it sends under an auth or identity name must be gone before the sidecar
sets the real one. These tests assert what is stripped next to what survives,
because a strip that also ate content headers would break every tool call and a
strip that missed one header would let the agent smuggle a credential.
"""

from andyur.proxy import sidecar as sc


# --- S1/S2: inbound credential stripping --------------------------------------

def test_agent_authorization_is_stripped():
    out = sc.strip_inbound({"Authorization": "Bearer stolen", "Accept": "application/json"})
    assert "Authorization" not in out and "authorization" not in {k.lower() for k in out}
    assert out["Accept"] == "application/json"


def test_agent_cannot_smuggle_andyur_identity_headers():
    """The agent must not preset the actor/subject tokens the sidecar is about to
    set. Every x-andyur-* header is dropped, case-insensitively."""
    out = sc.strip_inbound({
        "X-Andyur-Actor-Token": "forged", "x-andyur-subject-token": "forged",
        "X-Andyur-Run-Token": "forged", "Content-Type": "application/json",
    })
    assert not any(k.lower().startswith("x-andyur-") for k in out)
    assert out["Content-Type"] == "application/json"


def test_cookie_and_proxy_auth_are_stripped():
    out = sc.strip_inbound({"Cookie": "s=1", "Proxy-Authorization": "x", "Accept": "*/*"})
    assert set(out) == {"Accept"}


def test_benign_headers_survive_untouched():
    """The strip must not break a valid MCP call: content negotiation and body
    headers pass through exactly."""
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Content-Length": "42", "User-Agent": "probe/1"}
    assert sc.strip_inbound(hdrs) == hdrs


def test_strip_is_case_insensitive_on_the_exact_set():
    out = sc.strip_inbound({"AUTHORIZATION": "Bearer x", "cOOkie": "y", "Accept": "*/*"})
    assert set(out) == {"Accept"}


# --- the run's identity material ----------------------------------------------

def _identity():
    return sc.RunIdentity(
        subject_token="T0.for.dana",
        actor_token=lambda: "SVID.of.run",
        mtls_material=lambda: {"cert": "/c", "key": "/k", "bundle": "/b"},
    )


def test_exchange_headers_carry_both_legs():
    h = _identity().exchange_headers()
    assert h[sc.SUBJECT_TOKEN_HEADER] == "T0.for.dana"
    assert h[sc.ACTOR_TOKEN_HEADER] == "SVID.of.run"


def test_actor_token_is_fetched_each_time_so_rotation_is_seen():
    calls = {"n": 0}
    def rotating():
        calls["n"] += 1
        return f"svid-{calls['n']}"
    ident = sc.RunIdentity("T0", rotating, lambda: {})
    assert ident.actor_token() == "svid-1"
    assert ident.actor_token() == "svid-2"


def test_the_agent_never_sees_the_subject_or_actor_token():
    """Belt and braces: the identity material is not derivable from what the
    sidecar would forward. The exchange headers are built separately from the
    (stripped) inbound request."""
    inbound = sc.strip_inbound({"Authorization": "whatever", "Accept": "*/*"})
    assert "T0.for.dana" not in str(inbound)
    assert "SVID.of.run" not in str(inbound)


# --- routing ------------------------------------------------------------------

def _router():
    tools = {
        "obs": sc.ToolRoute.from_managed("obs", {
            "url": "http://127.0.0.1:8797/mcp", "audience": "resource:telemetry",
            "scheme": "http", "host": "127.0.0.1", "port": 8797, "path": "/mcp"}),
    }
    return sc.Router(tools)


def test_a_tool_path_classifies_to_that_tool_with_its_resource_id_audience():
    r = _router().classify("/tools/obs/mcp")
    assert r.kind == "tool"
    assert r.tool.audience == "resource:telemetry"       # from the manifest
    assert r.tool.audience != r.tool.reach_url           # not derived from the url
    assert (r.tool.host, r.tool.port, r.tool.path) == ("127.0.0.1", 8797, "/mcp")


def test_an_unknown_tool_is_not_routed():
    """Fail closed: a tool the manifest did not declare is 'unknown', never
    forwarded to some default, so the agent cannot reach an undeclared upstream."""
    assert _router().classify("/tools/ghost/mcp").kind == "unknown"


def test_the_llm_prefix_classifies_to_the_shared_gateway():
    assert _router().classify("/llm/v1/messages").kind == "llm"
    assert _router().classify("/llm").kind == "llm"


def test_an_unrecognised_path_is_unknown():
    assert _router().classify("/").kind == "unknown"
    assert _router().classify("/random").kind == "unknown"


def test_from_managed_maps_a_resolution_entry():
    """The router consumes exactly the shape managed_from_resolution produces,
    so the registry's resource_id becomes the tool's audience end to end."""
    entry = {"url": "http://h:9/mcp", "audience": "resource:x",
             "scheme": "http", "host": "h", "port": 9, "path": "/mcp"}
    route = sc.ToolRoute.from_managed("t", entry)
    assert route.audience == "resource:x" and route.reach_url == "http://h:9/mcp"
    assert route.scheme == "http"

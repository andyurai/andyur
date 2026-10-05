"""The wiring that turns a resolved agent into gateway + ceiling inputs.

The security-relevant property is that the audience the gateway mints for comes
from the manifest's resource_id, decoupled from the reach_url -- the whole point
of the registry. So the tests assert audience != url, and that a managed tool
whose url cannot be honoured aborts launch rather than being passed through bare.
"""

import logging

import pytest

from andyur.registry.models import (
    AgentResolution,
    AuthorityCeiling,
    ToolBinding,
)
from andyur.runner import registry_consumption as rc


def _resolution(tools, actions=("files:read",), resources=("resource:fs",)):
    return AgentResolution(
        agent_id="agt_x", name="x", instructions="do the thing", model=None,
        tools=tuple(tools),
        ceiling=AuthorityCeiling(actions=actions, resources=resources))


def test_managed_audience_is_the_resource_id_not_the_url():
    r = _resolution([
        ToolBinding("obs", "http://127.0.0.1:8797/mcp", "resource:telemetry",
                    "managed"),
    ])
    managed, passthrough = rc.managed_from_resolution(r)
    assert set(managed) == {"obs"}
    entry = managed["obs"]
    # the audience is the manifest identifier, NOT canonicalised from the url
    assert entry["audience"] == "resource:telemetry"
    assert entry["audience"] != entry["url"]
    # routing is taken apart from the reach_url
    assert (entry["host"], entry["port"], entry["path"]) == ("127.0.0.1", 8797, "/mcp")
    assert passthrough == {}


def test_passthrough_tool_gets_no_audience_and_is_handed_to_the_sdk():
    r = _resolution([
        ToolBinding("scratch", "http://127.0.0.1:9000/mcp", "resource:scratch",
                    "passthrough"),
    ])
    managed, passthrough = rc.managed_from_resolution(r)
    assert managed == {}
    assert passthrough == {"scratch": {"type": "http", "url": "http://127.0.0.1:9000/mcp"}}


def test_a_managed_tool_with_an_unusable_url_is_a_launch_failure():
    """A 'validated, launchable' resolution that silently drops a managed tool is
    not launchable. A reach_url the gateway cannot honour at all must RAISE
    (launch failure), never be quietly withheld leaving the agent fewer tools
    than the manifest declares."""
    r = _resolution([
        ToolBinding("bank", "ftp://bank.internal/mcp", "resource:bank",
                    "managed"),
    ])
    with pytest.raises(rc.UnlaunchableResolution):
        rc.managed_from_resolution(r)


def test_an_https_managed_reach_url_is_honoured_with_its_scheme():
    """https is a first-class managed scheme: the sidecar performs the TLS
    handshake and presents the run's X509-SVID on it, so refusing it (the old
    agentgateway-era rule) would forbid the only transport on which the
    delegated token is not readable in flight."""
    r = _resolution([
        ToolBinding("bank", "https://bank.internal/mcp", "resource:bank",
                    "managed"),
    ])
    managed, _ = rc.managed_from_resolution(r)
    assert managed["bank"]["scheme"] == "https"
    assert managed["bank"]["port"] == 443


def test_prod_refuses_a_plaintext_managed_reach_url(monkeypatch):
    """In production the delegated token may not ride plaintext http: the
    partition makes the resolution unlaunchable rather than shipping a run
    whose bearer any on-path observer can capture."""
    from andyur import config
    monkeypatch.setattr(config, "PROD", True)
    r = _resolution([
        ToolBinding("bank", "http://bank.internal/mcp", "resource:bank",
                    "managed"),
    ])
    with pytest.raises(rc.UnlaunchableResolution, match="https"):
        rc.managed_from_resolution(r)


def test_prod_accepts_an_https_managed_reach_url(monkeypatch):
    """Positive control for the refusal above: PROD plus https launches."""
    from andyur import config
    monkeypatch.setattr(config, "PROD", True)
    r = _resolution([
        ToolBinding("bank", "https://bank.internal/mcp", "resource:bank",
                    "managed"),
    ])
    managed, _ = rc.managed_from_resolution(r)
    assert managed["bank"]["scheme"] == "https"


def test_a_query_in_a_managed_url_is_a_launch_failure():
    import pytest
    r = _resolution([
        ToolBinding("t", "http://h:8000/mcp?tenant=a", "resource:t", "managed"),
    ])
    with pytest.raises(rc.UnlaunchableResolution):
        rc.managed_from_resolution(r)


def test_managed_and_passthrough_partition_together():
    r = _resolution([
        ToolBinding("obs", "http://h:8797/mcp", "resource:telemetry", "managed"),
        ToolBinding("tix", "http://h:8798/mcp", "resource:tickets", "managed"),
        ToolBinding("notes", "http://h:9000/mcp", "resource:notes", "passthrough"),
    ])
    managed, passthrough = rc.managed_from_resolution(r)
    assert set(managed) == {"obs", "tix"}
    assert set(passthrough) == {"notes"}
    assert managed["obs"]["audience"] == "resource:telemetry"
    assert managed["tix"]["audience"] == "resource:tickets"


def test_in_process_binding_with_unknown_authority_fails_closed():
    r = _resolution([
        ToolBinding("obs", "http://h:8797/mcp", "resource:telemetry", "new-mode"),
    ])
    with pytest.raises(rc.UnlaunchableResolution, match="unknown authority"):
        rc.managed_from_resolution(r)


# --- the over-the-wire tool path: GET /runs/{run_id}/registry-tools -----------
#
# A split/sidecar run fetches only its tool descriptors from the run-auth'd
# endpoint. They must funnel through the SAME partition as an in-process
# resolution, so audience==resource_id and fail-closed launch behavior holds
# identically however the tools arrived.

def _descriptor(name="obs", url="http://127.0.0.1:8797/mcp",
                resource="resource:telemetry", authority="managed",
                permitted_tools=None):
    return {"name": name, "reach_url": url, "resource_id": resource,
            "authority": authority,
            # Required by the descriptor contract: the server's per-run
            # decision. None keeps the audience-level posture these tests
            # already assume.
            "permitted_tools": permitted_tools}


def test_descriptors_partition_exactly_like_a_resolution():
    """The wire path and the in-process path must agree tool-for-tool, so a
    split run and a headless run of the same agent get identical tool config."""
    tools = [
        ToolBinding("obs", "http://h:8797/mcp", "resource:telemetry", "managed"),
        ToolBinding("tix", "http://h:8798/mcp", "resource:tickets", "managed"),
        ToolBinding("notes", "http://h:9000/mcp", "resource:notes", "passthrough"),
    ]
    from_res = rc._partition_tools(tools, {})
    from_wire = rc.managed_from_descriptors([
        _descriptor("obs", "http://h:8797/mcp", "resource:telemetry", "managed"),
        _descriptor("tix", "http://h:8798/mcp", "resource:tickets", "managed"),
        _descriptor("notes", "http://h:9000/mcp", "resource:notes", "passthrough"),
    ])
    assert from_wire == from_res


def test_descriptor_managed_audience_is_the_resource_id():
    managed, passthrough = rc.managed_from_descriptors([_descriptor()])
    assert managed["obs"]["audience"] == "resource:telemetry"
    assert managed["obs"]["audience"] != managed["obs"]["url"]
    assert passthrough == {}


def test_descriptor_with_unusable_managed_url_is_a_launch_failure():
    """Same rule as a resolution: a managed reach_url the gateway cannot honour
    RAISES, it is never quietly dropped."""
    with pytest.raises(rc.UnlaunchableResolution):
        rc.managed_from_descriptors([
            _descriptor(url="ftp://bank.internal/mcp", resource="resource:bank")])


def test_descriptor_https_managed_url_is_honoured():
    """Wire-path parity for the https rule: a split run gets the same https
    scheme in its managed entry as an in-process run would."""
    managed, _ = rc.managed_from_descriptors([
        _descriptor(url="https://bank.internal/mcp", resource="resource:bank")])
    assert managed["obs"]["scheme"] == "https"


def test_a_descriptor_missing_authority_is_a_launch_failure_not_passthrough():
    """The security-critical case: if the authority field is absent, the tool
    must NOT default to passthrough (which would call a managed resource with no
    token). A missing promised field fails the launch loudly."""
    import pytest
    bad = _descriptor()
    del bad["authority"]
    with pytest.raises(rc.UnlaunchableResolution):
        rc.managed_from_descriptors([bad])


def test_a_descriptor_missing_resource_id_is_a_launch_failure():
    import pytest
    bad = _descriptor()
    del bad["resource_id"]
    with pytest.raises(rc.UnlaunchableResolution):
        rc.managed_from_descriptors([bad])


@pytest.mark.parametrize("authority", ["passthru", "new-mode", None, 1])
def test_descriptor_with_unknown_authority_fails_instead_of_becoming_managed(
        authority):
    with pytest.raises(rc.UnlaunchableResolution, match="unknown authority"):
        rc.managed_from_descriptors([_descriptor(authority=authority)])


@pytest.mark.parametrize("field,value", [
    ("name", ""), ("name", None), ("reach_url", 7), ("resource_id", ""),
])
def test_descriptor_fields_are_nonempty_strings(field, value):
    bad = _descriptor()
    bad[field] = value
    with pytest.raises(rc.UnlaunchableResolution, match="invalid string"):
        rc.managed_from_descriptors([bad])


def test_duplicate_tool_names_fail_instead_of_overwriting_by_order():
    with pytest.raises(rc.UnlaunchableResolution, match="duplicated"):
        rc.managed_from_descriptors([
            _descriptor("same", authority="managed"),
            _descriptor("same", authority="passthrough"),
        ])


def test_registry_tool_count_cannot_bypass_gateway_listener_cap(monkeypatch):
    monkeypatch.setattr(rc.gateway, "_MAX_MANAGED", 2)
    passthrough = [_descriptor("note-one", authority="passthrough"),
                   _descriptor("note-two", authority="passthrough")]
    managed = [_descriptor("one"), _descriptor("two")]
    result = rc.managed_from_descriptors(passthrough + managed)
    assert set(result[0]) == {"one", "two"}
    assert set(result[1]) == {"note-one", "note-two"}
    with pytest.raises(rc.UnlaunchableResolution,
                       match="2-managed-tool runtime limit"):
        rc.managed_from_descriptors(
            passthrough + managed + [_descriptor("three")])


def test_wire_conversion_rejects_total_bindings_before_construction():
    allowed = [_descriptor(f"tool-{i}", authority="passthrough")
               for i in range(32)]
    assert len(rc.tool_bindings_from_descriptors(allowed)) == 32
    with pytest.raises(rc.UnlaunchableResolution, match="32-binding limit"):
        rc.tool_bindings_from_descriptors(allowed + [
            _descriptor("tool-32", authority="passthrough")])


def test_direct_resolution_rejects_total_bindings_over_definition_limit():
    allowed = [ToolBinding(f"tool-{i}", "http://h/mcp", f"tool:{i}",
                           "passthrough") for i in range(32)]
    assert len(rc.managed_from_resolution(_resolution(allowed))[1]) == 32
    with pytest.raises(rc.UnlaunchableResolution, match="32-binding limit"):
        rc.managed_from_resolution(_resolution(allowed + [
            ToolBinding("tool-32", "http://h/mcp", "tool:32", "passthrough")]))


def test_empty_descriptors_is_no_tools_not_an_error():
    """A legacy/unbound run's endpoint returns []; that is a valid 'no tools',
    never a failure."""
    assert rc.managed_from_descriptors([]) == ({}, {})


# (Ceiling materialization moved SERVER-side: POST with registry_agent_id applies
# the manifest ceiling atomically, so there is no client materialize_ceiling.)


# --- model_from_ctx: the runner reads the SERVER-resolved manifest model -------

def test_model_from_ctx_returns_the_manifest_model():
    """The server resolves the binding and puts the approved model in
    ctx["registry_model"]; the runner reads it, never doing its own lookup. The
    full resolution is NOT in the run-readable context (it would leak the ceiling
    and reach_urls)."""
    ctx = {"instructions": "server-overridden", "registry_model": "claude-fable-5"}
    assert rc.model_from_ctx(ctx) == "claude-fable-5"


def test_model_from_ctx_none_for_a_legacy_agent():
    """No registry_model (an unbound/legacy agent) -> None -> driver default."""
    assert rc.model_from_ctx({"instructions": "legacy"}) is None


def test_model_from_ctx_none_when_the_manifest_pins_no_model():
    """A bound agent whose manifest sets model:null -> None -> driver default,
    NOT an empty string that would select a nonexistent model."""
    assert rc.model_from_ctx({"registry_model": None}) is None
    assert rc.model_from_ctx({"registry_model": ""}) is None


# --- compensated provisioning (option b): ambiguous POST + safe compensation ---

class _FakeApi:
    """api(method, path, json=None) -> (status, body).

    `status` maps 'METHOD /prefix' -> the HTTP status to return (default 200).
    `raise_on` maps 'METHOD /prefix' -> an exception to raise, modelling a
    TRANSPORT failure (no response at all).
    """

    def __init__(self, status: dict | None = None, raise_on: dict | None = None):
        self.calls = []
        self._status = status or {}
        self._raise = raise_on or {}

    def __call__(self, method, path, json=None):
        self.calls.append((method, path, json))
        for prefix, exc in self._raise.items():
            m, p = prefix.split(" ", 1)
            if method == m and path.startswith(p):
                raise exc
        for prefix, st in self._status.items():
            m, p = prefix.split(" ", 1)
            if method == m and path.startswith(p):
                return (st, {})
        return (200, {})

    def methods_paths(self):
        return [(m, p.split("?")[0]) for m, p, _ in self.calls]

    def raw_paths(self):
        return [p for _, p, _ in self.calls]


def _agent(name="alice", actions=("files:read",), resources=("resource:fs",)):
    return AgentResolution(agent_id="agt_x", name=name, instructions="i",
                           model=None, tools=(),
                           ceiling=AuthorityCeiling(actions, resources))


def test_provision_binds_in_one_atomic_server_call():
    """One POST carrying the immutable binding; the server applies the ceiling
    atomically. No client ceiling PUT, and no delete to compensate."""
    api = _FakeApi()
    rc.provision_agent(api, _agent())
    assert api.methods_paths() == [("POST", "/agents")]
    assert api.calls[0][2]["registry_agent_id"] == "agt_x"
    assert not any("force" in p for p in api.raw_paths()), "provision must not delete"


def test_a_preexisting_name_409_is_never_touched():
    """A 409 means the name belongs to an agent this call did not create. It must
    not be modified -- never adopt or destroy another owner's agent."""
    import pytest
    api = _FakeApi(status={"POST /agents": 409})
    with pytest.raises(rc.ProvisionError) as e:
        rc.provision_agent(api, _agent())
    assert e.value.resolved is True
    assert api.methods_paths() == [("POST", "/agents")]


def test_ambiguous_create_that_may_exist_is_left_for_reconciliation():
    """req 5: a POST that raises (no response) may still have committed. If the
    agent now exists (or cannot be confirmed absent) the outcome is AMBIGUOUS --
    resolved=False -- and nothing is deleted or assumed."""
    import pytest
    api = _FakeApi(raise_on={"POST /agents": ConnectionError("no response")})
    with pytest.raises(rc.ProvisionError) as e:
        rc.provision_agent(api, _agent())
    assert e.value.resolved is False
    assert api.methods_paths() == [("POST", "/agents"), ("GET", "/agents/alice")]
    assert "ambiguous" in str(e.value).lower() or "reconcile" in str(e.value).lower()
    assert not any(m == "DELETE" for m, _ in api.methods_paths())


def test_ambiguous_create_confirmed_absent_is_a_clean_failure():
    """A confirmed 404 after the raised POST means nothing was created:
    resolved=True, nothing to reconcile."""
    import pytest
    api = _FakeApi(raise_on={"POST /agents": ConnectionError("no response")},
                   status={"GET /agents/alice": 404})
    with pytest.raises(rc.ProvisionError) as e:
        rc.provision_agent(api, _agent())
    assert e.value.resolved is True
    assert api.methods_paths() == [("POST", "/agents"), ("GET", "/agents/alice")]


def test_a_4xx_create_is_a_definite_rejection():
    import pytest
    api = _FakeApi(status={"POST /agents": 400})
    with pytest.raises(rc.ProvisionError) as e:
        rc.provision_agent(api, _agent())
    assert e.value.resolved is True
    assert api.methods_paths() == [("POST", "/agents")]   # no probe: 4xx is definite


def test_a_5xx_create_is_ambiguous_not_absent():
    """A 5xx is NOT definite absence: the server may have committed the row
    before a later failure. So it is probed like a lost response, and an existing
    agent makes the outcome ambiguous (resolved=False), not a clean failure."""
    import pytest
    api = _FakeApi(status={"POST /agents": 500})  # GET probe returns 200 (exists)
    with pytest.raises(rc.ProvisionError) as e:
        rc.provision_agent(api, _agent())
    assert e.value.resolved is False
    assert api.methods_paths() == [("POST", "/agents"), ("GET", "/agents/alice")]


def test_runtime_name_binds_the_same_definition():
    """Two prefixed runtime names bind the one immutable definition; the POST
    carries the runtime name and the shared registry_agent_id."""
    for runtime in ("demo-classifier", "t1-classifier"):
        api = _FakeApi()
        rc.provision_agent(api, _agent(), runtime_name=runtime)
        post = api.calls[0]
        assert post[1] == "/agents"
        assert post[2]["name"] == runtime
        assert post[2]["registry_agent_id"] == "agt_x"


def test_a_descriptor_missing_permitted_tools_fails_the_launch(env=None):
    """`permitted_tools` carries the server's per-run authority decision, and
    `null` is one of its meaningful values. Read with a .get() default, a
    descriptor that lost the key -- a rolled-back control plane, a bug in the
    response builder -- would look exactly like "this binding enumerates
    nothing" and silently switch per-tool authority OFF for the whole run, on
    both sides, with no error anywhere.

    So it is a launch failure, matching what _DESCRIPTOR_KEYS already promises
    for every other field it guards.
    """
    import pytest as _pytest

    from andyur.runner.registry_consumption import (
        UnlaunchableResolution,
        tool_bindings_from_descriptors,
    )
    d = _descriptor()
    del d["permitted_tools"]
    with _pytest.raises(UnlaunchableResolution, match="permitted_tools"):
        tool_bindings_from_descriptors([d])


def test_a_descriptor_carrying_permitted_tools_launches(env=None):
    """Positive control: the refusal above must not be refusing everything."""
    from andyur.runner.registry_consumption import tool_bindings_from_descriptors
    assert tool_bindings_from_descriptors([_descriptor()])[0].name == "obs"

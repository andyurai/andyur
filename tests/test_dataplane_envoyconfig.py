"""The Envoy bootstrap generator emits Andyur's two authority facts into
Envoy's own config: the run identity as the SDS cert resource, and the tool's
expected SPIFFE ID as a URI-SAN matcher (N-02). Nothing here runs Envoy; the
generated structure is asserted directly, and a live gate proves it on the wire.
"""
from __future__ import annotations

import yaml
import pytest

from andyur.dataplane import envoyconfig


TOOL = {"name": "calendar", "host": "tool.internal", "port": 8443,
        "path": "/mcp", "expected_spiffe_id": "spiffe://andyur.local/tool/calendar"}
RUN_ID = "spiffe://andyur.local/agent/scout/run/r1"


def _boot(tool=TOOL):
    return envoyconfig.build_bootstrap(
        run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=tool,
        listen_port=15000, authz_cluster="andyur-authz:9000")


def _tool_cluster(boot):
    return next(c for c in boot["static_resources"]["clusters"]
               if c["name"] == "tool_upstream")


def _default_ctx(boot):
    tls = _tool_cluster(boot)["transport_socket"]["typed_config"]
    return tls["common_tls_context"]["combined_validation_context"][
        "default_validation_context"]


def test_the_run_svid_is_the_presented_certificate():
    """Envoy presents the run's X509-SVID (SDS resource = the per-run SPIFFE
    ID), so on rotation the SPIRE agent hot-swaps it -- N-03, for free."""
    tls = _tool_cluster(_boot())["transport_socket"]["typed_config"]
    certs = tls["common_tls_context"]["tls_certificate_sds_secret_configs"]
    assert certs[0]["name"] == RUN_ID


def test_expected_spiffe_id_becomes_an_exact_uri_san_matcher():
    """The N-02 control: the tool's declared identity is pinned as an exact URI
    SAN, so any other trust-domain workload is rejected at the handshake."""
    matchers = _default_ctx(_boot())["match_typed_subject_alt_names"]
    assert matchers == [{"san_type": "URI",
                         "matcher": {"exact": TOOL["expected_spiffe_id"]}}]


def test_no_expected_spiffe_id_means_no_san_matcher_only_bundle_trust():
    """Without a declared identity the config falls back to trust-bundle
    membership only (the pre-spike posture), stated by the ABSENCE of a matcher
    rather than a silent wildcard that would match anything."""
    tool = {**TOOL}
    del tool["expected_spiffe_id"]
    assert "match_typed_subject_alt_names" not in _default_ctx(_boot(tool))


def test_the_bundle_is_fetched_from_sds_for_chain_validation():
    tls = _tool_cluster(_boot())["transport_socket"]["typed_config"]
    ctx = tls["common_tls_context"]["combined_validation_context"]
    assert ctx["validation_context_sds_secret_config"]["name"] == \
        "spiffe://andyur.local"


def test_ext_authz_filter_is_present_and_precedes_the_router():
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    names = [f["name"] for f in hcm["http_filters"]]
    # allowlist Lua, then ext_authz, then the tools/list-rewrite Lua (response
    # phase runs before the allowlist's -- Lua response order is reversed),
    # then the router.
    assert names == ["envoy.filters.http.lua", "envoy.filters.http.ext_authz",
                     "envoy.filters.http.lua", "envoy.filters.http.router"]


def _route(boot=None):
    boot = boot or _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    return hcm["route_config"]["virtual_hosts"][0]["routes"][0]


def test_path_is_confined_by_exact_match_not_prefix_rewrite():
    """The agent cannot splice a different upstream path. A prefix `/` match with
    prefix_rewrite `/mcp` would turn `/admin` into `/mcpadmin` and reach other
    endpoints on the tool host -- so the route matches the tool's EXACT path and
    method, and everything else 404s. (The live gate proves /admin etc. do not
    reach the tool; this pins the config that makes that true.)"""
    r = _route()
    assert r["match"]["path"] == "/mcp"
    assert "prefix" not in r["match"] and "prefix_rewrite" not in r["route"]
    hdrs = {h["name"]: h for h in r["match"]["headers"]}
    assert "POST" in hdrs[":method"]["string_match"]["safe_regex"]["regex"]
    # :path exact rejects query strings (/mcp?x=1)
    assert hdrs[":path"]["string_match"]["exact"] == "/mcp"


def test_agent_headers_are_reduced_to_a_transport_allowlist():
    """No credential the untrusted agent supplies may reach the tool. A Lua
    filter BEFORE ext_authz keeps ONLY the transport allowlist and removes
    everything else (an allowlist, not a denylist -- so unknown credential
    headers are dropped too). authorization is NOT in the allowlist: the agent's
    is stripped and ext_authz injects the platform one."""
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    lua = hcm["http_filters"][0]
    assert lua["name"] == "envoy.filters.http.lua"
    code = lua["typed_config"]["default_source_code"]["inline_string"]
    assert '["content-type"] = true' in code and '["mcp-session-id"] = true' in code
    assert '["authorization"]' not in code and '["cookie"]' not in code
    # no route-level denylist anymore: the allowlist is the mechanism
    assert "request_headers_to_remove" not in _route()


def test_forgeable_trace_context_is_not_allowlisted():
    """traceparent/tracestate are not Envoy-managed here, so an agent-supplied
    trace context would reach the tool forged -- they are dropped."""
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    code = hcm["http_filters"][0]["typed_config"]["default_source_code"][
        "inline_string"]
    assert '["traceparent"] = true' not in code
    assert '["tracestate"] = true' not in code


def test_envoy_is_the_authority_for_forwarding_and_request_id():
    """The forwarding + request-id headers are kept, but Envoy makes them
    authoritative BEFORE the filter runs: use_remote_address overwrites
    x-forwarded-* from the real peer (the agent's forged value cannot survive)
    and generate_request_id mints a fresh x-request-id. So keeping them in the
    allowlist forwards Envoy's values, not the agent's, and routing (which needs
    x-forwarded-proto) is not broken."""
    hcm = _boot()["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    assert hcm["use_remote_address"] is True
    assert hcm["generate_request_id"] is True
    code = hcm["http_filters"][0]["typed_config"]["default_source_code"][
        "inline_string"]
    # kept (Envoy-authoritative), and Envoy's own x-envoy-* survive by prefix
    assert '["x-forwarded-for"] = true' in code and '["x-request-id"] = true' in code
    assert 'x-envoy-' in code


def test_ext_authz_buffers_the_body_for_mcp_aware_authorization():
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    ext = next(f for f in hcm["http_filters"]
               if f["name"] == "envoy.filters.http.ext_authz")["typed_config"]
    assert ext["with_request_body"]["max_request_bytes"] >= 4096


def test_authz_over_unix_socket_is_not_a_network_endpoint():
    """With authz_socket the ext_authz cluster is a pipe (UDS), so the
    token-dispensing decision service has no network port a workload could
    call directly (finding #3)."""
    boot = envoyconfig.build_bootstrap(
        run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=TOOL,
        listen_port=15000, authz_cluster="andyur-authz:9000",
        authz_socket="/authzsock/authz.sock")
    ac = next(c for c in boot["static_resources"]["clusters"]
              if c["name"] == "andyur-authz:9000")
    addr = ac["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
    assert addr == {"pipe": {"path": "/authzsock/authz.sock"}}
    assert "socket_address" not in addr


def test_deny_only_profile_uses_the_qualified_ext_authz_deadline():
    boot = envoyconfig.build_bootstrap(
        run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=TOOL,
        listen_port=15000, authz_cluster="andyur-authz",
        authz_socket="/authz/authz.sock", authz_timeout_ms=850)
    filters = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]["http_filters"]
    ext = next(item for item in filters
               if item["name"] == "envoy.filters.http.ext_authz")
    assert ext["typed_config"]["http_service"]["server_uri"]["timeout"] == "0.850s"


@pytest.mark.parametrize("timeout", [True, 0, 249, 2001, 850.0])
def test_ext_authz_deadline_is_bounded_and_exactly_typed(timeout):
    with pytest.raises(ValueError, match="timeout"):
        envoyconfig.build_bootstrap(
            run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=TOOL,
            listen_port=15000, authz_cluster="andyur-authz",
            authz_socket="/authz/authz.sock", authz_timeout_ms=timeout)


def test_production_generator_fails_closed_without_a_pinned_tool_identity():
    """require_identity (the production path) refuses a managed tool that
    declares no expected_spiffe_id: trust-domain membership alone is not N-02."""
    import pytest
    tool = {"name": "calendar", "host": "h", "port": 8443, "path": "/mcp"}
    with pytest.raises(ValueError, match="expected_spiffe_id"):
        envoyconfig.build_bootstrap(
            run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=tool,
            listen_port=15000, authz_cluster="a:9000", require_identity=True)
    # dev (default) still allows it
    envoyconfig.build_bootstrap(
        run_spiffe_id=RUN_ID, trust_domain="andyur.local", tool=tool,
        listen_port=15000, authz_cluster="a:9000")


def test_the_whole_bootstrap_is_yaml_serialisable():
    """Envoy is booted from YAML; a non-serialisable node would fail only at
    launch, so prove it here."""
    text = yaml.safe_dump(_boot())
    assert "spire_agent" in text and "ext_authz" in text


def test_bootstrap_carries_the_node_block_sds_requires():
    """Envoy's SDS API requires a node id + cluster in the bootstrap; without
    it the config is rejected at load. Proven against real Envoy in the gate;
    pinned here so a regression fails fast."""
    boot = _boot()
    assert boot["node"]["id"] == RUN_ID
    assert boot["node"]["cluster"]


def test_ext_authz_does_not_forward_the_run_token_and_upstreams_the_bearer():
    """Identity is provisioned, so NO run token is forwarded to the decision
    service (the agent does not select the run). The injected Authorization is
    forwarded upstream, or the delegation is inert on the wire."""
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    ext = next(f for f in hcm["http_filters"]
               if f["name"] == "envoy.filters.http.ext_authz")["typed_config"]
    assert ext["include_peer_certificate"] is True
    http = ext["http_service"]
    assert http["path_prefix"] == "/authz"
    fwd = [p["exact"] for p in http["authorization_request"][
        "allowed_headers"]["patterns"]]
    assert "x-andyur-run-token" not in fwd
    up = [p["exact"] for p in http["authorization_response"][
        "allowed_upstream_headers"]["patterns"]]
    # authorization is the injected delegated token; accept-encoding rides only
    # a tools/list allow (set to identity by the decision service) so the
    # response rewrite reads an uncompressed body.
    assert up == ["authorization", "accept-encoding"]


def test_the_authz_and_spire_clusters_exist_and_addr_parses():
    boot = _boot()
    names = {c["name"] for c in boot["static_resources"]["clusters"]}
    assert {"spire_agent", "tool_upstream", "andyur-authz:9000"} <= names
    # _authz_addr default-port branch: no port -> 9000
    assert envoyconfig._authz_addr("h") == {"address": "h", "port_value": 9000}
    assert envoyconfig._authz_addr("h:1234") == {"address": "h", "port_value": 1234}



def test_the_mcp_method_tag_becomes_dynamic_metadata_not_an_upstream_header():
    """x-andyur-mcp is emitted by the DECISION SERVICE and extracted into
    dynamic metadata for the response filter; it is deliberately NOT in
    allowed_upstream_headers, so the tag never reaches the tool."""
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    ext = next(f for f in hcm["http_filters"]
               if f["name"] == "envoy.filters.http.ext_authz")["typed_config"]
    resp = ext["http_service"]["authorization_response"]
    meta = [p["exact"] for p in resp["dynamic_metadata_from_headers"]["patterns"]]
    assert meta == ["x-andyur-mcp"]
    up = [p["exact"] for p in resp["allowed_upstream_headers"]["patterns"]]
    assert "x-andyur-mcp" not in up


def test_the_toolfilter_lua_rewrites_via_the_decision_service_and_fails_closed():
    """The response-side Lua acts only on the ext_authz tools/list tag, calls
    the SAME decision service (/toolfilter), and substitutes the fail-closed
    JSON-RPC error when the rewrite is refused or unreachable."""
    boot = _boot()
    hcm = boot["static_resources"]["listeners"][0]["filter_chains"][0][
        "filters"][0]["typed_config"]
    luas = [f for f in hcm["http_filters"]
            if f["name"] == "envoy.filters.http.lua"]
    src = luas[-1]["typed_config"]["default_source_code"]["inline_string"]
    assert "envoy.filters.http.ext_authz" in src        # reads the authz tag
    assert '"x-andyur-mcp"] ~= "tools/list"' in src      # acts on tools/list only
    assert "/toolfilter" in src                          # same decision service
    assert "tools/list filtering unavailable" in src     # fail-closed payload
    # the request-phase allowlist filter is untouched by the rewrite concern
    assert "envoy_on_request" in luas[0]["typed_config"][
        "default_source_code"]["inline_string"]

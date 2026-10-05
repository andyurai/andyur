"""Generate an Envoy bootstrap for one per-run tool-egress proxy.

SPIKE (ADR-004). This is CONFIG GENERATION, not a data plane. Envoy owns TLS,
SDS certificate delivery and rotation, URI-SAN peer authorization, routing,
pooling and streaming. Andyur owns only the two facts a generic proxy cannot
know and emits them into Envoy's own config:

  * the run's identity (the SDS resource name = the per-run SPIFFE ID), so
    Envoy presents the run's X509-SVID to the tool and hot-swaps it on rotation;
  * the TOOL's expected identity (`expected_spiffe_id` from the registry), so
    Envoy's `match_typed_subject_alt_names` URI matcher authorizes the specific
    tool workload -- not merely any certificate chaining to the trust bundle
    (this is finding N-02).

The authorization DECISION and the credential exchange are not here: Envoy's
ext_authz filter calls the Andyur decision service (`andyur.dataplane.extauthz`)
per request. Nothing in this module is Andyur-invented protocol; every field
name is Envoy's own (see the SPIRE/Envoy X.509-SVID reference config).

The output is a plain dict, YAML-serialized by the caller, so it is asserted
directly in tests without standing up Envoy.
"""

from __future__ import annotations

from typing import Any

from .extauthz import TOOLS_LIST_UNAVAILABLE

# The ONLY request headers allowed from the untrusted agent to survive to the
# tool. An allowlist: everything else -- every credential, known or not -- is
# removed by a Lua filter that runs BEFORE ext_authz, so the agent's own
# `authorization` is gone before the platform token is injected.
#
# The forwarding and request-id headers ARE kept, but NOT on trust of the agent:
# `use_remote_address: true` (edge posture, set on the HCM) makes Envoy overwrite
# `x-forwarded-for`/`-proto`/`-port` from the real downstream connection and
# `generate_request_id` mint a fresh `x-request-id`, BOTH before this filter --
# so by the time the tool sees them they are Envoy's authoritative values, not
# whatever the agent forged, and the agent's copies cannot survive. Envoy also
# sanitizes inbound `x-envoy-*` internal headers from an external (edge) request
# itself, so its own `x-envoy-*` are trustworthy and are preserved by prefix.
#
# `traceparent`/`tracestate` are the exception and are NOT kept: without tracing
# configured Envoy does not manage them, so an agent-supplied trace context would
# reach the tool forged. When distributed tracing is enabled, Envoy injects a
# trusted context after this filter; the agent's is dropped here regardless.
_AGENT_HEADER_ALLOWLIST = [
    # MCP / HTTP transport + content metadata
    "content-type", "content-length", "accept", "accept-encoding", "user-agent",
    "mcp-session-id", "mcp-protocol-version",
    # Envoy-authoritative by the time this filter runs (see above); routing also
    # needs them, and dropping x-forwarded-proto is a route_not_found (404).
    "x-request-id", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-port",
]

# The allowlist keeps the transport + Envoy-authoritative headers above (and, by
# prefix, Envoy's own `x-envoy-*`, which Envoy sanitizes on an edge request so
# the agent cannot forge them); everything else the untrusted agent supplied --
# every credential known or not, and the forgeable `traceparent`/`tracestate`
# trace context -- is removed. Pseudo-headers (:method, :path, :authority,
# :scheme) are routing-critical and NEVER touched (removing them breaks routing).
_LUA_ALLOWLIST = """
local KEEP = {%s}
function envoy_on_request(handle)
  local h = handle:headers()
  local drop = {}
  for k, _ in pairs(h) do
    local lk = string.lower(k)
    if string.sub(lk, 1, 1) ~= ":"
       and string.sub(lk, 1, 8) ~= "x-envoy-"
       and not KEEP[lk] then
      drop[#drop + 1] = k
    end
  end
  for _, k in ipairs(drop) do h:remove(k) end
end
""" % ", ".join('["%s"] = true' % h for h in _AGENT_HEADER_ALLOWLIST)


def _lua_allowlist_filter() -> dict[str, Any]:
    """A Lua filter (first in the chain) that reduces the agent's request to the
    transport allowlist -- the outbound header allowlist the sidecar's
    `_AGENT_FORWARD` was, now on the composed plane. Runs before ext_authz so
    the agent's credentials (authorization included) are gone before the
    delegated token is injected."""
    return {
        "name": "envoy.filters.http.lua",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http."
                     "lua.v3.Lua",
            "default_source_code": {"inline_string": _LUA_ALLOWLIST},
        },
    }


# Response-side counterpart of the MCP-aware decision (negative test #9, "no
# ghost tools"): when ext_authz tagged the request as an authorized tools/list,
# the buffered response body is handed to the SAME decision service
# (/toolfilter) and replaced with its rewrite, so the menu the agent sees and
# the calls it may make come from one decision.
#
# The decision service (Python) owns ALL body construction -- the filtered list
# AND the fail-closed error -- because only it can frame the substitute per the
# upstream content-type (JSON vs SSE) and carry the JSON-RPC id. So /toolfilter
# ALWAYS returns 200 with the exact bytes to emit, and this filter only:
#   1. acts on an authorized tools/list (the ext_authz dynamic-metadata tag);
#   2. leaves a NON-2xx upstream untouched -- a tool-down 5xx is the tool's own
#      error, not a list to rewrite, and must not be masked as "list
#      unavailable";
#   3. forwards the upstream content-type so the service frames correctly;
#   4. on an unreachable decision service (httpCall synthesizes a 5xx, or a
#      malformed call returns nil), fails closed with a minimal error rather
#      than passing the unfiltered list.
# %s slots: authz cluster name, authz authority host, the last-resort payload.
_LUA_TOOLFILTER = """
function envoy_on_response(handle)
  local meta = handle:streamInfo():dynamicMetadata():get(
      "envoy.filters.http.ext_authz")
  if meta == nil or meta["x-andyur-mcp"] ~= "tools/list" then
    return
  end
  local status = handle:headers():get(":status")
  if status == nil or string.sub(status, 1, 1) ~= "2" then
    return
  end
  local ct = handle:headers():get("content-type") or ""
  local body = handle:body()
  local len = body:length()
  local bytes = ""
  if len > 0 then
    bytes = body:getBytes(0, len)
  end
  -- Two coroutine rules, both proven live ("object used outside of proper
  -- scope"): httpCall must not sit inside a pcall closure, and the buffer
  -- object from before the yielding call is dead after it resumes -- the body
  -- must be re-fetched from the handle for setBytes. On an unreachable cluster
  -- httpCall returns a SYNTHESIZED 5xx (not nil, not a Lua error); the status
  -- check below is that fail-closed path, the nil arm covers a malformed call.
  local headers, fb = handle:httpCall("%s",
    {[":method"] = "POST", [":path"] = "/toolfilter",
     [":authority"] = "%s",
     ["x-andyur-upstream-ct"] = ct,
     ["content-type"] = "application/octet-stream"},
    bytes, 2000)
  if headers == nil or headers[":status"] ~= "200" or fb == nil then
    handle:body():setBytes('%s')
    return
  end
  handle:body():setBytes(fb)
end
"""


def _lua_toolfilter(authz_cluster: str) -> dict[str, Any]:
    host = authz_cluster.partition(":")[0]
    return {
        "name": "envoy.filters.http.lua",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http."
                     "lua.v3.Lua",
            "default_source_code": {"inline_string": _LUA_TOOLFILTER % (
                authz_cluster, host,
                TOOLS_LIST_UNAVAILABLE.decode().replace("'", "\\'"))},
        },
    }


def _sds(resource_name: str, cluster: str = "spire_agent") -> dict[str, Any]:
    """An SDS secret config fetched from the SPIRE agent over gRPC. `resource_name`
    is a SPIFFE ID: the workload's own id for a certificate, or the trust-domain
    id for the validation bundle."""
    return {
        "name": resource_name,
        "sds_config": {
            "resource_api_version": "V3",
            "api_config_source": {
                "api_type": "GRPC",
                "transport_api_version": "V3",
                "grpc_services": [{"envoy_grpc": {"cluster_name": cluster}}],
            },
        },
    }


def _spire_agent_cluster(socket_path: str) -> dict[str, Any]:
    """The gRPC cluster Envoy uses to reach the SPIRE agent's SDS, served on the
    Workload API unix socket."""
    return {
        "name": "spire_agent",
        "connect_timeout": "1s",
        "http2_protocol_options": {},
        "load_assignment": {
            "cluster_name": "spire_agent",
            "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
                "pipe": {"path": socket_path}}}}]}],
        },
    }


def _upstream_tls(run_spiffe_id: str, trust_domain_id: str,
                  expected_spiffe_id: str | None) -> dict[str, Any]:
    """The UpstreamTlsContext for the tool leg: present the run's X509-SVID and
    verify the tool's certificate against the trust bundle. When the registry
    declared the tool's `expected_spiffe_id`, ALSO pin its URI SAN exactly --
    the N-02 control. Without it, membership in the trust domain is the only
    check (the pre-spike posture), and that is stated by the absence of a
    matcher rather than a silent default."""
    default_vc: dict[str, Any] = {}
    if expected_spiffe_id is not None:
        # match_typed_subject_alt_names / san_type URI / matcher.exact is Envoy's
        # own SAN authorization; `exact` means the tool cert's URI SAN must equal
        # this SPIFFE ID, so any other trust-domain workload is rejected. The
        # trust CHAIN is still validated against the bundle (the sibling
        # validation_context_sds_secret_config), so this is chain + SAN, not
        # SAN-only.
        default_vc["match_typed_subject_alt_names"] = [{
            "san_type": "URI",
            "matcher": {"exact": expected_spiffe_id},
        }]
    return {
        "name": "envoy.transport_sockets.tls",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets."
                     "tls.v3.UpstreamTlsContext",
            "common_tls_context": {
                # Envoy's default TLS floor is 1.2 (safe). Pinning 1.3 is
                # reasonable production hardening but requires BOTH ends to
                # negotiate it -- the spike's tool does not, and a live run
                # proved a forced 1.3 breaks the handshake (NO_SUPPORTED_
                # VERSIONS). Left at the default; raising it is a Slice-2 item
                # to verify against the real tool set, not assume.
                "tls_certificate_sds_secret_configs": [_sds(run_spiffe_id)],
                "combined_validation_context": {
                    "default_validation_context": default_vc,
                    "validation_context_sds_secret_config": _sds(trust_domain_id),
                },
            },
        },
    }


def _tool_cluster(tool: dict[str, Any], run_spiffe_id: str,
                  trust_domain_id: str) -> dict[str, Any]:
    return {
        "name": "tool_upstream",
        "connect_timeout": "5s",
        "type": "STRICT_DNS",
        "load_assignment": {
            "cluster_name": "tool_upstream",
            "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
                "socket_address": {"address": tool["host"],
                                   "port_value": int(tool["port"])}}}}]}],
        },
        "transport_socket": _upstream_tls(
            run_spiffe_id, trust_domain_id, tool.get("expected_spiffe_id")),
    }


def _ext_authz_filter(authz_cluster: str, authz_path: str,
                      timeout_ms: int = 2000) -> dict[str, Any]:
    """The ext_authz HTTP filter. On a 200 the Andyur decision service may
    return the delegated Authorization header, which Envoy forwards upstream
    (`allowed_upstream_headers`); on a 403 Envoy refuses the call. The peer
    certificate is included so the decision service can bind to it later
    (F-02, Slice 2)."""
    return {
        "name": "envoy.filters.http.ext_authz",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http."
                     "ext_authz.v3.ExtAuthz",
            "transport_api_version": "V3",
            "include_peer_certificate": True,
            # Buffer the JSON-RPC body and send it to the decision service so it
            # can authorize the specific MCP method + tool, not just the server
            # (audience). 64 KiB is ample for a tools/call envelope.
            "with_request_body": {
                "max_request_bytes": 65536,
                "allow_partial_message": False,
            },
            "http_service": {
                "server_uri": {
                    "uri": f"http://{authz_cluster}",
                    "cluster": authz_cluster,
                    "timeout": f"{timeout_ms / 1000:.3f}s",
                },
                "path_prefix": authz_path,
                "authorization_request": {
                    # Identity is PROVISIONED into the decision service (one
                    # Envoy per run), so no run token is forwarded -- the agent
                    # does not get to select the run. Only the tool call shape
                    # is passed.
                    "allowed_headers": {"patterns": [
                        {"exact": ":path"}, {"exact": ":method"}]},
                },
                "authorization_response": {
                    # `accept-encoding: identity` is set by the decision service
                    # on tools/list only, so the response rewrite reads an
                    # uncompressed body (an unreadable one fails closed).
                    "allowed_upstream_headers": {"patterns": [
                        {"exact": "authorization"},
                        {"exact": "accept-encoding"}]},
                    # The AUTHORIZED MCP method, surfaced as dynamic metadata
                    # for the response-side tools/list rewrite. Emitted from
                    # the decision service's response -- agent headers never
                    # reach this, so the tag cannot be forged.
                    "dynamic_metadata_from_headers": {"patterns": [
                        {"exact": "x-andyur-mcp"}]},
                },
            },
        },
    }


def build_bootstrap(*, run_spiffe_id: str, trust_domain: str,
                    tool: dict[str, Any], listen_port: int,
                    authz_cluster: str, authz_path: str = "/authz",
                    spire_socket: str = "/run/spire/sockets/api.sock",
                    admin_port: int = 9901,
                    require_identity: bool = False,
                    authz_socket: str | None = None,
                    authz_timeout_ms: int = 2000) -> dict[str, Any]:
    """A complete Envoy bootstrap for a per-run tool-egress proxy.

    `tool` = {name, host, port, path, expected_spiffe_id?}. The agent connects
    to Envoy on `listen_port` and Envoy proxies to the tool over mTLS, calling
    `authz_cluster` for the ext_authz decision.

    `require_identity` (the production generator sets it) FAILS CLOSED when a
    managed tool declares no `expected_spiffe_id`: without it the peer is only
    trust-domain-checked, which the production composed path must not accept.
    """
    if require_identity and not tool.get("expected_spiffe_id"):
        raise ValueError(
            f"tool {tool.get('name')!r} has no expected_spiffe_id; the "
            "production data plane refuses a managed tool whose workload "
            "identity is not pinned (trust-domain membership alone is not N-02)")
    if type(authz_timeout_ms) is not int or not 250 <= authz_timeout_ms <= 2000:
        raise ValueError("ext_authz timeout must be an integer from 250 to 2000 ms")
    trust_domain_id = f"spiffe://{trust_domain}"
    return {
        # SDS requires a node id + cluster (Envoy uses them as the SDS request
        # node); set from the run so each per-run Envoy is distinct in logs.
        "node": {"id": run_spiffe_id, "cluster": "andyur-tool-egress"},
        "admin": {"address": {"socket_address": {
            "address": "127.0.0.1", "port_value": admin_port}}},
        "static_resources": {
            "listeners": [{
                "name": "tool_listener",
                "address": {"socket_address": {
                    "address": "0.0.0.0", "port_value": listen_port}},
                # Bound the buffered tools/list response the Lua filter holds:
                # the rewrite forces `accept-encoding: identity` on exactly this
                # response, and a real MCP server's tool list (full inputSchemas)
                # can be large. Set explicitly rather than inheriting Envoy's
                # 1 MiB default so the ceiling is named and a bigger list fails
                # closed (Envoy resets) instead of silently over-buffering. 4
                # MiB comfortably holds hundreds of tools; the /toolfilter POST
                # is capped to match on the decision side.
                "per_connection_buffer_limit_bytes": 4 * 1024 * 1024,
                "filter_chains": [{"filters": [{
                    "name": "envoy.filters.network.http_connection_manager",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters."
                                 "network.http_connection_manager.v3."
                                 "HttpConnectionManager",
                        "stat_prefix": "tool_egress",
                        # EDGE posture toward the untrusted agent: Envoy derives
                        # x-forwarded-for/-proto from the real downstream
                        # connection and does NOT trust any the agent supplied,
                        # and mints a fresh x-request-id instead of honoring the
                        # agent's. Together with the header allowlist (which
                        # strips the agent's trace/forwarding/x-envoy-* copies),
                        # the tool sees only Envoy-authoritative provenance.
                        "use_remote_address": True,
                        "generate_request_id": True,
                        "route_config": {"name": "tool_route", "virtual_hosts": [{
                            "name": "tool", "domains": ["*"],
                            "routes": [{
                                # EXACT path + method, not a prefix. A prefix
                                # match with prefix_rewrite only replaces the
                                # matched prefix, so `/` -> `/mcp` turns `/admin`
                                # into `/mcpadmin` and hands the run cert +
                                # delegated token to arbitrary endpoints on the
                                # tool host. Matching the tool's one declared MCP
                                # path exactly means every other path 404s here.
                                "match": {
                                    "path": tool["path"],
                                    "headers": [
                                        {"name": ":method",
                                         "string_match": {"safe_regex": {"regex":
                                             "^(POST|GET|DELETE)$"}}},
                                        # :path INCLUDES the query, so an exact
                                        # match on it rejects `/mcp?x=1` -- a
                                        # query could select a different tenant
                                        # or object on the tool and must not ride
                                        # the run's delegated authority.
                                        {"name": ":path",
                                         "string_match": {"exact": tool["path"]}}],
                                },
                                "route": {"cluster": "tool_upstream"},
                                # Credential stripping is the Lua ALLOWLIST filter
                                # below (runs before ext_authz), not a route
                                # denylist: everything the agent sends except the
                                # transport allowlist is removed, so no credential
                                # -- known or not -- reaches the tool, and the
                                # delegated token is injected by ext_authz after.
                            }],
                        }]},
                        "http_filters": [
                            _lua_allowlist_filter(),
                            _ext_authz_filter(
                                authz_cluster, authz_path, authz_timeout_ms),
                            _lua_toolfilter(authz_cluster),
                            {"name": "envoy.filters.http.router",
                             "typed_config": {"@type": "type.googleapis.com/"
                                 "envoy.extensions.filters.http.router.v3.Router"}},
                        ],
                    },
                }]}],
            }],
            "clusters": [
                _spire_agent_cluster(spire_socket),
                _tool_cluster(tool, run_spiffe_id, trust_domain_id),
                _authz_cluster(authz_cluster, authz_socket),
            ],
        },
    }


def _authz_addr(authz_cluster: str) -> dict[str, Any]:
    host, _, port = authz_cluster.partition(":")
    return {"address": host, "port_value": int(port or "9000")}


def _authz_cluster(authz_cluster: str, authz_socket: str | None) -> dict[str, Any]:
    """The cluster Envoy calls for the ext_authz decision. When `authz_socket`
    is given the endpoint is a Unix-domain socket (`pipe`) -- the production
    shape: the decision service (which dispenses delegated tokens) is reachable
    ONLY over a same-Pod socket, not a network Service any workload could call.
    Otherwise a TCP endpoint (spike/dev; the plaintext hop is the open #3)."""
    endpoint_addr = ({"pipe": {"path": authz_socket}} if authz_socket
                     else {"socket_address": _authz_addr(authz_cluster)})
    return {
        "name": authz_cluster,
        "connect_timeout": "2s",
        "type": "STATIC" if authz_socket else "STRICT_DNS",
        "load_assignment": {
            "cluster_name": authz_cluster,
            "endpoints": [{"lb_endpoints": [{"endpoint": {
                "address": endpoint_addr}}]}],
        },
    }

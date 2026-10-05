#!/usr/bin/env python3
"""Closed-policy assertions for the disposable Envoy schema candidate."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Callable

import yaml


class PolicyError(ValueError):
    pass


EXPECTED_LUA = """local KEEP = {
  ["content-type"] = true,
  ["content-length"] = true,
  ["accept"] = true,
  ["mcp-session-id"] = true,
  ["mcp-protocol-version"] = true,
  ["x-forwarded-proto"] = true
}
function envoy_on_request(handle)
  local headers = handle:headers()
  local drop = {}
  for name, _ in pairs(headers) do
    local lower = string.lower(name)
    if string.sub(lower, 1, 1) ~= ":" and not KEEP[lower] then
      drop[#drop + 1] = name
    end
  end
  for _, name in ipairs(drop) do headers:remove(name) end
end
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def _hcm(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]


def _clusters(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {cluster["name"]: cluster for cluster in doc["static_resources"]["clusters"]}


def validate_policy(doc: dict[str, Any]) -> None:
    hcm = _hcm(doc)
    require(hcm.get("normalize_path") is True, "normalize_path")
    require(hcm.get("merge_slashes") is False, "merge_slashes")
    require(hcm.get("path_with_escaped_slashes_action") == "REJECT_REQUEST", "escaped slashes")
    require(hcm.get("max_request_headers_kb") == 60, "request header ceiling")
    require(hcm["common_http_protocol_options"].get("headers_with_underscores_action") == "REJECT_REQUEST", "underscores")

    filters = hcm["http_filters"]
    names = [item["name"] for item in filters]
    require(names == ["envoy.filters.http.lua", "envoy.filters.http.ext_authz", "envoy.filters.http.router"], "filter order")
    lua = filters[0]["typed_config"]["default_source_code"]["inline_string"]
    require(lua == EXPECTED_LUA, "exact reviewed Lua allowlist")

    ext = filters[1]["typed_config"]
    require(ext.get("failure_mode_allow") is False, "failure_mode_allow")
    body = ext["with_request_body"]
    require(body == {"max_request_bytes": 65536, "allow_partial_message": False}, "body bound")
    service = ext["http_service"]
    require(service["server_uri"]["timeout"] == "0.850s", "ext_authz timeout")
    require("authorization_request" not in service, "deprecated authz request header matcher")
    response_headers = {p["exact"] for p in service["authorization_response"]["allowed_upstream_headers"]["patterns"]}
    require(response_headers == {"authorization", "dpop", "x-andyur-decision-id"}, "authz response headers")

    route = hcm["route_config"]["virtual_hosts"][0]["routes"][0]
    require(route["match"] == {"path": "/mcp"}, "exact route")
    action = route["route"]
    require(action == {"cluster": "resource", "timeout": "2s"}, "closed route action")

    clusters = _clusters(doc)
    require(set(clusters) == {"broker", "resource", "spire_agent"}, "closed clusters")
    require(clusters["broker"]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["pipe"]["path"] == "/tmp/andyur-broker.sock", "broker UDS")
    breaker = clusters["resource"]["circuit_breakers"]["thresholds"]
    require(breaker == [{"priority": "DEFAULT", "max_connections": 8, "max_pending_requests": 8, "max_requests": 8, "max_retries": 0}], "resource breakers")
    require(clusters["resource"].get("connect_timeout") == "0.500s", "resource connect timeout")

    tls = clusters["resource"]["transport_socket"]["typed_config"]
    require(tls.get("sni") == "resource.example", "resource SNI")
    common = tls["common_tls_context"]
    require(common["tls_params"].get("tls_minimum_protocol_version") == "TLSv1_2", "TLS floor")
    require(len(common["tls_certificate_sds_secret_configs"]) == 1, "client SDS")
    validation = common["combined_validation_context"]
    san = validation["default_validation_context"]["match_typed_subject_alt_names"]
    require(san == [{"san_type": "URI", "matcher": {"exact": "spiffe://andyur.local/resource/feasibility"}}], "resource SAN")
    require("validation_context_sds_secret_config" in validation, "trust-bundle SDS")

    admin = doc["admin"]["address"]
    require(admin == {"pipe": {"path": "/tmp/andyur-envoy-admin.sock"}}, "admin UDS")
    monitors = doc["overload_manager"]["resource_monitors"]
    require(monitors == [{
        "name": "envoy.resource_monitors.global_downstream_max_connections",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
            "max_active_downstream_connections": 32,
        },
    }], "downstream connection bound")


def self_test(doc: dict[str, Any]) -> list[str]:
    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("remove_lua", lambda d: _hcm(d)["http_filters"].pop(0)),
        ("lua_extra_keep", lambda d: _hcm(d)["http_filters"][0]["typed_config"]["default_source_code"].__setitem__("inline_string", EXPECTED_LUA.replace("local KEEP = {", 'local KEEP = {\n  ["x-hostile"] = true,'))),
        ("lua_remove_bypass", lambda d: _hcm(d)["http_filters"][0]["typed_config"]["default_source_code"].__setitem__("inline_string", EXPECTED_LUA.replace("headers:remove(name)", "-- bypass"))),
        ("wrong_filter_order", lambda d: _hcm(d)["http_filters"].reverse()),
        ("allow_failure", lambda d: _hcm(d)["http_filters"][1]["typed_config"].__setitem__("failure_mode_allow", True)),
        ("allow_partial_body", lambda d: _hcm(d)["http_filters"][1]["typed_config"]["with_request_body"].__setitem__("allow_partial_message", True)),
        ("wrong_body_bound", lambda d: _hcm(d)["http_filters"][1]["typed_config"]["with_request_body"].__setitem__("max_request_bytes", 65535)),
        ("wrong_authz_timeout", lambda d: _hcm(d)["http_filters"][1]["typed_config"]["http_service"]["server_uri"].__setitem__("timeout", "2s")),
        ("extra_upstream_header", lambda d: _hcm(d)["http_filters"][1]["typed_config"]["http_service"]["authorization_response"]["allowed_upstream_headers"]["patterns"].append({"exact": "cookie"})),
        ("route_rewrite", lambda d: _hcm(d)["route_config"]["virtual_hosts"][0]["routes"][0]["route"].__setitem__("prefix_rewrite", "/")),
        ("pending_queue", lambda d: _clusters(d)["resource"]["circuit_breakers"]["thresholds"][0].__setitem__("max_pending_requests", 9)),
        ("retry_capacity", lambda d: _clusters(d)["resource"]["circuit_breakers"]["thresholds"][0].__setitem__("max_retries", 1)),
        ("remove_tls", lambda d: _clusters(d)["resource"].pop("transport_socket")),
        ("wrong_sni", lambda d: _clusters(d)["resource"]["transport_socket"]["typed_config"].__setitem__("sni", "other.example")),
        ("wrong_san", lambda d: _clusters(d)["resource"]["transport_socket"]["typed_config"]["common_tls_context"]["combined_validation_context"]["default_validation_context"]["match_typed_subject_alt_names"][0]["matcher"].__setitem__("exact", "spiffe://andyur.local/resource/other")),
        ("admin_tcp", lambda d: d["admin"].__setitem__("address", {"socket_address": {"address": "127.0.0.1", "port_value": 9901}})),
        ("allow_underscores", lambda d: _hcm(d)["common_http_protocol_options"].__setitem__("headers_with_underscores_action", "ALLOW")),
        ("normalize_off", lambda d: _hcm(d).__setitem__("normalize_path", False)),
        ("header_ceiling_removed", lambda d: _hcm(d).pop("max_request_headers_kb")),
        ("downstream_unbounded", lambda d: d.pop("overload_manager")),
    ]
    passed: list[str] = []
    for name, mutate in mutations:
        changed = copy.deepcopy(doc)
        mutate(changed)
        require(changed != doc, f"mutation did not apply: {name}")
        try:
            validate_policy(changed)
        except (PolicyError, KeyError, IndexError, TypeError):
            passed.append(name)
        else:
            raise AssertionError(f"mutation stayed green: {name}")
    validate_policy(doc)
    return passed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    document = yaml.safe_load(args.config.read_text())
    validate_policy(document)
    mutations = self_test(document) if args.self_test else []
    print(json.dumps({"status": "pass", "mutations": mutations}, sort_keys=True))


if __name__ == "__main__":
    main()

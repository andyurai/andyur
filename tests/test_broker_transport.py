import json

import pytest

from andyur.dataplane.brokertransport import (
    BrokerIngressTransport, BrokerTransport, build_egress_bootstrap,
    build_ingress_bootstrap, write_ingress_bootstrap,
)


def _profile():
    return BrokerTransport(
        run_spiffe_id="spiffe://andyur.local/agent/scout/run/" + "a" * 32,
        control_plane_spiffe_id="spiffe://andyur.local/control-plane",
        trust_domain="andyur.local",
        egress_socket="/run/andyur-broker/state.sock",
        ingress_host="andyur-broker-state.andyur-system.svc",
        ingress_port=9443,
        backend_socket="/run/andyur-server/broker-state.sock",
    )


def test_one_profile_generates_fixed_uds_mtls_uds_route():
    profile = _profile()
    egress = build_egress_bootstrap(profile)
    ingress = build_ingress_bootstrap(profile)

    el = egress["static_resources"]["listeners"][0]
    assert el["address"] == {"pipe": {
        "path": profile.egress_socket, "mode": 0o660}}
    eroute = el["filter_chains"][0]["filters"][0]["typed_config"]
    assert eroute["common_http_protocol_options"] == {
        "max_requests_per_connection": 1}
    route = eroute["route_config"]["virtual_hosts"][0]["routes"][0]
    assert route["request_headers_to_remove"] == [
        "x-forwarded-client-cert", "x-forwarded-for", "x-forwarded-host",
        "x-forwarded-proto", "forwarded",
    ]
    assert eroute["route_config"]["virtual_hosts"][0]["domains"] == [
        "andyur-broker-state"]
    cluster = egress["static_resources"]["clusters"][1]
    assert cluster["common_http_protocol_options"] == {
        "max_requests_per_connection": 1}
    tls = cluster["transport_socket"]["typed_config"]["common_tls_context"]
    matcher = tls["combined_validation_context"][
        "default_validation_context"]["match_typed_subject_alt_names"]
    assert matcher == [{"san_type": "URI", "matcher": {
        "exact": profile.control_plane_spiffe_id}}]
    assert "transport_socket" not in el["filter_chains"][0]
    assert egress["admin"]["address"] == {"pipe": {
        "path": "/tmp/andyur-broker-state-admin.sock", "mode": 0o600}}

    il = ingress["static_resources"]["listeners"][0]
    downstream = il["filter_chains"][0]["transport_socket"]["typed_config"]
    assert downstream["require_client_certificate"] is True
    ihcm = il["filter_chains"][0]["filters"][0]["typed_config"]
    assert ihcm["forward_client_cert_details"] == "SANITIZE_SET"
    assert ihcm["set_current_client_cert_details"] == {"uri": True}
    assert ingress["admin"]["address"] == {"socket_address": {
        "address": "127.0.0.1", "port_value": 9902}}
    backend = ingress["static_resources"]["clusters"][1]
    assert backend["circuit_breakers"] == {"thresholds": [{
        "priority": "DEFAULT", "max_connections": 64,
        "max_pending_requests": 64, "max_requests": 64, "max_retries": 0,
    }]}
    assert backend["load_assignment"]["endpoints"][0]["lb_endpoints"][0][
        "endpoint"]["address"] == {"pipe": {"path": profile.backend_socket}}


@pytest.mark.parametrize("changes", [
    {"run_spiffe_id": "spiffe://other.local/run/a"},
    {"control_plane_spiffe_id": "spiffe://other.local/control-plane"},
    {"egress_socket": "relative.sock"},
    {"ingress_port": 0},
])
def test_profile_refuses_cross_domain_relative_or_invalid_transport(changes):
    values = _profile().__dict__ | changes
    with pytest.raises(ValueError):
        BrokerTransport(**values)


def test_profile_refuses_valid_shape_from_different_trust_domain():
    values = _profile().__dict__ | {
        "run_spiffe_id": "spiffe://other.local/agent/scout/run/" + "a" * 32,
    }
    with pytest.raises(ValueError):
        BrokerTransport(**values)


def test_control_plane_ingress_bootstrap_is_atomic_restart_safe_and_one_source(tmp_path):
    profile = BrokerIngressTransport(
        control_plane_spiffe_id="spiffe://andyur.local/control-plane",
        trust_domain="andyur.local", ingress_port=9443,
        backend_socket="/run/andyur-server-root/broker/state.sock")
    path = tmp_path / "bootstrap.json"
    write_ingress_bootstrap(str(path), profile)
    assert path.stat().st_mode & 0o777 == 0o440
    assert json.loads(path.read_text()) == build_ingress_bootstrap(profile)
    path.chmod(0o640)
    path.write_text("partial prior init")
    write_ingress_bootstrap(str(path), profile)
    assert path.stat().st_mode & 0o777 == 0o440
    assert json.loads(path.read_text()) == build_ingress_bootstrap(profile)
    assert not list(tmp_path.glob(".broker-ingress-*"))


@pytest.mark.parametrize("changes", [
    {"control_plane_spiffe_id": "spiffe://other/control-plane"},
    {"ingress_port": 0},
    {"backend_socket": "relative.sock"},
])
def test_control_plane_ingress_profile_refuses_unsealed_inputs(changes):
    values = {
        "control_plane_spiffe_id": "spiffe://andyur.local/control-plane",
        "trust_domain": "andyur.local", "ingress_port": 9443,
        "backend_socket": "/run/andyur-server-root/broker/state.sock",
    } | changes
    with pytest.raises(ValueError):
        BrokerIngressTransport(**values)

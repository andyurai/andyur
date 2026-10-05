"""One-source Envoy/SPIRE mTLS transport for deny-only broker state."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import sys
import tempfile
from typing import Any

from .envoyconfig import _sds, _spire_agent_cluster, _upstream_tls


@dataclass(frozen=True)
class BrokerTransport:
    run_spiffe_id: str
    control_plane_spiffe_id: str
    trust_domain: str
    egress_socket: str
    ingress_host: str
    ingress_port: int
    backend_socket: str
    spire_socket: str = "/spiffe-workload-api/spire-agent.sock"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", self.trust_domain):
            raise ValueError("broker transport trust domain is malformed")
        prefix = f"spiffe://{self.trust_domain}/agent/"
        if not self.run_spiffe_id.startswith(prefix):
            raise ValueError("broker transport identities must share the sealed trust domain")
        parts = self.run_spiffe_id[len(prefix):].split("/")
        agent = parts[0] if len(parts) == 3 and parts[1] == "run" else None
        run = parts[2] if agent is not None else None
        if not agent or not re.fullmatch(r"[0-9a-f]{32}", run or "") \
                or self.control_plane_spiffe_id != (
                    f"spiffe://{self.trust_domain}/control-plane"):
            raise ValueError("broker transport identities must share the sealed trust domain")
        for path in (self.egress_socket, self.backend_socket, self.spire_socket):
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("broker transport sockets must be absolute paths")
        if not self.ingress_host or not 1 <= self.ingress_port <= 65535:
            raise ValueError("broker transport ingress endpoint is invalid")


@dataclass(frozen=True)
class BrokerIngressTransport:
    control_plane_spiffe_id: str
    trust_domain: str
    ingress_port: int
    backend_socket: str
    spire_socket: str = "/spiffe-workload-api/spire-agent.sock"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", self.trust_domain) \
                or self.control_plane_spiffe_id != (
                    f"spiffe://{self.trust_domain}/control-plane"):
            raise ValueError("broker ingress identity is malformed")
        if not 1 <= self.ingress_port <= 65535:
            raise ValueError("broker ingress port is invalid")
        for path in (self.backend_socket, self.spire_socket):
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("broker ingress sockets must be absolute paths")


def _hcm(*, route: dict[str, Any], cluster: str,
         forward_client_cert: bool = False) -> dict[str, Any]:
    removed = ["x-forwarded-for", "x-forwarded-host",
               "x-forwarded-proto", "forwarded"]
    if not forward_client_cert:
        removed.insert(0, "x-forwarded-client-cert")
    config: dict[str, Any] = {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": "broker_state",
        "use_remote_address": True,
        "common_http_protocol_options": {"max_requests_per_connection": 1},
        "route_config": {
            "name": "broker_state",
            "virtual_hosts": [{
                "name": "broker_state",
                "domains": ["andyur-broker-state"],
                "routes": [{"match": route, "route": {
                    "cluster": cluster,
                    "timeout": "0.15s",
                    "retry_policy": {"num_retries": 0},
                }, "request_headers_to_remove": removed}],
            }],
        },
        "http_filters": [{
            "name": "envoy.filters.http.router",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
            },
        }],
    }
    if forward_client_cert:
        config["forward_client_cert_details"] = "SANITIZE_SET"
        config["set_current_client_cert_details"] = {"uri": True}
    return config


def _listener(name: str, address: dict[str, Any], hcm: dict[str, Any],
              transport_socket: dict[str, Any] | None = None) -> dict[str, Any]:
    chain: dict[str, Any] = {"filters": [{
        "name": "envoy.filters.network.http_connection_manager",
        "typed_config": hcm,
    }]}
    if transport_socket is not None:
        chain["transport_socket"] = transport_socket
    return {"name": name, "address": address, "filter_chains": [chain]}


def _pipe(path: str, *, mode: int | None = None) -> dict[str, Any]:
    pipe: dict[str, Any] = {"path": path}
    if mode is not None:
        pipe["mode"] = mode
    return {"pipe": pipe}


def _downstream_tls(profile: BrokerTransport | BrokerIngressTransport) -> dict[str, Any]:
    return {
        "name": "envoy.transport_sockets.tls",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
            "require_client_certificate": True,
            "common_tls_context": {
                "tls_certificate_sds_secret_configs": [
                    _sds(profile.control_plane_spiffe_id)],
                "validation_context_sds_secret_config": _sds(
                    f"spiffe://{profile.trust_domain}"),
            },
        },
    }


def build_egress_bootstrap(profile: BrokerTransport) -> dict[str, Any]:
    """Broker-owned UDS -> one exact route -> exact-server-SAN mTLS."""
    return {
        "node": {"id": profile.run_spiffe_id, "cluster": "broker-state-egress"},
        "static_resources": {
            "listeners": [_listener(
                "broker_state_uds", _pipe(profile.egress_socket, mode=0o660),
                _hcm(
                    route={"safe_regex": {"google_re2": {},
                                           "regex": r"^/runs/[0-9a-f]{32}/broker-state$"},
                           "headers": [{"name": ":method", "string_match": {"exact": "GET"}}]},
                    cluster="control_plane_mtls"))],
            "clusters": [
                _spire_agent_cluster(profile.spire_socket),
                {
                    "name": "control_plane_mtls", "type": "STRICT_DNS",
                    "connect_timeout": "0.05s",
                    "common_http_protocol_options": {
                        "max_requests_per_connection": 1,
                    },
                    "load_assignment": {"cluster_name": "control_plane_mtls",
                        "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
                            "socket_address": {"address": profile.ingress_host,
                                               "port_value": profile.ingress_port}}}}]}]},
                    "transport_socket": _upstream_tls(
                        profile.run_spiffe_id, f"spiffe://{profile.trust_domain}",
                        profile.control_plane_spiffe_id),
                },
            ],
        },
        "admin": {"access_log_path": "/dev/null",
                  "address": _pipe("/tmp/andyur-broker-state-admin.sock",
                                   mode=0o600)},
    }


def build_ingress_bootstrap(
    profile: BrokerTransport | BrokerIngressTransport,
) -> dict[str, Any]:
    """SPIRE mTLS ingress -> XFCC from verified peer -> private backend UDS."""
    return {
        "node": {"id": profile.control_plane_spiffe_id,
                 "cluster": "broker-state-ingress"},
        "static_resources": {
            "listeners": [_listener(
                "broker_state_mtls",
                {"socket_address": {"address": "0.0.0.0",
                                    "port_value": profile.ingress_port}},
                _hcm(
                    route={"safe_regex": {"google_re2": {},
                                           "regex": r"^/runs/[0-9a-f]{32}/broker-state$"},
                           "headers": [{"name": ":method", "string_match": {"exact": "GET"}}]},
                    cluster="broker_state_backend", forward_client_cert=True),
                _downstream_tls(profile))],
            "clusters": [
                _spire_agent_cluster(profile.spire_socket),
                {
                    "name": "broker_state_backend", "type": "STATIC",
                    "connect_timeout": "0.02s",
                    "circuit_breakers": {"thresholds": [{
                        "priority": "DEFAULT",
                        "max_connections": 64,
                        "max_pending_requests": 64,
                        "max_requests": 64,
                        "max_retries": 0,
                    }]},
                    "load_assignment": {
                        "cluster_name": "broker_state_backend",
                        "endpoints": [{
                            "lb_endpoints": [{
                                "endpoint": {
                                    "address": _pipe(profile.backend_socket),
                                },
                            }],
                        }],
                    },
                },
            ],
        },
        "admin": {"access_log_path": "/dev/null", "address": {
            "socket_address": {"address": "127.0.0.1", "port_value": 9902},
        }},
    }


def write_ingress_bootstrap(path: str, profile: BrokerIngressTransport) -> None:
    """Atomically replace one bootstrap without a partial-init restart wedge."""
    raw = json.dumps(build_ingress_bootstrap(profile), sort_keys=True).encode()
    if len(raw) > 64 << 10:
        raise ValueError("broker ingress bootstrap exceeds 64 KiB")
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix=".broker-ingress-", dir=directory)
    try:
        os.fchmod(fd, 0o440)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    if sys.argv[1:] != ["--write-ingress-config"]:
        raise SystemExit(
            "usage: python -m andyur.dataplane.brokertransport "
            "--write-ingress-config")
    write_ingress_bootstrap(
        os.environ.get("ANDYUR_BROKER_INGRESS_CONFIG", ""),
        BrokerIngressTransport(
            control_plane_spiffe_id=os.environ.get("ANDYUR_SPIFFE_ID", ""),
            trust_domain=os.environ.get("ANDYUR_TRUST_DOMAIN", ""),
            ingress_port=int(os.environ.get("ANDYUR_BROKER_STATE_PORT", "0")),
            backend_socket=os.environ.get("ANDYUR_BROKER_STATE_BACKEND_SOCKET", ""),
            spire_socket=os.environ.get(
                "ANDYUR_SPIRE_SOCKET", "/spiffe-workload-api/spire-agent.sock"),
        ),
    )


if __name__ == "__main__":
    main()

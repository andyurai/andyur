"""Deterministic Kubernetes resources for one isolated Andyur run group.

The trusted proxy and untrusted agent are separate Pods on purpose. Kubernetes
NetworkPolicy is Pod-scoped; putting both containers in one Pod would give the
agent every destination allowed to the proxy.

This module only builds ordinary dictionaries. Applying, watching, reconciling,
and deleting them belongs to the Kubernetes orchestrator, so the security
contract can be tested without a cluster or a second representation in YAML.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping, Sequence

from .. import execconfig
from ..dataplane.brokertransport import BrokerTransport, build_egress_bootstrap
from ..registry.models import (
    RUNTIME_PROTOCOL_EXEC_V1,
    TEMPLATE_REF_RE,
    ConfigurationSpec,
)


_DIGEST_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_LABEL_NAME = re.compile(r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$")
_SPIFFE_MOUNT = "/spiffe-workload-api"
_SPIFFE_SOCKET = f"unix://{_SPIFFE_MOUNT}/spire-agent.sock"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclasses.dataclass(frozen=True)
class ClusterPeer:
    """One cluster-local destination the trusted proxy may reach."""

    namespace: str
    labels: Mapping[str, str]
    port: int
    protocol: str = "TCP"


@dataclasses.dataclass(frozen=True)
class RunGroupSpec:
    namespace: str
    run_id: str
    generation: str
    agent_id: str
    registry_agent_id: str
    proxy_image: str
    agent_image: str
    server_url: str = ""
    litellm_url: str = ""
    llm_mode: str = "api"
    ollama_url: str = ""
    trust_domain: str = "andyur.local"
    otel_mode: str = "on"
    otel_endpoint: str = ""
    as_token_endpoint: str = ""
    as_issuer: str = ""
    as_jwks_url: str = ""
    as_client_id: str = ""
    as_provider: str = ""
    as_capability: str = ""
    as_resource_scope: str = ""
    as_product_version: str = ""
    as_certified: bool = False
    # Empty means the real Andyur runtime commands, rendered with this run's
    # identity below. Explicit commands remain useful for cluster conformance
    # probes that test the controller without invoking a model.
    proxy_args: tuple[str, ...] = ()
    agent_args: tuple[str, ...] = ()
    # Which runtime the agent container is. Stated, not inferred from whether
    # `agent_args` happens to be set: it decides what the workload is allowed
    # to see, and a launch that guesses that wrong leaks platform internals
    # into a third-party container.
    agent_runtime: str = "builtin-claude"
    # The INTERFACE, which is a different question from the runtime type: a
    # runtime-v1 BYOA container and an exec/v1 one are both "container", and
    # only this tells them apart. Empty means runtime-v1 or builtin-claude.
    agent_interface: str = ""
    # The manifest's declared configuration, UNRESOLVED. Not a pre-resolved
    # environment, because half of this vocabulary cannot be resolved here:
    # services.model.* and services.tools.mcp_url are the proxy's address, and
    # the agent Pod has no DNS, so the real value is a Pod IP that does not
    # exist until the proxy is ready. The controller completes it at the same
    # point it already late-binds ANDYUR_RUNTIME_URL, for the same reason.
    #
    # What CAN be decided here is everything IP-independent: which variables are
    # literals, which are bearer-backed and need a secretKeyRef, and which files
    # exist. Those shape the Pod; the remaining values only fill it in.
    exec_configuration: ConfigurationSpec | None = None
    # exec/v1 INPUT DELIVERY. `exec_input_mode` is "" when this controller has
    # nothing to deliver (no input, mode 'none', mode 'argv' -- already in
    # agent_args -- or not exec/v1 at all), else "stdin" or "file". The bytes
    # never appear in any Pod object: the controller writes them by attach
    # once the TARGET container is Running -- the workload itself for 'stdin',
    # the platform's init container for 'file', which persists them VERBATIM
    # to execconfig.INPUT_PATH before the workload starts. `stdinOnce` on the
    # target closes its stdin when the attach ends, so the process reads EOF.
    exec_input_mode: str = ""
    exec_input: bytes = b""
    # The manifest's bound, handed to the init container so the stream is
    # refused inside the Pod too if it is longer than declared.
    exec_input_max_bytes: int = 0
    # Public facts as JSON, for the init container. Written by the controller
    # once the proxy IP is known; empty here is normal, not a defect.
    exec_facts: str = ""
    # What services.model.name resolves to. Empty is legal and fails CLOSED at
    # resolution rather than silently: the model a run was granted does not
    # currently travel in the runtime envelope, so a manifest naming this
    # reference gets a clear refusal instead of an empty model name the
    # workload would report as its own fault. Closing that needs the granted
    # model to reach the launcher, which is a wire change, not this increment.
    exec_model_name: str = ""
    # THIS RUN's granted wall clock, resolved by the server. The runner arms its
    # own asyncio timeout from it; without it the server, the run token and the
    # reaper all honour a 24h grant while the runner kills the agent at the
    # built-in 900s default. Zero/None keeps that default.
    run_ttl_seconds: int = 0
    proxy_port: int = 8765
    mcp_port: int = 8766
    proxy_cpu: str = "1"
    proxy_memory: str = "1Gi"
    proxy_ephemeral_storage: str = "1Gi"
    agent_cpu: str = "2"
    agent_memory: str = "2Gi"
    agent_ephemeral_storage: str = "2Gi"
    proxy_egress: tuple[ClusterPeer, ...] = ()
    agent_model_egress: ClusterPeer | None = None
    # Presence is an explicit capability opt-in; all transport inputs remain
    # empty in off mode so an ordinary run cannot inherit broker reachability.
    broker_enabled: bool = False
    broker_envoy_image: str = ""
    broker_state_host: str = ""
    broker_state_port: int = 0
    broker_state_peer: ClusterPeer | None = None


def _digest(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _is_canonical_dns_name(value: str) -> bool:
    return isinstance(value, str) and len(value) <= 253 \
        and all(1 <= len(label) <= 63 and _DNS_LABEL.fullmatch(label)
                for label in value.split("."))


def run_group_names(spec: RunGroupSpec) -> dict[str, str]:
    return run_group_names_for_identity(spec.run_id, spec.generation)


def run_group_names_for_identity(run_id: str, generation: str) -> dict[str, str]:
    base = f"andyur-run-{_digest(run_id, 12)}-{_digest(generation, 8)}"
    lease = f"andyur-run-{_digest(run_id, 32)}-owner"
    return {
        "base": base,
        "proxy": f"{base}-proxy",
        "agent": f"{base}-agent",
        "channel_secret": f"{base}-channel",
        "runtime_secret": f"{base}-runtime",
        "broker_config": f"{base}-broker-envoy",
        "exec_config": f"{base}-exec-config",
        "lease": lease,
    }


def _validate_label(name: str, value: str) -> None:
    if not value or len(value) > 63 or not _DNS_LABEL.fullmatch(value):
        raise ValueError(f"{name} must be a Kubernetes DNS label")


def _validate_selector(labels: Mapping[str, str]) -> None:
    for key, value in labels.items():
        name = key.rsplit("/", 1)[-1]
        if not name or len(name) > 63 or not _LABEL_NAME.fullmatch(name):
            raise ValueError("proxy egress peer has an invalid pod-label key")
        if not value or len(value) > 63 or not _LABEL_NAME.fullmatch(value):
            raise ValueError("proxy egress peer has an invalid pod-label value")


def _validate(spec: RunGroupSpec) -> None:
    if type(spec.broker_enabled) is not bool:
        raise ValueError("broker_enabled must be an exact boolean")
    _validate_label("namespace", spec.namespace)
    if not RUN_ID_PATTERN.fullmatch(spec.run_id):
        raise ValueError("run_id must match [A-Za-z0-9_-]{1,64}")
    for field in ("generation", "agent_id", "registry_agent_id"):
        value = getattr(spec, field)
        if not value or len(value) > 256:
            raise ValueError(f"{field} must be nonempty and at most 256 characters")
    for field in ("proxy_image", "agent_image"):
        if not _DIGEST_IMAGE.fullmatch(getattr(spec, field)):
            raise ValueError(f"{field} must be pinned by sha256 digest")
    broker_values = (spec.broker_envoy_image, spec.broker_state_host,
                     spec.broker_state_port, spec.broker_state_peer)
    if spec.broker_enabled:
        if not _DIGEST_IMAGE.fullmatch(spec.broker_envoy_image):
            raise ValueError("broker Envoy image must be pinned by sha256 digest")
        if not _is_canonical_dns_name(spec.broker_state_host):
            raise ValueError("broker state host must be a canonical DNS name")
        if not 1 <= spec.broker_state_port <= 65535:
            raise ValueError("broker state port must be in 1..65535")
        if spec.broker_state_peer is None \
                or spec.broker_state_peer.port != spec.broker_state_port \
                or spec.broker_state_peer not in spec.proxy_egress:
            raise ValueError(
                "broker state port requires an explicit proxy egress peer")
    elif any(broker_values):
        raise ValueError("broker transport configuration requires broker_enabled")
    if not 1 <= spec.proxy_port <= 65535:
        raise ValueError("proxy_port must be in 1..65535")
    if spec.exec_input_mode not in ("", "stdin", "file"):
        raise ValueError("exec_input_mode must be '', 'stdin' or 'file'")
    if type(spec.exec_input) is not bytes:
        raise ValueError("exec_input must be bytes")
    if spec.exec_input_mode:
        if spec.agent_interface != RUNTIME_PROTOCOL_EXEC_V1:
            raise ValueError("exec input delivery requires the exec/v1 interface")
        if spec.exec_input_max_bytes < 1:
            raise ValueError("exec input delivery requires the manifest's bound")
        if len(spec.exec_input) > spec.exec_input_max_bytes:
            raise ValueError("exec input exceeds the manifest's bound")
    elif spec.exec_input or spec.exec_input_max_bytes:
        raise ValueError("exec input without a delivery mode")
    if not 1 <= spec.mcp_port <= 65535 or spec.mcp_port == spec.proxy_port:
        raise ValueError("mcp_port must be in 1..65535 and differ from proxy_port")
    if spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1 and spec.agent_model_egress:
        # The launcher never grants it; the renderer refuses it too, so the
        # invariant does not live in one caller (R LOW): a stock workload
        # reaches the model only through its proxy Pod's pinned front.
        raise ValueError("an exec/v1 workload gets no direct model egress")
    # A generated configuration (init container + bearer secretKeyRef +
    # ConfigMap) belongs ONLY to exec/v1: a runtime-v1 agent learns its
    # configuration from its context document. The codec refuses the
    # combination upstream, but the builder is fed a RunGroupSpec that a caller
    # constructs in code, so it fails closed here too rather than shaping a Pod
    # for a runtime-v1 spec that should never have carried one.
    if spec.exec_configuration is not None \
            and spec.agent_interface != RUNTIME_PROTOCOL_EXEC_V1:
        raise ValueError(
            "exec_configuration applies only to the exec/v1 interface; a "
            f"{spec.agent_interface!r} agent takes its configuration from its "
            "context document")
    for field in (
        "proxy_cpu", "proxy_memory", "proxy_ephemeral_storage",
        "agent_cpu", "agent_memory", "agent_ephemeral_storage",
    ):
        if not getattr(spec, field):
            raise ValueError(f"{field} must be nonempty")
    peers = (*spec.proxy_egress,
             *((spec.agent_model_egress,) if spec.agent_model_egress else ()))
    for peer in peers:
        _validate_label("peer namespace", peer.namespace)
        if not peer.labels:
            raise ValueError("proxy egress peer needs at least one pod label")
        _validate_selector(peer.labels)
        if not 1 <= peer.port <= 65535:
            raise ValueError("peer port must be in 1..65535")
        if peer.protocol not in ("TCP", "UDP"):
            raise ValueError("peer protocol must be TCP or UDP")


def _labels(spec: RunGroupSpec, role: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": "andyur-run",
        "app.kubernetes.io/managed-by": "andyur-worker",
        "app.kubernetes.io/component": role,
        "andyur.run/id": _digest(spec.run_id),
        "andyur.run/generation": _digest(spec.generation),
        "andyur.agent/id": _digest(spec.agent_id),
        "andyur.registry/id": _digest(spec.registry_agent_id),
    }


def _metadata(
    name: str, namespace: str, labels: Mapping[str, str],
    annotations: Mapping[str, str] | None = None,
) -> dict:
    result = {"name": name, "namespace": namespace, "labels": dict(labels)}
    if annotations:
        result["annotations"] = dict(annotations)
    return result


def _security_context(uid: int) -> dict:
    return {
        "runAsNonRoot": True,
        "runAsUser": uid,
        "runAsGroup": uid,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _secret_env(name: str, secret: str, key: str, *, optional: bool = False) -> dict:
    ref = {"name": secret, "key": key}
    if optional:
        ref["optional"] = True
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": ref},
    }


def _resources(spec: RunGroupSpec, role: str) -> dict:
    values = {
        "cpu": getattr(spec, f"{role}_cpu"),
        "memory": getattr(spec, f"{role}_memory"),
        "ephemeral-storage": getattr(spec, f"{role}_ephemeral_storage"),
    }
    return {"requests": dict(values), "limits": dict(values)}


def _broker_resources() -> dict:
    """Bound each infrastructure helper independently of the model runner."""
    values = {"cpu": "250m", "memory": "256Mi", "ephemeral-storage": "128Mi"}
    return {"requests": dict(values), "limits": dict(values)}


def _service_account(spec: RunGroupSpec, name: str, role: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": _metadata(name, spec.namespace, _labels(spec, role)),
        "automountServiceAccountToken": False,
    }


def _proxy_pod(spec: RunGroupSpec, name: str, service_account: str) -> dict:
    labels = _labels(spec, "proxy")
    names = run_group_names(spec)
    env = [
        {"name": "ANDYUR_RUN_ID", "value": spec.run_id},
        {"name": "ANDYUR_AGENT_ID", "value": spec.agent_id},
        {"name": "ANDYUR_REGISTRY_AGENT_ID", "value": spec.registry_agent_id},
        {"name": "ANDYUR_SPIFFE_ID",
         "value": f"spiffe://{spec.trust_domain}/agent/{spec.agent_id}/run/{spec.run_id}"},
        {"name": "ANDYUR_DEPLOYMENT", "value": "kubernetes"},
        {"name": "ANDYUR_AGENT_SPLIT", "value": "pod"},
        {"name": "ANDYUR_OTEL", "value": spec.otel_mode},
        {"name": "ANDYUR_CHANNEL_PORT", "value": str(spec.proxy_port)},
        {"name": "ANDYUR_MCP_PORT", "value": str(spec.mcp_port)},
        {"name": "ANDYUR_POD_IP", "valueFrom": {
            "fieldRef": {"fieldPath": "status.podIP"},
        }},
        {"name": "SPIFFE_ENDPOINT_SOCKET", "value": _SPIFFE_SOCKET},
        _secret_env("ANDYUR_CHANNEL_TOKEN", names["channel_secret"], "token"),
        _secret_env("ANDYUR_RUN_TOKEN", names["runtime_secret"], "run-token"),
        _secret_env("LITELLM_MASTER_KEY", names["runtime_secret"], "litellm-key"),
    ]
    if spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1:
        # The serve-only sidecar accepts THIS as its MCP tool-service bearer --
        # the same dedicated per-run token the exec/v1 workload presents (M1), so
        # the declared bearer is what /mcp accepts. Only exec/v1 runs carry
        # mcp-token in the runtime Secret.
        env.append(_secret_env(
            "ANDYUR_MCP_TOKEN", names["runtime_secret"], "mcp-token"))
        # The model the assignment GRANTED -- the one source the sidecar's
        # front pins to (the same value services.model.name resolves to for
        # the workload). A public fact, so a plain value; empty = no grant.
        env.append({"name": "ANDYUR_EXEC_MODEL", "value": spec.exec_model_name})
    if spec.server_url:
        env.append({"name": "ANDYUR_SERVER_URL", "value": spec.server_url})
    if spec.run_ttl_seconds:
        env.append({"name": "ANDYUR_RUN_TTL_SECONDS",
                    "value": str(spec.run_ttl_seconds)})
    if spec.otel_endpoint:
        env.append({"name": "ANDYUR_OTEL_ENDPOINT", "value": spec.otel_endpoint})
    env.append({"name": "ANDYUR_LLM", "value": spec.llm_mode})
    if spec.ollama_url:
        env.append({"name": "ANDYUR_OLLAMA_URL", "value": spec.ollama_url})
    if spec.litellm_url:
        env.append({"name": "ANDYUR_LITELLM_URL", "value": spec.litellm_url})
    authority = {
        "ANDYUR_AS_TOKEN_ENDPOINT": spec.as_token_endpoint,
        "ANDYUR_AS_ISSUER": spec.as_issuer,
        "ANDYUR_AS_JWKS": spec.as_jwks_url,
        "ANDYUR_AS_CLIENT_ID": spec.as_client_id,
        "ANDYUR_AS_PROVIDER": spec.as_provider,
        "ANDYUR_AS_CAPABILITY": spec.as_capability,
        "ANDYUR_AS_RESOURCE_SCOPE": spec.as_resource_scope,
        "ANDYUR_AS_PRODUCT_VERSION": spec.as_product_version,
    }
    env.extend({"name": name, "value": value}
               for name, value in authority.items() if value)
    if spec.as_token_endpoint:
        env.append(_secret_env("ANDYUR_AS_CLIENT_SECRET",
                               names["runtime_secret"], "as-client-secret",
                               optional=True))
    evidence_mounts = []
    evidence_volumes = []
    if spec.as_certified:
        env.extend([
            {"name": "ANDYUR_AS_CERTIFICATION_FILE",
             "value": "/run/secrets/andyur-as/certification.json"},
            {"name": "ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE",
             "value": "/run/secrets/andyur-as/certifier.pub"},
        ])
        evidence_mounts.append({
            "name": "as-certification", "mountPath": "/run/secrets/andyur-as",
            "readOnly": True,
        })
        evidence_volumes.append({
            "name": "as-certification",
            "secret": {
                "secretName": names["runtime_secret"],
                "items": [
                    {"key": "as-certification", "path": "certification.json"},
                    {"key": "as-certification-public-key", "path": "certifier.pub"},
                ],
            },
        })
    containers = [{
        "name": "proxy",
        "image": spec.proxy_image,
        "imagePullPolicy": "IfNotPresent",
        "command": list(spec.proxy_args or (
            "python", "-m", "andyur.runner", "--agent", spec.agent_id,
            "--run-id", spec.run_id,
            # The SERVER-supplied interface -- not the image, not the env --
            # decides serve-only: an exec/v1 stock workload reports no completion
            # of its own, so this sidecar serves the model proxy + MCP and never
            # arms the connect watchdog or posts /finish (the daemon does, from
            # the container exit). A runtime-v1 container gets no such flag.
            *(("--serve-only",)
              if spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1 else ()),
        )),
        "env": env,
        "ports": [
            {"name": "proxy", "containerPort": spec.proxy_port},
            {"name": "mcp", "containerPort": spec.mcp_port},
        ],
        "readinessProbe": {
            "httpGet": {"path": "/ready", "port": "proxy", "scheme": "HTTP"},
            "periodSeconds": 2, "timeoutSeconds": 1, "failureThreshold": 15,
        },
        "securityContext": _security_context(1000),
        "resources": _resources(spec, "proxy"),
        "volumeMounts": [
            {"name": "spiffe-workload-api", "mountPath": _SPIFFE_MOUNT,
             "readOnly": True},
            {"name": "runtime-data", "mountPath": "/app/data"},
            {"name": "runtime-tmp", "mountPath": "/tmp"},
            *evidence_mounts,
        ],
    }]
    native_sidecars = []
    volumes = [
        {"name": "spiffe-workload-api",
         "csi": {"driver": "csi.spiffe.io", "readOnly": True}},
        {"name": "runtime-data", "emptyDir": {}},
        {"name": "runtime-tmp", "emptyDir": {}},
        *evidence_volumes,
    ]
    if spec.broker_enabled:
        broker_env = [
            {"name": "ANDYUR_RUN_ID", "value": spec.run_id},
            {"name": "ANDYUR_BROKER_STATE_SOCKET",
             "value": "/run/andyur-state/state.sock"},
            {"name": "ANDYUR_BROKER_SOCKET",
             "value": "/run/andyur-broker-root/broker/authz.sock"},
            {"name": "ANDYUR_BROKER_PROVISION_PARENT", "value": "on"},
            {"name": "SPIFFE_ENDPOINT_SOCKET", "value": _SPIFFE_SOCKET},
            _secret_env("ANDYUR_BROKER_TOKEN", names["runtime_secret"],
                        "broker-token"),
        ]
        native_sidecars.extend([
            {
                "name": "deny-broker", "image": spec.proxy_image,
                "imagePullPolicy": "IfNotPresent",
                "restartPolicy": "Always",
                "command": ["python", "-m", "andyur.dataplane.denybroker"],
                "env": broker_env,
                "readinessProbe": {
                    "exec": {"command": [
                        "python", "-m", "andyur.dataplane.denybroker", "--check"]},
                    "periodSeconds": 2, "timeoutSeconds": 1,
                    "failureThreshold": 15,
                },
                "securityContext": _security_context(1000),
                "resources": _broker_resources(),
                "volumeMounts": [
                    {"name": "spiffe-workload-api", "mountPath": _SPIFFE_MOUNT,
                     "readOnly": True},
                    {"name": "broker-state-uds", "mountPath": "/run/andyur-state"},
                    {"name": "broker-authz-uds",
                     "mountPath": "/run/andyur-broker-root"},
                    {"name": "broker-tmp", "mountPath": "/tmp"},
                ],
            },
            {
                "name": "broker-state-envoy", "image": spec.broker_envoy_image,
                "imagePullPolicy": "IfNotPresent",
                "restartPolicy": "Always",
                "args": ["-c", "/etc/andyur-broker/bootstrap.json",
                         "--disable-hot-restart"],
                "securityContext": _security_context(1337),
                "resources": _broker_resources(),
                "volumeMounts": [
                    {"name": "spiffe-workload-api", "mountPath": _SPIFFE_MOUNT,
                     "readOnly": True},
                    {"name": "broker-state-uds", "mountPath": "/run/andyur-state"},
                    {"name": "broker-envoy-config", "mountPath": "/etc/andyur-broker",
                     "readOnly": True},
                    {"name": "broker-envoy-tmp", "mountPath": "/tmp"},
                ],
            },
        ])
        volumes.extend([
            {"name": "broker-state-uds", "emptyDir": {}},
            {"name": "broker-authz-uds", "emptyDir": {}},
            {"name": "broker-tmp", "emptyDir": {}},
            {"name": "broker-envoy-tmp", "emptyDir": {}},
            {"name": "broker-envoy-config", "configMap": {
                "name": names["broker_config"], "items": [{
                    "key": "bootstrap.json", "path": "bootstrap.json"}] }},
        ])
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": _metadata(name, spec.namespace, labels, {
            "andyur.agent/id-raw": spec.agent_id,
            "andyur.run/id-raw": spec.run_id,
            "andyur.run/generation-raw": spec.generation,
        }),
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 20,
            "securityContext": {
                "runAsNonRoot": True,
                **({"fsGroup": 1000,
                    "fsGroupChangePolicy": "OnRootMismatch"}
                   if spec.broker_enabled else {}),
            },
            "containers": containers,
            **({"initContainers": native_sidecars} if native_sidecars else {}),
            "volumes": volumes,
        },
    }


def _exec_literal_env(spec: RunGroupSpec) -> list[tuple[str, str]]:
    """Declared variables whose value needs no run-time fact."""
    if spec.exec_configuration is None:
        return []
    return [(var.name, var.literal) for var in spec.exec_configuration.env
            if var.literal is not None]


def _exec_secret_env(spec: RunGroupSpec) -> list[str]:
    """Declared variables whose value is this run's bearer.

    Derived here rather than passed in, so a caller cannot hand this module a
    name it believes is public and have the credential inlined as a literal.
    """
    if spec.exec_configuration is None:
        return []
    return [var.name for var in spec.exec_configuration.env
            if var.reference and execconfig.is_secret_reference(var.reference)]


def _exec_files(spec: RunGroupSpec) -> list[tuple[str, str]]:
    if spec.exec_configuration is None:
        return []
    return [(f.path, f.template) for f in spec.exec_configuration.files]


def _exec_files_need_bearer(spec: RunGroupSpec) -> bool:
    """Whether any template names the bearer at all.

    A file set that never references it gets an init container with no
    credential in its environment. The smallest thing that works is the thing
    to build, and an unused credential in a process environment is exactly the
    kind of thing that is discovered later by someone reading a core dump.
    """
    for path, template in _exec_files(spec):
        for text in (path, template):
            if any(execconfig.is_secret_reference(ref)
                   for ref in TEMPLATE_REF_RE.findall(text)):
                return True
    return False


def _agent_pod(
    spec: RunGroupSpec, name: str, service_account: str, service_name: str,
) -> dict:
    names = run_group_names(spec)
    scratch_mounts = (
        {"name": "agent-home", "mountPath": execconfig.WORKSPACE_HOME},
        {"name": "agent-tmp", "mountPath": execconfig.WORKSPACE_TMP},
    )
    volumes = [
        {"name": "agent-home", "emptyDir": {}},
        {"name": "agent-tmp", "emptyDir": {}},
    ]
    # CONDITIONAL, and only on FILES. A declared environment needs no helper --
    # it goes into the Pod spec exactly as the builtin agent's does. Only a
    # generated FILE has nowhere else to come from: the root filesystem is
    # read-only, a ConfigMap mount would be read-only where a stock tool
    # rewrites its own config, and nothing inside the workload knows the file
    # should exist. So a workload configured entirely by variables gets the
    # same Pod shape as a native agent, with no extra container and no extra
    # startup latency.
    # The same init container ALSO persists the run's input under mode
    # 'file': the controller attaches to its stdin and writes the bytes, it
    # writes them verbatim to INPUT_PATH, and only then does the workload
    # start. One container for both jobs, present when either is needed.
    # THE CONTAINMENT BARRIER, and it runs before anything else in this Pod.
    #
    # A Pod's network is usable before the CNI has programmed its NetworkPolicy
    # rules. Measured on this platform's own run group, with the policies
    # already in place for minutes beforehand: the agent Pod reached the public
    # internet, the Kubernetes API and cluster DNS for the first 0.3-0.9s of its
    # life, then enforcement began. The window is a property of the POD, not of
    # the policy's age -- which is why "Policies, Service and proxy exist before
    # untrusted code" (kubernetes_controller.launch) is correct and does not
    # close it.
    #
    # That window belongs to a THIRD-PARTY IMAGE. An exec/v1 workload is stock
    # code we did not write; an entrypoint that opens a socket in its first
    # 100ms is not a race it has to win by luck, and its env holds the run's MCP
    # bearer. So the agent container must not be allowed to run during it.
    #
    # kubelet will not start any app container until every initContainer has
    # exited 0, and a workload image controls only its own container -- never
    # this one. So the barrier is simply: do not exit until the egress this
    # Pod is forbidden is actually refused.
    #
    # WHAT IT PROBES, and why two things rather than one. The Kubernetes API
    # (whose address kubelet injects into every Pod, so this needs no plumbing)
    # and cluster DNS -- the exfiltration channel `agent_policy` removes on
    # purpose. Either alone could be denied for a reason that is not
    # enforcement; both at once, from a Pod whose policy forbids both, is the
    # signal. It FAILS CLOSED: a Pod that never observes enforcement never runs
    # its workload.
    init_containers: list[dict] = [{
        "name": "await-containment",
        # The PLATFORM's image. The barrier is exactly the thing a workload
        # image must not be able to influence.
        "image": spec.proxy_image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-c", _CONTAINMENT_BARRIER],
        "env": [{"name": "ANDYUR_BARRIER_TIMEOUT",
                 "value": str(CONTAINMENT_BARRIER_TIMEOUT)}],
        "securityContext": _security_context(1001),
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"memory": "64Mi"}},
    }]
    exec_files = _exec_files(spec)
    file_input = spec.exec_input_mode == "file"
    if exec_files:
        volumes.append({"name": "exec-config", "configMap": {
            "name": names["exec_config"],
            "items": [{"key": execconfig.TEMPLATES_FILE,
                       "path": execconfig.TEMPLATES_FILE}]}})
    if exec_files or file_input:
        init_containers.append({
            "name": "materialize-config",
            # The PLATFORM's image, not the workload's. Rendering enforces the
            # closed vocabulary and re-establishes containment on the resolved
            # path, so it has to be code we control; a stock image has neither
            # the code nor any reason to carry it.
            "image": spec.proxy_image,
            "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-m", "andyur.execconfig"],
            **({"stdin": True, "stdinOnce": True} if file_input else {}),
            "env": [
                {"name": execconfig.FACTS_ENV, "value": spec.exec_facts},
                # M1 / ADR-011 D2: the exec/v1 bearer is the DEDICATED per-run
                # MCP token from the runtime Secret, NOT the channel token, as
                # the complete Authorization header value (`mcp-authorization`
                # = `Bearer <token>`): the reference a template names is a
                # HEADER, and the rendered file must hold what a stock tool
                # sends verbatim. The serve-only tool service accepts exactly
                # the token inside it.
                *([_secret_env(execconfig.BEARER_ENV,
                               names["runtime_secret"], "mcp-authorization")]
                  if _exec_files_need_bearer(spec) else []),
                *([{"name": execconfig.INPUT_PATH_ENV,
                    "value": execconfig.INPUT_PATH},
                   {"name": execconfig.INPUT_MAX_ENV,
                    "value": str(spec.exec_input_max_bytes)},
                   {"name": execconfig.INPUT_LEN_ENV,
                    "value": str(len(spec.exec_input))}]
                  if file_input else []),
            ],
            "securityContext": _security_context(1001),
            "resources": _broker_resources(),
            "volumeMounts": [
                *scratch_mounts,
                *([{"name": "exec-config",
                    "mountPath": execconfig.TEMPLATES_MOUNT, "readOnly": True}]
                  if exec_files else []),
            ],
        })
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": _metadata(name, spec.namespace, _labels(spec, "agent")),
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 10,
            "securityContext": {"runAsNonRoot": True},
            "containers": [{
                "name": "agent",
                "image": spec.agent_image,
                "imagePullPolicy": "IfNotPresent",
                "command": list(spec.agent_args or (
                    "python", "-m", "andyur.agent", "--channel-url",
                    f"http://{service_name}:{spec.proxy_port}",
                )),
                # Mode 'stdin': the workload's stdin stays open for exactly
                # one attach (the controller's) and closes when it ends.
                **({"stdin": True, "stdinOnce": True}
                   if spec.exec_input_mode == "stdin" else {}),
                "env": _agent_env(spec, names),
                "securityContext": _security_context(1001),
                "resources": _resources(spec, "agent"),
                "volumeMounts": list(scratch_mounts),
            }],
            **({"initContainers": init_containers} if init_containers else {}),
            "volumes": volumes,
        },
    }


# How long the barrier waits for enforcement before refusing to start the
# workload. The measured window is under a second; this is two orders of
# magnitude of headroom, and a Pod that exceeds it has something wrong with its
# CNI rather than a slow one.
CONTAINMENT_BARRIER_TIMEOUT = 60

# Runs in the PLATFORM's image, in the agent Pod's network namespace, before
# the workload container is allowed to start. Prints a timeline so the window
# this Pod actually had is visible in `kubectl logs -c await-containment`
# rather than inferred.
_CONTAINMENT_BARRIER = r"""
import os, socket, sys, time

api = os.environ.get("KUBERNETES_SERVICE_HOST", "")
port = int(os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or 443)
deadline = time.monotonic() + float(os.environ.get("ANDYUR_BARRIER_TIMEOUT") or 60)
t0 = time.monotonic()

def open_(host, p):
    try:
        socket.create_connection((host, p), 1).close()
        return True
    except OSError:
        return False

def resolves():
    socket.setdefaulttimeout(1)
    try:
        socket.getaddrinfo("kubernetes.default.svc", 443)
        return True
    except OSError:
        return False

saw_open = False
while time.monotonic() < deadline:
    reachable = bool(api) and open_(api, port)
    resolved = resolves()
    if reachable or resolved:
        saw_open = True
    else:
        waited = round(time.monotonic() - t0, 3)
        sys.stdout.write(
            "containment in force after %ss (window observed: %s)\n"
            % (waited, "yes" if saw_open else "no -- already enforced at start"))
        sys.stdout.flush()
        raise SystemExit(0)
    time.sleep(0.02)

sys.stdout.write(
    "REFUSING TO START THE WORKLOAD: this Pod could still reach the Kubernetes "
    "API or resolve DNS after %ss, both of which its NetworkPolicy forbids. "
    "Either the policy was not applied or the CNI is not enforcing it.\n"
    % round(time.monotonic() - t0, 3))
sys.stdout.flush()
raise SystemExit(1)
"""


def _agent_env(spec: RunSpec, names: dict) -> list:
    """What the agent workload is allowed to see.

    A BYOA container is a third party. The published contract
    (docs/agent-runtime-protocol-v1.md section 2) promises it EXACTLY two
    variables, both added by the controller once the proxy's Pod IP is known,
    so this returns nothing for it. The variables below are the builtin
    agent's own configuration: passing them to a BYOA workload would hand a
    third party the platform's model mode, its CLI path, and -- worst --
    ANDYUR_CHANNEL_TOKEN, which is the same secret value the contract already
    exposes under its documented name. Two names for one bearer invites an
    agent to depend on the undocumented one, and widens what a compromised
    workload can see for no benefit to it.
    """
    if spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1:
        # exec/v1 is the one BYOA case that receives more than the contract's
        # two variables, and the reason it is not a widening: every name here
        # was declared by a REVIEWED MANIFEST and resolved through the closed
        # vocabulary, which cannot name a downstream credential. None of it is
        # platform internals -- the objection above is about handing a third
        # party the platform's own configuration, not about honouring the
        # configuration that party's own approved manifest asked for.
        #
        # Bearer-backed names are absent from these values by construction:
        # plan_environment returns them as NAMES, so this function could not
        # inline the credential even if it tried.
        return [
            *({"name": name, "value": value}
              for name, value in _exec_literal_env(spec)),
            # M1 / ADR-011 D2: a declared bearer-backed env (e.g. the manifest's
            # MCP_AUTH) resolves to the DEDICATED per-run MCP token from the
            # runtime Secret, NOT the channel token, as the complete header
            # value (`mcp-authorization` = `Bearer <token>`) -- what the
            # serve-only tool service accepts, in the form a stock tool sends.
            # The workload never holds the channel secret by any delivery path
            # (env or rendered file), and never the bare `mcp-token` key.
            *(_secret_env(name, names["runtime_secret"], "mcp-authorization")
              for name in _exec_secret_env(spec)),
        ]
    if spec.agent_runtime != "builtin-claude":
        return []
    return [
        {"name": "ANDYUR_RUN_ID", "value": spec.run_id},
        {"name": "ANDYUR_AGENT_ID", "value": spec.agent_id},
        # This Pod already runs exclusively as uid 1001. The image's setpriv
        # wrapper is for a uid-1000 Docker sidecar spawning uid 1001; invoking
        # it here would require privileges this intentionally capability-free
        # Pod does not have.
        {"name": "ANDYUR_AGENT_CLI", "value": "/usr/bin/claude"},
        {"name": "ANDYUR_LLM", "value": spec.llm_mode},
        *([{"name": "ANDYUR_OLLAMA_URL", "value": spec.ollama_url}]
          if spec.ollama_url else []),
        {"name": "HOME", "value": "/home/agent"},
        _secret_env("ANDYUR_CHANNEL_TOKEN", names["channel_secret"], "token"),
    ]


def _dns_egress() -> dict:
    return {
        "to": [{
            "namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "kube-system",
            }},
            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
        }],
        "ports": [
            {"protocol": "UDP", "port": 53},
            {"protocol": "TCP", "port": 53},
        ],
    }


def _peer_egress(peer: ClusterPeer) -> dict:
    return {
        "to": [{
            "namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": peer.namespace,
            }},
            "podSelector": {"matchLabels": dict(peer.labels)},
        }],
        "ports": [{"protocol": peer.protocol, "port": peer.port}],
    }


def build_run_group(spec: RunGroupSpec) -> Sequence[dict]:
    """Return the complete, ordered resource set for one run."""
    _validate(spec)
    names = run_group_names(spec)
    base = names["base"]
    proxy_name, agent_name = names["proxy"], names["agent"]
    proxy_sa, agent_sa = names["proxy"], names["agent"]
    service_name = names["proxy"]
    run_label = {
        "app.kubernetes.io/managed-by": "andyur-worker",
        "andyur.run/id": _digest(spec.run_id),
        "andyur.run/generation": _digest(spec.generation),
    }
    proxy_selector = {**run_label, "app.kubernetes.io/component": "proxy"}
    agent_selector = {**run_label, "app.kubernetes.io/component": "agent"}

    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _metadata(service_name, spec.namespace, _labels(spec, "proxy")),
        "spec": {
            "selector": proxy_selector,
            "ports": [{"name": "proxy", "port": spec.proxy_port,
                       "targetPort": "proxy"}],
        },
    }
    default_deny = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{base}-deny", spec.namespace, run_label),
        "spec": {
            "podSelector": {"matchLabels": run_label},
            "policyTypes": ["Ingress", "Egress"],
        },
    }
    agent_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{base}-agent", spec.namespace, agent_selector),
        "spec": {
            "podSelector": {"matchLabels": agent_selector},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            # No DNS. A recursive resolver is an exfiltration channel. The
            # controller replaces ANDYUR_PROXY_URL with the proxy Pod IP before
            # creating the untrusted agent.
            "egress": [{
                "to": [{"podSelector": {"matchLabels": proxy_selector}}],
                "ports": [
                    {"protocol": "TCP", "port": spec.proxy_port},
                    {"protocol": "TCP", "port": spec.mcp_port},
                ],
            }, *([_peer_egress(spec.agent_model_egress)]
                 if spec.agent_model_egress else [])],
        },
    }
    proxy_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{base}-proxy", spec.namespace, proxy_selector),
        "spec": {
            "podSelector": {"matchLabels": proxy_selector},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": agent_selector}}],
                "ports": [
                    {"protocol": "TCP", "port": spec.proxy_port},
                    {"protocol": "TCP", "port": spec.mcp_port},
                ],
            }],
            "egress": [_dns_egress(), *map(_peer_egress, spec.proxy_egress)],
        },
    }
    broker_config = ()
    if spec.broker_enabled:
        transport = BrokerTransport(
            run_spiffe_id=(f"spiffe://{spec.trust_domain}/agent/{spec.agent_id}/"
                           f"run/{spec.run_id}"),
            control_plane_spiffe_id=(
                f"spiffe://{spec.trust_domain}/control-plane"),
            trust_domain=spec.trust_domain,
            egress_socket="/run/andyur-state/state.sock",
            ingress_host=spec.broker_state_host,
            ingress_port=spec.broker_state_port,
            backend_socket="/run/andyur-server/broker-state.sock",
        )
        broker_config = ({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": _metadata(names["broker_config"], spec.namespace,
                                  _labels(spec, "broker-config")),
            "immutable": True,
            "data": {"bootstrap.json": json.dumps(
                build_egress_bootstrap(transport), sort_keys=True)},
        },)
    exec_config = ()
    if _exec_files(spec):
        exec_config = ({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": _metadata(names["exec_config"], spec.namespace,
                                  _labels(spec, "exec-config")),
            "immutable": True,
            # TEMPLATES, not rendered output. These are manifest data already
            # carried in the signed resolution and hold no credential; the
            # rendered result would, which is why it never becomes an object.
            "data": {execconfig.TEMPLATES_FILE: json.dumps(
                [{"path": path, "template": template}
                 for path, template in _exec_files(spec)], sort_keys=True)},
        },)
    return (
        _service_account(spec, proxy_sa, "proxy"),
        _service_account(spec, agent_sa, "agent"),
        service,
        default_deny,
        agent_policy,
        proxy_policy,
        *broker_config,
        *exec_config,
        _proxy_pod(spec, proxy_name, proxy_sa),
        _agent_pod(spec, agent_name, agent_sa, service_name),
    )

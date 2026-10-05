"""Lifecycle controller for a Kubernetes Andyur run group.

The Kubernetes SDK is deliberately behind :class:`KubernetesApi`. This module
owns the safety semantics -- exact-generation ownership, proxy-first startup,
bounded readiness, rollback and adoption validation -- while an SDK adapter
owns transport details. Tests exercise the same controller with an in-memory
API; the real-cluster suite exercises the adapter and CNI behavior.
"""

from __future__ import annotations

import logging
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Protocol, Sequence

from .. import execconfig, otel
from ..registry.models import RUNTIME_PROTOCOL_EXEC_V1
from .kubernetes_manifests import (
    RUN_ID_PATTERN,
    RunGroupSpec,
    build_run_group,
    run_group_names,
    run_group_names_for_identity,
)


_TERMINAL = {"Succeeded": 0, "Failed": 1}


# The launching process's service name -- the daemon's, or the engine's
# execution worker's (see daemon.SERVICE; read here directly to avoid an import
# cycle).
_SERVICE = os.environ.get("ANDYUR_SERVICE_NAME", "").strip() or "andyur-daemon"


class _wait:
    """One bounded wait as a span with its duration and outcome BY NAME, and
    the `andyur.controller.wait_seconds` histogram (observability-exit-criteria
    4, 5): `controller.wait_ready`, `controller.attach`, `controller.rollback`,
    `controller.delete`. A child of the daemon's launch span (same thread), so
    it sits in the run's trace. Telemetry never changes the control's outcome."""

    # span suffix -> the bounded metric operation (observability._OPERATIONS)
    METRIC_OPERATION = {"wait_ready": "readiness", "attach": "attach", "rollback": "rollback", "delete": "delete"}

    def __init__(self, operation: str, run_id: str, **attributes):
        self.operation, self.run_id, self.attributes = operation, run_id, attributes
        self.outcome = "unknown"
        self._manager = None
        self._span = None
        self._started = time.monotonic()

    def __enter__(self):
        try:
            self._manager = otel.setup_tracing(_SERVICE).start_as_current_span(
                f"controller.{self.operation}")
            self._span = self._manager.__enter__()
            self._span.set_attribute("andyur.run_id", self.run_id)
            self._span.set_attribute("andyur.operation", self.operation)
            for key, value in self.attributes.items():
                self._span.set_attribute(f"andyur.{key}", value)
        except Exception:
            self._manager, self._span = None, None
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed = time.monotonic() - self._started
        if exc is not None and self.outcome == "unknown":
            self.outcome = f"error:{type(exc).__name__}"
        metric_outcome = ("success" if self.outcome in ("ready", "delivered", "rolled_back", "deleted")
                          else "timeout" if self.outcome == "timeout" else "failure")
        otel.try_record_metric(_SERVICE, "andyur.controller.wait_seconds", elapsed,
                               andyur__operation=self.METRIC_OPERATION.get(self.operation, self.operation),
                               andyur__outcome=metric_outcome)
        if self._span is not None:
            try:
                self._span.set_attribute("andyur.outcome", self.outcome)
                self._span.set_attribute("andyur.seconds", round(elapsed, 3))
                if exc is not None:
                    from opentelemetry.trace import Status, StatusCode
                    self._span.set_status(Status(StatusCode.ERROR))
            except Exception:
                pass
        if self._manager is not None:
            try:
                self._manager.__exit__(None, None, None)
            except Exception:
                pass
        return False


log = logging.getLogger("andyur.kubernetes-controller")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class PodSnapshot:
    name: str
    phase: str
    labels: dict[str, str]
    annotations: dict[str, str]


@dataclass(frozen=True)
class LeaseClaim:
    name: str
    uid: str
    resource_version: str
    holder: str


@dataclass(frozen=True)
class RunCredentials:
    channel_token: str
    run_token: str
    litellm_key: str
    as_client_secret: str = ""
    as_certification: str = ""
    as_certification_public_key: str = ""
    broker_token: str = ""
    # exec/v1 only (M1 / ADR-011 D2): a DEDICATED per-run MCP bearer, distinct
    # from the channel token. The stock workload authenticates to /mcp with this
    # (delivered by secretKeyRef, never the channel secret), and the serve-only
    # tool service accepts exactly this -- so "the declared bearer is what /mcp
    # accepts" holds without the third-party image ever holding the channel token.
    mcp_bearer: str = ""


class KubernetesApi(Protocol):
    """Narrow capability required from the official Kubernetes client adapter."""

    def apply(self, resource: dict) -> None: ...

    def wait_pod_ready(self, namespace: str, name: str, timeout: float) -> bool: ...

    def pod_ip(self, namespace: str, name: str) -> str: ...

    def assert_isolation_ready(self, namespace: str) -> None: ...

    def claim_run_singleton(
        self, namespace: str, name: str, labels: dict[str, str], owner: str,
    ) -> LeaseClaim | None: ...

    def release_run_singleton(
        self, namespace: str, claim: LeaseClaim, timeout: float,
    ) -> None: ...

    def read_run_singleton(
        self, namespace: str, name: str, labels: dict[str, str], owner: str,
        timeout: float,
    ) -> LeaseClaim | None: ...

    def pod_phase(self, namespace: str, name: str) -> str | None: ...

    def read_container_exit(
        self, namespace: str, name: str, container: str,
    ) -> int | None: ...

    def wait_container_running(
        self, namespace: str, name: str, container: str, timeout: float,
    ) -> bool: ...

    def attach_stdin(
        self, namespace: str, name: str, container: str, data: bytes,
    ) -> None: ...

    def list_pods(
        self, namespace: str, selector: dict[str, str], timeout: float, limit: int,
    ) -> Sequence[PodSnapshot]: ...

    def delete_run_group(
        self, namespace: str, selector: dict[str, str], timeout: float,
    ) -> None: ...


class KubernetesRunHandle:
    """Popen-shaped status handle consumed by the existing daemon loop."""

    # Kubernetes has no meaningful local process id. Zero is never used for
    # signalling: KubernetesOrchestrator marks a handle terminal before the
    # daemon considers its local process-group fallback.
    pid = 0

    def __init__(self, api: KubernetesApi, namespace: str, pod_name: str,
                 absent_grace_until: float | None = None) -> None:
        self._api = api
        self._namespace = namespace
        self._pod_name = pod_name
        self._forced_code: int | None = None
        # ADOPTED handles only (see `adopt`): until this monotonic instant an
        # absent agent Pod means "not created yet", not "exited".
        self._absent_grace_until = absent_grace_until

    def mark_deleted(self) -> None:
        self._forced_code = 137

    def poll(self) -> int | None:
        if self._forced_code is not None:
            return self._forced_code
        phase = self._api.pod_phase(self._namespace, self._pod_name)
        if (phase is None and self._absent_grace_until is not None
                and time.monotonic() < self._absent_grace_until):
            return None
        # Once launch returned, absence is terminal. Treating it as running
        # forever would strand a worker slot after an external eviction/delete.
        return 1 if phase is None else _TERMINAL.get(phase)


def _bind_exec_configuration(spec, agent: dict, proxy_ip: str) -> None:
    """Resolve the exec/v1 references that only exist once the proxy does.

    Deliberately here, beside the ANDYUR_RUNTIME_URL binding, and for the same
    reason: the agent Pod has no DNS, so every services.* reference resolves to
    a Pod IP that does not exist until the trusted proxy is ready. Resolving
    them at manifest-build time would mean inventing an address.

    The bearer is NOT resolved here. plan_environment returns bearer-backed
    variables as names, and the Pod builder already wired those to a
    secretKeyRef, so the credential never passes through this process.
    """
    facts = execconfig.RunFacts(
        run_id=spec.run_id,
        deadline_epoch=int(time.time()) + (spec.run_ttl_seconds or 0),
        model_base_url=f"http://{proxy_ip}:{spec.proxy_port}/llm",
        model_openai_base_url=f"http://{proxy_ip}:{spec.proxy_port}/llm/v1",
        model_name=spec.exec_model_name,
        # The same governed endpoint runtime-v1 hands its agents: one
        # ToolService per run, at MCP_PATH on the proxy Pod's mcp port.
        mcp_url=f"http://{proxy_ip}:{spec.mcp_port}{execconfig.MCP_PATH}",
        workspace_home=execconfig.WORKSPACE_HOME,
        workspace_tmp=execconfig.WORKSPACE_TMP,
        # Only mode 'file' writes the input file, so only then does
        # ${run.input_path} have a referent. Empty under every other mode, and
        # empty fails closed at resolve() -- a template naming it there is a
        # manifest the parser already refused, but the launcher does not assume
        # the parser ran.
        input_path=(execconfig.INPUT_PATH
                    if spec.exec_input_mode == "file" else ""),
    )
    [agent_container] = agent["spec"]["containers"]
    # Only variables the Pod builder could not already decide. It emitted the
    # literals and the secretKeyRef entries; adding them again would leave two
    # entries with one name, where the value depends on which the API server
    # keeps.
    present = {entry["name"] for entry in agent_container.get("env", [])}
    plain, _secret_names = execconfig.plan_environment(
        spec.exec_configuration, facts)
    agent_container.setdefault("env", []).extend(
        {"name": name, "value": value}
        for name, value in plain if name not in present)

    resolved_facts = json.dumps(facts.public(), sort_keys=True)
    for init_container in agent["spec"].get("initContainers", []):
        for entry in init_container.get("env", []):
            if entry["name"] == execconfig.FACTS_ENV:
                entry["value"] = resolved_facts


# Which container receives the attach, per delivery mode. 'stdin' goes to the
# workload itself; 'file' goes to the platform's init container, which
# persists the bytes to execconfig.INPUT_PATH before the workload starts.
_EXEC_INPUT_TARGET = {"stdin": "agent", "file": "materialize-config"}


def _deliver_exec_input(api: KubernetesApi, namespace: str, pod: str,
                        spec: RunGroupSpec, timeout: float) -> None:
    """Write the run's input into the target container's stdin, by attach.

    Ordered AFTER the Pod is applied and the target container is Running,
    because the API refuses an attach to a container that has not started
    (probed on k3s: the handshake fails). wait_container_running is bounded by
    READY_TIMEOUT; the attach WRITE is bounded by the socket timeout plus
    attach_stdin's chunked total-deadline (see kubernetes_api); the attach
    HANDSHAKE is the one unbounded leg (a wedged node can stall it -- stated
    residual, see _open_attach_stream). A stock image that cannot start fails
    the launch by name here, inside the rollback scope.

    The bytes are the run's input VERBATIM. They never pass through
    execconfig.substitute(): an input containing ${...} is delivered as those
    characters, which is what keeps a caller-controlled payload from ever
    resolving to this run's bearer.
    """
    target = _EXEC_INPUT_TARGET[spec.exec_input_mode]
    if not api.wait_container_running(namespace, pod, target, timeout):
        raise RuntimeError(
            f"exec/v1 input target container {target!r} of run {spec.run_id} "
            f"was not running within {timeout:.0f}s; input not delivered")
    api.attach_stdin(namespace, pod, target, spec.exec_input)


class KubernetesRunController:
    # First issuance for a newly created per-run SPIFFE entry and cold model
    # proxy startup can legitimately exceed 30s on a local or autoscaled node.
    # Still bounded: a broken proxy rolls the complete generation back.
    READY_TIMEOUT = 60.0
    DELETE_TIMEOUT = 30.0
    ADOPTION_TIMEOUT = 10.0
    # One full launch: the proxy's readiness wait, then input delivery (bounded
    # by the same wait), plus margin.
    ADOPTION_LAUNCH_GRACE = 2 * READY_TIMEOUT + 30.0
    MAX_ADOPTED_PODS = 64

    # COMPLETION BEFORE CLEANUP on the launch-failure path (run execution
    # draft R4). Set for the engine's run-scoped controller: a failed launch
    # still deletes everything it created, but keeps the run's fence until
    # Andyur has acknowledged the failure (`release_fence`). Released first, an
    # unacknowledged failure let the engine's retry launch the run again.
    retain_fence_on_failed_launch = False

    def __init__(
        self, api: KubernetesApi, namespace: str, owner_generation: str | None = None,
    ) -> None:
        self.api = api
        self.namespace = namespace
        self.owner_generation = owner_generation
        self.api.assert_isolation_ready(namespace)
        self._handles: dict[tuple[str, str], KubernetesRunHandle] = {}
        self._claims: dict[tuple[str, str], LeaseClaim] = {}

    @staticmethod
    def selector(spec: RunGroupSpec) -> dict[str, str]:
        return {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "andyur.run/id": _digest(spec.run_id),
            "andyur.run/generation": _digest(spec.generation),
        }

    def launch(
        self, spec: RunGroupSpec, credentials: RunCredentials,
    ) -> KubernetesRunHandle:
        if spec.namespace != self.namespace:
            raise ValueError("run namespace does not match controller namespace")
        if type(spec.broker_enabled) is not bool:
            raise ValueError("broker_enabled must be an exact boolean")
        if type(credentials.broker_token) is not str:
            raise ValueError("broker token must be a string")
        if spec.broker_enabled != bool(credentials.broker_token):
            raise ValueError(
                "broker-enabled run requires exactly one explicit broker token")
        # exec/v1 (M1): the workload's bearer env and its config-render init
        # container, and the serve-only proxy's ANDYUR_MCP_TOKEN, all reference
        # keys of the runtime Secret that exist only when a bearer was minted.
        # An empty bearer must be refused HERE, by name -- otherwise the group
        # is created, the Pods sit in CreateContainerConfigError ("secret key
        # not found"), and the failure surfaces as READY_TIMEOUT with no cause.
        # The converse is refused too: a runtime-v1 sidecar mints its own MCP
        # token over the channel, so a bearer on that group is a credential
        # nothing reads, sitting in a Secret.
        exec_v1 = spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1
        if exec_v1 and not credentials.mcp_bearer:
            raise ValueError(
                "exec/v1 run group requires the dedicated per-run MCP bearer "
                "(credentials.mcp_bearer); refusing to launch a workload whose "
                "/mcp bearer would reference an absent Secret key")
        if credentials.mcp_bearer and not exec_v1:
            raise ValueError(
                "only an exec/v1 run group carries an MCP bearer; a runtime-v1 "
                "sidecar mints its own tool-service token")
        # The capability stamp is deliberately short-lived. A construction-only
        # check lets a long-running worker launch forever after it expires.
        self.api.assert_isolation_ready(self.namespace)
        if spec.as_certified and (not credentials.as_certification or
                                  not credentials.as_certification_public_key):
            raise ValueError(
                "certified AS launch requires certification and pinned public key")
        if not spec.as_certified and (credentials.as_certification or
                                      credentials.as_certification_public_key):
            raise ValueError("uncertified AS launch cannot carry certification evidence")
        resources = list(build_run_group(spec))
        agent = resources.pop()
        proxy = next(
            item for item in resources
            if item["kind"] == "Pod"
            and item["metadata"]["labels"]["app.kubernetes.io/component"] == "proxy"
        )
        selector = self.selector(spec)
        names = run_group_names(spec)
        claim = self.api.claim_run_singleton(
            self.namespace, names["lease"], selector, spec.generation,
        )
        if claim is None:
            raise RuntimeError(
                f"Kubernetes run {spec.run_id!r} is already owned")
        secrets = [
            {
                "apiVersion": "v1", "kind": "Secret", "immutable": True,
                "metadata": {
                    "name": names["channel_secret"], "namespace": self.namespace,
                    "labels": {**selector, "app.kubernetes.io/component": "channel"},
                },
                "stringData": {"token": credentials.channel_token},
            },
            {
                "apiVersion": "v1", "kind": "Secret", "immutable": True,
                "metadata": {
                    "name": names["runtime_secret"], "namespace": self.namespace,
                    "labels": {**selector, "app.kubernetes.io/component": "runtime"},
                },
                "stringData": {
                    "run-token": credentials.run_token,
                    "litellm-key": credentials.litellm_key,
                    # exec/v1's dedicated MCP bearer (M1), in TWO spellings of
                    # ONE minted value: `mcp-token` is the bare token the
                    # serve-only proxy's ToolService compares against;
                    # `mcp-authorization` is the complete header value
                    # (`Bearer <token>`) the workload sends, because the
                    # reference it declared names the Authorization HEADER
                    # (`services.tools.mcp_headers.Authorization`, the same
                    # header runtime-v1 publishes) and a secretKeyRef delivers
                    # bytes verbatim -- nothing between the Secret and a stock
                    # tool can add the scheme. The workload gets ONLY
                    # `mcp-authorization` by secretKeyRef, never run-token.
                    **({"mcp-token": credentials.mcp_bearer,
                        "mcp-authorization": f"Bearer {credentials.mcp_bearer}"}
                       if credentials.mcp_bearer else {}),
                    **({"broker-token": credentials.broker_token}
                       if spec.broker_enabled else {}),
                    **({"as-client-secret": credentials.as_client_secret}
                       if credentials.as_client_secret else {}),
                    **({
                        "as-certification": credentials.as_certification,
                        "as-certification-public-key":
                            credentials.as_certification_public_key,
                    } if credentials.as_certification else {}),
                },
            },
        ]
        try:
            # Policies, Service and proxy exist before untrusted code. The agent
            # is never created unless its only allowed destination is ready.
            for resource in [*secrets, *resources]:
                self.api.apply(resource)
            with _wait("wait_ready", spec.run_id, timeout_seconds=float(self.READY_TIMEOUT)) as waited:
                ready = self.api.wait_pod_ready(
                    self.namespace, proxy["metadata"]["name"], self.READY_TIMEOUT)
                if not ready:
                    # wait_pod_ready returns at once for a Pod that EXITED; say so,
                    # rather than reporting the timeout it did not wait for (R LOW).
                    try:
                        phase = self.api.pod_phase(self.namespace, proxy["metadata"]["name"])
                    except Exception:                              # noqa: BLE001
                        phase = None
                    waited.outcome = f"phase:{phase}" if phase in ("Failed", "Succeeded") else "timeout"
                    if phase in ("Failed", "Succeeded"):
                        raise RuntimeError(
                            f"Kubernetes proxy for run {spec.run_id} exited before "
                            f"it was ready (Pod phase {phase})")
                    raise RuntimeError(
                        f"Kubernetes proxy for run {spec.run_id} was not ready "
                        f"within {self.READY_TIMEOUT}s"
                    )
                waited.outcome = "ready"
            proxy_ip = self.api.pod_ip(self.namespace, proxy["metadata"]["name"])
            [agent_container] = agent["spec"]["containers"]
            runtime_url = f"http://{proxy_ip}:{spec.proxy_port}"
            if spec.agent_interface == RUNTIME_PROTOCOL_EXEC_V1:
                # M1 / ADR-011 D2: a stock exec/v1 image is a THIRD PARTY and
                # gets NO runtime channel token. It reaches the model proxy and
                # MCP by the resolved configuration below, authenticating to /mcp
                # with the DECLARED bearer (services.tools.mcp_headers), never the
                # platform's channel secret. Injecting ANDYUR_RUNTIME_TOKEN here
                # would hand a third-party image the exact bearer the runtime-v1
                # channel uses -- the whole point of exec/v1's separate identity.
                _bind_exec_configuration(spec, agent, proxy_ip)
            else:
                # runtime-v1 BYOA public contract: the two published aliases,
                # added only after the trusted proxy is ready and its exact Pod
                # IP is known. The token comes from the same immutable Secret as
                # the legacy channel token; it is never materialized here.
                agent_container.setdefault("env", []).extend([
                    {"name": "ANDYUR_RUNTIME_URL", "value": runtime_url},
                    {"name": "ANDYUR_RUNTIME_TOKEN", "valueFrom": {
                        "secretKeyRef": {
                            "name": names["channel_secret"], "key": "token",
                        },
                    }},
                ])

            command = agent_container["command"]
            if "--channel-url" in command:
                index = command.index("--channel-url") + 1
                if index >= len(command):
                    raise RuntimeError("agent --channel-url has no value")
                # Legacy platform agent compatibility. BYOA runtimes consume
                # ANDYUR_RUNTIME_URL instead and do not need a command rewrite.
                command[index] = runtime_url
            self.api.apply(agent)
            if spec.exec_input_mode:
                with _wait("attach", spec.run_id, input_mode=spec.exec_input_mode,
                           input_bytes=len(spec.exec_input or b"")) as attached:
                    _deliver_exec_input(
                        self.api, self.namespace, agent["metadata"]["name"], spec,
                        self.READY_TIMEOUT)
                    attached.outcome = "delivered"
        except Exception as launch_error:
            proxy_logs = ""
            read_logs = getattr(self.api, "pod_logs", None)
            if read_logs is not None:
                try:
                    proxy_logs = read_logs(
                        self.namespace, proxy["metadata"]["name"], 80)[-4000:]
                except Exception:
                    proxy_logs = ""
            with _wait("rollback", spec.run_id, cause=type(launch_error).__name__) as rolled:
                try:
                    cleanup_deadline = time.monotonic() + self.DELETE_TIMEOUT
                    self.api.delete_run_group(
                        self.namespace, selector, self.DELETE_TIMEOUT)
                    if self.retain_fence_on_failed_launch:
                        # Held for `release_fence`, after the outcome lands.
                        self._claims[(spec.run_id, spec.generation)] = claim
                        rolled.outcome = "rolled_back_fence_held"
                    else:
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError(
                                "Kubernetes singleton rollback deadline expired")
                        self.api.release_run_singleton(
                            self.namespace, claim, remaining)
                        rolled.outcome = "rolled_back"
                except Exception as cleanup_error:
                    rolled.outcome = "rollback_failed"
                    raise RuntimeError(
                        f"run-group launch failed ({launch_error}); rollback also "
                        f"failed ({cleanup_error})"
                    ) from launch_error
            # ALWAYS the wrapped shape: "run-group launch failed (<cause>)" says
            # the group was rolled back, and callers (the daemon's launch log,
            # the live gates' refusal checks) key on it. This used to re-raise
            # the bare cause when the proxy had no log output -- unnoticed
            # while pod_logs returned a bytes-repr ("b''") for an empty log,
            # and exposed the moment that read was fixed (PR #20 H3): a silent
            # proxy then produced an unwrapped refusal (broker-lifecycle gate).
            raise RuntimeError(
                f"run-group launch failed ({launch_error}); "
                + (f"proxy tail:\n{proxy_logs}" if proxy_logs
                   else "proxy produced no output")
            ) from launch_error
        handle = KubernetesRunHandle(
            self.api, self.namespace, agent["metadata"]["name"])
        self._handles[(spec.run_id, spec.generation)] = handle
        self._claims[(spec.run_id, spec.generation)] = claim
        return handle

    def release_fence(self, run_id: str, generation: str) -> None:
        """Release a fence this controller holds for a failed launch, once the
        failure is recorded. Nothing held (already released, or never taken
        here): nothing to do -- an observer never releases a fence."""
        claim = self._claims.pop((run_id, generation), None)
        if claim is not None:
            self.api.release_run_singleton(self.namespace, claim, self.DELETE_TIMEOUT)

    def adopt(self, run_id: str, generation: str) -> "KubernetesRunHandle":
        """Take over ONE exact run generation launched by another process.

        Architecture B+ (ADR-014 D11): the engine retries an execution
        Activity on whichever worker is alive, so the retry must be able to
        pick up the run its predecessor launched. It adopts only through the
        run's fence: the Lease must exist, carry exactly these labels, and be
        held by exactly this generation -- `read_run_singleton` refuses any
        other holder or a rewritten Lease, so a guessed or foreign generation
        cannot be taken over. Nothing is created; the handle watches the agent
        Pod the launch created.

        A MISSING AGENT POD IS NOT YET AN EXIT. The fence is taken first and
        the agent is created last, after the proxy is ready and the input is
        delivered -- so a retry that adopts while its predecessor is still
        launching finds the fence and no agent. Reading that as "exited" (the
        first version did) reaped the half-built group and recorded a run that
        would have succeeded as failed. Absence counts as an exit only once a
        whole launch could have completed since adoption.
        """
        if not RUN_ID_PATTERN.fullmatch(run_id) or not generation:
            raise ValueError("invalid Kubernetes run generation identity")
        names = run_group_names_for_identity(run_id, generation)
        selector = {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "andyur.run/id": _digest(run_id),
            "andyur.run/generation": _digest(generation),
        }
        claim = self.api.read_run_singleton(
            self.namespace, names["lease"], selector, generation, self.ADOPTION_TIMEOUT)
        if claim is None:
            raise RuntimeError(
                f"Kubernetes run {run_id!r} has no fence to adopt")
        key = (run_id, generation)
        handle = KubernetesRunHandle(
            self.api, self.namespace, names["agent"],
            absent_grace_until=time.monotonic() + self.ADOPTION_LAUNCH_GRACE)
        self._handles[key] = handle
        # Held so that this process's cleanup releases the fence, exactly as
        # the launching process's would have.
        self._claims[key] = claim
        return handle

    def delete(self, spec: RunGroupSpec) -> None:
        key = (spec.run_id, spec.generation)
        with _wait("delete", spec.run_id, timeout_seconds=float(self.DELETE_TIMEOUT)) as deleted:
            deadline = time.monotonic() + self.DELETE_TIMEOUT
            self.api.delete_run_group(
                self.namespace, self.selector(spec), self.DELETE_TIMEOUT)
            claim = self._claims.get(key)
            if claim is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    deleted.outcome = "timeout"
                    raise TimeoutError("Kubernetes singleton release deadline expired")
                self.api.release_run_singleton(
                    self.namespace, claim, remaining)
                self._claims.pop(key, None)
            handle = self._handles.pop(key, None)
            if handle is not None:
                handle.mark_deleted()
            deleted.outcome = "deleted"

    def list_running(self) -> list[str]:
        return sorted({run_id for run_id, _ in self.list_running_generations()})

    def list_running_generations(self) -> list[tuple[str, str]]:
        """Return only run generations whose raw identity matches its labels.

        The generation is retained because a restarted worker must be able to
        destroy exactly what it adopted. Reducing this to run ids and later
        deleting every generation with that id would let a stale worker destroy
        a replacement owned by another worker.
        """
        selector = {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "app.kubernetes.io/component": "proxy",
        }
        if self.owner_generation is not None:
            # A worker may adopt only its own stable generation. Without this,
            # every worker in a shared namespace reports every run and a halt
            # delivered to either one can destroy another worker's workload.
            selector["andyur.run/generation"] = _digest(self.owner_generation)
        found: set[tuple[str, str]] = set()
        adoption_deadline = time.monotonic() + self.ADOPTION_TIMEOUT
        pods = list(self.api.list_pods(
            self.namespace, selector, self.ADOPTION_TIMEOUT,
            self.MAX_ADOPTED_PODS + 1))
        if len(pods) > self.MAX_ADOPTED_PODS:
            raise RuntimeError("Kubernetes adoption cardinality exceeds safe bound")
        seen: set[tuple[str, str]] = set()
        for pod in pods:
            key = self._verified_generation(pod, seen, adoption_deadline)
            if key is not None:
                found.add(key)
        return sorted(found)

    # The ENGINE VIEW's own bound (Architecture B+, ADR-014 D11). It lists every
    # execution worker's runs, so it grows with the number of replicas times
    # their concurrency, not with one daemon's slots.
    MAX_ENGINE_PODS = 1024

    def list_engine_generations(self, prefix: str) -> list[tuple[str, str]]:
        """Every live generation whose raw identity starts with `prefix`,
        verified POD BY POD.

        The reconciler's reach over engine runs, and it must not be blinded by
        a run it has no business with. `list_running_generations` refuses the
        whole set on one ambiguous Pod -- right for adopting one's OWN runs,
        where a guess could destroy a replacement -- but this view spans every
        worker in the namespace, and one Pod in `Unknown` on a lost node, or
        another daemon's run past the adoption bound, stopped every engine run
        from being condemned or killed. Here a Pod that fails verification is
        named and skipped; the others are still found. Nothing is ever
        destroyed on a Pod that failed verification.
        """
        selector = {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "app.kubernetes.io/component": "proxy",
        }
        deadline = time.monotonic() + self.ADOPTION_TIMEOUT
        pods = list(self.api.list_pods(
            self.namespace, selector, self.ADOPTION_TIMEOUT, self.MAX_ENGINE_PODS + 1))
        if len(pods) > self.MAX_ENGINE_PODS:
            log.warning(f"engine view: more than {self.MAX_ENGINE_PODS} run proxies; "
                        "verifying the first ones only")
            pods = pods[:self.MAX_ENGINE_PODS]
        found: set[tuple[str, str]] = set()
        seen: set[tuple[str, str]] = set()
        for pod in pods:
            # Filtered BEFORE verification: another daemon's run is not this
            # view's to judge, and must not be able to fail it.
            if not pod.annotations.get("andyur.run/generation-raw", "").startswith(prefix):
                continue
            try:
                key = self._verified_generation(pod, seen, deadline)
            except Exception as exc:                          # noqa: BLE001
                log.warning(f"engine view: skipping proxy {pod.name}: "
                            f"{type(exc).__name__}: {exc}")
                continue
            if key is not None:
                found.add(key)
        return sorted(found)

    def _verified_generation(self, pod, seen: set, deadline: float):
        """One proxy's (run_id, generation) if it is live and its identity,
        name and fence all agree; None if it has ended; raises otherwise."""
        if pod.phase in {"Succeeded", "Failed"}:
            return None
        if pod.phase not in {"Pending", "Running"}:
            raise RuntimeError("owned Kubernetes proxy has ambiguous phase")
        run_id = pod.annotations.get("andyur.run/id-raw", "")
        generation = pod.annotations.get("andyur.run/generation-raw", "")
        if not RUN_ID_PATTERN.fullmatch(run_id) or not generation:
            raise RuntimeError("active Kubernetes proxy has invalid raw identity")
        if pod.labels.get("andyur.run/id") != _digest(run_id):
            raise RuntimeError("active Kubernetes proxy run identity was rewritten")
        if pod.labels.get("andyur.run/generation") != _digest(generation):
            raise RuntimeError(
                "active Kubernetes proxy generation identity was rewritten")
        names = run_group_names_for_identity(run_id, generation)
        key = (run_id, generation)
        if pod.name != names["proxy"]:
            raise RuntimeError("noncanonical Kubernetes proxy in adoption set")
        if key in seen:
            raise RuntimeError("duplicate Kubernetes proxy generation")
        seen.add(key)
        claim = self.api.read_run_singleton(
            self.namespace, names["lease"], {
                "app.kubernetes.io/managed-by": "andyur-worker",
                "andyur.run/id": _digest(run_id),
                "andyur.run/generation": _digest(generation),
            }, generation, deadline - time.monotonic())
        if claim is None:
            raise RuntimeError(
                f"live Kubernetes run {run_id!r} lacks its singleton fence")
        return key

    def list_orphaned_agent_generations(self) -> list[tuple[str, str]]:
        """Agent Pods that outlived the proxy they were single-homed on.

        WHY THIS CAN EXIST AT ALL. A run here is two Pods, and adoption
        (`list_running_generations`) selects the PROXY. So an agent Pod whose
        proxy is gone is invisible to it: nothing reports the run as executing,
        so nothing condemns it, and the group deletion that would remove it
        correctly is never reached. Nothing else bounds it either -- the agent
        Pod has `restartPolicy: Never`, no `activeDeadlineSeconds`, and no
        ownerReference to the proxy, so Kubernetes will not collect it.

        WHY THIS CANNOT RACE A LAUNCH, which is the obvious fear. The launch
        order is load-bearing and stated where it happens: "Policies, Service
        and proxy exist before untrusted code. The agent is never created
        unless its only allowed destination is ready." An agent Pod therefore
        cannot precede its proxy. If an agent exists with no live proxy, the
        proxy DIED -- there is no window in which this is a half-built run.

        A proxy in a terminal phase counts as gone. The agent is single-homed on
        that proxy and can reach nothing else; a Succeeded or Failed proxy
        leaves the agent with no destination just as an absent one does.

        Returns raw `(run_id, generation)` pairs, verified against their label
        digests exactly as adoption verifies them.
        """
        base = {"app.kubernetes.io/managed-by": "andyur-worker"}
        if self.owner_generation is not None:
            # A worker reconciles only its OWN generation, for the same reason
            # it may adopt only its own: in a shared namespace, sweeping another
            # worker's workload is destroying a run nobody asked us about.
            base["andyur.run/generation"] = _digest(self.owner_generation)

        def _live(component):
            pods = list(self.api.list_pods(
                self.namespace, {**base, "app.kubernetes.io/component": component},
                self.ADOPTION_TIMEOUT, self.MAX_ADOPTED_PODS + 1))
            if len(pods) > self.MAX_ADOPTED_PODS:
                raise RuntimeError(
                    "Kubernetes reconcile cardinality exceeds safe bound")
            return [p for p in pods if p.phase in {"Pending", "Running"}]

        # AGENTS FIRST, PROXIES SECOND, and the order is the safety argument.
        #
        # The launch path creates the proxy, waits for it to be ready, and only
        # then creates the agent -- so an agent with no proxy means the proxy
        # died. That holds for a SINGLE instant, not across two calls: listing
        # proxies first let a launch complete in between, so an agent created
        # after the proxy snapshot appeared orphaned and a healthy, just-started
        # run was destroyed. The two calls are genuinely concurrent -- the
        # daemon launches on an executor while the heartbeat sweeps on the loop
        # thread, and each list carries a ten-second timeout.
        #
        # Reversed, a stale snapshot can only ever MISS an orphan, never invent
        # one: any agent seen here existed before the proxy listing, so if its
        # proxy is absent from the later listing the proxy is genuinely gone.
        # Missing an orphan costs one more beat; inventing one destroys a live
        # run.
        agents = _live("agent")
        proxied = {
            (pod.labels.get("andyur.run/id"), pod.labels.get("andyur.run/generation"))
            for pod in _live("proxy")
        }

        orphans: set[tuple[str, str]] = set()
        for pod in agents:
            key = (pod.labels.get("andyur.run/id"),
                   pod.labels.get("andyur.run/generation"))
            if key in proxied:
                continue
            run_id = pod.annotations.get("andyur.run/id-raw", "")
            generation = pod.annotations.get("andyur.run/generation-raw", "")
            # SKIPPED, NOT GUESSED, when the identity does not verify. Deleting
            # on the strength of an identity we could not confirm would let a
            # rewritten label aim this at another run's generation, which is a
            # worse outcome than leaving one Pod for an operator to find. Not
            # agent-reachable in any case: the workload has no Kubernetes API
            # access, which the containment barrier asserts before it starts.
            if (not RUN_ID_PATTERN.fullmatch(run_id) or not generation
                    or pod.labels.get("andyur.run/id") != _digest(run_id)
                    or pod.labels.get("andyur.run/generation") != _digest(generation)):
                log.error(
                    "orphaned Kubernetes agent Pod %s has unverifiable identity; "
                    "not reconciled", pod.name)
                continue
            if pod.name != run_group_names_for_identity(run_id, generation)["agent"]:
                log.error(
                    "noncanonical Kubernetes agent Pod %s; not reconciled", pod.name)
                continue
            orphans.add((run_id, generation))
        return sorted(orphans)

    def delete_generation(self, run_id: str, generation: str) -> None:
        """Delete one exact adopted generation without reconstructing a spec."""
        if not RUN_ID_PATTERN.fullmatch(run_id) or not generation:
            raise ValueError("invalid Kubernetes run generation identity")
        selector = {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "andyur.run/id": _digest(run_id),
            "andyur.run/generation": _digest(generation),
        }
        # The daemon's cleanup path (reap -> orchestrator.cleanup): the same
        # `controller.delete` span as delete(spec), so a run's trace ends with
        # its group's deletion whichever way the delete was reached.
        with _wait("delete", run_id, timeout_seconds=float(self.DELETE_TIMEOUT),
                   generation=generation) as deleted:
            deadline = time.monotonic() + self.DELETE_TIMEOUT
            self.api.delete_run_group(self.namespace, selector, self.DELETE_TIMEOUT)
            key = (run_id, generation)
            claim = self._claims.get(key)
            if claim is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    deleted.outcome = "timeout"
                    raise TimeoutError("Kubernetes singleton release deadline expired")
                self.api.release_run_singleton(
                    self.namespace, claim, remaining)
                self._claims.pop(key, None)
            handle = self._handles.pop((run_id, generation), None)
            if handle is not None:
                handle.mark_deleted()
            deleted.outcome = "deleted"

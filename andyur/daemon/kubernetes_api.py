"""Official Kubernetes Python-client adapter for run-group lifecycle."""

from __future__ import annotations

import os
import time
from collections.abc import Mapping

from .kubernetes_controller import LeaseClaim, PodSnapshot


_KINDS = (
    ("v1", "Pod"),
    ("v1", "Service"),
    ("v1", "ServiceAccount"),
    ("networking.k8s.io/v1", "NetworkPolicy"),
    ("v1", "Secret"),
    ("v1", "ConfigMap"),
)


def _selector(labels: Mapping[str, str]) -> str:
    # Generated labels use a closed character set, but still reject separators
    # here so a future caller cannot turn one deletion into a broader selector.
    for key, value in labels.items():
        if any(char in key or char in value for char in ",=()!"):
            raise ValueError("unsafe Kubernetes label selector")
    return ",".join(f"{key}={value}" for key, value in sorted(labels.items()))


def _attach_stream():
    """The kubernetes websocket attach factory, imported lazily (uvicorn/starlette
    stay off module load) and behind one name so a test can substitute it
    without the `from kubernetes.stream import stream` submodule/function
    ambiguity."""
    from kubernetes.stream import stream
    return stream


class OfficialKubernetesApi:
    """Synchronous adapter used from the daemon's existing worker thread."""

    def __init__(self) -> None:
        from kubernetes import client, config
        from kubernetes.dynamic import DynamicClient

        kubeconfig = os.environ.get("ANDYUR_KUBECONFIG")
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            # Production defaults to the Pod's ServiceAccount identity. An
            # operator must opt into a host kubeconfig explicitly.
            config.load_incluster_config()
        api_client = client.ApiClient()
        self._dynamic = DynamicClient(api_client)
        # Resolve the fixed owned kinds during adapter initialization/readiness.
        # Dynamic discovery may perform network I/O and must never begin inside
        # the security teardown deadline.
        self._run_resources = tuple(
            self._dynamic.resources.get(api_version=version, kind=kind)
            for version, kind in _KINDS
        )
        self._lease_resource = self._dynamic.resources.get(
            api_version="coordination.k8s.io/v1", kind="Lease")
        self._core = client.CoreV1Api(api_client)
        self._api_exception = client.ApiException

    def apply(self, resource: dict) -> None:
        api = self._dynamic.resources.get(
            api_version=resource["apiVersion"], kind=resource["kind"])
        metadata = resource["metadata"]
        api.patch(
            name=metadata["name"], namespace=metadata["namespace"], body=resource,
            content_type="application/apply-patch+yaml",
            field_manager="andyur-worker", force=False,
            _request_timeout=(3, 10),
        )

    def assert_isolation_ready(self, namespace: str) -> None:
        ns = self._core.read_namespace(namespace, _request_timeout=(3, 5))
        labels = dict(ns.metadata.labels or {})
        annotations = dict(ns.metadata.annotations or {})
        try:
            verified_at = int(annotations["andyur.network-policy/verified-at"])
        except (KeyError, TypeError, ValueError):
            verified_at = 0
        fresh = 0 <= time.time() - verified_at <= 600
        bound = annotations.get("andyur.network-policy/namespace-uid") == ns.metadata.uid
        if labels.get("andyur.network-policy/verified") != "true" or not fresh or not bound:
            raise RuntimeError(
                f"namespace {namespace!r} lacks a fresh, namespace-bound active "
                "NetworkPolicy verification (maximum age 600s)"
            )

    def claim_run_singleton(
        self, namespace: str, name: str, labels: dict[str, str], owner: str,
    ) -> LeaseClaim | None:
        try:
            created = self._lease_resource.create(
                namespace=namespace,
                body={
                    "apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                    "metadata": {"name": name, "namespace": namespace,
                                 "labels": dict(labels)},
                    "spec": {"holderIdentity": owner},
                },
                _request_timeout=(3, 10),
            )
            return self._validated_claim(
                created, namespace, name, labels, owner)
        except self._api_exception as exc:
            if exc.status == 409:
                return None
            raise

    @staticmethod
    def _validated_claim(created, namespace, name, labels, owner) -> LeaseClaim:
        metadata = created.metadata
        spec = created.spec
        returned_namespace = getattr(metadata, "namespace", namespace)
        returned_labels = dict(getattr(metadata, "labels", None) or {})
        uid = getattr(metadata, "uid", "")
        resource_version = getattr(metadata, "resourceVersion", "")
        holder = getattr(spec, "holderIdentity", "")
        forbidden = ("leaseDurationSeconds", "acquireTime", "renewTime")
        if (getattr(metadata, "name", "") != name
                or returned_namespace != namespace
                or returned_labels != labels
                or holder != owner
                or any(getattr(spec, field, None) is not None for field in forbidden)
                or not isinstance(uid, str) or not uid
                or not isinstance(resource_version, str) or not resource_version):
            raise RuntimeError("Kubernetes singleton Lease response was rewritten")
        return LeaseClaim(name, uid, resource_version, holder)

    def read_run_singleton(
        self, namespace: str, name: str, labels: dict[str, str], owner: str,
        timeout: float,
    ) -> LeaseClaim | None:
        if timeout <= 0:
            raise TimeoutError("Kubernetes singleton observation deadline expired")
        half = timeout / 2
        try:
            current = self._lease_resource.get(
                name=name, namespace=namespace,
                _request_timeout=(min(3, half), min(7, half)))
        except self._api_exception as exc:
            if exc.status == 404:
                return None
            raise
        return self._validated_claim(current, namespace, name, labels, owner)

    def release_run_singleton(
        self, namespace: str, claim: LeaseClaim, timeout: float,
    ) -> None:
        if not all((claim.name, claim.uid, claim.resource_version, claim.holder)):
            raise ValueError("complete Kubernetes singleton claim is required")
        half = timeout / 2
        try:
            self._lease_resource.delete(
                name=claim.name, namespace=namespace,
                body={"preconditions": {"uid": claim.uid,
                                         "resourceVersion": claim.resource_version}},
                _request_timeout=(min(3, half), min(7, half)),
            )
        except self._api_exception as exc:
            if exc.status == 404:
                return
            raise

    def wait_pod_ready(self, namespace: str, name: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                remaining = max(0.1, deadline - time.monotonic())
                pod = self._core.read_namespaced_pod(
                    name, namespace, _request_timeout=(3, remaining))
            except self._api_exception as exc:
                if exc.status == 404:
                    time.sleep(0.1)
                    continue
                raise
            phase = getattr(pod.status, "phase", None)
            if phase in {"Failed", "Succeeded"}:
                return False
            conditions = getattr(pod.status, "conditions", None) or []
            if any(c.type == "Ready" and c.status == "True" for c in conditions):
                return True
            time.sleep(0.1)
        return False

    def pod_phase(self, namespace: str, name: str) -> str | None:
        try:
            return self._core.read_namespaced_pod(
                name, namespace, _request_timeout=(2, 5)).status.phase
        except self._api_exception as exc:
            if exc.status == 404:
                return None
            raise

    def pod_ip(self, namespace: str, name: str) -> str:
        pod = self._core.read_namespaced_pod(
            name, namespace, _request_timeout=(2, 5))
        ip = getattr(pod.status, "pod_ip", None)
        if not ip:
            raise RuntimeError(f"ready proxy Pod {name!r} has no Pod IP")
        return ip

    def pod_logs(self, namespace: str, name: str, tail_lines: int | None = 80,
                 limit_bytes: int | None = None) -> str:
        """One pod's log as text, bounded at the API and honestly decoded.

        ``_preload_content=False`` is load-bearing. This client version
        (kubernetes 36.0.3) deserialises a "str" response by ``json.loads``-ing
        the body and, on failure, ``str()``-ing the raw bytes -- so a plain-text
        log comes back as a bytes REPR (``"b'plain\\n'"``), a JSON line as a
        Python literal, and bare ``null`` as ``None`` (see verify-exec-input.py,
        which reads via kubectl for exactly this reason). Reading the raw body
        and decoding it here returns what the container actually wrote.

        ``limit_bytes`` is passed to the API *and* re-applied locally, so a
        hostile workload's output is bounded before anything -- redaction,
        storage -- ever touches the whole of it. limitBytes reads from the START
        of the stream; callers that keep a head window (execlifecycle) match that.
        """
        kwargs = {"_preload_content": False, "_request_timeout": (3, 10)}
        if tail_lines is not None:
            kwargs["tail_lines"] = tail_lines
        if limit_bytes is not None:
            kwargs["limit_bytes"] = limit_bytes
        try:
            resp = self._core.read_namespaced_pod_log(name, namespace, **kwargs)
        except self._api_exception as exc:
            if exc.status == 404:
                return ""
            raise
        raw = getattr(resp, "data", resp)
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8")
        if limit_bytes is not None:
            raw = raw[:limit_bytes]
        return bytes(raw).decode("utf-8", errors="replace")

    def read_container_exit(
        self, namespace: str, name: str, container: str,
    ) -> int | None:
        """The exact exit code of a container that has TERMINATED, or None.

        None means the code is not (yet) knowable: the Pod is gone (404), the
        container is not terminated, or it terminated with no readable code
        (evicted/OOM before status was written). The exit CODE is a control-
        plane fact -- only the kubelet has it, reported here in the container
        status -- which is exactly why the daemon, not the credential-holding
        proxy, reads it. exec_lifecycle.exit_error maps None to a failed run,
        never a clean one, so an unreadable code fails closed.
        """
        try:
            pod = self._core.read_namespaced_pod(
                name, namespace, _request_timeout=(2, 5))
        except self._api_exception as exc:
            if exc.status == 404:
                return None
            raise
        statuses = [*(pod.status.init_container_statuses or []),
                    *(pod.status.container_statuses or [])]
        for status in statuses:
            if status.name != container:
                continue
            state = getattr(status, "state", None)
            terminated = getattr(state, "terminated", None) if state else None
            if terminated is None:
                return None                    # this container is not terminated
            # A terminated container ALWAYS carries an exit code -- the generated
            # client raises deserialising a terminated state without one, so the
            # old `getattr(..., None)` branch was unreachable. OOMKilled is exit
            # 137 with reason "OOMKilled", NOT a missing code: it maps to a failed
            # run through exit_error like any non-zero exit, never to "vanished".
            return terminated.exit_code
        return None

    def wait_container_running(
        self, namespace: str, name: str, container: str, timeout: float,
    ) -> bool:
        """True once `container` (init or regular) reports state.running.

        False on a terminal Pod phase or a terminated container: a target that
        already exited cannot take an attach, and waiting for the deadline
        would only delay the same refusal.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pod = self._core.read_namespaced_pod(
                    name, namespace, _request_timeout=(3, 5))
            except self._api_exception as exc:
                if exc.status == 404:
                    time.sleep(0.1)
                    continue
                raise
            if getattr(pod.status, "phase", None) in {"Failed", "Succeeded"}:
                return False
            statuses = [*(pod.status.init_container_statuses or []),
                        *(pod.status.container_statuses or [])]
            for status in statuses:
                if status.name != container:
                    continue
                state = getattr(status, "state", None)
                if state is not None and state.running is not None:
                    return True
                if state is not None and state.terminated is not None:
                    return False
            time.sleep(0.1)
        return False

    # The WRITE leg of an attach must be bounded, and it is (below). Each frame
    # is bounded against a full stall by the socket timeout, and the whole write
    # by attach_stdin's chunked total-deadline. This matters because launch runs
    # inline in the worker's heartbeat loop (daemon.run -> heartbeat ->
    # run_in_executor(launch) awaited inline), so an unbounded attach write
    # would stop the whole worker: no heartbeats, no reaping, no kills.
    # `_request_timeout` does NOT reach the websocket (the generated client
    # honours it only on the _preload_content path this call skips), so the
    # bound lives on the socket. The HANDSHAKE leg is a stated residual, NOT
    # bounded here (see _open_attach_stream) -- it is the one phase that can
    # still stall the worker, against a wedged node on the untrusted workload's
    # path, until TCP gives up.
    ATTACH_TIMEOUT_SECONDS = 30.0
    # A DISTINCT, larger total-write deadline. The per-send socket timeout above
    # bounds one frame's send against a FULL stall; it does not bound a peer
    # that trickles (reads a little each period, so no single send blocks for
    # ATTACH_TIMEOUT_SECONDS) -- that peer stretches the whole write to
    # payload/rate. The total deadline, checked BETWEEN chunked frames, bounds
    # it. Larger than the per-send bound so a legitimately slow-but-progressing
    # write is not cut off by it.
    ATTACH_WRITE_DEADLINE_SECONDS = 60.0
    # One frame's worth of stdin. stdin is a byte stream, so the kubelet
    # reassembles chunks transparently; small enough that the deadline is
    # checked often, large enough to keep framing overhead negligible.
    ATTACH_CHUNK_BYTES = 64 * 1024

    def _open_attach_stream(self, namespace: str, name: str, container: str):
        """Open a stdin-only attach websocket, with the socket write-bounded.

        Isolated as its own method so the retry/one-shot policy in attach_stdin
        is testable without a live apiserver, and so the lazy kubernetes.stream
        import stays out of module load.

        THE BOUND LANDS ON THE OPENED SOCKET, and this is the correction to the
        first attempt: `websocket.setdefaulttimeout` is consulted only by
        `create_connection()` and `WebSocketApp`, NOT by the `WebSocket()` +
        `.connect()` path kubernetes.stream uses (its connect resolves
        `options.get("timeout", sock_opt.timeout)` = None and then
        `settimeout(None)`s the socket), so the previous fix bounded a socket
        this call never opens. `WSClient.sock` is the WebSocket, whose
        `settimeout` propagates to the OS socket -- so this bounds every read and
        WRITE, and a stalled write then raises WebSocketTimeoutException
        (a socket.timeout), the fatal post-handshake failure attach_stdin
        already rolls the launch back on. That closes the case with an untrusted
        party: a workload that upgrades then never reads an 8 MiB write.

        THE HANDSHAKE IS NOT BOUNDED, and this is a stated residual, not a
        guarantee. The 101 upgrade is not answered by the trusted apiserver
        alone: it is proxied apiserver -> kubelet -> CRI streaming on the node
        that hosts the UNTRUSTED workload, kube-apiserver exempts attach from
        --request-timeout (the long-running regexp), and TCP has no idle
        timeout without keepalive -- so a wedged node can stall the connect, and
        the worker with it. Bounding it needs WebSocket.connect(url, timeout=T),
        which websocket-client accepts but kubernetes.stream's create_websocket
        does not pass; closing it means building the connection here rather than
        through stream(), and that is the named follow-up. The WRITE (the
        untrusted-workload leg) IS bounded: the per-send socket timeout above,
        plus attach_stdin's chunked total-deadline.
        """
        ws = _attach_stream()(
            self._core.connect_get_namespaced_pod_attach, name, namespace,
            container=container, stdin=True, stdout=False, stderr=False,
            tty=False, _preload_content=False)
        ws.sock.settimeout(self.ATTACH_TIMEOUT_SECONDS)
        return ws

    def attach_stdin(
        self, namespace: str, name: str, container: str, data: bytes,
    ) -> None:
        """Write `data` to the container's stdin over one attach, then close.

        With `stdinOnce` on the container, closing this attach closes the
        process's stdin, so it reads EOF after exactly these bytes. Text
        frames: the payload is UTF-8 by construction (canonical JSON or a
        JSON string's text), and the container receives the same bytes.
        """
        # ONLY THE HANDSHAKE IS RETRYABLE, and the reason is stdinOnce. The
        # container reports Running a moment before the runtime's attach
        # endpoint is ready, so an attach REFUSED at that edge is safe to retry:
        # nothing was delivered. A write that fails AFTER the stream opened is
        # not: under stdinOnce the kubelet closes the workload's stdin when this
        # session disconnects, so a partial write leaves the process reading EOF
        # after a truncated payload, and a retry re-opens an attach the kubelet
        # no longer feeds and would report a false success. So a post-handshake
        # failure is FATAL -- it propagates, the controller's rollback fires,
        # and the run never starts on a half-delivered task.
        last: Exception | None = None
        for attempt in range(3):
            try:
                ws = self._open_attach_stream(namespace, name, container)
            except Exception as exc:   # handshake failure, nothing sent: retry
                last = exc
                time.sleep(0.5 * (attempt + 1))
                continue
            try:
                self._write_bounded(ws, data)
            except Exception as exc:
                raise RuntimeError(
                    f"attach write to {name}/{container} failed after the "
                    f"stream opened; under stdinOnce this may have delivered a "
                    f"partial task, so the launch fails rather than retry: "
                    f"{type(exc).__name__}: {exc}") from exc
            finally:
                ws.close()
            return
        raise RuntimeError(
            f"attach handshake to {name}/{container} for stdin delivery failed "
            f"after 3 attempts: {type(last).__name__}: {last}") from last

    def _write_bounded(self, ws, data: bytes) -> None:
        """Write stdin as chunked frames under a TOTAL wall-clock deadline.

        The deadline is checked BETWEEN frames -- no cross-thread interruption,
        which is why the previous watchdog failed: WebSocket.send holds a frame
        lock for the whole send and close() needs that same lock, so a watchdog
        could never interrupt a slow-trickle writer (it parked waiting for the
        lock while the write ran to payload/rate). Each frame is still bounded
        against a full stall by the socket timeout; the between-frame deadline
        bounds a peer that trickles just fast enough to keep each send under
        that timeout. A blown deadline raises, which attach_stdin turns into the
        fatal post-handshake failure that rolls the launch back.

        Chunks are sliced on BYTES (write_stdin of a bytes slice sends a BINARY
        stdin frame of exactly that length), so ATTACH_CHUNK_BYTES is a true
        byte bound on the frame -- slicing a str would count CHARACTERS and a
        multibyte payload could emit a frame several times larger.

        WORST-CASE WALL CLOCK, stated precisely: the between-frame check fires
        only AFTER the frame in flight returns, so a write can run to
        ATTACH_WRITE_DEADLINE_SECONDS + one ATTACH_TIMEOUT_SECONDS (the last
        frame's per-send bound) + the ~3s WebSocket close grace -- ~93s at the
        defaults, not the 60s total deadline alone. Bounded and finite, which is
        the property that matters (the worker is never wedged), just not exactly
        the total-deadline constant.
        """
        deadline = time.monotonic() + self.ATTACH_WRITE_DEADLINE_SECONDS
        for start in range(0, len(data), self.ATTACH_CHUNK_BYTES):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"attach write exceeded its {self.ATTACH_WRITE_DEADLINE_SECONDS}s "
                    "total deadline; the peer is draining stdin too slowly")
            ws.write_stdin(data[start:start + self.ATTACH_CHUNK_BYTES])

    def list_pods(
        self, namespace: str, selector: dict[str, str], timeout: float, limit: int,
    ):
        if timeout <= 0 or limit <= 0:
            raise ValueError("bounded Kubernetes Pod list is required")
        half = timeout / 2
        response = self._core.list_namespaced_pod(
            namespace, label_selector=_selector(selector), limit=limit,
            _request_timeout=(min(3, half), min(7, half)))
        if getattr(getattr(response, "metadata", None), "_continue", None):
            raise RuntimeError("Kubernetes adoption cardinality exceeds safe bound")
        return [
            PodSnapshot(
                name=pod.metadata.name,
                phase=pod.status.phase,
                labels=dict(pod.metadata.labels or {}),
                annotations=dict(pod.metadata.annotations or {}),
            )
            for pod in response.items
        ]

    def delete_run_group(
        self, namespace: str, selector: dict[str, str], timeout: float,
    ) -> None:
        deadline = time.monotonic() + timeout

        def request_timeout() -> tuple[float, float]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Kubernetes run-group deletion did not finish within {timeout}s")
            # urllib3's tuple budgets connect and read separately; each equal
            # to `remaining` can consume nearly twice the total deadline.
            half = remaining / 2
            return min(3, half), min(7, half)

        label_selector = _selector(selector)
        resources = self._run_resources
        # The run-scoped singleton Lease is deliberately excluded. The
        # controller releases it separately, with UID/resourceVersion
        # preconditions, only after these generation-exact resources are absent.
        errors: list[Exception] = []
        for resource in resources:
            try:
                resource.delete(
                    namespace=namespace, label_selector=label_selector,
                    body={"propagationPolicy": "Foreground"},
                    _request_timeout=request_timeout(),
                )
            except Exception as exc:  # attempt cleanup of every owned surface
                errors.append(exc)
        delay = 0.1
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            if not any(
                resource.get(
                    namespace=namespace, label_selector=label_selector,
                    _request_timeout=request_timeout()).items
                for resource in resources
            ):
                if errors:
                    raise RuntimeError(
                        f"Kubernetes run-group deletion had {len(errors)} delete error(s)"
                    ) from errors[0]
                return
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 2.0)
        raise TimeoutError(
            f"Kubernetes run-group deletion did not finish within {timeout}s")

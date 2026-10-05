#!/usr/bin/env python3
"""Live K3s proof for broker fsGroup restart adoption and native sidecars."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from andyur.daemon.kubernetes_api import OfficialKubernetesApi
from andyur.daemon.kubernetes_controller import KubernetesRunController, RunCredentials
from andyur.daemon.kubernetes_manifests import RunGroupSpec, run_group_names


ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "andyur/daemon/kubernetes_api.py",
    "andyur/daemon/kubernetes_controller.py",
    "andyur/dataplane/denybroker.py",
    "andyur/dataplane/brokeruds.py",
    "andyur/daemon/kubernetes_manifests.py",
    "infra/kubernetes/verify-broker-lifecycle.py",
    "infra/kubernetes/verify-broker-lifecycle.sh",
}


def controller_rollback_gate(namespace: str, image: str) -> dict[str, object]:
    """Prove positive readiness and permanent-unready rollback on real K3s."""
    api = OfficialKubernetesApi()
    controller = KubernetesRunController(api, namespace)
    controller.READY_TIMEOUT = 5.0
    credentials = RunCredentials("channel", "run", "llm")

    def spec(run_id: str, ready_status: int) -> RunGroupSpec:
        server = (
            "from http.server import BaseHTTPRequestHandler,HTTPServer;"
            "H=type('H',(BaseHTTPRequestHandler,),{"
            "'do_GET':lambda s:(s.send_response(%d),s.end_headers()),"
            "'log_message':lambda *a:None});"
            "HTTPServer(('0.0.0.0',8765),H).serve_forever()" % ready_status
        )
        return RunGroupSpec(
            namespace=namespace, run_id=run_id, generation="live-gate",
            agent_id="scout", registry_agent_id="scout",
            proxy_image=image, agent_image=image, proxy_port=8765, mcp_port=8766,
            proxy_args=("python", "-c", server),
            agent_args=("python", "-c", "import time;time.sleep(3600)"),
        )

    positive = spec(uuid.uuid4().hex, 200)
    controller.launch(positive, credentials)
    positive_names = run_group_names(positive)
    controller.delete(positive)
    positive_absent = not kubectl(
        "get", "pod,service,secret,configmap,serviceaccount,networkpolicy,lease",
        "-n", namespace, "-l", "andyur.run/id", "-o", "name",
    ).strip()
    if not positive_absent:
        raise RuntimeError("controller positive cleanup left run resources")

    refused = spec(uuid.uuid4().hex, 503)
    refused_names = run_group_names(refused)
    refusal = ""
    try:
        controller.launch(refused, credentials)
    except RuntimeError as exc:
        refusal = str(exc)
    else:
        raise RuntimeError("permanently unready proxy unexpectedly launched")
    expected_refusal = (
        f"run-group launch failed (Kubernetes proxy for run {refused.run_id} "
        f"was not ready within {controller.READY_TIMEOUT}s)")
    if not refusal.startswith(expected_refusal) or "rollback also failed" in refusal:
        raise RuntimeError(f"unexpected controller refusal outcome: {refusal}")
    residual = kubectl(
        "get", "pod,service,secret,configmap,serviceaccount,networkpolicy,lease",
        "-n", namespace, "-l", "andyur.run/id", "-o", "name",
    ).strip()
    agent_created = bool(kubectl(
        "get", "pod", refused_names["agent"], "-n", namespace,
        "-o", "name", check=False).strip())
    lease_present = bool(kubectl(
        "get", "lease", refused_names["lease"], "-n", namespace,
        "-o", "name", check=False).strip())
    if residual or agent_created or lease_present:
        raise RuntimeError(
            "permanent-refusal rollback left agent, generation resources or Lease")
    return {
        "positive_ready_launch": True,
        "positive_teardown_absent": positive_absent,
        "permanent_refusal": refusal,
        "refused_agent_absent_after_rollback": not agent_created,
        "refused_generation_absent": not residual,
        "refused_lease_released": not lease_present,
        "ready_timeout_seconds": controller.READY_TIMEOUT,
        "positive_lease": positive_names["lease"],
        "surrogate_image": image,
    }


def kubectl(*args: str, body: dict | None = None, check: bool = True) -> str:
    command = ["kubectl", "--kubeconfig", os.environ["ANDYUR_KUBECONFIG"], *args]
    completed = subprocess.run(
        command, input=None if body is None else json.dumps(body), text=True,
        capture_output=True, timeout=30,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"kubectl {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout


def main() -> None:
    namespace = f"andyur-broker-life-{uuid.uuid4().hex[:8]}"
    image = os.environ.get("ANDYUR_BROKER_LIFECYCLE_IMAGE", "").strip()
    if not image:
        raise RuntimeError(
            "ANDYUR_BROKER_LIFECYCLE_IMAGE must name a freshly built "
            "current-source image in the cluster node's local image store"
        )
    namespace_doc = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": namespace},
    }
    first = """
import os, socket, stat, time
from andyur.dataplane.denybroker import provision_socket_parent
from andyur.dataplane.brokeruds import bind_private_broker_socket
p='/shared/broker/authz.sock'; marker='/shared/first'
provision_socket_parent(p)
i=os.lstat('/shared/broker')
print(f'PROVISION mode={oct(stat.S_IMODE(i.st_mode))} uid={i.st_uid} gid={i.st_gid}', flush=True)
if not os.path.exists(marker):
    bound,_=bind_private_broker_socket(p)
    open(marker, 'x').write('first')
    print('BOUND_THEN_CRASHED', flush=True)
    os._exit(17)
bound,_=bind_private_broker_socket(p, adopt_stale=True)
s=os.lstat(p)
open('/shared/adopted', 'x').write(f'{stat.S_IMODE(i.st_mode):o} {i.st_uid} {i.st_gid} socket={stat.S_IMODE(s.st_mode):o}')
print('ADOPTED_AND_REBOUND', flush=True)
time.sleep(3600)
"""
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "lifecycle", "namespace": namespace},
        "spec": {
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 5,
            "securityContext": {
                "runAsNonRoot": True, "fsGroup": 1000,
                "fsGroupChangePolicy": "OnRootMismatch",
            },
            "initContainers": [
                {
                    "name": "broker-restart", "image": image,
                    "imagePullPolicy": "Never", "restartPolicy": "Always",
                    "command": ["python", "-c", first],
                    "readinessProbe": {"exec": {"command": [
                        "python", "-c",
                        "import os,sys;sys.exit(0 if os.path.exists('/shared/adopted') else 1)",
                    ]}, "periodSeconds": 1, "failureThreshold": 30},
                    "securityContext": {
                        "runAsUser": 1000, "runAsGroup": 1000,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [{"name": "shared", "mountPath": "/shared"}],
                },
                {
                    "name": "envoy-shape", "image": image,
                    "imagePullPolicy": "Never", "restartPolicy": "Always",
                    "command": ["python", "-c", "import time; time.sleep(3600)"],
                    "securityContext": {
                        "runAsUser": 1337, "runAsGroup": 1337,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [{"name": "shared", "mountPath": "/shared"}],
                },
            ],
            "containers": [{
                "name": "runner", "image": image, "imagePullPolicy": "Never",
                # WAIT for the adoption marker with a bounded deadline, do not
                # assert it at startup. The broker-restart sidecar writes
                # /shared/adopted only AFTER its deliberate os._exit(17) +
                # restart + adopt cycle, which the main container has no ordering
                # guarantee over -- asserting on entry raced that cycle and made
                # the gate a coin flip (recorded green only on the runs it won).
                # Waiting makes an honest run deterministic: adoption completes
                # (~10s) -> the runner proceeds; adoption never completes -> the
                # gate fails for a real reason, at 45s, not a lost race.
                "command": ["python", "-c",
                            "import pathlib,time\n"
                            "d=pathlib.Path('/shared/adopted')\n"
                            "deadline=time.monotonic()+45\n"
                            "while not d.exists():\n"
                            "    if time.monotonic()>deadline:\n"
                            "        raise SystemExit('/shared/adopted not written "
                            "within 45s: broker adoption never completed')\n"
                            "    time.sleep(0.2)\n"
                            # Stay up long enough for the gate to exec its
                            # adopted/socket/source-hash checks, then EXIT so the
                            # Pod reaches a terminal phase within the gate's 60s
                            # deadline (the sibling native sidecars sleep on; the
                            # gate asserts they did not block termination).
                            "time.sleep(20)"],
                "securityContext": {
                    "runAsUser": 1000, "runAsGroup": 1000,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "shared", "mountPath": "/shared"}],
            }],
            "volumes": [{"name": "shared", "emptyDir": {}}],
        },
    }
    started = time.time()
    diagnostic = ""
    try:
        kubectl("create", "-f", "-", body=namespace_doc)
        namespace_uid = json.loads(kubectl(
            "get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
        kubectl("patch", "namespace", namespace, "--type=merge", "-p",
                json.dumps({"metadata": {"labels": {
                    "andyur.network-policy/verified": "true"}, "annotations": {
                    "andyur.network-policy/verified-at": str(int(time.time())),
                    "andyur.network-policy/namespace-uid": namespace_uid}}}))
        kubectl("apply", "-f", "-", body=pod)
        deadline = time.monotonic() + 60
        ready = None
        while time.monotonic() < deadline:
            ready = json.loads(kubectl(
                "get", "pod", "lifecycle", "-n", namespace, "-o", "json"))
            conditions = {item["type"]: item["status"]
                          for item in ready.get("status", {}).get("conditions", [])}
            if conditions.get("Ready") == "True":
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("native-sidecar Pod did not become Ready")
        adopted = kubectl(
            "exec", "-n", namespace, "lifecycle", "-c", "runner", "--",
            "python", "-c", "print(open('/shared/adopted').read())").strip()
        socket_connect = kubectl(
            "exec", "-n", namespace, "lifecycle", "-c", "runner", "--",
            "python", "-c",
            "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/shared/broker/authz.sock'); print('connected'); s.close()",
        ).strip()
        executed_sources = json.loads(kubectl(
            "exec", "-n", namespace, "lifecycle", "-c", "broker-restart", "--",
            "python", "-c",
            "import hashlib,json,pathlib; from andyur.dataplane import brokeruds,denybroker; "
            "print(json.dumps({n:hashlib.sha256(pathlib.Path(m.__file__).read_bytes()).hexdigest() "
            "for n,m in [('andyur/dataplane/brokeruds.py',brokeruds),"
            "('andyur/dataplane/denybroker.py',denybroker)]}))",
        ))
        host_sources = {
            item: hashlib.sha256((ROOT / item).read_bytes()).hexdigest()
            for item in sorted(SOURCES)
        }
        expected_executed = {
            item: host_sources[item] for item in executed_sources
        }
        if executed_sources != expected_executed:
            raise RuntimeError("running image source does not match host source")
        while time.monotonic() < deadline:
            final = json.loads(kubectl(
                "get", "pod", "lifecycle", "-n", namespace, "-o", "json"))
            if final.get("status", {}).get("phase") in {"Succeeded", "Failed"}:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("native sidecars prevented terminal Pod phase")
        statuses = {item["name"]: item for item in
                    final["status"]["initContainerStatuses"]}
        if final["status"]["phase"] != "Succeeded":
            raise RuntimeError("lifecycle positive control did not succeed")
        if statuses["broker-restart"]["restartCount"] < 1:
            raise RuntimeError("broker restart mutation did not apply")
        runtime_image = kubectl(
            "get", "statefulset", "andyur-server", "-n", "andyur-system",
            "-o", "jsonpath={.spec.template.spec.containers[0].image}").strip()
        if "@sha256:" not in runtime_image:
            raise RuntimeError("controller rollback gate requires a pinned image")
        rollback = controller_rollback_gate(namespace, runtime_image)
        result = {
            "started_at_epoch": started,
            "finished_at_epoch": time.time(),
            "cluster_version": json.loads(kubectl("version", "-o", "json"))[
                "serverVersion"]["gitVersion"],
            "image": image,
            "image_id": next(item["imageID"] for item in
                             ready["status"]["initContainerStatuses"]
                             if item["name"] == "broker-restart"),
            "executed_source_sha256": executed_sources,
            "adopted_directory": adopted,
            "rebound_socket_connect": socket_connect,
            "broker_restart_count": statuses["broker-restart"]["restartCount"],
            "pod_phase_after_runner_exit": final["status"]["phase"],
            "controller_rollback": rollback,
            "native_sidecars": [item["name"] for item in pod["spec"]["initContainers"]],
            "teardown_absent": False,
            "source_sha256": host_sources,
        }
    except BaseException:
        diagnostic = kubectl(
            "describe", "pod", "lifecycle", "-n", namespace, check=False)
        for container in ("broker-restart", "envoy-shape", "runner"):
            diagnostic += "\n" + kubectl(
                "logs", "-n", namespace, "lifecycle", "-c", container,
                check=False)
            diagnostic += "\nPREVIOUS:\n" + kubectl(
                "logs", "-p", "-n", namespace, "lifecycle", "-c", container,
                check=False)
        raise
    finally:
        kubectl("delete", "namespace", namespace, "--wait=true", check=False)
        if diagnostic:
            print(diagnostic)
    result["teardown_absent"] = kubectl(
        "get", "namespace", namespace, check=False).strip() == ""
    if not result["teardown_absent"]:
        raise RuntimeError("broker lifecycle namespace teardown was incomplete")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

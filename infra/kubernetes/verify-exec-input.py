#!/usr/bin/env python3
"""Live k3s proof that an exec/v1 run's INPUT reaches the process (ADR-011 D10).

Drives the REAL controller (KubernetesRunController.launch, the same object the
worker uses) and the REAL launcher translation (_exec_input_delivery) for every
declared mode, against a current-source image whose executing execconfig.py
and runinput.py are hash-checked against this checkout:

  stdin   the workload reads its stdin: byte-identical, then EOF
  file    the init container persists /tmp/andyur/input (0600, uid 1001)
          before the workload starts; the workload reads it byte-identical
  file+templates
          the SAME init container also renders a declared file that names
          the run's bearer (M1: the DEDICATED per-run MCP bearer as a complete
          header value, never the channel token) -- and the input file still holds the literal
          ${services.tools.mcp_headers.Authorization}, because input is never
          a template (the security property this gate exists to prove live)
  argv    the input is the last argument, byte-identical

Negative control: the same stdin-reading workload launched with NO delivery
is still blocked after the wait, proving the attach is what completes it.
RBAC: the worker's Role grants pods/attach with verb get (GET ws upgrade), plus a configmaps rule and not pods/exec.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import yaml

from andyur import runinput
from andyur.daemon.governed_kubernetes import _exec_input_delivery
from andyur.daemon.kubernetes_api import OfficialKubernetesApi
from andyur.daemon.kubernetes_controller import (KubernetesRunController,
                                                 RunCredentials)
from andyur.daemon.kubernetes_manifests import RunGroupSpec, run_group_names
from andyur.daemon.orchestrator import RunSpec
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, ConfigFile,
                                    ConfigurationSpec, ProcessSpec,
                                    RuntimeResolution)

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "andyur/daemon/kubernetes_api.py",
    "andyur/daemon/kubernetes_controller.py",
    "andyur/daemon/kubernetes_manifests.py",
    "andyur/daemon/governed_kubernetes.py",
    "andyur/execconfig.py",
    "andyur/runinput.py",
    "infra/kubernetes/run-isolation.yaml",
    "infra/kubernetes/bounded_exec.py",
    "infra/kubernetes/verify-exec-input.py",
    "infra/kubernetes/verify-exec-input.sh",
)
# Names the bearer reference, carries non-ASCII, and is an object: everything
# that could go wrong in transit (templating, encoding, quoting) shows up.
INPUT_VALUE = {"incident": "INC-4471",
               "note": "${services.tools.mcp_headers.Authorization}",
               "unicode": "ünïcødé ✓"}
# exec/v1 launches carry the DEDICATED per-run MCP bearer (M1); the channel
# token is a distinct value so its absence from every workload-facing surface
# is checkable by value.
CREDENTIALS = RunCredentials("channel-token-value", "run", "llm",
                             mcp_bearer="mcp-bearer-value-" + uuid.uuid4().hex)
BLOCKED_WAIT_SECONDS = 8

PROXY_HTTP_200 = (
    "from http.server import BaseHTTPRequestHandler,HTTPServer;"
    "H=type('H',(BaseHTTPRequestHandler,),{"
    "'do_GET':lambda s:(s.send_response(200),s.end_headers()),"
    "'log_message':lambda *a:None});"
    "HTTPServer(('0.0.0.0',8765),H).serve_forever()")
REPORT = ("print('LEN',len(d));print('SHA',hashlib.sha256(d).hexdigest());"
          "print('B64',base64.b64encode(d).decode())")
READ_STDIN = "import sys,hashlib,base64;d=sys.stdin.buffer.read();" + REPORT
READ_FILE = ("import os,hashlib,base64;p='/tmp/andyur/input';d=open(p,'rb').read();"
             "st=os.stat(p);print('MODE',oct(st.st_mode&0o777));print('UID',st.st_uid);"
             + REPORT)
READ_FILE_AND_CFG = (READ_FILE + ";c=open('/home/agent/cfg.yaml','rb').read();"
                     "print('CFG',base64.b64encode(c).decode())")
READ_ARGV = "import sys,hashlib,base64;d=sys.argv[-1].encode();" + REPORT


def admin_kubeconfig_path() -> str:
    """ANDYUR_KUBECONFIG, or a refusal that names it (a bare KeyError sent a
    reviewer's first run into OfficialKubernetesApi's in-cluster fallback)."""
    path = os.environ.get("ANDYUR_KUBECONFIG", "").strip()
    if not path:
        raise RuntimeError(
            "set ANDYUR_KUBECONFIG to the admin kubeconfig of the target k3s "
            "cluster (e.g. $HOME/.kube/config); see infra/kubernetes/README.md")
    return path


def kubectl(*args: str, body: dict | str | None = None, check: bool = True) -> str:
    command = ["kubectl", "--kubeconfig", admin_kubeconfig_path(), *args]
    stdin = None if body is None else (body if isinstance(body, str) else json.dumps(body))
    completed = subprocess.run(command, input=stdin, text=True,
                               capture_output=True, timeout=60)
    if check and completed.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout


def pod_logs(namespace: str, name: str) -> str:
    """Read one pod's logs by kubectl. The official client's
    read_namespaced_pod_log returns the body as a bytes-repr string in this
    client version (probed: `b'LINE 0\\n...'`), so anything that PARSES logs
    -- the delivered bytes, the source hashes -- reads them this way instead.
    Best-effort log tails inside the controller are unaffected."""
    return kubectl("logs", "-n", namespace, name, check=False)


def host_hashes() -> dict[str, str]:
    return {item: hashlib.sha256((ROOT / item).read_bytes()).hexdigest()
            for item in SOURCES}


def parse_report(logs: str) -> dict:
    out = {}
    for line in logs.splitlines():
        key, _, value = line.partition(" ")
        if key in {"LEN", "SHA", "B64", "MODE", "UID", "CFG"}:
            out[key] = value.strip()
    return out


def runtime_for(image: str, mode: str, command: tuple[str, ...],
                configuration: ConfigurationSpec | None) -> RuntimeResolution:
    ref, digest = image.split("@", 1)
    return RuntimeResolution(
        runtime_type="container", interface_version=RUNTIME_PROTOCOL_EXEC_V1,
        manifest_digest="sha256:" + "0" * 64, image_ref=ref, image_digest=digest,
        command=command, process=ProcessSpec(input_mode=mode, input_max_bytes=4096),
        configuration=configuration)


def wait_phase(api: OfficialKubernetesApi, namespace: str, name: str,
               wanted: set[str], timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    phase = None
    while time.monotonic() < deadline:
        phase = api.pod_phase(namespace, name)
        if phase in wanted:
            return phase
        time.sleep(0.5)
    return phase


def launch_and_observe(api, controller, namespace, image, mode, command,
                       configuration, sealed, expect_complete=True) -> dict:
    """One run through the real launcher translation and the real controller."""
    runtime = runtime_for(image, mode, command, configuration)
    args, delivery, payload, bound = _exec_input_delivery(
        RunSpec(run_id="r", agent="stock", run_input=sealed), runtime)
    run_id = uuid.uuid4().hex
    spec = RunGroupSpec(
        namespace=namespace, run_id=run_id, generation="exec-input-gate",
        agent_id="stock", registry_agent_id="agt_stock",
        proxy_image=image, agent_image=image, proxy_port=8765, mcp_port=8766,
        proxy_args=("python", "-c", PROXY_HTTP_200),
        agent_args=args, agent_runtime="container",
        agent_interface=RUNTIME_PROTOCOL_EXEC_V1,
        exec_configuration=configuration,
        exec_input_mode=delivery, exec_input=payload, exec_input_max_bytes=bound,
        run_ttl_seconds=600)
    names = run_group_names(spec)
    started = time.monotonic()
    controller.launch(spec, CREDENTIALS)
    result: dict = {"mode": mode, "delivery": delivery, "run_id": run_id,
                    "launch_seconds": round(time.monotonic() - started, 2)}
    try:
        if expect_complete:
            phase = wait_phase(api, namespace, names["agent"], {"Succeeded", "Failed"}, 120)
            result["phase"] = phase
            result["report"] = parse_report(pod_logs(namespace, names["agent"]))
        else:
            time.sleep(BLOCKED_WAIT_SECONDS)
            result["phase_after_wait"] = api.pod_phase(namespace, names["agent"])
            result["logs_after_wait"] = pod_logs(namespace, names["agent"])
    finally:
        controller.delete(spec)
    result["resources_absent"] = kubectl(
        "get", "pod,service,secret,configmap,serviceaccount,networkpolicy,lease",
        "-n", namespace, "-l", f"andyur.run/id={names['base'].split('-')[2]}",
        "-o", "name", check=False).strip() == ""
    return result


def check_delivery(result: dict, expected: bytes) -> dict:
    report = result.get("report", {})
    delivered = base64.b64decode(report.get("B64", "")) if report.get("B64") else b""
    return {
        **result,
        "expected_len": len(expected),
        "expected_sha256": hashlib.sha256(expected).hexdigest(),
        "byte_identical": delivered == expected,
        "reference_survived_verbatim": b"${services.tools.mcp_headers.Authorization}" in delivered,
        "bearer_absent_from_input": (CREDENTIALS.channel_token.encode() not in delivered
                                     and CREDENTIALS.mcp_bearer.encode() not in delivered),
        "ok": result.get("phase") == "Succeeded" and delivered == expected
              and result.get("resources_absent") is True,
    }


_GATE_CLEANUP = []


def check_output_read_through_sa(admin_api, sa_api, sa_api_nolog, controller,
                                 namespace, image) -> dict:
    """H5/H6, proven live: the daemon reads a stock workload's OUTPUT through the
    worker SA (GET pods/{name}/log). Positive: the REAL SA reads the workload's
    stdout byte for byte, with the daemon's kwargs (tail_lines=None + limitBytes,
    so H6's head window is what is actually sent). Negative: the SAME read under
    a Role clone WITHOUT pods/log is 403, BY NAME -- so the grant is load-bearing,
    not decoration, the way the attach verb was proven. Nothing reads as admin.
    """
    marker = "ANDYUR-H5-OUTPUT-" + uuid.uuid4().hex + "\n"
    run_id = uuid.uuid4().hex
    spec = RunGroupSpec(
        namespace=namespace, run_id=run_id, generation="exec-input-gate",
        agent_id="stock", registry_agent_id="agt_stock",
        proxy_image=image, agent_image=image, proxy_port=8765, mcp_port=8766,
        proxy_args=("python", "-c", PROXY_HTTP_200),
        agent_args=("python", "-c", f"import sys; sys.stdout.write({marker!r})"),
        agent_runtime="container", agent_interface=RUNTIME_PROTOCOL_EXEC_V1,
        exec_input_mode="", exec_input=b"", exec_input_max_bytes=0,
        run_ttl_seconds=600)
    names = run_group_names(spec)
    out: dict = {}
    controller.launch(spec, CREDENTIALS)
    try:
        out["phase"] = wait_phase(
            admin_api, namespace, names["agent"], {"Succeeded", "Failed"}, 120)
        body = sa_api.pod_logs(namespace, names["agent"], tail_lines=None,
                               limit_bytes=len(marker.encode()) + 4096)
        out["granted_read_byte_identical"] = body == marker
        try:
            sa_api_nolog.pod_logs(namespace, names["agent"], tail_lines=None,
                                  limit_bytes=len(marker.encode()) + 4096)
            out["ungranted_read_403"] = False
            out["ungranted_read_status"] = "unexpectedly succeeded"
        except Exception as exc:                                 # noqa: BLE001
            status = getattr(exc, "status", None)
            out["ungranted_read_403"] = status == 403
            out["ungranted_read_status"] = str(status)
    finally:
        controller.delete(spec)
    out["ok"] = bool(out.get("granted_read_byte_identical")
                     and out.get("ungranted_read_403"))
    return out


def sa_authed_api(namespace: str, sa: str = "andyur-worker-gate",
                  drop_resources: frozenset = frozenset()):
    """An OfficialKubernetesApi authenticated as the worker's ServiceAccount,
    bound to the REAL Role (infra/kubernetes/run-isolation.yaml) plus the
    namespace-get the worker's preflight ClusterRole grants for its own
    namespace. The controller under test then acts with exactly the worker's
    cluster authority instead of the admin kubeconfig -- so a wrong RBAC rule
    (e.g. attach's verb, or a missing configmaps rule) surfaces as the 403 it
    is, reddening the gate, which running as admin sailed straight past. Returns
    (api, principal).

    ``drop_resources`` omits the Role rules naming those resources, so a caller
    can build a DELIBERATELY-underpowered SA (e.g. without pods/log) to prove
    the negative: that the grant is load-bearing, not decoration.

    The SA bearer kubeconfig is written to this PROCESS's real $TMPDIR via
    mkstemp and reaped in main()'s finally. If you ever clean one up by hand,
    target that path -- NOT a sandboxed $TMPDIR (a tool sandbox may report
    /private/tmp/... while the file is under /var/folders/.../T on macOS), or
    the rm silently misses and leaves a live bearer on disk.
    """
    admin_kubeconfig = admin_kubeconfig_path()
    cfg = yaml.safe_load(Path(admin_kubeconfig).read_text())
    ctx = next(c for c in cfg["contexts"] if c["name"] == cfg["current-context"])["context"]
    cluster = next(c for c in cfg["clusters"] if c["name"] == ctx["cluster"])["cluster"]
    server = cluster["server"]
    ca_data = cluster.get("certificate-authority-data")
    if not ca_data and cluster.get("certificate-authority"):
        ca_data = base64.b64encode(
            Path(cluster["certificate-authority"]).read_bytes()).decode()

    kubectl("apply", "-f", "-", body={
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": sa, "namespace": namespace}})
    role = next(d for d in yaml.safe_load_all(
        (ROOT / "infra/kubernetes/run-isolation.yaml").read_text())
        if d and d.get("kind") == "Role")
    rules = [r for r in role["rules"]
             if not (set(r.get("resources", [])) & set(drop_resources))]
    role = {**role, "metadata": {"name": sa, "namespace": namespace},
            "rules": rules}
    kubectl("apply", "-f", "-", body=role)
    kubectl("apply", "-f", "-", body={
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": sa, "namespace": namespace},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": sa},
        "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": namespace}]})
    cr = f"{sa}-{namespace}"
    kubectl("apply", "-f", "-", body={
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": cr},
        "rules": [{"apiGroups": [""], "resources": ["namespaces"],
                   "verbs": ["get"], "resourceNames": [namespace]}]})
    _GATE_CLEANUP.append(lambda: kubectl("delete", "clusterrole", cr, "--wait=false", check=False))
    kubectl("apply", "-f", "-", body={
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": cr},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": cr},
        "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": namespace}]})
    _GATE_CLEANUP.append(lambda: kubectl("delete", "clusterrolebinding", cr, "--wait=false", check=False))
    token = kubectl("create", "token", sa, "-n", namespace, "--duration=30m").strip()

    cluster_block = {"server": server}
    if ca_data:
        cluster_block["certificate-authority-data"] = ca_data
    else:
        cluster_block["insecure-skip-tls-verify"] = True
    kubeconfig = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "c", "cluster": cluster_block}],
        "users": [{"name": "sa", "user": {"token": token}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "sa",
                                                 "namespace": namespace}}],
        "current-context": "ctx"}
    fd, path = tempfile.mkstemp(prefix="andyur-worker-gate-", suffix=".kubeconfig")
    _GATE_CLEANUP.append(lambda: os.unlink(path))
    os.write(fd, yaml.safe_dump(kubeconfig).encode())
    os.close(fd)

    previous = os.environ.get("ANDYUR_KUBECONFIG")
    os.environ["ANDYUR_KUBECONFIG"] = path
    try:
        api = OfficialKubernetesApi()
    finally:
        if previous is not None:
            os.environ["ANDYUR_KUBECONFIG"] = previous
    # Cleanups (kubeconfig unlink + cluster-scoped RBAC delete) are registered
    # AS EACH RESOURCE IS CREATED, above, so a failure mid-setup still reaps
    # what was made rather than orphaning it (R L6). main()'s finally runs them.
    return api, f"system:serviceaccount:{namespace}:{sa}"


def main() -> None:
    image = os.environ.get("ANDYUR_EXEC_INPUT_IMAGE", "").strip()
    if "@sha256:" not in image:
        raise RuntimeError(
            "ANDYUR_EXEC_INPUT_IMAGE must be a digest-pinned image built from the "
            "current checkout and pushed where the cluster node can pull it")
    namespace = f"andyur-exec-input-{uuid.uuid4().hex[:8]}"
    api = OfficialKubernetesApi()
    sealed = runinput.seal(INPUT_VALUE)
    expected = runinput.delivery_bytes(sealed)
    started = time.time()
    result: dict = {"gate": "exec-input-delivery", "started_at_epoch": started,
                    "host": platform.platform(), "image": image}
    diagnostic = ""
    try:
        kubectl("create", "-f", "-", body={"apiVersion": "v1", "kind": "Namespace",
                                            "metadata": {"name": namespace}})
        namespace_uid = json.loads(kubectl(
            "get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
        # The controller refuses to launch into a namespace without a fresh
        # isolation stamp; this gate is about delivery, so the stamp is
        # applied here exactly as the sibling gates apply it. Stamp BEFORE the
        # controller is constructed: its constructor asserts the stamp.
        kubectl("patch", "namespace", namespace, "--type=merge", "-p",
                json.dumps({"metadata": {"labels": {
                    "andyur.network-policy/verified": "true"}, "annotations": {
                    "andyur.network-policy/verified-at": str(int(time.time())),
                    "andyur.network-policy/namespace-uid": namespace_uid}}}))
        # THE CONTROLLER RUNS AS THE WORKER, not admin. `api` (admin) stays the
        # harness's observation client; the system under test acts under the SA.
        sa_api, sa_principal = sa_authed_api(namespace)
        result["controller_identity"] = sa_principal
        controller = KubernetesRunController(sa_api, namespace)

        # H5/H6: the daemon reads a stock workload's OUTPUT through the worker SA
        # (GET pods/log), a path the real in-cluster worker never exercises (no
        # SPIRE agent mounted, so it never runs under its Role). A second SA whose
        # Role LACKS pods/log proves the grant is load-bearing, not decoration.
        sa_api_nolog, _ = sa_authed_api(
            namespace, sa="andyur-worker-gate-nolog",
            drop_resources=frozenset({"pods/log"}))
        result["output_read_rbac"] = check_output_read_through_sa(
            api, sa_api, sa_api_nolog, controller, namespace, image)

        # 1. The executing image runs THIS checkout's delivery code.
        kubectl("apply", "-f", "-", body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "source-probe", "namespace": namespace},
            "spec": {"restartPolicy": "Never", "containers": [{
                "name": "probe", "image": image,
                # Emit "HASH <name> <sha>" lines rather than a JSON blob: the
                # platform image's entrypoint renders a dict with repr() (single
                # quotes), so a JSON parse of its stdout is not portable. One
                # prefixed line per file is unambiguous under either.
                "command": ["python", "-c",
                            "import hashlib, pathlib\n"
                            "from andyur import execconfig, runinput\n"
                            "from andyur.daemon import kubernetes_controller\n"
                            "for n, m in [('andyur/execconfig.py', execconfig), "
                            "('andyur/runinput.py', runinput), "
                            "('andyur/daemon/kubernetes_controller.py', kubernetes_controller)]:\n"
                            "    print('HASH', n, "
                            "hashlib.sha256(pathlib.Path(m.__file__).read_bytes()).hexdigest())"],
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1001}}]}})
        if wait_phase(api, namespace, "source-probe", {"Succeeded", "Failed"}, 90) != "Succeeded":
            raise RuntimeError("source probe did not complete: "
                               + kubectl("describe", "pod", "source-probe", "-n", namespace, check=False))
        executed = {parts[1]: parts[2]
                    for parts in (ln.split() for ln in
                                  pod_logs(namespace, "source-probe").splitlines())
                    if len(parts) == 3 and parts[0] == "HASH"}
        if not executed:
            raise RuntimeError("source probe emitted no HASH line")
        hosts = host_hashes()
        if any(executed[k] != hosts[k] for k in executed):
            raise RuntimeError(f"running image source does not match host source: {executed}")
        result["executed_source_sha256"] = executed
        result["image_id"] = json.loads(kubectl(
            "get", "pod", "source-probe", "-n", namespace, "-o", "json"))[
            "status"]["containerStatuses"][0]["imageID"]

        # 2. RBAC, checked TWO honest ways under the worker SA (not admin).
        #
        # (a) LIVE, and load-bearing: the controller below runs under
        # `sa_principal`, so if the Role's attach verb were wrong (create-only,
        # the R H1 defect) or the configmaps rule were missing (H2), launch
        # would 403 and the gate would go red. That is the real proof; the
        # can-i lines here are a cross-check.
        #
        # (b) can-i WITH `--subresource`, which discriminates correctly on this
        # cluster (the earlier `pods/attach` form was parsed as a Pod named
        # "attach" -- a resourceName -- which is why it answered yes for
        # pods/nonsense too). The client opens attach as a GET ws upgrade, so
        # `get` is the verb that must be granted.
        can = lambda verb, sub: kubectl(
            "auth", "can-i", verb, "pods", "--subresource", sub,
            "-n", namespace, "--as", sa_principal, check=False).strip()
        result["rbac"] = {
            "controller_ran_as": sa_principal,
            "get_pods_attach": can("get", "attach"),
            "create_pods_attach": can("create", "attach"),
            "get_pods_exec": can("get", "exec"),
            "create_pods_exec": can("create", "exec"),
            "get_pods_portforward": can("get", "portforward"),
        }
        r = result["rbac"]
        # The GET verb attach uses must be granted; exec/portforward must not be.
        if not (r["get_pods_attach"] == "yes"
                and r["get_pods_exec"] == "no"
                and r["get_pods_portforward"] == "no"):
            raise RuntimeError(f"worker SA RBAC for attach is wrong: {r}")

        # 3. Delivery, every mode, through the real translation and controller.
        modes = {}
        modes["stdin"] = check_delivery(launch_and_observe(
            api, controller, namespace, image, "stdin",
            ("python", "-c", READ_STDIN), None, sealed), expected)
        modes["file"] = check_delivery(launch_and_observe(
            api, controller, namespace, image, "file",
            ("python", "-c", READ_FILE), None, sealed), expected)
        cfg = ConfigurationSpec(files=(ConfigFile(
            path="${workspace.home}/cfg.yaml",
            template=("mcp: ${services.tools.mcp_url}\n"
                      "auth: ${services.tools.mcp_headers.Authorization}\n"
                      "input: ${run.input_path}\n")),))
        modes["file_with_templates"] = check_delivery(launch_and_observe(
            api, controller, namespace, image, "file",
            ("python", "-c", READ_FILE_AND_CFG), cfg, sealed), expected)
        rendered = base64.b64decode(modes["file_with_templates"]["report"].get("CFG", "")).decode()
        modes["file_with_templates"]["rendered_config"] = rendered
        # M1: the reference renders as the complete header value of the
        # DEDICATED bearer -- and the channel token appears nowhere in the file.
        modes["file_with_templates"]["bearer_rendered_into_declared_file"] = (
            f"auth: Bearer {CREDENTIALS.mcp_bearer}" in rendered)
        modes["file_with_templates"]["channel_token_absent_from_rendered_file"] = (
            CREDENTIALS.channel_token not in rendered)
        modes["file_with_templates"]["input_path_rendered"] = "input: /tmp/andyur/input" in rendered
        modes["file_with_templates"]["ok"] = (
            modes["file_with_templates"]["ok"]
            and modes["file_with_templates"]["bearer_rendered_into_declared_file"]
            and modes["file_with_templates"]["channel_token_absent_from_rendered_file"]
            and modes["file_with_templates"]["bearer_absent_from_input"]
            and modes["file_with_templates"]["reference_survived_verbatim"]
            and modes["file_with_templates"]["input_path_rendered"])
        for key in ("file", "file_with_templates"):
            modes[key]["file_private_to_workload_uid"] = (
                modes[key]["report"].get("MODE") == "0o600"
                and modes[key]["report"].get("UID") == "1001")
            modes[key]["ok"] = modes[key]["ok"] and modes[key]["file_private_to_workload_uid"]
        modes["argv"] = check_delivery(launch_and_observe(
            api, controller, namespace, image, "argv",
            ("python", "-c", READ_ARGV), None, sealed), expected)
        result["modes"] = modes

        # 4. Negative control: the SAME stdin-reading workload, launched with
        # stdin+stdinOnce open but NOBODY attaching, does not complete -- it
        # blocks on read until it is killed. This is the hazard the door
        # refuses and the attach resolves; the three passing modes above show
        # the attach completing it, and this shows its absence hanging it.
        # A bare Pod, not the controller (which always attaches when a mode is
        # set), because the point is precisely the missing attach.
        kubectl("apply", "-f", "-", body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "no-attach", "namespace": namespace},
            "spec": {"restartPolicy": "Never", "containers": [{
                "name": "w", "image": image, "imagePullPolicy": "Never",
                "stdin": True, "stdinOnce": True,
                "command": ["python", "-c", READ_STDIN],
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1001}}]}})
        wait_phase(api, namespace, "no-attach", {"Running"}, 60)
        time.sleep(BLOCKED_WAIT_SECONDS)
        phase = api.pod_phase(namespace, "no-attach")
        logs = pod_logs(namespace, "no-attach")
        kubectl("delete", "pod", "no-attach", "-n", namespace, "--wait=false", check=False)
        blocked = {"phase_after_wait": phase, "logs_after_wait": logs,
                   "still_blocked": phase == "Running" and "LEN" not in logs}
        blocked["ok"] = blocked["still_blocked"]
        result["no_delivery_control"] = blocked

        result["source_sha256"] = hosts
        result["cluster_version"] = json.loads(kubectl("version", "-o", "json"))[
            "serverVersion"]["gitVersion"]
        result["ok"] = (all(m["ok"] for m in modes.values()) and blocked["ok"]
                        and result["output_read_rbac"]["ok"])
        if not result["ok"]:
            raise RuntimeError("exec input delivery gate failed: "
                               + json.dumps(result, sort_keys=True, default=str))
    except BaseException:
        diagnostic = kubectl("get", "pods", "-n", namespace, "-o", "wide", check=False)
        diagnostic += kubectl("describe", "pods", "-n", namespace, check=False)[-6000:]
        raise
    finally:
        for _cleanup in _GATE_CLEANUP:
            try:
                _cleanup()
            except Exception:
                pass
        kubectl("delete", "namespace", namespace, "--wait=true", check=False)
        if diagnostic:
            print(diagnostic)
    result["finished_at_epoch"] = time.time()
    result["teardown_absent"] = kubectl("get", "namespace", namespace, check=False).strip() == ""
    print(json.dumps(result, sort_keys=True, default=str))


if __name__ == "__main__":
    main()

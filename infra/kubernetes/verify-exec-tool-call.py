#!/usr/bin/env python3
"""Live k3s proof that an exec/v1 workload's declared MCP bearer is what /mcp
accepts (ADR-011 acceptance #3; the M1 flip gate, PR #21).

Drives the REAL controller (KubernetesRunController.launch, under the worker's
ServiceAccount, not admin) against a current-source runner image whose executing
toolservice.py / execfront.py / runner.py / execconfig.py are hash-checked
against this checkout. The proxy container runs the REAL serve-only services --
`runner._start_serve_only_services`: the ToolService keyed on ANDYUR_MCP_TOKEN
from the runtime Secret, then the ExecFront on the proxy port -- so the
readiness the controller waits on and the /mcp the workload calls are the
sidecar's own code, not a stand-in. The workload is a stock process (python in
the same image, uid 1001) handed ONLY what the manifest declared: MCP_URL and
MODEL_URL as resolved literals, MCP_AUTH by secretKeyRef, and a rendered file
naming the same two references.

What the workload proves from inside its Pod, over the real wire:
  declared    Authorization: <MCP_AUTH> (the reference resolves to a complete
              header value, `Bearer <token>`) -> initialize, tools/list (the
              real platform registry), tools/call reaching the real tool body
  wrong       a different bearer                      -> 401
  none        no Authorization header                 -> 401
  channel     the run's CHANNEL token as the bearer   -> 401  (M1 separation)
  bare        the bare token without the scheme       -> 401  (why the header
              value, not the bare token, is what the reference must resolve to)
  undeclared  tools/call on a tool not in the registry -> refused by the server
  front       services.model.base_url (proxy_port/llm) answers 503 by name (no
              model proxy in this gate) rather than connection refused; /ready
              on the same port is 200 -- the probe the controller waited on
  absence     the channel token, run token and LiteLLM key appear in no env
              value, argv, or generated file (ADR-011 acceptance #2)
And from outside: the SAME group shape with a proxy that serves ToolService
but NO front does not become ready and is rolled back (R MED-2's mutant, live).

NOT covered, on purpose: the server-side scope refusal (auth.require_scope, the
true 'ungranted tool' PEP). Every control-plane call needs a SPIRE JWT-SVID and a
gate namespace has no SPIRE registration, so the granted call's control-plane
leg fails inside the tool body here (recorded as such); that leg belongs to the
kubernetes-verify lane with the in-cluster control plane.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

from andyur.daemon.kubernetes_api import OfficialKubernetesApi
from andyur.daemon.kubernetes_controller import (KubernetesRunController,
                                                 RunCredentials)
from andyur.daemon.kubernetes_manifests import ClusterPeer, RunGroupSpec, run_group_names
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, ConfigFile,
                                    ConfigurationSpec, EnvVar)

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

# The sibling gate's harness (kubectl, pod_logs, wait_phase, the worker-SA
# kubeconfig builder): imported by path, not copied, so the two exec/v1 gates
# cannot drift on how they bind the worker's authority.
_spec = importlib.util.spec_from_file_location(
    "verify_exec_input", HERE / "verify-exec-input.py")
_ei = importlib.util.module_from_spec(_spec)
sys.modules["verify_exec_input"] = _ei
_spec.loader.exec_module(_ei)
kubectl, pod_logs, wait_phase, sa_authed_api = (
    _ei.kubectl, _ei.pod_logs, _ei.wait_phase, _ei.sa_authed_api)

SOURCES = (
    "andyur/daemon/kubernetes_api.py",
    "andyur/daemon/kubernetes_controller.py",
    "andyur/daemon/kubernetes_manifests.py",
    "andyur/daemon/governed_kubernetes.py",
    "andyur/execconfig.py",
    "andyur/identity.py",
    "andyur/runner/execfront.py",
    "andyur/runner/runner.py",
    "andyur/runner/toolservice.py",
    # WHERE THE TOOL REGISTRY IS. toolservice.build_app serves the object
    # build_platform_server builds, so a tool added here changes what this gate
    # observes -- and without this binding the artifact would go on claiming a
    # green that no longer reproduces.
    "andyur/runner/driver.py",
    "infra/kubernetes/run-isolation.yaml",
    "infra/kubernetes/bounded_exec.py",
    "infra/kubernetes/verify-exec-input.py",
    "infra/kubernetes/verify-exec-tool-call.py",
    "infra/kubernetes/verify-exec-tool-call.sh",
    # the telemetry path the ON posture and the read-back rest on (R MED-2)
    "infra/kubernetes/observability.yaml",
    "infra/observability/otel-collector.yaml",
    "infra/observability/jaeger.yaml",
    "infra/observability/trace_readback.py",
)
# Executed INSIDE the image by the source probe; must equal the host's.
IN_IMAGE = {
    "andyur/execconfig.py": "andyur.execconfig",
    "andyur/identity.py": "andyur.identity",
    "andyur/runner/execfront.py": "andyur.runner.execfront",
    "andyur/runner/runner.py": "andyur.runner.runner",
    "andyur/runner/toolservice.py": "andyur.runner.toolservice",
}
# THE REGISTRY A STOCK WORKLOAD IS SERVED, listed rather than imported: the
# point of this check is to NOTICE when it changes, and a list derived from the
# thing under test can never disagree with it.
#
# It said seven for as long as the platform served seven, and then the
# consequential action added `request_rollback` to
# `driver.build_platform_server` -- which `toolservice.build_app` serves
# verbatim, so the workload saw eight. This gate would have failed from that
# moment. It did not, because its artifact binds toolservice.py and NOT
# driver.py, where the registry actually lives: the recorded evidence stayed
# "current" against a source that no longer produced it. Currency proves the
# evidence describes today's source; it cannot prove re-running would still
# pass, and the binding is what closes the gap. driver.py is bound below now.
PLATFORM_TOOLS = sorted([
    "update_short_term_memory", "append_long_term_memory", "create_task",
    "update_task", "send_message", "handle_message", "search_memory_graph",
    "request_rollback"])

# Distinctive values, so absence can be checked by value.
CREDENTIALS = RunCredentials(
    "channel-token-value-" + uuid.uuid4().hex, "run-token-value-" + uuid.uuid4().hex,
    "llm-key-value-" + uuid.uuid4().hex, mcp_bearer=secrets.token_urlsafe(32))

# The REAL serve-only services, in the real image. ANDYUR_SVID_TIMEOUT bounds
# the granted call's control-plane leg (no SPIRE registration here) so the
# probe reports the failure instead of waiting the default 30s. Everything the
# function reads -- ANDYUR_MCP_TOKEN, ANDYUR_POD_IP, ANDYUR_MCP_PORT,
# ANDYUR_CHANNEL_PORT, ANDYUR_DEPLOYMENT, ANDYUR_AGENT_SPLIT -- is what the
# controller's proxy Pod carries.
# Parked via the REAL _serve_only_park (the SIGTERM-aware park the production
# --serve-only entry uses), not a bare Event: the Pod delete this gate times is
# then the sidecar's own termination behaviour (R MED-0 / round-2 follow-up).
GATE_MODEL = "gate-model:latest"
# Telemetry ON (observability-exit-criteria.md 7): the sidecar exports to the
# Collector the manifests configured (ANDYUR_OTEL_ENDPOINT, reached through
# the proxy egress peer the gate adds), under ONE root span whose traceparent
# is printed so the gate can read the trace back from Jaeger by id after the
# Pod is gone. COLLECTOR_FROM_PROXY is the proxy's own live probe of that
# endpoint -- the positive control for the workload's denial below.
PROXY_SERVE = (
    "import os, asyncio, socket\n"
    "from urllib.parse import urlsplit\n"
    "os.environ['ANDYUR_SVID_TIMEOUT'] = '3'\n"
    "os.environ['ANDYUR_MCP_TOKEN_PROBE'] = os.environ.get('ANDYUR_MCP_TOKEN', '')  # read before the pop\n"
    "from andyur import otel\n"
    "from andyur.runner import runner\n"
    "u = urlsplit(os.environ.get('ANDYUR_OTEL_ENDPOINT', ''))\n"
    "# a fresh Pod's policy is programmed by the CNI a moment after start:\n"
    "# retry within a bound, so a first-millisecond drop is not read as deny\n"
    "import time\n"
    "reach, t0 = 'deny', time.monotonic()\n"
    "while reach == 'deny' and time.monotonic() - t0 < 15:\n"
    "    try:\n"
    "        socket.create_connection((u.hostname, u.port or 4318), 3).close(); reach = 'allow'\n"
    "    except OSError:\n"
    "        time.sleep(0.5)\n"
    "print('COLLECTOR_FROM_PROXY', reach, u.hostname, u.port, round(time.monotonic() - t0, 1), flush=True)\n"
    "tracer = otel.setup_tracing('andyur-runner')\n"
    "with tracer.start_as_current_span('exec-tool-call-gate.serve') as span:\n"
    "    span.set_attribute('andyur.run_id', os.environ['ANDYUR_RUN_ID'])\n"
    "    print('TRACEPARENT', otel.current_traceparent(), flush=True)\n"
    "    # the listeners' trusted fixed parent: THIS span (a run's is its record's)\n"
    "    front, svc, url = runner._start_serve_only_services(\n"
    "        os.environ['ANDYUR_AGENT_ID'], os.environ['ANDYUR_RUN_ID'], otel.current_traceparent(), None,\n"
    "        enforced_model=runner._exec_granted_model())\n"
    "    print('SERVING', url, flush=True)\n"
    "    # R MED-3 (PR #25): the delete below must stay prompt with a REAL MCP\n"
    "    # stream open and a stalled POST in flight -- open both against this\n"
    "    # sidecar's own /mcp and hold them across the park.\n"
    "    import json, socket, threading, urllib.request\n"
    "    def hold_open():\n"
    "        try:\n"
    "            bearer = 'Bearer ' + os.environ.get('ANDYUR_MCP_TOKEN_PROBE', '')\n"
    "            init = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {\n"
    "                'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'probe', 'version': '0'}}}).encode()\n"
    "            req = urllib.request.Request(url, data=init, headers={'Authorization': bearer, 'Content-Type': 'application/json',\n"
    "                                                              'Accept': 'application/json, text/event-stream'})\n"
    "            with urllib.request.urlopen(req, timeout=10) as r:\n"
    "                session = r.headers.get('mcp-session-id', '')\n"
    "            host, port = url.split('//')[1].split('/')[0].split(':')\n"
    "            stream = socket.create_connection((host, int(port)))\n"
    "            stream.sendall(('GET /mcp HTTP/1.1\\r\\nHost: x\\r\\nAuthorization: ' + bearer + '\\r\\nMcp-Session-Id: ' + session\n"
    "                            + '\\r\\nAccept: text/event-stream\\r\\n\\r\\n').encode())\n"
    "            stalled = socket.create_connection((host, int(port)))\n"
    "            stalled.sendall(('POST /mcp HTTP/1.1\\r\\nHost: x\\r\\nAuthorization: ' + bearer\n"
    "                             + '\\r\\nContent-Type: application/json\\r\\nContent-Length: 100\\r\\n\\r\\n{').encode())\n"
    "            print('STREAM_OPEN', bool(session), flush=True)\n"
    "            threading.Event().wait()\n"
    "        except Exception as exc:\n"
    "            print('STREAM_OPEN_FAILED', type(exc).__name__, flush=True)\n"
    "    threading.Thread(target=hold_open, daemon=True).start()\n"
    "    print('PARK', asyncio.run(runner._serve_only_park(3600)), flush=True)\n"
    "otel.flush()\n")
# The mutant: ToolService only, nothing on the proxy port. Same image, same
# env, same park; the controller must refuse to consider it ready.
PROXY_NO_FRONT = (
    "import os, asyncio\n"
    "os.environ['ANDYUR_SVID_TIMEOUT'] = '3'\n"
    "from andyur.runner import runner\n"
    "svc = runner.ToolService(os.environ['ANDYUR_AGENT_ID'], None,\n"
    "    os.environ['ANDYUR_RUN_ID'], token=runner._serve_only_mcp_token(),\n"
    "    **runner._tool_service_network())\n"
    "print('SERVING-NO-FRONT', svc.start(), flush=True)\n"
    "print('PARK', asyncio.run(runner._serve_only_park(3600)), flush=True)\n")
# A parked PID-1 python without the handler pays terminationGracePeriodSeconds
# (20 s) before the kubelet's SIGKILL; with it the Pod goes in a few seconds.
# Measured 0.8 s (group) / 1.7 s (rollback) with the handler; a handler that
# honoured SIGTERM late would still be caught by this bound (R, round 2).
PROMPT_DELETE_SECONDS = 5.0

WORKLOAD = r'''
import asyncio, json, os, sys
import httpx
from mcp import ClientSession
from mcp.client import streamable_http as _sh
import contextlib

@contextlib.asynccontextmanager
async def _client(url, headers):
    """mcp 1.x: streamablehttp_client(url, headers=...) is the header-taking
    form; the newer streamable_http_client takes an httpx client instead."""
    if hasattr(_sh, "streamablehttp_client"):
        async with _sh.streamablehttp_client(url, headers=headers) as streams:
            yield streams
    else:
        async with httpx.AsyncClient(headers=headers, timeout=30) as hc:
            async with _sh.streamable_http_client(url, http_client=hc) as streams:
                yield streams
_KW = {}

def emit(name, **fields):
    print("PROBE", name, json.dumps(fields, sort_keys=True, default=str), flush=True)

def status_of(exc):
    """The HTTP status behind an MCP client failure, walking ExceptionGroups."""
    found = []
    def walk(e):
        if isinstance(e, httpx.HTTPStatusError):
            found.append(e.response.status_code)
        for sub in getattr(e, "exceptions", ()) or ():
            walk(sub)
        if e.__cause__ is not None:
            walk(e.__cause__)
        if e.__context__ is not None and e.__context__ is not e.__cause__:
            walk(e.__context__)
    walk(exc)
    return found[0] if found else None

async def session(url, headers):
    async with _client(url, headers=headers, **_KW) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            return s, names

async def probe_declared(url, auth):
    async with _client(url, headers={"Authorization": auth}, **_KW) as (r, w, *_):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            res = await s.call_tool("send_message", {"to": "operator", "body": "exec/v1 tool-call gate"})
            text = " ".join(getattr(c, "text", "") for c in res.content)[:300]
            emit("declared", initialized=bool(init.serverInfo.name), server=init.serverInfo.name,
                 tools=names, call_returned=True, call_is_error=bool(res.isError), call_text=text)
            try:
                bad = await s.call_tool("not_a_declared_tool", {})
                emit("undeclared", refused=bool(bad.isError),
                     text=" ".join(getattr(c, "text", "") for c in bad.content)[:200])
            except Exception as exc:
                emit("undeclared", refused=True, text=f"{type(exc).__name__}: {exc}"[:200])

async def probe_refused(name, url, headers):
    try:
        await session(url, headers)
        emit(name, status=None, refused=False)
    except BaseException as exc:
        emit(name, status=status_of(exc), refused=status_of(exc) in (401, 403),
             error=f"{type(exc).__name__}"[:80])

async def main():
    url, auth, model = os.environ["MCP_URL"], os.environ["MCP_AUTH"], os.environ["MODEL_URL"]
    # ${workspace.home} is the platform's fixed scratch (/home/agent), NOT this
    # image's $HOME -- the runner image sets HOME=/home/runner for its own uid.
    cfg = open("/home/agent/cfg.yaml").read()
    emit("delivery", auth_is_header_value=auth.startswith("Bearer "),
         rendered_auth_matches_env=(f"auth: {auth}" in cfg), rendered_mcp_matches_env=(f"mcp: {url}" in cfg),
         mcp_url=url, model_url=model)
    secrets = json.loads(os.environ["GATE_SECRETS"])          # what must be ABSENT
    haystack = "\n".join([*os.environ.values(), *sys.argv, cfg])
    hay_without_probe = haystack.replace(os.environ["GATE_SECRETS"], "")
    emit("absence", **{k: (v not in hay_without_probe) for k, v in secrets.items()})
    await probe_declared(url, auth)
    # The Collector trusts its network: the trusted proxy may export to it, the
    # untrusted workload must be refused by its rendered policy (default deny +
    # proxy-only egress). Probed by address (no DNS here), AFTER the MCP calls
    # through the proxy succeeded -- this Pod's policy is proven programmed, so
    # a refusal is the rule, not an unprogrammed CNI -- and SUSTAINED: every
    # attempt across the window must be refused (a first-millisecond read
    # proves nothing either way; R on PR A).
    import socket, time
    host, port = os.environ["COLLECTOR_ADDR"].rsplit(":", 1)
    attempts, denied, t0 = 0, 0, time.monotonic()
    while time.monotonic() - t0 < 5.0:
        attempts += 1
        try:
            socket.create_connection((host, int(port)), 1).close()
        except OSError:
            denied += 1
        time.sleep(0.5)
    emit("collector_from_agent", reachable=(denied != attempts), attempts=attempts, denied=denied,
         window_seconds=round(time.monotonic() - t0, 1), after_positive_control=True,
         target=os.environ["COLLECTOR_ADDR"])
    await probe_refused("wrong", url, {"Authorization": "Bearer " + "x" * len(auth[7:])})
    await probe_refused("none", url, {})
    await probe_refused("channel", url, {"Authorization": "Bearer " + secrets["channel_token"]})
    await probe_refused("bare", url, {"Authorization": auth[7:]})
    async with httpx.AsyncClient(timeout=10) as c:
        base = model.rsplit("/llm", 1)[0]
        ready = await c.get(base + "/ready")
        model_name = os.environ["MODEL_NAME"]
        # the front's POLICY, live: a granted endpoint with the granted model
        # passes the policy and reaches the (absent) upstream -> 503 by name; the
        # wrong model -> 403; a listing/management endpoint -> 404 by name.
        granted = await c.post(model + "/api/chat", json={"model": model_name, "messages": []})
        wrong = await c.post(model + "/api/chat", json={"model": "other-model", "messages": []})
        # a case-variant duplicate key: Go's json (Ollama) would run the OTHER
        # model; the front must refuse it, not forward it (R HIGH, live)
        variant = await c.post(model + "/api/chat", content=b'{"model": "' + model_name.encode() + b'", "MODEL": "other-model"}',
                               headers={"content-type": "application/json"})
        tags = await c.get(model + "/api/tags")
        delete = await c.request("DELETE", model + "/api/delete", json={"model": model_name})
        emit("front", ready_status=ready.status_code, ready_body=ready.text[:100],
             granted_status=granted.status_code, granted_body=granted.text[:120],
             wrong_model_status=wrong.status_code, variant_key_status=variant.status_code,
             tags_status=tags.status_code,
             delete_status=delete.status_code)
    emit("done", ok=True)

asyncio.run(main())
'''


def host_hashes() -> dict[str, str]:
    return {item: hashlib.sha256((ROOT / item).read_bytes()).hexdigest()
            for item in SOURCES}


def parse_probes(logs: str) -> dict:
    """`PROBE <name> <json>` lines the workload printed, by name."""
    out = {}
    for line in logs.splitlines():
        if line.startswith("PROBE "):
            name, _, payload = line[len("PROBE "):].partition(" ")
            out[name] = json.loads(payload)
    return out


# The in-cluster telemetry path (infra/kubernetes/observability.yaml): the
# sidecar exports here; the peer is what its NetworkPolicy admits.
OTEL_ENDPOINT = os.environ.get("ANDYUR_GATE_OTEL_ENDPOINT",
                               "http://otel-collector.andyur-system.svc:4318")
COLLECTOR_PEER = ClusterPeer(namespace="andyur-system", labels={"app": "otel-collector"}, port=4318)


def collector_address() -> str:
    """The Collector's cluster IP:4318 -- the workload's probe target (no DNS there)."""
    ip = kubectl("get", "service", "otel-collector", "-n", "andyur-system",
                 "-o", "jsonpath={.spec.clusterIP}").strip()
    if not ip:
        raise RuntimeError("the telemetry path is not deployed (service otel-collector "
                           "absent): infra/kubernetes/apply-observability.sh")
    return f"{ip}:4318"


def exec_spec(namespace: str, image: str, proxy_script: str, run_ttl: int = 600,
              collector_addr: str = "") -> RunGroupSpec:
    return RunGroupSpec(
        namespace=namespace, run_id=uuid.uuid4().hex, generation="exec-tool-call-gate",
        agent_id="stock", registry_agent_id="agt_stock",
        proxy_image=image, agent_image=image, proxy_port=8765, mcp_port=8766,
        proxy_args=("python", "-c", proxy_script),
        agent_args=("python", "-c", WORKLOAD),
        agent_runtime="container", agent_interface=RUNTIME_PROTOCOL_EXEC_V1,
        exec_configuration=ConfigurationSpec(
            env=(EnvVar(name="MCP_URL", reference="services.tools.mcp_url"),
                 EnvVar(name="MODEL_URL", reference="services.model.base_url"),
                 EnvVar(name="MODEL_NAME", reference="services.model.name"),
                 EnvVar(name="MCP_AUTH",
                        reference="services.tools.mcp_headers.Authorization"),
                 EnvVar(name="COLLECTOR_ADDR", literal=collector_addr or "127.0.0.1:1"),
                 EnvVar(name="GATE_SECRETS", literal=json.dumps({
                     "channel_token": CREDENTIALS.channel_token,
                     "run_token": CREDENTIALS.run_token,
                     "litellm_key": CREDENTIALS.litellm_key}))),
            files=(ConfigFile(
                path="${workspace.home}/cfg.yaml",
                template=("mcp: ${services.tools.mcp_url}\n"
                          "auth: ${services.tools.mcp_headers.Authorization}\n")),)),
        exec_input_mode="", exec_input=b"", exec_input_max_bytes=0,
        exec_model_name=GATE_MODEL, otel_mode="on", otel_endpoint=OTEL_ENDPOINT,
        proxy_egress=(COLLECTOR_PEER,), run_ttl_seconds=run_ttl)


def resources_absent(namespace: str, spec: RunGroupSpec) -> bool:
    names = run_group_names(spec)
    return kubectl(
        "get", "pod,service,secret,configmap,serviceaccount,networkpolicy,lease",
        "-n", namespace, "-l", f"andyur.run/id={names['base'].split('-')[2]}",
        "-o", "name", check=False).strip() == ""


def proxy_markers(log: str) -> dict:
    """The proxy script's own lines: COLLECTOR_FROM_PROXY <allow|deny> and TRACEPARENT."""
    out = {}
    for line in log.splitlines():
        parts = line.split()
        if parts[:1] == ["COLLECTOR_FROM_PROXY"] and len(parts) >= 5:
            out["collector_from_proxy"] = parts[1]
            out["collector_from_proxy_seconds"] = float(parts[4])
            out["collector_from_proxy_bound_seconds"] = 15.0
        elif parts[:1] == ["TRACEPARENT"] and len(parts) == 2:
            out["traceparent"] = parts[1]
        elif parts[:1] == ["STREAM_OPEN"] and len(parts) == 2:
            out["mcp_stream_open_during_delete"] = parts[1] == "True"
    return out


def trace_refusals(trace: dict, operation: str) -> set:
    """The andyur.refusal codes on the spans of one listener (`execfront POST`,
    `mcp POST`, ...), as the read-back summarised them."""
    return {s["attributes"].get("andyur.refusal") for s in trace.get("spans", [])
            if s["name"].startswith(operation + " ") and "andyur.refusal" in s["attributes"]}


def read_trace_back(traceparent: str, wait: int = 60, expect: str = "") -> dict:
    """The gates' shared read-back, executed from the operator (the one vantage
    point Jaeger's query port admits): one JSON line, or the failure by name."""
    helper = (ROOT / "infra" / "observability" / "trace_readback.py").read_text()
    proc = subprocess.run(
        ["kubectl", "exec", "-i", "-n", "andyur-system", "deployment/andyur-operator", "--",
         "python", "-", "http://andyur-jaeger:16686", traceparent, "--wait", str(wait),
         *(["--expect", expect] if expect else [])],
        input=helper, capture_output=True, text=True, timeout=wait + 60)
    line = (proc.stdout.strip().splitlines() or ["{}"])[-1]
    try:
        return json.loads(line)
    except ValueError:
        return {"error": "readback_failed", "stdout": proc.stdout[-400:], "stderr": proc.stderr[-400:]}


def tool_call_run(admin_api, sa_api, controller, namespace, image) -> dict:
    spec = exec_spec(namespace, image, PROXY_SERVE, collector_addr=collector_address())
    names = run_group_names(spec)
    started = time.monotonic()
    out: dict = {"run_id": spec.run_id}
    # THE LAUNCH IS THE READINESS PROOF: the controller (under the worker SA)
    # waits on the proxy Pod's /ready before it creates the agent Pod, and that
    # /ready is the ExecFront the real serve-only services started.
    controller.launch(spec, CREDENTIALS)
    out["launch_seconds"] = round(time.monotonic() - started, 2)
    try:
        proxy = json.loads(kubectl("get", "pod", names["proxy"], "-n", namespace, "-o", "json"))
        out["proxy_ready_condition"] = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in proxy["status"].get("conditions", []))
        out["proxy_command_is_the_real_serve_only_services"] = (
            "_start_serve_only_services" in proxy["spec"]["containers"][0]["command"][2])
        out["phase"] = wait_phase(admin_api, namespace, names["agent"], {"Succeeded", "Failed"}, 150)
        # Read the workload's output the way the daemon does: through the
        # worker SA (pods/log with limitBytes, no tail_lines).
        body = sa_api.pod_logs(namespace, names["agent"], tail_lines=None, limit_bytes=65536)
        out["probes"] = parse_probes(body)
        proxy_log = pod_logs(namespace, names["proxy"])
        out["proxy_log_tail"] = proxy_log[-600:]
        out.update(proxy_markers(proxy_log))
        if out["phase"] != "Succeeded":
            out["agent_log_tail"] = body[-1500:]
    finally:
        deleting = time.monotonic()
        controller.delete(spec)
        out["delete_seconds"] = round(time.monotonic() - deleting, 2)
    out["resources_absent"] = resources_absent(namespace, spec)
    # The trace the sidecar exported, read back by id from Jaeger AFTER the
    # group is gone (the export is flushed on the park's SIGTERM exit, so the
    # delete above paid for it -- and stayed under the bound). The gate's
    # evidence carries the trace id (observability-exit-criteria.md 7).
    out["trace"] = (read_trace_back(out["traceparent"],
                                    expect="exec-tool-call-gate.serve,runner.serve,execfront POST,execfront GET,mcp POST")
                    if out.get("traceparent") else {"error": "no_traceparent_in_proxy_log"})
    p = out.get("probes", {})
    checks = {
        "declared_bearer_is_a_header_value": p.get("delivery", {}).get("auth_is_header_value") is True,
        "rendered_file_matches_env": (p.get("delivery", {}).get("rendered_auth_matches_env") is True
                                      and p.get("delivery", {}).get("rendered_mcp_matches_env") is True),
        "declared_initialized_and_listed_the_real_registry": (
            p.get("declared", {}).get("initialized") is True
            and p.get("declared", {}).get("tools") == PLATFORM_TOOLS),
        # The tool BODY ran: its first act is the control-plane call, whose
        # identity leg (JWT-SVID from the Workload API) is what fails here, and
        # that failure text is the only evidence the body was reached -- a call
        # refused before the body returns isError too (R MED-1). The undeclared
        # probe's "not found" is the negative control.
        "declared_tool_call_reached_the_tool_body": (
            p.get("declared", {}).get("call_returned") is True
            and p.get("declared", {}).get("call_is_error") is True
            and bool(re.search(r"JwtSource|JWT.SVID|SPIFFE|Workload API",
                               p.get("declared", {}).get("call_text", "")))
            and "not found" not in p.get("declared", {}).get("call_text", "")),
        "undeclared_tool_refused": p.get("undeclared", {}).get("refused") is True,
        "wrong_bearer_401": p.get("wrong", {}).get("status") == 401,
        "no_bearer_401": p.get("none", {}).get("status") == 401,
        "channel_token_as_bearer_401": p.get("channel", {}).get("status") == 401,
        "bare_token_without_scheme_401": p.get("bare", {}).get("status") == 401,
        "front_ready_200_on_proxy_port": p.get("front", {}).get("ready_status") == 200,
        # the front's policy, live (R HIGH-1): granted endpoint + granted model
        # passes to the (absent) upstream; wrong model 403; listing and
        # management endpoints 404 by name
        "front_granted_call_passes_policy_503_no_upstream": p.get("front", {}).get("granted_status") == 503,
        "front_wrong_model_403": p.get("front", {}).get("wrong_model_status") == 403,
        "front_case_variant_model_key_403": p.get("front", {}).get("variant_key_status") == 403,
        "front_model_listing_404": p.get("front", {}).get("tags_status") == 404,
        "front_model_delete_404": p.get("front", {}).get("delete_status") == 404,
        "credentials_absent_from_workload": (bool(p.get("absence"))
                                             and all(p["absence"].values())),
        "workload_completed": out.get("phase") == "Succeeded",
        "resources_absent": out["resources_absent"] is True,
        # MED-0 live: the parked sidecar honours SIGTERM, so deleting the group
        # (both Pods, sequentially) does not pay the 20 s grace per Pod.
        "group_delete_prompt": out["delete_seconds"] < PROMPT_DELETE_SECONDS,
        # ... with a real MCP stream open and a stalled POST in flight (R MED-3)
        "group_delete_prompt_with_open_stream": out.get("mcp_stream_open_during_delete") is True,
        # Telemetry ON, live: the trusted proxy reaches the Collector, the
        # untrusted workload is refused by its rendered policy, and the run's
        # trace is readable from Jaeger by id with the sidecar's root span.
        "collector_from_proxy_allowed_within_bound": (
            out.get("collector_from_proxy") == "allow"
            and out.get("collector_from_proxy_seconds", 99.0) < out.get("collector_from_proxy_bound_seconds", 0)),
        "collector_from_agent_denied_sustained_after_proxy_allow": (
            p.get("collector_from_agent", {}).get("after_positive_control") is True
            and p.get("collector_from_agent", {}).get("attempts", 0) >= 5
            and p.get("collector_from_agent", {}).get("denied") == p.get("collector_from_agent", {}).get("attempts")),
        "trace_read_back_by_id": ("exec-tool-call-gate.serve" in out["trace"].get("span_names", [])
                                  and "andyur-runner" in out["trace"].get("services", [])),
        # PR B: every decision the probes provoked is IN THE TRACE by the same
        # name the body carried (observability-exit-criteria.md 1): the front's
        # refusals and the tool service's bearer refusals, plus the park's
        # own span with its exit by name.
        "trace_front_refusals_by_name": {"no_model_proxy", "model_not_granted", "model_key_variant",
                                         "path_not_model_call"} <= trace_refusals(out["trace"], "execfront"),
        "trace_mcp_bearer_rejected": trace_refusals(out["trace"], "mcp") >= {"bearer_rejected", "none"},
        "trace_serve_exit_by_name": any(
            s["name"] == "runner.serve" and s["attributes"].get("andyur.serve.exit") == "sigterm"
            for s in out["trace"].get("spans", [])),
    }
    out["checks"] = checks
    out["ok"] = all(checks.values())
    return out


def no_front_rollback(controller, namespace, image) -> dict:
    """R MED-2's mutant, live: the same group whose proxy serves ToolService but
    nothing on the proxy port must NOT become ready; the controller rolls the
    group back and raises, by name."""
    spec = exec_spec(namespace, image, PROXY_NO_FRONT)
    previous = controller.READY_TIMEOUT
    controller.READY_TIMEOUT = 25.0
    out: dict = {"run_id": spec.run_id, "ready_timeout": 25.0}
    started = time.monotonic()
    try:
        controller.launch(spec, CREDENTIALS)
        out["launched"] = True
        controller.delete(spec)
    except Exception as exc:                                     # noqa: BLE001
        out["launched"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"[:300]
    finally:
        controller.READY_TIMEOUT = previous
    out["seconds"] = round(time.monotonic() - started, 2)
    # what remains after the readiness wait is the rollback's Pod delete --
    # valid ONLY if the refusal was the readiness timeout (a proxy that crashed
    # early would make this negative and prove nothing: R MED-B)
    out["rollback_seconds"] = round(out["seconds"] - 25.0, 2)
    out["refused_for_readiness"] = "was not ready within" in out.get("error", "")
    out["resources_absent"] = resources_absent(namespace, spec)
    out["rollback_prompt"] = 0.0 <= out["rollback_seconds"] < PROMPT_DELETE_SECONDS
    out["ok"] = (out["launched"] is False and out["refused_for_readiness"]
                 and out["resources_absent"] is True and out["rollback_prompt"])
    return out


def main() -> None:
    if not os.environ.get("ANDYUR_KUBECONFIG"):
        raise RuntimeError(
            "set ANDYUR_KUBECONFIG to the admin kubeconfig of the target k3s "
            "cluster (e.g. $HOME/.kube/config); the gate builds the worker-SA "
            "kubeconfig from it")
    image = os.environ.get("ANDYUR_EXEC_TOOL_CALL_IMAGE", "").strip()
    if "@sha256:" not in image:
        raise RuntimeError(
            "ANDYUR_EXEC_TOOL_CALL_IMAGE must be a digest-pinned RUNNER image built "
            "from the current checkout (Dockerfile.runner) and pushed where the "
            "cluster node can pull it")
    namespace = f"andyur-exec-tool-call-{uuid.uuid4().hex[:8]}"
    api = OfficialKubernetesApi()
    started = time.time()
    result: dict = {"gate": "exec-tool-call", "started_at_epoch": started,
                    "host": platform.platform(), "image": image,
                    "otel": {"mode": "on", "endpoint": OTEL_ENDPOINT,
                             "readback": "jaeger v3 API by trace id, from the operator"}}
    diagnostic = ""
    try:
        kubectl("create", "-f", "-", body={"apiVersion": "v1", "kind": "Namespace",
                                            "metadata": {"name": namespace}})
        namespace_uid = json.loads(kubectl(
            "get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
        kubectl("patch", "namespace", namespace, "--type=merge", "-p",
                json.dumps({"metadata": {"labels": {
                    "andyur.network-policy/verified": "true"}, "annotations": {
                    "andyur.network-policy/verified-at": str(int(time.time())),
                    "andyur.network-policy/namespace-uid": namespace_uid}}}))
        sa_api, sa_principal = sa_authed_api(namespace)
        result["controller_identity"] = sa_principal
        controller = KubernetesRunController(sa_api, namespace)

        # 1. The executing image runs THIS checkout's sidecar + delivery code.
        probe_cmd = ("import hashlib, pathlib, importlib\n"
                     + "".join(f"m = importlib.import_module({mod!r}); "
                               f"print('HASH', {path!r}, hashlib.sha256("
                               f"pathlib.Path(m.__file__).read_bytes()).hexdigest())\n"
                               for path, mod in IN_IMAGE.items()))
        kubectl("apply", "-f", "-", body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "source-probe", "namespace": namespace},
            "spec": {"restartPolicy": "Never", "containers": [{
                "name": "probe", "image": image,
                "command": ["python", "-c", probe_cmd],
                "env": [{"name": "ANDYUR_OTEL", "value": "on"},
                        {"name": "ANDYUR_OTEL_ENDPOINT", "value": OTEL_ENDPOINT}],
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1001}}]}})
        if wait_phase(api, namespace, "source-probe", {"Succeeded", "Failed"}, 120) != "Succeeded":
            raise RuntimeError("source probe did not complete: "
                               + kubectl("describe", "pod", "source-probe", "-n", namespace, check=False)
                               + pod_logs(namespace, "source-probe"))
        executed = {parts[1]: parts[2]
                    for parts in (ln.split() for ln in pod_logs(namespace, "source-probe").splitlines())
                    if len(parts) == 3 and parts[0] == "HASH"}
        hosts = host_hashes()
        if set(executed) != set(IN_IMAGE) or any(executed[k] != hosts[k] for k in executed):
            raise RuntimeError(f"running image source does not match host source: {executed}")
        result["executed_source_sha256"] = executed
        result["image_id"] = json.loads(kubectl(
            "get", "pod", "source-probe", "-n", namespace, "-o", "json"))[
            "status"]["containerStatuses"][0]["imageID"]

        # 2. The tool call, from inside a real exec/v1 workload, against the
        #    real serve-only services, launched under the worker SA.
        result["tool_call"] = tool_call_run(api, sa_api, controller, namespace, image)
        # 3. The readiness negative: no front -> no launch.
        result["no_front_rollback"] = no_front_rollback(controller, namespace, image)

        result["source_sha256"] = hosts
        result["cluster_version"] = json.loads(kubectl("version", "-o", "json"))[
            "serverVersion"]["gitVersion"]
        result["not_covered"] = (
            "server-side scope refusal (auth.require_scope) needs the in-cluster "
            "control plane + SPIRE registration: kubernetes-verify lane")
        result["ok"] = result["tool_call"]["ok"] and result["no_front_rollback"]["ok"]
        if not result["ok"]:
            raise RuntimeError("exec tool-call gate failed: "
                               + json.dumps(result, sort_keys=True, default=str))
    except BaseException:
        diagnostic = kubectl("get", "pods", "-n", namespace, "-o", "wide", check=False)
        diagnostic += kubectl("describe", "pods", "-n", namespace, check=False)[-6000:]
        raise
    finally:
        for _cleanup in _ei._GATE_CLEANUP:
            try:
                _cleanup()
            except Exception:
                pass
        kubectl("delete", "namespace", namespace, "--wait=true", check=False)
        if diagnostic:
            print(diagnostic, file=sys.stderr)
    result["finished_at_epoch"] = time.time()
    result["teardown_absent"] = kubectl("get", "namespace", namespace, check=False).strip() == ""
    print(json.dumps(result, sort_keys=True, default=str))


if __name__ == "__main__":
    main()

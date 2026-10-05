#!/usr/bin/env python3
"""Architecture B+ Gate A: can a retried execution Activity create a second
runtime for one run, or must it adopt the first?

Real Temporal (ANDYUR_TEMPORAL_ADDRESS), real worker PROCESSES killed outright,
and the real run fence on the live Kubernetes API (ANDYUR_KUBECONFIG), in a
scratch namespace created and deleted BY NAME. See spike_worker.py for exactly
what is real and what stands in.

Scenarios, each asserted on what EXISTS in the cluster afterwards, not on what
the workers said:
  after-launch   worker A launches, dies before acking; worker B's retry must
                 ADOPT -- one fence, one runtime
  before-launch  worker A dies before any effect; worker B's retry LAUNCHES --
                 one fence, one runtime
  foreign        the fence is already held by another generation; the Activity
                 must refuse without retrying and create nothing
  invented       no Andyur record for the id: refused, nothing created
  halted         the record says halted: refused, nothing created

Prints the verdict as JSON on stdout; exit 0 only on PASS.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import platform
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

NAMESPACE = "andyur-bplus-spike"
ADDRESS = os.environ.get("ANDYUR_TEMPORAL_ADDRESS", "localhost:7233")
SOURCES = ("infra/bplus-spike/gate_a.py", "infra/bplus-spike/spike_worker.py",
           "andyur/daemon/kubernetes_api.py", "andyur/daemon/kubernetes_manifests.py")


def kubectl(*args, check=True):
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, check=check)


def count(kind: str, run_label: str) -> int:
    out = kubectl("get", kind, "-n", NAMESPACE, "-l", f"andyur.run/id={run_label}",
                  "-o", "name", check=False).stdout
    return len([l for l in out.splitlines() if l.strip()])


def worker(queue, records, tag, crash=""):
    env = {**os.environ, "SPIKE_QUEUE": queue, "SPIKE_RECORDS": str(records),
           "SPIKE_NAMESPACE": NAMESPACE, "SPIKE_TAG": tag, "SPIKE_CRASH": crash,
           "PYTHONUNBUFFERED": "1"}
    return subprocess.Popen([sys.executable, str(HERE / "spike_worker.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def wait_up(proc, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if "up" in line:
            return
        if proc.poll() is not None:
            break
    raise RuntimeError("a spike worker did not come up")


async def start(client, queue, run_id):
    return await client.start_workflow("SpikeRun", run_id, id=f"spike-{run_id}",
                                       task_queue=queue)


async def attempts(handle) -> int:
    """How many times the engine ran the Activity, from its own history -- so
    "not retried" is measured, not inferred from the error."""
    top = 0
    async for event in handle.fetch_history_events():
        if event.HasField("activity_task_started_event_attributes"):
            top = max(top, event.activity_task_started_event_attributes.attempt)
    return top


async def outcome(handle, timeout=90):
    try:
        got = {"result": await asyncio.wait_for(handle.result(), timeout)}
    except Exception as exc:                       # noqa: BLE001 - recorded
        from temporalio.exceptions import ApplicationError

        # The FIRST application error in the chain is the Activity's own
        # verdict; anything beneath it is the cause it chained (`from exc`),
        # which the first version of this gate reported by mistake.
        cause = exc
        while cause is not None and not isinstance(cause, ApplicationError):
            cause = getattr(cause, "cause", None)
        cause = cause or exc
        got = {"error": type(cause).__name__, "type": getattr(cause, "type", None),
               "message": str(cause)[:200]}
    got["activity_attempts"] = await attempts(handle)
    return got


def admit(records, state="admitted", generation=None):
    run_id = uuid.uuid4().hex
    gen = generation or f"gen-{secrets.token_hex(6)}"
    (records / f"{run_id}.json").write_text(json.dumps({"state": state, "generation": gen}))
    return run_id, gen


def run_label(run_id):
    from andyur.daemon.kubernetes_manifests import _digest
    return _digest(run_id)


async def crash_scenario(client, records, crash):
    queue = f"spike-{uuid.uuid4().hex[:8]}"
    run_id, _gen = admit(records)
    a = worker(queue, records, "A", crash=crash)
    wait_up(a)
    handle = await start(client, queue, run_id)
    a_exit = a.wait(timeout=60)                  # A kills itself mid-Activity
    before_b = {"leases": count("lease", run_label(run_id)),
                "runtimes": count("configmap", run_label(run_id))}
    b = worker(queue, records, "B")
    wait_up(b)
    try:
        got = await outcome(handle)
    finally:
        b.terminate(); b.wait(timeout=20)
    after = {"leases": count("lease", run_label(run_id)),
             "runtimes": count("configmap", run_label(run_id))}
    return {"run_id": run_id, "worker_a_exit": a_exit, "before_worker_b": before_b,
            "after": after, **got}


async def refused_scenario(client, records, run_id, pre=None):
    queue = f"spike-{uuid.uuid4().hex[:8]}"
    if pre:
        pre(run_id)
    w = worker(queue, records, "C")
    wait_up(w)
    try:
        got = await outcome(await start(client, queue, run_id))
    finally:
        w.terminate(); w.wait(timeout=20)
    return {"run_id": run_id, "leases": count("lease", run_label(run_id)),
            "runtimes": count("configmap", run_label(run_id)), **got}


def foreign_fence(run_id):
    """Pre-claim the run's fence under a DIFFERENT generation, with the real API."""
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    from andyur.daemon.kubernetes_manifests import _digest, run_group_names_for_identity

    other = "gen-someone-else"
    names = run_group_names_for_identity(run_id, other)
    labels = {"app.kubernetes.io/managed-by": "andyur-worker",
              "andyur.run/id": _digest(run_id), "andyur.run/generation": _digest(other)}
    assert OfficialKubernetesApi().claim_run_singleton(NAMESPACE, names["lease"], labels, other)


async def main() -> int:
    from temporalio.client import Client

    started = datetime.now(timezone.utc).isoformat()
    kubectl("delete", "namespace", NAMESPACE, "--ignore-not-found", "--wait=true", check=False)
    kubectl("create", "namespace", NAMESPACE)
    client = await Client.connect(ADDRESS)
    records = pathlib.Path(tempfile.mkdtemp(prefix="bplus-records-"))
    try:
        after_launch = await crash_scenario(client, records, "after-launch")
        before_launch = await crash_scenario(client, records, "before-launch")
        foreign_id, _ = admit(records)
        foreign = await refused_scenario(client, records, foreign_id, pre=foreign_fence)
        invented = await refused_scenario(client, records, uuid.uuid4().hex)
        halted_id, _ = admit(records, state="halted")
        halted = await refused_scenario(client, records, halted_id)
    finally:
        kubectl("delete", "namespace", NAMESPACE, "--wait=true", check=False)
    teardown_absent = kubectl("get", "namespace", NAMESPACE, check=False).returncode != 0

    checks = {
        "after_launch_worker_a_died_hard": after_launch["worker_a_exit"] == 137,
        "after_launch_runtime_existed_before_retry":
            after_launch["before_worker_b"] == {"leases": 1, "runtimes": 1},
        "after_launch_retry_adopted":
            after_launch.get("result", {}).get("outcome") == "adopted"
            and after_launch["result"]["worker"] == "B"
            and after_launch["result"]["attempt"] >= 2
            and after_launch["result"]["runtime_present"] is True,
        "after_launch_one_runtime": after_launch["after"] == {"leases": 1, "runtimes": 1},
        "before_launch_worker_a_died_hard": before_launch["worker_a_exit"] == 137,
        "before_launch_nothing_before_retry":
            before_launch["before_worker_b"] == {"leases": 0, "runtimes": 0},
        "before_launch_retry_launched":
            before_launch.get("result", {}).get("outcome") == "launched"
            and before_launch["result"]["worker"] == "B",
        "before_launch_one_runtime": before_launch["after"] == {"leases": 1, "runtimes": 1},
        "foreign_generation_refused_not_retried":
            foreign.get("type") == "SecurityRefusal" and foreign["runtimes"] == 0
            and foreign["activity_attempts"] == 1,
        "invented_run_refused":
            invented.get("type") == "SecurityRefusal" and invented["activity_attempts"] == 1
            and invented["leases"] == 0 and invented["runtimes"] == 0,
        "halted_run_refused":
            halted.get("type") == "SecurityRefusal" and halted["activity_attempts"] == 1
            and halted["leases"] == 0 and halted["runtimes"] == 0,
        "teardown_absent": teardown_absent,
    }
    verdict = "PASS" if all(checks.values()) else "FAIL"
    server = kubectl("config", "view", "--minify", "-o",
                     "jsonpath={.clusters[0].cluster.server}", check=False).stdout
    print(json.dumps({
        "gate": "bplus-gate-a-idempotent-launch", "verdict": verdict, "checks": checks,
        "scenarios": {"after_launch": after_launch, "before_launch": before_launch,
                      "foreign_generation": foreign, "invented_run": invented,
                      "halted_run": halted},
        "temporal_address": ADDRESS, "platform": platform.platform(),
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "api_server_sha256": hashlib.sha256(server.encode()).hexdigest(),
        "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                          for p in SOURCES},
    }, indent=2, sort_keys=True))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

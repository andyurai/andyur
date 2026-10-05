"""Gate A spike worker: one Temporal execution Activity, launched against the
REAL Kubernetes run fence, in a process the gate can kill outright.

What is real: the Temporal service, the retry and heartbeat machinery, the
worker processes and their death, and the run-scoped create-only Lease --
claimed, read and named by the SAME `OfficialKubernetesApi` and
`run_group_names_for_identity` the production controller uses, against the
live API server.

What stands in, and why that is enough for this gate: the run group is one
ConfigMap created only AFTER the fence is claimed, exactly as
`KubernetesRunController.launch` creates its Pods only after its claim. The
question Gate A asks is whether a retried Activity can create a SECOND logical
runtime or must ADOPT the first; that is decided at the claim, and the claim is
the real one. Andyur's run record is a JSON file carrying the run's state and
its execution GENERATION -- recorded once per run, which is the design point:
a retry on any worker presents the same generation, so it can adopt, while a
different generation is refused by the fence.

Run: python spike_worker.py   (env: SPIKE_QUEUE, SPIKE_RECORDS, SPIKE_NAMESPACE,
SPIKE_TAG, SPIKE_CRASH=before-launch|after-launch, ANDYUR_KUBECONFIG)
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import pathlib
import sys
from datetime import timedelta

from temporalio import activity, workflow
from temporalio.common import RetryPolicy

ACTIVITY = "spike_execute_run"


class SecurityRefusal(Exception):
    """Refused on Andyur's authority: never retried as if transient."""


def _record(run_id: str) -> dict | None:
    path = pathlib.Path(os.environ["SPIKE_RECORDS"]) / f"{run_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def _selector(run_id: str, generation: str) -> dict[str, str]:
    from andyur.daemon.kubernetes_manifests import _digest

    # The controller's own selector (KubernetesRunController.selector).
    return {"app.kubernetes.io/managed-by": "andyur-worker",
            "andyur.run/id": _digest(run_id),
            "andyur.run/generation": _digest(generation)}


@activity.defn(name=ACTIVITY)
def spike_execute_run(run_id: str) -> dict:
    from temporalio.exceptions import ApplicationError

    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    from andyur.daemon.kubernetes_manifests import run_group_names_for_identity

    info = activity.info()
    tag = os.environ["SPIKE_TAG"]
    crash = os.environ.get("SPIKE_CRASH", "")

    # 1. ANDYUR'S RECORD, not anything Temporal carried: only the id crossed.
    record = _record(run_id)
    if record is None:
        raise ApplicationError(f"no admitted run {run_id!r}", type="SecurityRefusal",
                               non_retryable=True)
    if record["state"] != "admitted":
        raise ApplicationError(f"run {run_id!r} is {record['state']}",
                               type="SecurityRefusal", non_retryable=True)
    generation = record["generation"]
    activity.heartbeat({"run_id": run_id, "generation": generation, "phase": "fetched"})

    if crash == "before-launch" and info.attempt == 1:
        os._exit(137)                        # dies holding the task, before any effect

    namespace = os.environ["SPIKE_NAMESPACE"]
    api = OfficialKubernetesApi()
    names = run_group_names_for_identity(run_id, generation)
    labels = _selector(run_id, generation)
    runtime_name = f"{names['base']}-runtime"

    # 2. THE FENCE: create-only, one Lease per RUN, holder = generation.
    claim = api.claim_run_singleton(namespace, names["lease"], labels, generation)
    if claim is None:
        # Somebody already launched this run. Adopt ONLY if it is this run's
        # generation; `_validated_claim` refuses any other holder or labels.
        try:
            api.read_run_singleton(namespace, names["lease"], labels, generation, 10)
        except RuntimeError as exc:
            raise ApplicationError(
                f"run {run_id!r} is held by another generation: {exc}",
                type="SecurityRefusal", non_retryable=True) from exc
        cm = api._dynamic.resources.get(api_version="v1", kind="ConfigMap")
        try:
            existing = cm.get(name=runtime_name, namespace=namespace)
        except api._api_exception as exc:
            if exc.status != 404:
                raise
            existing = None
        activity.heartbeat({"run_id": run_id, "generation": generation, "phase": "adopted"})
        return {"outcome": "adopted", "attempt": info.attempt, "worker": tag,
                "runtime_present": existing is not None}

    # 3. LAUNCH, only after the claim -- as the controller does.
    cm = api._dynamic.resources.get(api_version="v1", kind="ConfigMap")
    cm.create(namespace=namespace, body={
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": runtime_name, "namespace": namespace, "labels": labels},
        "data": {"stands-in-for": "the run group"}})
    activity.heartbeat({"run_id": run_id, "generation": generation, "phase": "launched"})

    if crash == "after-launch" and info.attempt == 1:
        os._exit(137)                        # the runtime exists; the ack never will

    return {"outcome": "launched", "attempt": info.attempt, "worker": tag,
            "runtime_present": True}


@workflow.defn(name="SpikeRun")
class SpikeRun:
    @workflow.run
    async def run(self, run_id: str) -> dict:
        return await workflow.execute_activity(
            ACTIVITY, run_id,
            # heartbeat: worker liveness -- how soon a dead worker's task is
            # retried elsewhere. start_to_close: an engine upper bound only.
            heartbeat_timeout=timedelta(seconds=4),
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1), maximum_attempts=5,
                non_retryable_error_types=["SecurityRefusal"]))


async def main() -> None:
    from temporalio.client import Client
    from temporalio.worker import Worker

    client = await Client.connect(os.environ.get("ANDYUR_TEMPORAL_ADDRESS", "localhost:7233"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        worker = Worker(client, task_queue=os.environ["SPIKE_QUEUE"],
                        workflows=[SpikeRun], activities=[spike_execute_run],
                        activity_executor=pool)
        print(f"spike worker {os.environ['SPIKE_TAG']} up", flush=True)
        await worker.run()


if __name__ == "__main__":
    # The repository on the path for the ACTIVITY's imports. Done here, not at
    # module level: the workflow sandbox re-imports this module and refuses
    # filesystem access (`Path.resolve`) during that import.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    asyncio.run(main())

"""Execute ONE engine-dispatched run: claim it by id, launch or adopt it, watch
it to the end (Architecture B+, ADR-014 D11).

The engine's execution Activity is a thin wrapper around this; nothing here
imports an engine SDK. It reuses the worker daemon's launcher, reaper and kill
path unchanged -- the only differences are where a run comes from (a claim by
id instead of an assignment loop) and whose generation it runs under (the
run's own, recorded by the control plane, instead of this process's).

RETRY CLASSIFICATION, which the engine's retry policy relies on:
  claim, network, 5xx      transient: raised, the engine retries elsewhere
  Andyur refused the claim permanent: `ExecutionRefused`, never retried
  launch failed            the run's outcome: recorded as failed by name,
                           exactly as the daemon records it, not retried
  launched, then lost      ambiguous: the retry ADOPTS through the run fence,
                           never launches a second runtime
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
from typing import AsyncIterator, Callable

import httpx

from ..redact import redact
from .daemon import Daemon, log
from ..runfinish import post_finish


# The workload identity every executor process presents to Andyur's claim
# endpoints, whichever orchestration provider invokes it. Named after the first
# provider; the name carries no Temporal authority.
EXECUTOR_IDENTITY = "temporal-execution-worker"


@contextlib.asynccontextmanager
async def hosted(provider: str) -> AsyncIterator["EngineExecutor"]:
    """The Run Execution Controller, ready to be invoked by `provider`.

    PROVIDER-NEUTRAL BOOTSTRAP. Every orchestration adapter hosts the SAME
    controller: the daemon's containment checks (this process launches agents,
    minus the run-token signing key it deliberately does not hold), an
    execution-mode daemon for the launcher, and a client to Andyur's claim
    endpoints under the executor's own identity. It lived inside Temporal's
    `serve()`, which meant a second provider could only host the controller by
    copying it.
    """
    import httpx

    from .. import config as andyur_config, identity
    from ..config import SERVER_URL
    from .daemon import assert_egress_locked

    andyur_config.assert_profile(signs_run_tokens=False)
    assert_egress_locked()
    identity.assert_agent_isolation()
    daemon = Daemon(execution=True)
    cert, verify = identity.client_tls(EXECUTOR_IDENTITY)
    async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10,
                                 auth=identity.httpx_auth(),
                                 cert=cert, verify=verify) as api:
        yield EngineExecutor(daemon, api, provider=provider)


class ExecutionRefused(Exception):
    """Andyur will not launch this run. Permanent by definition."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


class EngineExecutor:
    # How often a running execution asks whether its run is condemned, and
    # reports liveness to the engine. The kill latency for an engine run is
    # bounded by this, as the daemon's is by its heartbeat interval.
    POLL_SECONDS = 5.0
    # Liveness WHILE a launch or adoption blocks. A launch waits up to a
    # minute for the proxy and another for input delivery; with the engine's
    # 60s heartbeat timeout, one quiet launch was enough for the engine to
    # declare this attempt lost and hand the run to another worker mid-launch.
    LAUNCH_BEAT_SECONDS = 10.0

    def __init__(self, daemon: Daemon, api: httpx.AsyncClient, *,
                 provider: str) -> None:
        if not daemon.execution:
            raise ValueError("the engine executor needs a daemon in execution mode")
        self.daemon = daemon
        self.api = api
        # The orchestration provider this executor serves; the claim refuses a
        # run bound to any other.
        self.provider = provider

    async def execute(self, run_id: str, heartbeat: Callable[[dict], None]) -> dict:
        resp = await self.api.post(f"/runs/{run_id}/execute",
                                   json={"orchestrator": self.daemon.orch.name,
                                         "provider": self.provider})
        if resp.status_code == 409:
            body = resp.json()
            raise ExecutionRefused(body.get("refusal") or "refused",
                                   body.get("detail") or "")
        resp.raise_for_status()
        claim = resp.json()
        generation = claim["generation"]
        launch = claim.get("launch")
        progress = {"run_id": run_id, "generation": generation}
        heartbeat({**progress, "phase": "claimed"})

        loop = asyncio.get_running_loop()
        how = "adopted"
        if launch is not None and run_id not in self.daemon.procs:
            try:
                launching = loop.run_in_executor(None, functools.partial(
                    self.daemon.launch,
                    launch["id"], launch["agent"], launch.get("trace_ctx"),
                    launch.get("run_token"), launch.get("broker_token"),
                    launch.get("run_type") or "headless",
                    launch.get("registry_agent_id"), launch.get("runtime"),
                    launch.get("run_ttl"), launch.get("input"), launch.get("model"),
                    generation=generation))
                await self._beating(heartbeat, {**progress, "phase": "launching"},
                                    launching)
                how = "launched"
            except RuntimeError as exc:
                # THE FENCE SAYS SOMEONE ALREADY LAUNCHED THIS RUN -- this
                # generation, after a crash that lost the acknowledgement. Adopt
                # it below; a different generation is refused by the fence.
                if "already owned" not in str(exc):
                    return await self._launch_failed(run_id, generation, exc)
            except Exception as exc:                           # noqa: BLE001
                return await self._launch_failed(run_id, generation, exc)
        if run_id not in self.daemon.procs:
            runtime = (launch or {}).get("runtime") or claim.get("runtime")
            handle = await self._beating(
                heartbeat, {**progress, "phase": "adopting"}, loop.run_in_executor(
                    None, self.daemon.orch.adopt_governed, run_id, generation, runtime))
            self.daemon.procs[run_id] = handle
        heartbeat({**progress, "phase": how})
        log(f"run {run_id}: {how} under generation {generation}")
        return await self._watch(run_id, progress, how, heartbeat)

    async def _watch(self, run_id: str, progress: dict, how: str,
                     heartbeat: Callable[[dict], None]) -> dict:
        while True:
            heartbeat({**progress, "phase": "running"})
            # EXIT FIRST, THEN CONDEMNATION. A run that finished reports its
            # outcome and then exits; between the two, its record is terminal
            # while its process lives, which the server answers with "kill" --
            # correct for an orphan, and a false "killed" for a run that simply
            # ended. The daemon reaps every second and asks every ten, so it
            # sees the exit first; this keeps the same order.
            code = await self.daemon.reap_one(self.api, run_id)
            if code is not None:
                return {**progress, "outcome": "exited", "exit_code": code, "how": how}
            status = await self._status(run_id)
            if status.get("kill"):
                # The SERVER condemned it -- halted workflow, or a terminal
                # record -- and the executing process is not asked its opinion.
                await self.contain(run_id)
                return {**progress, "outcome": "killed", "how": how,
                        "state": status.get("state")}
            await asyncio.sleep(self.POLL_SECONDS)

    async def _status(self, run_id: str) -> dict:
        try:
            resp = await self.api.get(f"/runs/{run_id}/execution")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            # The control plane being briefly unreachable is not a reason to
            # kill a run; the next poll asks again, and Andyur's reaper bounds
            # a run whose control plane never comes back.
            log(f"run {run_id}: execution status unavailable ({exc}); retrying")
            return {}

    async def _beating(self, heartbeat: Callable[[dict], None], details: dict, work):
        """Await `work`, heartbeating every LAUNCH_BEAT_SECONDS meanwhile."""
        async def pulse():
            while True:
                await asyncio.sleep(self.LAUNCH_BEAT_SECONDS)
                heartbeat(details)
        beat = asyncio.create_task(pulse())
        try:
            return await work
        finally:
            beat.cancel()

    async def cancelled(self, run_id: str, *, requested: bool) -> bool:
        """The engine cancelled this execution. Contain the run ONLY IF ANDYUR
        CONDEMNS IT; returns whether it did.

        A cancellation is not a halt. The SDK cancels an activity for a
        workflow cancel, but also for its own worker shutting down, for a
        heartbeat timeout, and when the attempt is no longer current -- and the
        first version destroyed the runtime on every one of them. So a rolling
        restart failed every run in flight, and an attempt the engine had
        already replaced killed the run its successor adopted. The engine
        cannot condemn a run; only Andyur can (the halt is recorded in Andyur
        before the engine is told), so Andyur is asked.

        Unreachable, the reason decides, failing closed on a real cancel: a
        requested cancellation is the halt path's own, and not acting on it
        with the control plane down would leave the engine half of containment
        depending on the control plane. Anything else detaches: the runtime
        stays for the attempt that replaces this one to adopt, and the daemon's
        reconciler still reaches it if Andyur condemns it later.
        """
        status = await self._status(run_id)
        if status.get("kill") or (not status and requested):
            await self.contain(run_id)
            return True
        log(f"run {run_id}: execution cancelled by the engine "
            f"({'requested' if requested else 'not requested'}) and not condemned "
            f"by Andyur ({status.get('state', 'unreachable')}); detaching")
        self.daemon.procs.pop(run_id, None)
        return False

    async def contain(self, run_id: str) -> None:
        """Destroy this run's runtime now -- on condemnation, and when the
        engine cancels the execution. The daemon's own kill path: exact
        generation, and the reaper records nothing a condemned run did not
        report itself."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.daemon.kill, [run_id])
        await self.daemon.reap_one(self.api, run_id)

    async def _launch_failed(self, run_id: str, generation: str,
                             exc: BaseException) -> dict:
        error = redact(f"launch failed: {type(exc).__name__}: {exc}")
        log(error)
        confirmed, reason = await post_finish(
            self.api, run_id, summary=None, error=error,
            path=f"/runs/{run_id}/worker-finish",
            extra={"worker_id": self.daemon.worker_id})
        if not confirmed:
            # Not recorded: raise, so the engine retries the execution. The
            # run's fence is still held (the controller keeps it on a failed
            # launch), so the retry finds the run owned and ADOPTS it -- reading
            # the absent workload as exited and recording the outcome -- rather
            # than launching it a second time (run execution draft R4.3).
            raise RuntimeError(f"launch failed and the failure was not recorded ({reason})")
        # Recorded: only now may the fence go (R4.1).
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, self.daemon.orch.release_after_outcome, run_id, generation)
        except Exception as release_error:                  # noqa: BLE001
            # The outcome is recorded, so a fence left behind can only refuse a
            # relaunch of a run that has ended.
            log(f"run {run_id}: failure recorded, fence release failed "
                f"({type(release_error).__name__}: {release_error})")
        return {"run_id": run_id, "outcome": "launch_failed", "error": error}

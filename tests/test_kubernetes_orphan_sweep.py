"""Agent Pods that outlived their proxy, and what finds them.

A run on Kubernetes is two Pods. Adoption selects the PROXY, so an agent Pod
whose proxy is gone is invisible to it: nothing reports the run as executing, so
nothing condemns it, and the group deletion that would remove it correctly is
never reached. Nothing else bounds it either -- `restartPolicy: Never`, no
`activeDeadlineSeconds`, no ownerReference to the proxy, so Kubernetes will not
collect it.

`sweep` is the seam for exactly this, the daemon calls it on every beat, and
this shape inherited the no-op while the Docker pod shape implemented it.

The discovery half is tested against the real controller with a fake API, so the
label and annotation handling under test is the production code, not a
restatement of it.
"""

from types import SimpleNamespace

import pytest

from andyur.daemon import orchestrator
from andyur.daemon.kubernetes_controller import (
    KubernetesRunController,
    _digest,
    run_group_names_for_identity,
)

RUN = "a" * 32
OTHER = "b" * 32
GEN = "gen-1"


def _pod(run_id, generation, component, phase="Running", *, name=None,
         labels=None, annotations=None):
    names = run_group_names_for_identity(run_id, generation)
    return SimpleNamespace(
        name=name or names[component],
        phase=phase,
        labels=labels if labels is not None else {
            "app.kubernetes.io/managed-by": "andyur-worker",
            "app.kubernetes.io/component": component,
            "andyur.run/id": _digest(run_id),
            "andyur.run/generation": _digest(generation),
        },
        annotations=annotations if annotations is not None else {
            "andyur.run/id-raw": run_id,
            "andyur.run/generation-raw": generation,
        },
    )


class FakeApi:
    def __init__(self, pods):
        self._pods = pods

    def list_pods(self, namespace, selector, timeout, limit):
        # EVERY SELECTOR TERM IS HONOURED, and two were not. The fake matched
        # only `component` and `generation`, so dropping `managed-by` from the
        # real selector -- which would sweep Pods Andyur does not own -- passed
        # every test here.
        out = [p for p in self._pods
               if all(p.labels.get(k) == v for k, v in selector.items())]
        # AND `limit` TRUNCATES, as the real API does. The fake returned
        # everything, so the controller's "ask for one more than the bound, so
        # an over-full namespace is REFUSED rather than silently cut short" was
        # invisible: passing the bound itself instead of bound + 1 changed
        # nothing the fake could show, while the real API would have truncated
        # without an error and the cardinality check could never have fired.
        return out[:limit]


def _controller(pods, owner_generation=None):
    c = KubernetesRunController.__new__(KubernetesRunController)
    c.api = FakeApi(pods)
    c.namespace = "andyur-runs"
    c.owner_generation = owner_generation
    return c


# --- discovery ---------------------------------------------------------------

def test_an_agent_whose_proxy_is_gone_is_found():
    c = _controller([_pod(RUN, GEN, "agent")])          # no proxy at all

    assert c.list_orphaned_agent_generations() == [(RUN, GEN)]


def test_a_pod_andyur_does_not_manage_is_never_swept():
    """The selector's `managed-by` term is what keeps the sweep to Andyur's own
    Pods. Every fixture here carried it, so dropping it from the real selector
    changed nothing any test could see -- while in a shared namespace it would
    collect someone else's workload that merely shares the other labels."""
    labels = {"app.kubernetes.io/component": "agent",
              "andyur.run/id": _digest(RUN),
              "andyur.run/generation": _digest(GEN)}           # no managed-by
    c = _controller([_pod(RUN, GEN, "agent", labels=labels)])

    assert c.list_orphaned_agent_generations() == [], (
        "a Pod not managed by andyur-worker was treated as an orphan to sweep")


def test_an_agent_with_a_live_proxy_is_left_alone():
    """The negative control. A sweep that collects healthy runs is worse than
    no sweep."""
    c = _controller([_pod(RUN, GEN, "agent"), _pod(RUN, GEN, "proxy")])

    assert c.list_orphaned_agent_generations() == []


def test_a_proxy_that_has_exited_counts_as_gone():
    """The agent is single-homed on that proxy and can reach nothing else, so a
    Succeeded or Failed proxy leaves it with no destination just as an absent
    one does."""
    for phase in ("Succeeded", "Failed"):
        c = _controller([_pod(RUN, GEN, "agent"),
                         _pod(RUN, GEN, "proxy", phase=phase)])

        assert c.list_orphaned_agent_generations() == [(RUN, GEN)], phase


def test_an_agent_that_has_already_exited_is_not_swept():
    """Nothing is executing, so there is nothing to contain. Deleting it here
    would race the reap path that reads its exit code and logs."""
    for phase in ("Succeeded", "Failed"):
        c = _controller([_pod(RUN, GEN, "agent", phase=phase)])

        assert c.list_orphaned_agent_generations() == [], phase


def test_another_generation_of_the_same_run_does_not_shield_an_orphan():
    """Keyed on (run, generation), not run alone -- a replacement generation
    must not make its predecessor's agent look supervised."""
    c = _controller([_pod(RUN, "gen-old", "agent"),
                     _pod(RUN, "gen-new", "proxy")])

    assert c.list_orphaned_agent_generations() == [(RUN, "gen-old")]


def test_a_worker_reconciles_only_its_own_generation():
    """Same rule as adoption: in a shared namespace, sweeping another worker's
    workload is destroying a run nobody asked us about."""
    c = _controller([_pod(RUN, "mine", "agent"), _pod(OTHER, "theirs", "agent")],
                    owner_generation="mine")

    assert c.list_orphaned_agent_generations() == [(RUN, "mine")]


# --- identity is verified, never guessed -------------------------------------

def test_an_agent_whose_raw_identity_does_not_match_its_labels_is_skipped():
    """SKIPPED, NOT GUESSED. Deleting on an identity we could not confirm would
    let a rewritten label aim this at another run's generation -- worse than
    leaving one Pod for an operator to find."""
    pod = _pod(RUN, GEN, "agent")
    pod.annotations = {"andyur.run/id-raw": OTHER,          # disagrees with the label
                       "andyur.run/generation-raw": GEN}
    c = _controller([pod])

    assert c.list_orphaned_agent_generations() == []


def test_an_agent_with_no_raw_identity_is_skipped():
    pod = _pod(RUN, GEN, "agent")
    pod.annotations = {}
    c = _controller([pod])

    assert c.list_orphaned_agent_generations() == []


def test_a_noncanonical_agent_pod_name_is_skipped():
    """The name is derived from the identity, so one that disagrees is not a
    Pod this controller created."""
    c = _controller([_pod(RUN, GEN, "agent", name="something-else")])

    assert c.list_orphaned_agent_generations() == []


def test_more_agents_than_the_safe_bound_is_refused_rather_than_truncated():
    """A truncated list is a sweep that silently stops reconciling, which is
    the failure this whole file exists to prevent."""
    pods = [_pod("c" * 31 + str(i % 10), f"gen-{i}", "agent")
            for i in range(KubernetesRunController.MAX_ADOPTED_PODS + 2)]
    c = _controller(pods)

    with pytest.raises(RuntimeError, match="cardinality"):
        c.list_orphaned_agent_generations()


# --- the orchestrator destroys what discovery found --------------------------

class _Controller:
    def __init__(self, orphans, fail=()):
        self.orphans = orphans
        self.deleted = []
        self.fail = set(fail)

    def list_orphaned_agent_generations(self):
        return list(self.orphans)

    def delete_generation(self, run_id, generation):
        if run_id in self.fail:
            raise RuntimeError("delete refused")
        self.deleted.append((run_id, generation))


def _orch(controller):
    o = orchestrator.KubernetesOrchestrator.__new__(
        orchestrator.KubernetesOrchestrator)
    o.controller = controller
    # The owner-scoped daemon; the execution worker's run-scoped mode sweeps
    # nothing (it owns no generation the reconciler should compete for).
    o.run_scoped_generations = False
    return o


def test_sweeping_destroys_the_orphaned_generation():
    c = _Controller([(RUN, GEN)])

    _orch(c).sweep()

    assert c.deleted == [(RUN, GEN)]


def test_sweeping_destroys_nothing_when_there_is_nothing_to_destroy():
    c = _Controller([])

    _orch(c).sweep()

    assert c.deleted == []


def test_one_generation_that_will_not_delete_does_not_stop_the_next():
    """Best effort by contract: the daemon calls this every beat, so one
    generation that will not delete must not shield the others."""
    c = _Controller([(RUN, GEN), (OTHER, GEN)], fail={RUN})

    _orch(c).sweep()

    assert c.deleted == [(OTHER, GEN)]


def test_the_engine_view_and_the_daemon_own_sweep_fail_independently():
    """B+ (ADR-014 D11) added a second listing -- the engine's run-scoped
    generations. Its first version shared one try with the daemon's own
    listing, so an engine view that could not be built cost the daemon its
    OWN sweep too. Each half now fails alone, in both directions."""
    engine = _Controller([(OTHER, "exec-0123456789abcdef"), (RUN, "gen-9")])
    o = _orch(_Controller([(RUN, GEN)]))
    o._engine_view = lambda: (_ for _ in ()).throw(RuntimeError("no api"))
    o.sweep()
    assert o.controller.deleted == [(RUN, GEN)]

    class Broken:
        def list_orphaned_agent_generations(self):
            raise RuntimeError("apiserver unreachable")
    o = _orch(Broken())
    o._engine_view = lambda: engine
    o.sweep()
    # Only the engine's own generation; a non-engine one is not its to take.
    assert engine.deleted == [(OTHER, "exec-0123456789abcdef")]


def test_a_listing_failure_does_not_raise_into_the_heartbeat():
    class Broken:
        def list_orphaned_agent_generations(self):
            raise RuntimeError("the API server is unreachable")

    _orch(Broken()).sweep()          # must not raise


def test_an_agent_whose_LABELS_disagree_with_its_identity_is_skipped():
    """THE CASE THE FIRST DRAFT MISSED, found by mutation: removing the digest
    verification broke nothing, because the canonical-name check happened to
    catch every example the tests used.

    It is not redundant. Orphan MATCHING keys on the labels -- an agent is
    compared against live proxies by its label digests -- while DELETION uses
    the raw identity from the annotations. A Pod whose name and annotations
    agree with each other but whose labels were rewritten is therefore matched
    against the wrong proxy, and could be judged an orphan while its real proxy
    is alive.

    So the two must be checked against each other, and a Pod where they
    disagree is skipped.
    """
    pod = _pod(RUN, GEN, "agent")                 # canonical name, honest annotations
    pod.labels = {**pod.labels, "andyur.run/id": _digest(OTHER)}   # labels rewritten
    c = _controller([pod, _pod(RUN, GEN, "proxy")])                # its proxy IS alive

    assert c.list_orphaned_agent_generations() == [], (
        "a rewritten label made a supervised agent look orphaned")


def test_a_rewritten_generation_label_is_also_skipped():
    pod = _pod(RUN, GEN, "agent")
    pod.labels = {**pod.labels, "andyur.run/generation": _digest("other-gen")}
    c = _controller([pod])

    assert c.list_orphaned_agent_generations() == []


def test_agents_are_listed_before_proxies():
    """THE ORDER IS THE SAFETY ARGUMENT, and reversing it destroys live runs.

    The launch path creates the proxy, waits for it to be ready, then creates
    the agent -- so "an agent with no proxy means the proxy died" holds at a
    single instant, not across two API calls. Listing proxies FIRST let a launch
    complete in between: the agent appeared after the proxy snapshot, looked
    unsupervised, and a healthy just-started run was destroyed. The two are
    genuinely concurrent, since the daemon launches on an executor while the
    heartbeat sweeps on the loop thread.

    Reversed, a stale snapshot can only MISS an orphan, never invent one.
    Missing one costs a beat; inventing one costs a run.

    Asserted by watching the order of the calls, because the race is a timing
    property that a fixed set of pods cannot express.
    """
    order = []

    class RecordingApi(FakeApi):
        def list_pods(self, namespace, selector, timeout, limit):
            order.append(selector.get("app.kubernetes.io/component"))
            return super().list_pods(namespace, selector, timeout, limit)

    c = KubernetesRunController.__new__(KubernetesRunController)
    c.api = RecordingApi([_pod(RUN, GEN, "agent"), _pod(RUN, GEN, "proxy")])
    c.namespace = "andyur-runs"
    c.owner_generation = None

    c.list_orphaned_agent_generations()

    assert order == ["agent", "proxy"], (
        f"proxies were listed before agents ({order}); a launch completing "
        "between the two calls would make a healthy run look orphaned")

"""The containment reconciler: it stamps only when it re-proved containment.

This component exists because the worker refuses to launch without a fresh
NetworkPolicy verification stamp and nothing in a deployed cluster renewed it.
The whole risk of writing it is that it becomes a rubber stamp -- a component
that writes "containment verified" because time passed. So the tests here are
almost entirely about the cases where it must NOT stamp, and about the one
cross-module property that matters: what it writes is exactly what the worker's
admission check reads.
"""

from __future__ import annotations

import json
import types

import pytest

from andyur.daemon import network_policy_reconciler as npr


class FakeMeta:
    def __init__(self, uid="ns-uid-1", labels=None, annotations=None):
        self.uid = uid
        self.labels = labels or {}
        self.annotations = annotations or {}


class FakeNamespace:
    def __init__(self, uid="ns-uid-1"):
        self.metadata = FakeMeta(uid)


class FakePod:
    def __init__(self, ip="10.1.1.1", phase="Succeeded", ready=True):
        self.status = types.SimpleNamespace(
            pod_ip=ip, phase=phase,
            conditions=[types.SimpleNamespace(type="Ready",
                                              status="True" if ready else "False")])


class FakeCore:
    """Just enough Kubernetes to run one cycle, and a record of what was done."""

    def __init__(self, observed=None, log_line=None, fail_on=None,
                 first=None, attempts=1):
        self.observed = observed
        self.first = first
        self.attempts = attempts
        self.log_line = log_line
        self.fail_on = fail_on or set()
        self.created, self.deleted, self.patches = [], [], []

    def create_namespaced_pod(self, namespace, body):
        if "create_pod" in self.fail_on:
            raise RuntimeError("the API server said no")
        self.created.append(body["metadata"]["name"])

    def read_namespaced_pod(self, name, namespace):
        return FakePod()

    def read_namespaced_pod_log(self, name, namespace):
        if self.log_line is not None:
            return self.log_line
        # The shape the probe Pod actually prints: the settled observation it is
        # judged on, plus the first one it saw before its own NetworkPolicy was
        # programmed, plus how many attempts that took.
        return ("some noise\nANDYUR_PROBE " + json.dumps(
            {"observed": self.observed, "first_observation": self.first or self.observed,
             "attempts": self.attempts}, sort_keys=True) + "\nmore noise\n")

    def delete_collection_namespaced_pod(self, namespace, **kw):
        self.deleted.append(("pods", kw.get("label_selector")))

    def read_namespaced_service(self, name, namespace):
        return types.SimpleNamespace(spec=types.SimpleNamespace(cluster_ip="10.2.2.2"))

    def read_namespace(self, name):
        return FakeNamespace()

    def patch_namespace(self, name, body):
        self.patches.append(body)


class FakeNetworking:
    def __init__(self):
        self.created, self.deleted = [], []

    def create_namespaced_network_policy(self, namespace, body):
        self.created.append(body["metadata"]["name"])

    def delete_collection_namespaced_network_policy(self, namespace, **kw):
        self.deleted.append(kw.get("label_selector"))


ALL_GOOD = dict(npr.EXPECTED)


def _reconciler(observed=None, log_line=None, fail_on=None, first=None, attempts=1):
    core = FakeCore(observed=observed, log_line=log_line, fail_on=fail_on,
                    first=first, attempts=attempts)
    net = FakeNetworking()
    return npr.Reconciler(core, net, "andyur-runs", "andyur-system",
                          "reg/andyur-worker@sha256:" + "a" * 64,
                          clock=lambda: 1_700_000_000.0), core, net


# --- the only case that stamps ----------------------------------------------

def test_a_fully_proved_cycle_stamps_the_namespace():
    reconciler, core, _ = _reconciler(observed=ALL_GOOD)
    assert reconciler.cycle() is True
    assert len(core.patches) == 1
    metadata = core.patches[0]["metadata"]
    assert metadata["labels"][npr.LABEL_VERIFIED] == "true"
    assert metadata["annotations"][npr.ANNOTATION_UID] == "ns-uid-1"
    assert int(metadata["annotations"][npr.ANNOTATION_AT]) == 1_700_000_000
    # WHAT WAS CHECKED, on the stamp. A stamp that says only "verified" cannot
    # be told from one somebody wrote by hand.
    checks = json.loads(metadata["annotations"][npr.ANNOTATION_CHECKS])
    assert {k: checks[k] for k in npr.EXPECTED} == ALL_GOOD
    assert "mutation" in metadata["annotations"][npr.ANNOTATION_NOT_COVERED]


def test_the_stamp_is_exactly_what_the_workers_admission_check_reads():
    """THE CROSS-MODULE PROPERTY. A stamp written under a key the reader does
    not read is the most silent failure this component could have: the worker
    would refuse forever while the reconciler logged success every cycle. So
    the label and both annotations are re-read here through the real
    `assert_isolation_ready`, against a namespace carrying what was written."""
    import time as _time
    from andyur.daemon import kubernetes_api

    reconciler, core, _ = _reconciler(observed=ALL_GOOD)
    reconciler.clock = _time.time                # the reader compares to now
    assert reconciler.cycle() is True
    written = core.patches[0]["metadata"]

    class Core:
        def read_namespace(self, name, **kw):
            return types.SimpleNamespace(metadata=FakeMeta(
                uid="ns-uid-1", labels=written["labels"],
                annotations=written["annotations"]))

    api = kubernetes_api.OfficialKubernetesApi.__new__(
        kubernetes_api.OfficialKubernetesApi)
    api._core = Core()
    api.assert_isolation_ready("andyur-runs")    # raises if the stamp is unreadable


# --- everything that must not stamp -----------------------------------------

def test_a_failed_positive_control_withdraws_the_stamp():
    """If the probe could not reach its OWN run's proxy, every 'deny' beside it
    is uninformative -- it could be a broken image, a Pod with no network, or a
    cluster that never scheduled it. Stamping on that records the probe's
    failure as a security property."""
    observed = {**ALL_GOOD, "same_run_allow": "deny"}
    reconciler, core, _ = _reconciler(observed=observed)
    assert reconciler.cycle() is False
    metadata = core.patches[0]["metadata"]
    assert metadata["labels"][npr.LABEL_VERIFIED] is None
    assert metadata["annotations"][npr.ANNOTATION_AT] is None
    assert "positive control" in json.loads(
        metadata["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]


@pytest.mark.parametrize("check", ["cross_run_deny", "api_deny", "internet_deny",
                                   "metadata_deny", "collector_deny"])
def test_any_reachable_denial_target_withdraws_the_stamp(check):
    observed = {**ALL_GOOD, check: "allow"}
    reconciler, core, _ = _reconciler(observed=observed)
    assert reconciler.cycle() is False
    withdrawn = json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]
    assert check in withdrawn and "allow" in withdrawn


def test_resolving_dns_from_inside_isolation_withdraws_the_stamp():
    observed = {**ALL_GOOD, "dns_deny": "resolved"}
    reconciler, core, _ = _reconciler(observed=observed)
    assert reconciler.cycle() is False
    assert "dns_deny" in json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]


def test_a_probe_that_could_not_run_withdraws_rather_than_stamps():
    """'The probe did not run' and 'the probe found isolation' must never reach
    the same outcome. An unreachable API server is the ordinary way this
    happens, and carrying it as a pass is the false green this repository keeps
    finding."""
    reconciler, core, _ = _reconciler(observed=ALL_GOOD, fail_on={"create_pod"})
    assert reconciler.cycle() is False
    assert core.patches[0]["metadata"]["labels"][npr.LABEL_VERIFIED] is None
    assert "RuntimeError" in json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]


def test_a_probe_pod_that_printed_nothing_is_not_a_pass():
    reconciler, core, _ = _reconciler(log_line="crashed before it could report\n")
    assert reconciler.cycle() is False
    assert core.patches[0]["metadata"]["labels"][npr.LABEL_VERIFIED] is None


# --- it leaves nothing behind ------------------------------------------------

def test_probe_resources_are_deleted_even_when_the_probe_fails():
    """A probe Pod left in the run namespace is a Pod no run owns -- which is
    exactly what the workload gates check for and report as a reaper defect."""
    reconciler, core, net = _reconciler(observed=ALL_GOOD, fail_on={"create_pod"})
    reconciler.cycle()
    assert core.deleted and net.deleted
    assert core.deleted[0][1].startswith("andyur.probe/id=netpol-probe-")


def test_every_probe_object_carries_the_id_its_cleanup_selects_on():
    reconciler, core, net = _reconciler(observed=ALL_GOOD)
    reconciler.cycle()
    prefix = core.deleted[0][1].split("=", 1)[1]
    assert core.created and net.created
    assert all(name.startswith(prefix) for name in core.created + net.created)


# --- the interval is a safety property, not a preference ---------------------

def test_an_interval_no_shorter_than_the_stamps_life_is_refused(monkeypatch):
    """A cycle that is not comfortably inside the 600s the worker enforces
    produces a namespace whose stamp expires between cycles -- runs stop, for a
    reason that has nothing to do with containment."""
    monkeypatch.setenv("ANDYUR_PROBE_IMAGE", "reg/x@sha256:" + "a" * 64)
    monkeypatch.setenv("ANDYUR_NETPOL_INTERVAL", str(npr.MAX_STAMP_AGE))
    monkeypatch.setitem(__import__("sys").modules, "kubernetes",
                        types.SimpleNamespace(
                            client=types.SimpleNamespace(
                                CoreV1Api=lambda: None, NetworkingV1Api=lambda: None),
                            config=types.SimpleNamespace(load_incluster_config=lambda: None)))
    assert npr.main() == 2


def test_no_probe_image_is_refused_rather_than_defaulted(monkeypatch):
    monkeypatch.delenv("ANDYUR_PROBE_IMAGE", raising=False)
    monkeypatch.setitem(__import__("sys").modules, "kubernetes",
                        types.SimpleNamespace(
                            client=types.SimpleNamespace(
                                CoreV1Api=lambda: None, NetworkingV1Api=lambda: None),
                            config=types.SimpleNamespace(load_incluster_config=lambda: None)))
    assert npr.main() == 2


# --- the probe program itself ------------------------------------------------

def test_the_probe_reports_every_check_the_reconciler_judges():
    """The program that runs INSIDE the Pod and the expectations out here are
    two lists that must not drift: a check the probe stops reporting would be
    judged against `None` and, being != its expectation, would withdraw the
    stamp forever -- or worse, be dropped from EXPECTED and never checked."""
    for name in npr.EXPECTED:
        assert f'"{name}"' in npr._AGENT_PROGRAM, (
            f"{name} is expected but the probe never reports it")


# --- the window before the policy is programmed ------------------------------

def test_the_startup_window_is_recorded_and_not_judged():
    """A Pod's network exists before the CNI has written its NetworkPolicy
    rules, so the first observation showed an isolated agent reaching the API,
    the internet and DNS -- and the first live cycle withdrew the stamp on a
    cluster whose containment was fine.

    Retrying until settled is right; erasing what was seen first is not. That
    the Pod could reach the internet for the first few seconds of its life is a
    real property of this cluster, so it goes on the stamp -- beside, and not
    inside, the closed set of expectations that are judged."""
    leaky = {**ALL_GOOD, "api_deny": "allow", "internet_deny": "allow",
             "dns_deny": "resolved", "same_run_allow": "deny"}
    reconciler, core, _ = _reconciler(observed=ALL_GOOD, first=leaky, attempts=4)
    assert reconciler.cycle() is True, "the SETTLED observation is what is judged"
    checks = json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])
    assert checks["_first_observation"] == leaky
    assert checks["_settled_after_attempts"] == 4


def test_the_informational_keys_can_never_make_a_cycle_pass_or_fail():
    """They sit in the same dict as the judged values, so the judging has to
    read the closed set by name rather than compare dicts."""
    reconciler, core, _ = _reconciler(
        observed={**ALL_GOOD, "api_deny": "allow"}, first=ALL_GOOD, attempts=1)
    assert reconciler.cycle() is False
    withdrawn = json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]
    assert "api_deny" in withdrawn
    assert "_first_observation" not in withdrawn


def test_the_probe_waits_for_its_own_policy_rather_than_reporting_immediately():
    """The property, in the program that runs inside the Pod: it must loop, and
    it must stop when what it sees equals what was expected."""
    assert "observed == expected" in npr._AGENT_PROGRAM
    assert "SETTLE_SECONDS" in npr._AGENT_PROGRAM
    assert "first_observation" in npr._AGENT_PROGRAM


# --- reading the result back -------------------------------------------------

def test_the_result_is_read_whatever_surrounds_it():
    """`splitlines()` plus `json.loads` required the result to be a whole line
    with nothing after it. The program is carried in a RAW string, so the `\\n`
    it appended reached the Pod as backslash-n -- two stray characters, no
    newline -- and the reconciler reported "the probe Pod produced no result
    line" every cycle about a Pod that had printed a perfectly good result.

    A claim about the PROBE that was false, on a cluster whose containment was
    fine. So the marker is found wherever it is and exactly one JSON value is
    decoded from it."""
    # A LITERAL backslash-n where the newline should be, and rubbish after it.
    noisy = ("some warning\n" + npr.MARKER + json.dumps(
        {"observed": ALL_GOOD, "first_observation": ALL_GOOD, "attempts": 2},
        sort_keys=True) + "\\ntrailing rubbish")
    reconciler, core, _ = _reconciler(log_line=noisy)
    assert reconciler.cycle() is True
    assert core.patches[0]["metadata"]["labels"][npr.LABEL_VERIFIED] == "true"


def test_a_log_with_no_marker_says_what_it_did_contain():
    """"produced no result line" with nothing else sent the reader looking at
    the probe program. The message now shows both ends of what was actually
    there, which is what tells you it was a crash, an empty log, or a marker
    that changed."""
    reconciler, core, _ = _reconciler(log_line="Traceback (most recent call last):\nMemoryError\n")
    assert reconciler.cycle() is False
    withdrawn = json.loads(
        core.patches[0]["metadata"]["annotations"][npr.ANNOTATION_CHECKS])["withdrawn"]
    assert "MemoryError" in withdrawn and "ANDYUR_PROBE" in withdrawn


def test_the_program_and_the_reader_share_one_marker():
    """Two string literals that must be equal is one that will not be."""
    assert npr.MARKER in npr._AGENT_PROGRAM
    assert npr._AGENT_PROGRAM.count(repr(npr.MARKER)) == 1

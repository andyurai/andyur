"""The rollback, and specifically the difference between doing it and proving it.

The MVP claim is a REAL Kubernetes state change. These test the property that
makes "rollback succeeded" mean something: the revision is read back from the
cluster and compared, so a result can never be derived from our own request.
"""

import copy

import pytest

from andyur import rollback


def _dep(revision, name="checkout"):
    return {"metadata": {"name": name,
                         "annotations": {rollback.REVISION: str(revision)}}}


def _rs(revision, image="checkout:good"):
    return {"metadata": {"annotations": {rollback.REVISION: str(revision)}},
            "spec": {"template": {"spec": {"containers": [{"image": image}]}}}}


class FakeCluster:
    """A cluster that only moves when something moves it.

    The revision advances on patch, which is what a real Deployment does, so a
    test asserting `changed` is asserting the cluster reported a new revision
    rather than that we called a method.
    """

    def __init__(self, revision=3, advance_on_patch=True, history=None):
        self.revision = revision
        self.advance_on_patch = advance_on_patch
        self.history = history if history is not None else [_rs(1), _rs(2), _rs(3)]
        self.patched = []
        self.uid = "deployment-uid"
        self.generation = revision
        self.template = {"spec": {"containers": [{"image": "checkout:bad"}]}}

    def _state(self, name):
        doc = _dep(self.revision, name)
        doc["metadata"].update(uid=self.uid, resourceVersion=str(self.generation),
                               generation=self.generation)
        doc["spec"] = {"template": copy.deepcopy(self.template)}
        doc["status"] = {"observedGeneration": self.revision}
        return doc

    def read_deployment(self, ns, name):
        return self._state(name)

    def list_replicasets(self, ns, name, *, owner):
        assert owner["metadata"]["uid"] == self.uid
        return list(self.history)

    def patch_deployment_template(self, ns, name, template, *, expected):
        assert expected["metadata"]["resourceVersion"] == str(self.generation)
        self.patched.append(template)
        self.template = copy.deepcopy(template)
        self.generation += 1
        if self.advance_on_patch:
            self.revision += 1
        return self._state(name)


def test_a_rollback_that_moves_the_cluster_is_reported_as_changed():
    c = FakeCluster(revision=3)
    out = rollback.rollback(c, "prod", "checkout")
    assert out.changed is True
    assert out.from_revision == "3" and out.observed_revision == "4"
    assert c.patched, "no patch was issued"


def test_a_write_the_cluster_ignores_is_NOT_success():
    """THE PROPERTY THIS MODULE EXISTS FOR. The patch is accepted, the API
    returns normally, and the revision does not move. Reporting success here
    would be a green derived from our own request rather than from Kubernetes,
    which is the failure family this codebase found three times this week."""
    c = FakeCluster(revision=3, advance_on_patch=False)
    out = rollback.rollback(c, "prod", "checkout", observe_seconds=0)
    assert out.changed is False, "an ignored write was reported as a rollback"
    assert out.observed_revision == "3"
    assert "did not roll back" in out.detail


def test_an_ignored_write_is_an_outcome_not_an_exception():
    """It must reach the operator as a result, not as a dispatch failure: the
    write WAS accepted, and rendering that as 'failed to dispatch' would send
    someone to look at the wrong thing."""
    c = FakeCluster(revision=3, advance_on_patch=False)
    out = rollback.rollback(c, "prod", "checkout", observe_seconds=0)  # must not raise
    assert out.changed is False


@pytest.mark.parametrize("history,current,expected", [
    ([9, 10, 11], 11, "10"),      # lexical order is 10, 11, 9 -> picks 9
    ([9, 10], 10, "9"),           # lexical order is 10, 9    -> picks 9 by luck
    ([2, 10, 11], 11, "10"),      # lexical order is 10, 11, 2 -> picks 2
])
def test_revisions_are_ordered_NUMERICALLY_not_lexically(history, current, expected):
    """A lexical sort puts "9" after "10", so past the tenth release a
    deployment would roll back to the WRONG revision -- a wrong consequential
    action, one of the nine triggers, not a cosmetic bug.

    Parametrised because my first version of this test used revisions 8, 9, 10
    and SURVIVED a lexical-sort mutant: the filter compares integers, so with
    that data both orderings happen to yield 9. A test whose data cannot
    distinguish the two implementations is not testing the property. The first
    case discriminates; the second is the lucky one kept deliberately, so the
    difference between them stays visible.
    """
    target = rollback.previous_replicaset(_dep(current), [_rs(n) for n in history])
    assert target["metadata"]["annotations"][rollback.REVISION] == expected, \
        "rolled back to the lexically-previous revision, not the numeric one"


def test_the_first_revision_has_nowhere_to_go_and_says_so():
    """A distinct failure. A deployment on revision 1 is a legitimate state, and
    reporting it as a failed rollback would tell an operator the cluster
    refused when there was simply nowhere to go."""
    with pytest.raises(rollback.NoPreviousRevision):
        rollback.previous_replicaset(_dep(1), [_rs(1)])


def test_nothing_is_patched_when_there_is_no_previous_revision():
    """The refusal must come BEFORE the write, or a deployment with no history
    gets its template replaced by whatever was found."""
    c = FakeCluster(revision=1, history=[_rs(1)])
    with pytest.raises(rollback.NoPreviousRevision):
        rollback.rollback(c, "prod", "checkout")
    assert c.patched == [], "a deployment with no previous revision was patched"


def test_a_replicaset_with_an_unparseable_revision_is_skipped_not_ordered_around():
    c_history = [_rs(1), _rs("not-a-number"), _rs(2)]
    target = rollback.previous_replicaset(_dep(3), c_history)
    assert target["metadata"]["annotations"][rollback.REVISION] == "2"


# --- the consequence is ASYNCHRONOUS, and the read-back must survive that ---

def test_a_revision_that_appears_on_the_second_read_is_still_a_rollback():
    """FOUND BY THE LIVE GATE, not reasoned about. The patch is synchronous and
    its consequence is not: the API server accepts the pod template, and the
    Deployment controller writes the new revision annotation afterwards. Two
    identical rollbacks against real k3s reported `succeeded` and `failed` on
    consecutive runs, purely on how quickly the controller got to them.

    So the read-back keeps observing, bounded. A result that depends on how busy
    the cluster was is not an observation of anything."""
    class Late(FakeCluster):
        def __init__(self):
            super().__init__(revision=3, advance_on_patch=False)
            self.reads = 0

        def read_deployment(self, ns, name):
            self.reads += 1
            if self.reads > 2 and self.patched:   # the controller catches up
                self.revision = 4
            return super().read_deployment(ns, name)

    c = Late()
    slept = []
    out = rollback.rollback(c, "prod", "checkout", observe_seconds=10,
                            sleep=slept.append, clock=lambda: 0.0)
    assert out.changed is True and out.observed_revision == "4"
    assert slept, "the read-back did not wait at all"


def test_the_wait_is_BOUNDED_and_says_how_long_it_watched():
    """A cluster that never moves must not hang the request, and the detail must
    distinguish "it did not happen" from "it had not happened yet when we
    stopped looking"."""
    c = FakeCluster(revision=3, advance_on_patch=False)
    ticks = iter([0.0, 0.0, 5.0, 11.0])
    out = rollback.rollback(c, "prod", "checkout", observe_seconds=10,
                            sleep=lambda _: None, clock=lambda: next(ticks))
    assert out.changed is False
    assert "after 10s" in out.detail and "did not roll back" in out.detail


@pytest.mark.parametrize("change,reason", [
    ("template", "rollback_target_changed"),
    ("uid", "deployment_replaced"),
    ("generation", "rollback_target_changed"),
    ("unobserved", "controller_not_observed"),
])
def test_revision_change_alone_is_never_a_success(change, reason):
    class ChangedElsewhere(FakeCluster):
        def read_deployment(self, ns, name):
            doc = super().read_deployment(ns, name)
            if self.patched:
                if change == "template":
                    doc["spec"]["template"]["spec"]["containers"].append(
                        {"image": "unrelated:sidecar"})
                elif change == "uid":
                    doc["metadata"]["uid"] = "replacement-uid"
                elif change == "generation":
                    doc["metadata"]["generation"] += 1
                else:
                    doc["status"]["observedGeneration"] = 0
            return doc

    cluster = ChangedElsewhere()
    result = rollback.rollback(cluster, "prod", "checkout", observe_seconds=0)
    assert result.observed_revision != result.from_revision
    assert not result.changed
    assert result.reason == reason


@pytest.mark.parametrize("revision", [None, "", "garbage", "0", "-1"])
def test_unknown_current_revision_never_selects_a_guessed_target(revision):
    deployment = _dep(3)
    deployment["metadata"]["annotations"][rollback.REVISION] = revision
    with pytest.raises(rollback.NoPreviousRevision, match="current_revision_unknown"):
        rollback.previous_replicaset(deployment, [_rs(1), _rs(2), _rs(3)])

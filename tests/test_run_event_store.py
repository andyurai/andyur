from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from andyur.events.publisher import (
    EventDraft, ProducerNotAuthorized, RunContextSnapshot,
    WorkloadRunEventPublisher,
)
from andyur.events.sqlite import SQLiteRunEventStore
from andyur.events.store import _PendingRunEvent, TerminalRunError
from andyur.events.taxonomy import (
    DataClassification, Durability, EVENT_RULES, EventType, EventVisibility,
    TrustClass,
)


def draft(event_type=EventType.AGENT_OUTPUT, **overrides):
    values = {
        "type": event_type, "durability": Durability.DURABLE,
        "classification": DataClassification.CONFIDENTIAL,
        "visibility": EventVisibility.DEVELOPER,
        "summary": "safe progress", "payload": {"status": "working"},
    }
    values.update(overrides)
    return EventDraft(**values)


def context(tenant="tenant-a", run="run-a"):
    return RunContextSnapshot(tenant, run, "agent-a", "workflow-a",
                              "sha256:registry", "authority-v1")


def publisher(store=None, tenant="tenant-a", run="run-a"):
    return WorkloadRunEventPublisher(store or SQLiteRunEventStore(),
                                     context(tenant, run))


def terminal_pending():
    ctx = context()
    event_type = EventType.RUN_COMPLETED
    return _PendingRunEvent(
        tenant_id=ctx.tenant_id, workflow_id=ctx.workflow_id, run_id=ctx.run_id,
        agent_id=ctx.agent_id, occurred_at=None,
        category=EVENT_RULES[event_type].category, type=event_type,
        source="orchestrator", trust_class=TrustClass.AUTHORITATIVE,
        durability=Durability.DURABLE,
        classification=DataClassification.INTERNAL,
        visibility=EventVisibility.OPERATOR, summary="completed", payload={},
        trace_id=None, span_id=None, parent_event_id=None,
        registry_digest=ctx.registry_digest,
        authority_revision=ctx.authority_revision,
    )


def test_publisher_is_run_bound_and_store_assigns_identity_order():
    bound = publisher()
    first = bound.publish(draft())
    second = bound.publish(draft(EventType.AGENT_PROGRESS))
    assert (first.sequence, second.sequence) == (1, 2)
    assert first.event_id != second.event_id
    assert (first.tenant_id, first.run_id, first.source) == (
        "tenant-a", "run-a", "runner-sidecar")
    assert first.trust_class is TrustClass.ASSERTED
    assert first.registry_digest == "sha256:registry"


@pytest.mark.parametrize("forged_type", [
    EventType.POLICY_ALLOWED, EventType.AUTHORITY_RESOLVED,
    EventType.CREDENTIAL_ISSUED, EventType.RUN_COMPLETED,
])
def test_workload_publisher_has_no_authoritative_path(forged_type):
    with pytest.raises(ProducerNotAuthorized, match="workload cannot emit"):
        publisher().publish(draft(forged_type))


def test_replay_is_tenant_scoped_and_cursor_ordered():
    store = SQLiteRunEventStore()
    for tenant in ("tenant-a", "tenant-b"):
        bound = publisher(store, tenant)
        for _ in range(3):
            bound.publish(draft())
    replay = store.read_after("tenant-a", "run-a", 1, 10)
    assert [item.sequence for item in replay] == [2, 3]
    assert {item.tenant_id for item in replay} == {"tenant-a"}
    assert store.high_watermark("tenant-a", "run-a") == 3


def test_concurrent_writers_receive_unique_monotonic_sequences():
    store = SQLiteRunEventStore()
    bound = publisher(store)
    with ThreadPoolExecutor(max_workers=8) as pool:
        events = list(pool.map(lambda _: bound.publish(draft()), range(50)))
    assert sorted(item.sequence for item in events) == list(range(1, 51))
    assert len({item.event_id for item in events}) == 50


def test_independent_connections_allocate_one_sequence_space(tmp_path):
    path = str(tmp_path / "events.sqlite")
    stores = [SQLiteRunEventStore(path), SQLiteRunEventStore(path)]
    publishers = [publisher(item) for item in stores]
    with ThreadPoolExecutor(max_workers=8) as pool:
        events = list(pool.map(
            lambda index: publishers[index % 2].publish(draft()), range(80)))
    assert sorted(item.sequence for item in events) == list(range(1, 81))
    assert [item.sequence for item in stores[0].read_after("tenant-a", "run-a", 0)] == list(range(1, 81))
    for store in stores:
        store.close()


def test_base_exception_rolls_back_transaction_and_leaves_no_sequence_gap(monkeypatch):
    store = SQLiteRunEventStore()
    bound = publisher(store)
    real_dumps = json.dumps

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt("injected cancellation")

    monkeypatch.setattr("andyur.events.sqlite.json.dumps", interrupt)
    with pytest.raises(KeyboardInterrupt, match="injected cancellation"):
        bound.publish(draft())
    monkeypatch.setattr("andyur.events.sqlite.json.dumps", real_dumps)
    assert bound.publish(draft()).sequence == 1
    assert store.high_watermark("tenant-a", "run-a") == 1


def test_file_store_reopens_with_durable_replay(tmp_path):
    path = str(tmp_path / "events.sqlite")
    first = SQLiteRunEventStore(path)
    publisher(first).publish(draft())
    first.close()
    reopened = SQLiteRunEventStore(path)
    assert [item.sequence for item in reopened.read_after("tenant-a", "run-a", 0)] == [1]
    reopened.close()


def test_ephemeral_events_are_not_misrepresented_as_durable_rows():
    with pytest.raises(ValueError, match="durable events only"):
        publisher().publish(draft(durability=Durability.EPHEMERAL))


def test_store_atomically_rejects_append_after_terminal_event():
    store = SQLiteRunEventStore()
    writer = store._new_writer()  # trusted-platform composition seam
    assert writer.append(terminal_pending()).sequence == 1
    with pytest.raises(TerminalRunError):
        publisher(store).publish(draft())
    assert store.high_watermark("tenant-a", "run-a") == 1


def test_two_connections_never_linearize_ordinary_event_after_terminal(tmp_path):
    for attempt in range(20):
        path = str(tmp_path / f"terminal-race-{attempt}.sqlite")
        terminal_store = SQLiteRunEventStore(path)
        ordinary_store = SQLiteRunEventStore(path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            terminal_future = pool.submit(
                terminal_store._new_writer().append, terminal_pending())
            ordinary_future = pool.submit(publisher(ordinary_store).publish, draft())
            terminal_event = terminal_future.result()
            try:
                ordinary_event = ordinary_future.result()
            except TerminalRunError:
                ordinary_event = None
        if ordinary_event is not None:
            assert ordinary_event.sequence < terminal_event.sequence
        replay = terminal_store.read_after("tenant-a", "run-a", 0)
        terminal_index = next(index for index, item in enumerate(replay)
                              if item.type is EventType.RUN_COMPLETED)
        assert terminal_index == len(replay) - 1
        terminal_store.close()
        ordinary_store.close()

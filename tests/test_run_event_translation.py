import json
from concurrent.futures import ThreadPoolExecutor

from andyur.events.publisher import RunContextSnapshot, WorkloadRunEventPublisher
from andyur.events.sqlite import SQLiteRunEventStore
from andyur.events.translation import (
    MAX_ASSERTED_CHARACTERS_PER_SEGMENT, MAX_ASSERTED_ITEMS_PER_MESSAGE,
    RunEventTranslator,
)
from andyur.events.taxonomy import EventType, TrustClass
from andyur.runner.protocol import sanitize


def translate(event):
    return RunEventTranslator(max_drafts=10).translate(event)


def test_translation_never_copies_raw_content():
    secret = "Bearer secret-credential"
    source = sanitize({
        "kind": "msg", "record": {"raw": secret},
        "texts": ["private user text", secret],
        "tools": [{"id": "1", "name": "delete_customer", "input": {"token": secret}}],
        "results": [{"tool_use_id": "1", "content": secret, "is_error": True}],
        "result": None,
    })
    drafts = translate(source)
    wire = json.dumps([{"summary": item.summary, "payload": item.payload}
                       for item in drafts], allow_nan=False)
    for forbidden in (secret, "private user text", "delete_customer"):
        assert forbidden not in wire
    assert [item.type for item in drafts] == [
        EventType.AGENT_OUTPUT, EventType.AGENT_PROGRESS, EventType.AGENT_ERROR]


def test_translation_publishes_only_asserted_agent_events():
    store = SQLiteRunEventStore()
    publisher = WorkloadRunEventPublisher(
        store, RunContextSnapshot("tenant", "run", "agent"))
    drafts = translate(sanitize({
        "kind": "msg", "record": {}, "texts": ["hello"],
        "tools": [], "results": [], "result": None}))
    events = [publisher.publish(item) for item in drafts]
    assert [(item.type, item.trust_class) for item in events] == [
        (EventType.AGENT_OUTPUT, TrustClass.ASSERTED)]
    assert events[0].payload["character_count"] == 5


def test_done_and_unknown_shapes_are_safe():
    assert translate({"kind": "unknown"}) == ()
    assert translate({"kind": "done", "exit": 0}) == ()
    failed = translate(
        sanitize({"kind": "done", "exit": 7, "error": "secret detail"}))
    assert failed[0].type is EventType.AGENT_ERROR
    assert failed[0].payload == {"exit_nonzero": True}
    assert "secret" not in failed[0].summary


def test_hostile_lists_are_coalesced_and_bounded():
    texts = ["x"] * (MAX_ASSERTED_ITEMS_PER_MESSAGE + 100)
    drafts = translate(
        {"kind": "msg", "texts": texts, "tools": [], "results": []})
    assert len(drafts) == 1
    assert drafts[0].payload == {
        "segment_count": MAX_ASSERTED_ITEMS_PER_MESSAGE,
        "character_count": MAX_ASSERTED_ITEMS_PER_MESSAGE,
        "item_count_truncated": True,
        "character_count_truncated": False,
    }


def test_malformed_nested_shapes_do_not_crash_translation():
    drafts = translate({
        "kind": "msg", "texts": "not-list", "tools": [1, None],
        "results": [1, {"is_error": "yes"}]})
    assert [item.type for item in drafts] == [
        EventType.AGENT_PROGRESS, EventType.AGENT_PROGRESS]


def test_character_count_cap_is_explicit_at_sanitizer_boundary():
    exact = "x" * MAX_ASSERTED_CHARACTERS_PER_SEGMENT
    over = exact + " ...(truncated)"
    exact_payload = translate(
        {"kind": "msg", "texts": [exact], "tools": [], "results": []})[0].payload
    over_payload = translate(
        {"kind": "msg", "texts": [over], "tools": [], "results": []})[0].payload
    assert exact_payload["character_count"] == MAX_ASSERTED_CHARACTERS_PER_SEGMENT
    assert exact_payload["character_count_truncated"] is False
    assert over_payload["character_count"] == MAX_ASSERTED_CHARACTERS_PER_SEGMENT
    assert over_payload["character_count_truncated"] is True


def test_run_scoped_budget_bounds_high_volume_durable_amplification():
    translator = RunEventTranslator(max_drafts=5)
    source = {"kind": "msg", "texts": ["x"], "tools": [], "results": []}
    drafts = [draft for _ in range(10_000) for draft in translator.translate(source)]
    assert len(drafts) == 6
    assert drafts[-1].type is EventType.AGENT_WARNING
    assert drafts[-1].payload == {"events_truncated": True}


def test_exact_budget_has_no_false_marker_then_first_overflow_marks_once():
    translator = RunEventTranslator(max_drafts=2)
    source = {"kind": "msg", "texts": ["x"], "tools": [], "results": []}
    assert [item.type for item in translator.translate(source)] == [EventType.AGENT_OUTPUT]
    assert [item.type for item in translator.translate(source)] == [EventType.AGENT_OUTPUT]
    overflow = translator.translate(source)
    assert [item.type for item in overflow] == [EventType.AGENT_WARNING]
    assert translator.translate(source) == ()


def test_concurrent_translation_holds_the_run_budget_and_emits_one_marker():
    translator = RunEventTranslator(max_drafts=17)
    source = {"kind": "msg", "texts": ["x"], "tools": [], "results": []}
    with ThreadPoolExecutor(max_workers=16) as pool:
        batches = list(pool.map(translator.translate, [source] * 1_000))
    drafts = [draft for batch in batches for draft in batch]
    assert sum(item.type is EventType.AGENT_OUTPUT for item in drafts) == 17
    assert sum(item.type is EventType.AGENT_WARNING for item in drafts) == 1

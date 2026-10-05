"""The A<->B wire protocol.

B classifies live SDK objects into wire events; A reconstructs the run's outcome
from those events without ever holding the objects. These tests pin that the
classification is faithful and that the sidecar's failure-naming from forwarded
fields matches the in-process path's naming from live objects -- the two must
never disagree about why a run failed.
"""

import json

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from andyur.runner import protocol
from andyur.runner.runner import describe_failure, describe_failure_fields


def _result(**kw):
    base = dict(subtype="success", duration_ms=1, duration_api_ms=1, is_error=False,
                num_turns=1, session_id="s", total_cost_usd=0.0, result=None)
    base.update(kw)
    return ResultMessage(**base)


def test_assistant_text_and_tool_use_are_classified():
    a = AssistantMessage(
        content=[TextBlock(text="hello"),
                 ToolUseBlock(id="t1", name="mcp__andyur__create_task", input={"a": 1})],
        model="m")
    ev = protocol.normalize(a)
    assert ev["kind"] == "msg"
    assert ev["texts"] == ["hello"]
    assert ev["tools"] == [{"id": "t1", "name": "mcp__andyur__create_task", "input": {"a": 1}}]
    assert ev["results"] == [] and ev["result"] is None


def test_empty_text_block_is_not_forwarded_as_a_chunk():
    a = AssistantMessage(content=[TextBlock(text="")], model="m")
    assert protocol.normalize(a)["texts"] == []


def test_tool_result_is_classified():
    u = UserMessage(content=[ToolResultBlock(tool_use_id="t1", content="ok", is_error=True)])
    ev = protocol.normalize(u)
    assert ev["results"] == [{"tool_use_id": "t1", "content": "ok", "is_error": True}]


def test_result_message_carries_every_cause_field():
    r = _result(is_error=True, result="", api_error_status=529, subtype="success",
                num_turns=4, total_cost_usd=0.02)
    ev = protocol.normalize(r)
    res = ev["result"]
    assert res["is_error"] is True and res["num_turns"] == 4
    assert res["api_error_status"] == 529
    # the record round-trips through json (default=str) without raising
    json.loads(protocol.encode(ev).decode())


def test_encode_is_one_ndjson_line():
    raw = protocol.encode({"kind": "msg", "record": {}, "texts": [], "tools": [],
                           "results": [], "result": None})
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1


def test_done_event_shape():
    assert protocol.done_event(0, None) == {"kind": "done", "exit": 0, "error": None}
    assert protocol.done_event(1, "boom")["error"] == "boom"


# --- failure naming parity: forwarded fields == live object -----------------

def _fields(msg):
    """The dict the SPLIT PATH actually hands describe_failure_fields: whatever
    protocol.normalize put on the wire.

    This used to hand-build a dict with the key "result", which is exactly the
    key normalize did NOT emit -- it emitted "summary". So the test compared two
    things that agreed while the code paths disagreed, and the split path
    silently lost the highest-precedence cause of every failed run. A test that
    reconstructs its subject's output instead of using it can only ever prove
    the reconstruction."""
    return protocol.normalize(msg)["result"]


def test_failure_naming_matches_between_object_and_forwarded_fields():
    cases = [
        _result(is_error=True, result="API Error: parse fail"),
        _result(is_error=True, result="", api_error_status=429),
        _result(is_error=True, result="", subtype="error_max_turns"),
        _result(is_error=True, result="", subtype="success"),  # the honest sentence
        _result(is_error=True, result="", stop_reason="max_tokens"),
    ]
    for msg in cases:
        assert describe_failure(msg) == describe_failure_fields(_fields(msg)), msg


def test_the_wire_carries_the_sdks_own_cause_field():
    """The specific regression: the failure text lives in ResultMessage.result,
    and describe_failure_fields reads `result`. Naming it anything else on the
    wire turns every such failure into 'no cause attached'."""
    ev = protocol.normalize(_result(is_error=True, result="API Error: parse fail"))
    assert ev["result"]["result"] == "API Error: parse fail"
    assert "API Error: parse fail" in describe_failure_fields(ev["result"])


# --- the sidecar must not trust the untrusted side's TYPES ------------------

def test_wrongly_typed_fields_are_forced_into_shape():
    """"A never trusts B" was true of B's CONTENT but not of its SHAPES. The
    consumer did `for text in ev["texts"]`, so `texts` as a STRING was iterated
    one character at a time into the operator's log; `tools` as a string, or a
    list of scalars, raised AttributeError inside the trusted half."""
    ev = protocol.sanitize({
        "kind": "msg", "record": "not a dict", "texts": "abc",
        "tools": {"a": 1}, "results": "xyz", "result": "boom",
    })
    assert isinstance(ev["record"], dict)
    assert ev["texts"] == []          # a string is not a list of texts
    assert ev["tools"] == []
    assert ev["results"] == []
    assert ev["result"] is None       # so no .get() on a str downstream


def test_scalar_items_inside_the_lists_are_dropped():
    ev = protocol.sanitize({"kind": "msg", "record": {},
                            "tools": ["nope", 7, {"id": "t", "name": "n", "input": {}}],
                            "results": [1, {"tool_use_id": "t", "content": "c"}]})
    assert [t["id"] for t in ev["tools"]] == ["t"]
    assert [r["tool_use_id"] for r in ev["results"]] == ["t"]
    assert ev["results"][0]["is_error"] is False


def test_a_done_with_a_junk_exit_code_still_parses():
    ev = protocol.sanitize({"kind": "done", "exit": "not-an-int", "error": {"a": 1}})
    assert ev["kind"] == "done"
    assert ev["exit"] == -1                      # unusable => treated as failure
    assert isinstance(ev["error"], str)


def test_sanitize_survives_a_non_dict_event():
    ev = protocol.sanitize(["not", "a", "dict"])
    assert ev["kind"] == "msg" and ev["record"] == {}


def test_a_wellformed_event_passes_through_unchanged():
    """The caps and coercion must not damage a legitimate event."""
    good = {"kind": "msg", "record": {"type": "AssistantMessage"}, "texts": ["hi"],
            "tools": [{"id": "t1", "name": "Bash", "input": {"cmd": "ls"}}],
            "results": [{"tool_use_id": "t1", "content": "ok", "is_error": False}],
            "result": None}
    ev = protocol.sanitize(good)
    assert ev["texts"] == ["hi"]
    assert ev["tools"][0] == {"id": "t1", "name": "Bash", "input": {"cmd": "ls"}}
    assert ev["results"][0]["tool_use_id"] == "t1"
    assert ev["record"] == {"type": "AssistantMessage"}


def test_an_enormous_agent_string_is_truncated_before_it_reaches_a_log():
    ev = protocol.sanitize({"kind": "msg", "record": {}, "texts": ["z" * 5_000_000]})
    assert len(ev["texts"][0]) < 1_100_000


def test_provider_status_is_named_when_result_is_empty():
    assert "HTTP 529" in describe_failure_fields(
        {"result": "", "api_error_status": 529, "subtype": "success"})


def test_tool_result_content_is_normalised_for_the_consumer():
    """sanitize's promise is that the consumer may assume what it reads, and the
    consumer JOINS item["text"] across content. Passing content through raw left
    the same defect one nesting level down: a {"text": 123} item raised TypeError
    inside the trusted half's consume loop and aborted the whole run."""
    ev = protocol.sanitize({"kind": "msg", "record": {},
                            "results": [{"tool_use_id": "t", "content": [{"text": 123}]}]})
    content = ev["results"][0]["content"]
    assert all(isinstance(x["text"], str) for x in content)
    # the consumer's own expression must not raise on it
    " ".join(x.get("text", "") for x in content if isinstance(x, dict))


def test_a_failure_namer_never_raises_on_forged_fields():
    """describe_failure_fields is handed the agent's RAW result dict -- sanitize
    fixes the event's shape, not this dict's interior."""
    for forged in ({"result": {"a": 1}}, {"result": 123}, {"result": [1]},
                   {"errors": "boom"}, {"errors": 7},
                   {"permission_denials": 5}, {"api_error_status": {"h": 1}},
                   {"stop_reason": {"x": 1}}, {"subtype": {"s": 1}}):
        out = describe_failure_fields(forged)
        assert isinstance(out, str) and out.startswith("agent run failed")


def test_forged_errors_are_not_iterated_per_character():
    """A string is iterable; treating it as a list of errors produced
    "b; o; o; m"."""
    assert "b; o; o; m" not in describe_failure_fields(
        {"errors": "boom", "subtype": "x"})


def test_the_stored_error_text_is_bounded():
    huge = describe_failure_fields({"result": "z" * 5_000_000})
    assert len(huge) < 10_000

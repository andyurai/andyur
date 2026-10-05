"""Bounded translation of sanitized BYOA records into asserted events."""

from __future__ import annotations

from threading import Lock

from .publisher import EventDraft
from .taxonomy import DataClassification, Durability, EventType, EventVisibility

MAX_ASSERTED_ITEMS_PER_MESSAGE = 1024
MAX_ASSERTED_CHARACTERS_PER_SEGMENT = 1_000_000
MAX_DURABLE_DRAFTS_PER_RUN = 1000


class RunEventTranslator:
    """Run-scoped durable-row budget; emits one marker, then drops excess."""

    def __init__(self, max_drafts: int = MAX_DURABLE_DRAFTS_PER_RUN):
        if not isinstance(max_drafts, int) or isinstance(max_drafts, bool) or max_drafts < 1:
            raise ValueError("max_drafts must be positive")
        self._remaining = max_drafts
        self._marked = False
        self._lock = Lock()

    def translate(self, event: dict) -> tuple[EventDraft, ...]:
        drafts = _translate_sanitized_runtime_event(event)
        with self._lock:
            accepted = drafts[:self._remaining]
            self._remaining -= len(accepted)
            if len(accepted) < len(drafts) and not self._marked:
                self._marked = True
                return (*accepted, _draft(
                    EventType.AGENT_WARNING, "Run event budget exhausted",
                    {"events_truncated": True},
                ))
            return accepted


def _translate_sanitized_runtime_event(event: dict) -> tuple[EventDraft, ...]:
    """Emit bounded metadata only; never copy raw runtime content."""
    if not isinstance(event, dict):
        return ()
    if event.get("kind") == "done":
        code = event.get("exit")
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            return (_draft(EventType.AGENT_ERROR, "Agent process exited with an error",
                           {"exit_nonzero": True}),)
        return ()
    if event.get("kind") != "msg":
        return ()

    drafts = []
    texts = event.get("texts")
    if isinstance(texts, list) and texts:
        count = min(len(texts), MAX_ASSERTED_ITEMS_PER_MESSAGE)
        chars = sum(min(len(value), MAX_ASSERTED_CHARACTERS_PER_SEGMENT)
                    for value in texts[:count]
                    if isinstance(value, str))
        drafts.append(_draft(EventType.AGENT_OUTPUT, "Agent produced sanitized output",
                             {"segment_count": count, "character_count": chars,
                              "item_count_truncated": len(texts) > count,
                              "character_count_truncated": any(
                                  isinstance(value, str)
                                  and len(value) > MAX_ASSERTED_CHARACTERS_PER_SEGMENT
                                  for value in texts[:count])}))
    tools = event.get("tools")
    if isinstance(tools, list) and tools:
        count = min(len(tools), MAX_ASSERTED_ITEMS_PER_MESSAGE)
        drafts.append(_draft(EventType.AGENT_PROGRESS, "Agent requested an operation",
                             {"operation_count": count,
                              "item_count_truncated": len(tools) > count}))
    results = event.get("results")
    if isinstance(results, list) and results:
        count = min(len(results), MAX_ASSERTED_ITEMS_PER_MESSAGE)
        errors = sum(1 for value in results[:count]
                     if isinstance(value, dict) and value.get("is_error") is True)
        drafts.append(_draft(EventType.AGENT_ERROR if errors else EventType.AGENT_PROGRESS,
                             "Agent received operation results",
                             {"result_count": count, "error_count": errors,
                              "item_count_truncated": len(results) > count}))
    return tuple(drafts)


def _draft(event_type: EventType, summary: str, payload: dict) -> EventDraft:
    return EventDraft(event_type, Durability.DURABLE,
                      DataClassification.INTERNAL, EventVisibility.DEVELOPER,
                      summary, payload)

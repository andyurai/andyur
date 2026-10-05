"""The run's INPUT: one JSON value a caller hands a run, sealed and bounded.

A run used to carry exactly one task-shaped field, ``reason``: free text,
unbounded, rendered into a native agent's prompt and consumed nowhere else. That
is a wakeup, not an invocation. A caller with something concrete to hand an
agent -- an incident record, a ticket id, the parameters of this one run --
had nowhere to put it that was typed, bounded, sealed at insert and delivered
to every kind of workload. This module is that place.

WHAT IT IS. A single JSON value, canonicalised to one byte representation and
sealed into the run's INSERT beside ``scope`` and the pin, for the reason those
are: nothing may observe a run whose columns are half written. ``reason`` stays
what it was, the human WHY; input is the WITH WHAT. They are never merged, so a
consumer can tell an operator's intent from an operator's data.

WHAT IT IS NOT. It is not authority. The PDP authorises on the pin; an input
saying ``account: 999`` under a pin of ``447`` changes nothing at the sidecar.
It is not instruction: a native agent sees it fenced as untrusted data, exactly
as it sees task detail and messages. And it is never a template: input bytes
never pass through the ``${...}`` resolver in execconfig, which is the one path
by which caller-controlled text could reach a run's bearer.

ONE OWNER. The trigger endpoint, the coordinator, the prompt, the runtime-v1
context and the exec/v1 launcher all read this module rather than each
restating "what counts as too big" or "what bytes does a process get". The
second copy of either rule is how the door and the launcher come to disagree.
"""

from __future__ import annotations

import json
import re

from .registry.models import COMMAND_CREDENTIAL_RE, MAX_INPUT_BYTES, ProcessSpec

# The platform ceiling on a sealed input, and the SAME number the manifest
# vocabulary lets a process declare as its own bound (registry/models.py). One
# constant, so a manifest cannot declare more than the door will ever admit.
MAX_RUN_INPUT_BYTES = MAX_INPUT_BYTES

# A single argv string may not exceed Linux's MAX_ARG_STRLEN (32 pages,
# 131072 bytes INCLUDING the terminating NUL). Past it execve fails with
# E2BIG inside the container runtime, which reports a start failure that names
# nothing about input size. Refused here by name instead, at the door and at
# the launcher, for mode 'argv' only: stdin and file have no such limit.
ARGV_MAX_BYTES = 131072 - 1

# The deepest JSON nesting an input may carry. render() (indent=2, pure-Python
# iterencode) recurses at Python depth and raises RecursionError around 995 --
# outside build_prompt's try and before /start, so an over-nested input parks a
# native run at 'pending' until the reaper, re-dispatchable into a crash loop.
# The request decoder admits ~10k, so this is the bound that fails such input
# CLOSED at the door (422) instead of at prompt-assembly time. 64 is deeper than
# any real task and far below the recursion cliff.
MAX_INPUT_DEPTH = 64

# A footgun guard, not the security boundary (the parser says the same of its
# command and instructions check, and this is the same regex family). Run rows
# are what the F-08 ledger item keeps reusable bearers OUT of; an operator who
# pastes an API key into a run's input would put one back. Keys are checked as
# whole words inside the key name; strings use the parser's prose form.
_CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(^|[^a-z0-9])(secret|token|passw(or)?d|api[_-]?key|private[_-]?key)"
    r"([^a-z0-9]|$)")


class InputRefused(ValueError):
    """The input cannot be sealed, or cannot be delivered to this process.

    Its own class because the request itself is unusable and a caller retrying
    it unchanged will be refused forever: the trigger maps it to 422, never to
    the 409 that means "try again when the agent is idle".
    """


def canonical(value) -> str:
    """One byte representation per value, so the row, the prompt, the context
    document and the bytes a process reads all agree."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def seal(value, *, where: str = "input") -> str | None:
    """Canonicalise and bound a caller's input. ``None`` means no input.

    Refuses, in this order: a value JSON cannot represent (NaN, Infinity --
    Python's decoder admits them and no other consumer would), one over the
    platform ceiling, and one that looks like it carries a credential.
    """
    if value is None:
        return None
    try:
        text = canonical(value)
        # Inside the try on purpose: json.dumps(ensure_ascii=False) will emit a
        # lone surrogate (e.g. "\ud800") that then raises UnicodeEncodeError
        # here, not in canonical(). Left outside, that surrogate reached the
        # trigger as an uncaught 500 instead of the 422 every other bad input
        # gets. The size is measured on the delivered bytes regardless.
        encoded = text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise InputRefused(f"{where}: not representable as JSON: {exc}") from exc
    size = len(encoded)
    if size > MAX_RUN_INPUT_BYTES:
        raise InputRefused(
            f"{where}: {size} bytes exceeds the platform ceiling of "
            f"{MAX_RUN_INPUT_BYTES} bytes")
    _validate_input_shape(value, where)
    return text


def _render_path(where: str, crumb) -> str:
    """Rebuild a JSON path from a crumb chain. Called ONLY when raising."""
    segments = []
    while crumb is not None:
        crumb, segment = crumb
        segments.append(segment)
    return where + "".join(reversed(segments))


def _iter_children(node, crumb, where):
    """Yield ((crumb, segment), child) for a container's children, checking each
    dict KEY for a credential name as it goes. A GENERATOR, so the caller pulls
    one child at a time and the sibling frontier is never materialised."""
    if isinstance(node, dict):
        for key, child in node.items():
            if _CREDENTIAL_KEY_RE.search(key):
                raise InputRefused(
                    f"{_render_path(where, crumb)}: key {key!r} looks like it "
                    "names a credential; a run's input is stored on the run row "
                    "and shown to the workload, and neither may hold one")
            yield (crumb, f".{key}"), child
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield (crumb, f"[{index}]"), child


def _refuse_str_credential(node, crumb, where) -> None:
    """A string node that embeds a credential, or that IS a credential-shaped
    JSON object encoded as text. Returns the parsed container to recurse into,
    or None."""
    if not isinstance(node, str):
        return None
    if COMMAND_CREDENTIAL_RE.search(node):
        raise InputRefused(
            f"{_render_path(where, crumb)}: value looks like it embeds a "
            "credential; a run's input is stored on the run row and shown to "
            "the workload, and neither may hold one")
    # A JSON object encoded AS A STRING would dodge the key screen otherwise --
    # delivery_bytes hands a JSON string to the workload as that exact text.
    try:
        inner = json.loads(node)
    except (ValueError, RecursionError):
        return None
    return inner if isinstance(inner, (dict, list)) else None


def _validate_input_shape(value, where: str) -> None:
    """One pass that refuses over-nesting AND credential shapes.

    Depth is counted ACROSS the JSON-in-string reparse too: a string holding
    deep JSON contributes its parsed depth, so a shallow document that smuggles
    a deeply-nested object as a string is still refused (fail-closed). A stack
    of ITERATOR frames, one per open container, so at most MAX_INPUT_DEPTH
    frames are live at once -- O(depth), not O(width). Pushing
    the whole sibling frontier (the previous two-walk form) peaked near 90x the
    input on a wide flat list, an OOM of the shared control plane inside the
    8 MiB ceiling. Merged into one walk so a document is traversed once. The
    crumb chain shares the parent path and renders it only when raising.
    """
    inner = _refuse_str_credential(value, None, where)   # a top-level string
    root = inner if inner is not None else value
    if not isinstance(root, (dict, list)):
        return
    # (iterator, depth-of-this-container). Root container sits at depth 1; its
    # children are depth 2, refused when that exceeds MAX_INPUT_DEPTH.
    stack = [(_iter_children(root, None, where), 1)]
    while stack:
        iterator, depth = stack[-1]
        try:
            child_crumb, child = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        if depth + 1 > MAX_INPUT_DEPTH:
            raise InputRefused(
                f"{where}: nested deeper than {MAX_INPUT_DEPTH}, which no task "
                "needs and which fails prompt assembly for a native agent")
        reparsed = _refuse_str_credential(child, child_crumb, where)
        if isinstance(child, (dict, list)):
            stack.append((_iter_children(child, child_crumb, where), depth + 1))
        elif reparsed is not None:
            stack.append(
                (_iter_children(reparsed, (child_crumb, "(json)"), where), depth + 1))


def value_of(sealed: str):
    """The JSON value back from its sealed text."""
    return json.loads(sealed)


def delivery_bytes(sealed: str) -> bytes:
    """What a stock process READS: the one rule for turning a value into bytes.

    A JSON string is delivered as its text, so a tool that takes its task as
    prose (``goose run -i file``) is not handed a quoted, escaped literal. Any
    other value is delivered as its canonical JSON, which is what a tool that
    reads a structured task (``opensre investigate -i -``) expects. The rule
    is stated once, here, and ADR-011 documents it; a launcher that invented
    its own would hand two workloads two encodings of one row.
    """
    value = json.loads(sealed)
    if isinstance(value, str):
        return value.encode("utf-8")
    return sealed.encode("utf-8")


def render(sealed: str) -> str:
    """The input as a native agent's prompt shows it: text as text, anything
    else pretty-printed. This is for a model to read, not evidence to bind, so
    readability wins over the canonical form."""
    value = json.loads(sealed)
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2)


def check_against_process(
    sealed: str | None, process: ProcessSpec | None, *,
    where: str, error: type[Exception] = InputRefused,
) -> None:
    """Whether THIS input can be delivered to THIS process. Fails closed.

    Runs at two boundaries with one implementation: the coordinator, so a run
    that cannot be delivered is refused at the door with the caller still on
    the line; and the launcher, because an assignment is still untrusted input
    at the worker and "the server already checked" is the argument that would
    justify deleting every validator in the codebase.

    ``process`` is None for every interface but exec/v1, where input is
    optional and goes wherever that interface puts it. Under exec/v1 the
    manifest DECLARED how the task arrives, and both mismatches are refused:

      * mode ``none`` with an input: the process cannot receive it, and
        silently dropping it would leave a caller believing it did something.
      * any other mode with NO input: worse than a refusal. A container with
        ``stdin`` open and nobody attaching does not read EOF; it blocks until
        the deadline reaper kills it, and reports nothing useful when it does.
    """
    if process is None:
        return
    mode = process.input_mode
    if mode == "none":
        if sealed is not None:
            raise error(
                f"{where}: the manifest declares process.input.mode 'none', "
                "so this run cannot take an input")
        return
    if sealed is None:
        raise error(
            f"{where}: the manifest declares process.input.mode {mode!r}, so "
            "a run needs an input; launched without one the process would "
            "wait for it until the deadline")
    size = len(delivery_bytes(sealed))
    if size > process.input_max_bytes:
        raise error(
            f"{where}: input is {size} bytes but the manifest bounds "
            f"process.input.max_bytes at {process.input_max_bytes}")
    if mode == "argv" and size > ARGV_MAX_BYTES:
        raise error(
            f"{where}: input is {size} bytes, over the {ARGV_MAX_BYTES}-byte "
            "limit of a single argv string (Linux MAX_ARG_STRLEN); mode 'argv' "
            "cannot carry it, mode 'stdin' or 'file' can")
    if mode == "argv" and b"\x00" in delivery_bytes(sealed):
        # A NUL cannot appear in an argv string: execve rejects it (EINVAL) at
        # runc with a message that names nothing about the input. Refused here
        # by name instead. stdin and file carry arbitrary bytes, so the check
        # is argv-only, beside the length bound it shares this boundary with.
        raise error(
            f"{where}: input contains a NUL byte, which cannot appear in an "
            "argv string (execve rejects it); mode 'stdin' or 'file' can carry it")

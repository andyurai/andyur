"""The agent mind, stored through the storage backend (local FS or S3).

Each agent's mind is a set of text objects keyed by path:

    agents/<name>/profile.json          identity: description, personality, scope
    agents/<name>/knowledge.md          the agent's domain knowledge
    agents/<name>/instructions.md       standing instructions applied every run
    agents/<name>/memory/short_term.md  continuity notes carried between runs
    agents/<name>/memory/long_term.md   durable lessons and baselines
    agents/<name>/runs/<run_id>/        prompt, transcript, and summary of a run

Only the server imports this module. Everything routes through
`storage.backend()`, so the same code serves a local filesystem or an S3
bucket. Runners never touch storage; they read and write the mind over the
server's HTTP API.
"""

import json
import posixpath
import re

from . import storage

# Same rule the server applies when an agent is created. Duplicated rather
# than imported to avoid a server -> workspace import cycle; the delete path
# must not depend on the caller having validated.
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")

DEFAULT_KNOWLEDGE = "# Knowledge\n\nNothing learned yet.\n"

DEFAULT_INSTRUCTIONS = (
    "# Instructions\n\n"
    "Do the work described in your wakeup context. Be concrete, verify what\n"
    "you claim, and finish with a short summary of what you did and what\n"
    "should happen next.\n"
)

DEFAULT_SHORT_TERM = "# Short-term memory\n\nNo previous runs.\n"

DEFAULT_LONG_TERM = "# Long-term memory\n\nNothing recorded yet.\n"

# Mind files whose changes are versioned: the agent's editable self (what
# shapes its behaviour) and its learnings. Deliberate, consequential, reversible
# changes worth a full history. Working memory (memory/short_term.md) is
# NOT here: it is a scratchpad the agent overwrites every run, so versioning it
# is pure churn, and each run's episodic record (transcript + summary) already
# captures what that run did.
VERSIONED = ("knowledge.md", "instructions.md", "memory/long_term.md")


# --- what a RUN may change about its own agent -----------------------------
#
# Namespace confinement (R1) stops a run reaching ACROSS to another agent. It
# does not stop a run reaching FORWARD: rewriting its own tool grants or its own
# standing instructions, both of which live inside the namespace it legitimately
# owns. Every later run of that agent then starts from the attacker's version.
# Confinement alone therefore buys one run of delay, not containment.
#
# So the mind is split by what a file DOES, not by who owns it:
#
#   authority + identity   mcp.json (which tool servers this agent gets),
#                          instructions.md, knowledge.md, profile.json
#                          -> operator-provisioned; a run may READ, never write
#   memory                 memory/**  -> what the agent learned; runs write it,
#                          because recording what happened IS the agent's job
#   episodic record        runs/<id>/** -> written by the run it belongs to and
#                          nobody else, so no run can edit another's evidence
#
# The rule to remember, and the one worth stating in a design review: an agent
# may write what it LEARNED, never what it IS. Learning is the job; redefining
# itself is privilege escalation with a delay.
#
# This is a boundary at the API, not a rate: it is enforced server-side from the
# token's own run identity, so no prompt, no injected instruction and no
# compromised tool can talk its way past the HTTP path.
#
# Its precondition, stated because a boundary with an unstated precondition is a
# claim: it confines what a run can do THROUGH THE CONTROL PLANE. An unsandboxed
# run is a host process whose agent holds a shell, and the mind on the local
# backend is a directory it can write directly, with no HTTP call to intercept.
# The production profile therefore requires the sandbox; in the dev profile this
# check is a guard rail, not a wall.
#
# And what it stops is persistence of AUTHORITY (tool grants) and of the
# operator's own words (instructions, knowledge). It does not stop a compromised
# run writing a persuasive memory for its successor to read: memory is what a run
# is supposed to write. That residual is narrowed in the prompt, where memory is
# labelled as recollection rather than instruction (runner/prompt.py), which is a
# rate. Saying which half is which is the point.

# Where a run may write. An allowlist, not a denylist of protected files: a
# denylist fails OPEN the day someone adds a new authority-bearing file and
# forgets to list it, which is exactly the mistake this boundary exists to
# survive. New agent-writable areas are added here, deliberately.
AGENT_WRITABLE_PREFIXES = (
    "memory/",      # what the agent learned
    "artifacts/",   # what the agent produced: reports, outputs, working files
)
RUN_ARTIFACT_PREFIX = "runs/"


def transcript_path(run_id: str) -> str:
    """Where a run's transcript lives under its agent's workspace: the runner
    writes it, the server reads it, the CLI fetches it. One spelling."""
    return f"{RUN_ARTIFACT_PREFIX}{run_id}/transcript.jsonl"


def assert_valid_path(name: str, relpath: str) -> None:
    """Raise ValueError if the path is malformed or escapes the agent.

    Separate from the authority question so the two failures stay distinct: a
    traversal attempt is a bad request, an unauthorized write is a refusal, and
    conflating them makes both harder to debug.
    """
    _key(name, relpath)


def is_own_record(relpath: str, run_id: str | None) -> bool:
    """Is this the run's own episodic record -- what HAPPENED, as opposed to
    what the agent LEARNED?

    The distinction earns its keep when a run is being destroyed. A condemned
    run must still be able to write its transcript and summary, because that is
    the evidence of what it did; it must NOT be able to write memory, because
    that is influence over every run that follows. Evidence yes, influence no.
    """
    if not run_id or not relpath:
        return False
    rel = posixpath.normpath(relpath)
    return rel.startswith(f"{RUN_ARTIFACT_PREFIX}{run_id}/")


def run_may_write(relpath: str, run_id: str | None) -> bool:
    """May a RUN (not the operator) write this path in its own agent's mind?

    Takes the NORMALIZED path, because `memory/../mcp.json` is a write to
    mcp.json wearing a memory prefix. Normalizing here rather than trusting the
    caller keeps the check honest even if the endpoint order changes later.
    """
    if not relpath or relpath.startswith("/") or "\\" in relpath:
        return False
    rel = posixpath.normpath(relpath)
    if rel.startswith("../") or rel == ".." or rel.startswith("/"):
        return False
    if any(rel.startswith(p) for p in AGENT_WRITABLE_PREFIXES):
        return True
    # A run owns exactly one run directory: its own. Without the run_id check any
    # run could rewrite another run's transcript, which is the record of what it
    # did -- an attacker's first cleanup step.
    if run_id and rel.startswith(f"{RUN_ARTIFACT_PREFIX}{run_id}/"):
        return True
    return False


def _key(name: str, relpath: str) -> str:
    # Confine every access to agents/<name>/. Without this, a run scoped to its
    # own agent could pass a `relpath` with `..` and reach ANOTHER agent's mind or,
    # on the local backend, arbitrary host files (e.g. .env, the run-token secret).
    # Reject absolute paths and backslashes, then normalize and require the result
    # to stay under the agent's prefix.
    if not relpath or relpath.startswith("/") or "\\" in relpath:
        raise ValueError(f"invalid mind path '{relpath}'")
    prefix = f"agents/{name}/"
    normalized = posixpath.normpath(prefix + relpath)
    # must resolve strictly UNDER agents/<name>/ -- this rejects both traversal and
    # the bare agent directory (which is not a valid file and would 500 on write)
    if not normalized.startswith(prefix):
        raise ValueError(f"mind path '{relpath}' escapes agent '{name}'")
    return normalized


def read_text(name: str, relpath: str) -> str | None:
    return storage.backend().get(_key(name, relpath))


def read_text_bounded(name: str, relpath: str, limit: int) -> tuple[str, bool, int] | None:
    """At most `limit` bytes of an agent file, whether there was more, and how
    many RAW bytes were read.

    For a caller that reads MANY files in one request: an agent controls the
    size of anything under its own workspace, so bounding after the read has
    already happened bounds nothing -- and a caller charging a byte budget must
    charge the raw count, because content that decodes to nothing still cost a
    read.
    """
    return storage.backend().get_bounded(_key(name, relpath), limit)


def write_text(name: str, relpath: str, content: str) -> None:
    storage.backend().put(_key(name, relpath), content)


def exists(name: str, relpath: str) -> bool:
    return storage.backend().exists(_key(name, relpath))


def delete_agent_files(name: str) -> int:
    """Delete an agent's whole mind. Returns the number of files removed.

    The name is re-validated here rather than trusted from the caller. Every other
    entry point in this module funnels through `_key`, which confines access to
    `agents/<name>/`; this one bypasses `_key` because it targets the directory
    itself, so it has to carry that guarantee on its own."""
    if not NAME_RE.match(name):
        raise ValueError(f"invalid agent name '{name}'")
    return storage.backend().delete_prefix(f"agents/{name}/")


def load_profile(name: str) -> dict:
    text = read_text(name, "profile.json")
    if text is None:
        raise FileNotFoundError(f"no profile for agent '{name}'")
    return json.loads(text)


def create_agent_files(
    name: str,
    description: str = "",
    personality: str = "",
    scope: str = "",
) -> None:
    if exists(name, "profile.json"):
        raise FileExistsError(f"mind for agent '{name}' already exists")

    from . import identity

    profile = {
        "name": name,
        "description": description,
        "personality": personality,
        "scope": scope,
        "communication_style": "Plain, direct, no filler.",
        "spiffe_id": identity.agent_spiffe_id(name),
    }
    write_text(name, "profile.json", json.dumps(profile, indent=2) + "\n")
    write_text(name, "knowledge.md", DEFAULT_KNOWLEDGE)
    write_text(name, "instructions.md", DEFAULT_INSTRUCTIONS)
    write_text(name, "memory/short_term.md", DEFAULT_SHORT_TERM)
    write_text(name, "memory/long_term.md", DEFAULT_LONG_TERM)


def load_context(name: str) -> dict:
    """The mind an agent run needs in its prompt, in one call."""
    return {
        "profile": load_profile(name),
        "knowledge": read_text(name, "knowledge.md") or "",
        "instructions": read_text(name, "instructions.md") or "",
        "short_term": read_text(name, "memory/short_term.md") or "",
        "long_term": read_text(name, "memory/long_term.md") or "",
    }

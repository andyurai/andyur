"""A manifest-backed AgentRegistry stub for the demo.

Reads one fixture file or a directory of `*.json` manifests, validates every one
at construction, and indexes them by immutable `agent_id`. This is the read side
of the locked contract only (`docs/reviews/spire-registry-v2-review-notes.md`
section 7): no lifecycle, no persistence, no SPIRE reconciliation.

The production harness calls only `resolve(agent_id)`. It never opens these
fixture files, never infers an audience from a URL, and never reads a local
ceiling override -- the whole point is that the registry is the single source.
Seeding the fixtures is demo SETUP, outside the harness.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from .models import (
    SERVER_NAME_RE,
    AgentCard,
    AgentNotFound,
    AgentResolution,
    AuthorityCeiling,
    InvalidAgentManifest,
    MAX_TOOL_BINDINGS,
    McpToolGrant,
    ToolBinding,
)

SCHEMA_VERSION = "andyur.agent-resolution/v1"

# Reject anything outside these so schema drift fails at startup rather than
# silently dropping a field the author believed was doing something.
_MANIFEST_KEYS = {
    "schema_version", "agent_id", "name", "instructions", "model", "tools",
    "ceiling", "card",
}
# `card` is OPTIONAL, so every registry written before it keeps parsing. It is
# the one field here that no authority decision may read; see AgentCard.
_CARD_KEYS = {"summary", "category", "requires"}
MAX_CARD_SUMMARY_CHARS = 280
MAX_CARD_REQUIRES = 16
_TOOL_KEYS = {"name", "reach_url", "resource_id", "authority", "expected_spiffe_id",
              "credential_ref", "mcp_tools", "credential_headers"}
# A header name is an RFC 9110 field-name token. Anchored so a value carrying
# CR/LF, a colon or whitespace cannot reach the outbound request builder.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
MAX_CREDENTIAL_HEADERS = 8
# Headers a brokered credential may NEVER set, whatever the binding declares.
# These decide where the request goes, how it is framed, or who it claims to be
# from, so a vendor secret able to set one could redirect or desynchronize the
# outbound leg rather than merely authenticate it. Refused in the registry so a
# reviewer cannot approve one by accident.
FORBIDDEN_CREDENTIAL_HEADERS = frozenset({
    # Routing, framing and origin: where the request goes and who it claims to
    # be from.
    "host", "content-length", "transfer-encoding", "connection", "upgrade",
    "te", "trailer", "expect", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "forwarded",
    # SEMANTICS. A credential authenticates a request; it must not be able to
    # change what the request MEANS. These do, without touching the
    # destination: content negotiation decides how a body is parsed,
    # method-override turns a read into a write, session identity picks which
    # MCP session the call joins, trace headers reparent the audit record, and
    # origin/referer feed the vendor's own CSRF and policy decisions.
    "content-type", "content-encoding", "accept", "accept-encoding",
    "x-http-method-override", "x-method-override",
    "mcp-session-id", "mcp-protocol-version", "last-event-id",
    "traceparent", "tracestate", "baggage",
    "origin", "referer", "cookie", "set-cookie",
    "range",
})
_MCP_TOOL_KEYS = {"name", "requires"}
_CEILING_KEYS = {"actions", "resources"}
_AUTHORITY_MODES = {"managed", "brokered", "passthrough"}
_AGENT_ID_RE = re.compile(r"^agt_[a-z0-9][a-z0-9_-]{1,62}$")
# BOUND to models.SERVER_NAME_RE, not a second copy: the exec/v1
# reference regex is built from the same pattern, and a server name the
# manifest accepts must be one that `services.tools.<server>.mcp_url`
# can name.
_NAME_RE = SERVER_NAME_RE
_RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[^\s]+$")
# A SPIFFE ID (SPIFFE spec sec 2): spiffe://<trust-domain>/<path>. The trust
# domain is a lowercased DNS-like authority; the path is one or more segments.
# Deliberately strict so a malformed value fails at manifest-validation time
# rather than silently producing a SAN matcher that never matches.
_SPIFFE_ID_RE = re.compile(r"^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+$")
_CREDENTIAL_REF_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
# An MCP tool name as the protocol allows clients to see it. Deliberately the
# conservative common subset (the MCP schema itself is looser), because this
# value becomes a comparison key in the data-plane decision and a filter term
# in a rewritten tools/list response -- an exotic name that cannot round-trip
# those paths safely is a manifest error, not a runtime surprise.
_MCP_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
# Far above any real server's tool count, far below what an adversarial
# manifest could use to bloat every downstream decision and filter pass.
MAX_MCP_TOOLS = 128


def _reject_unknown(where: str, got: dict, allowed: set[str]) -> None:
    extra = set(got) - allowed
    if extra:
        raise InvalidAgentManifest(
            f"{where}: unknown field(s) {sorted(extra)}; allowed {sorted(allowed)}")


def _require_str(where: str, obj: dict, key: str) -> str:
    if key not in obj:
        raise InvalidAgentManifest(f"{where}: missing required field {key!r}")
    val = obj[key]
    if not isinstance(val, str) or not val:
        raise InvalidAgentManifest(f"{where}: {key!r} must be a non-empty string")
    return val


def _parse_dimension(where: str, value) -> tuple[str, ...] | None:
    """Preserve the tri-state: null -> None, [] -> (), [x...] -> (x,...)."""
    if value is None:
        return None
    if not isinstance(value, list) or not all(
        isinstance(v, str) and v for v in value
    ):
        raise InvalidAgentManifest(
            f"{where}: must be null or a list of strings, got {value!r}")
    if len(value) != len(set(value)):
        raise InvalidAgentManifest(f"{where}: duplicate values are not allowed")
    return tuple(value)


def _parse_mcp_tools(where: str, value) -> tuple[McpToolGrant, ...] | None:
    """`mcp_tools` with the ceiling's tri-state: null/absent -> None (the
    manifest does not enumerate this server's tools; the decision stays
    audience-level), [] -> () (no tool may be invoked), a list -> exactly the
    named tools. One JSON shape in, the same shape out of the API, so an
    operator reads back what they reviewed."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise InvalidAgentManifest(
            f"{where}: mcp_tools must be null or a list of "
            "{name, requires} objects")
    if len(value) > MAX_MCP_TOOLS:
        raise InvalidAgentManifest(
            f"{where}: mcp_tools exceeds the {MAX_MCP_TOOLS}-entry limit")
    grants: list[McpToolGrant] = []
    seen: set[str] = set()
    for i, entry in enumerate(value):
        at = f"{where} mcp_tools[{i}]"
        if not isinstance(entry, dict):
            raise InvalidAgentManifest(f"{at}: each entry must be an object")
        _reject_unknown(at, entry, _MCP_TOOL_KEYS)
        name = _require_str(at, entry, "name")
        if not _MCP_TOOL_NAME_RE.fullmatch(name):
            raise InvalidAgentManifest(
                f"{at}: {name!r} is not a safe MCP tool name")
        # Two entries for one tool cannot be reconciled: taking either
        # `requires` silently discards the other reviewer-approved line.
        if name in seen:
            raise InvalidAgentManifest(
                f"{where}: duplicate mcp_tools entry for {name!r}")
        seen.add(name)
        requires = _require_str(at, entry, "requires")
        # Whitespace breaks whole-string action comparison and space-joined
        # scope serialization; "@" would smuggle a pin qualifier into a plain
        # set-membership decision that does not evaluate qualifiers.
        if len(requires) > 256 or any(c.isspace() for c in requires) \
                or "@" in requires:
            raise InvalidAgentManifest(
                f"{at}: requires must be one plain action string "
                "(no whitespace, no '@' qualifier, at most 256 chars)")
        grants.append(McpToolGrant(name=name, requires=requires))
    return tuple(grants)


def _parse_credential_headers(where: str, raw, authority: str):
    """Which headers this binding's brokered credential may set.

    Only a brokered tool has a credential to inject, so declaring headers on any
    other authority mode is a claim nothing honours -- the same refusal
    expected_spiffe_id and mcp_tools already make for passthrough.
    """
    if raw is None:
        if authority == "brokered":
            # The sidecar refuses to inject anything a binding did not declare,
            # so a brokered binding without this field can never make a call.
            # Refusing HERE means the operator sees it while publishing;
            # refusing at call time means an immutable, already-signed snapshot
            # 502s every request with no in-place remedy.
            raise InvalidAgentManifest(
                f"{where}: a brokered tool must declare credential_headers; "
                "without them the sidecar has nothing it is permitted to inject")
        return None
    if authority != "brokered":
        raise InvalidAgentManifest(
            f"{where}: credential_headers is only meaningful for a brokered "
            "tool; no other mode injects a credential")
    if not isinstance(raw, list) or not raw:
        raise InvalidAgentManifest(
            f"{where}: credential_headers must be a non-empty list of header names")
    if len(raw) > MAX_CREDENTIAL_HEADERS:
        raise InvalidAgentManifest(
            f"{where}: credential_headers exceeds the "
            f"{MAX_CREDENTIAL_HEADERS}-header limit")
    seen: set[str] = set()
    names: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not _HEADER_NAME_RE.fullmatch(entry):
            raise InvalidAgentManifest(
                f"{where}: {entry!r} is not a valid HTTP header name")
        lowered = entry.lower()
        if lowered in FORBIDDEN_CREDENTIAL_HEADERS:
            raise InvalidAgentManifest(
                f"{where}: {entry!r} decides routing, framing or origin and can "
                "never be set by a credential")
        # Two spellings of one header cannot both be honoured, and which one
        # wins would depend on dict ordering rather than on review.
        if lowered in seen:
            raise InvalidAgentManifest(
                f"{where}: duplicate credential header {entry!r}")
        seen.add(lowered)
        names.append(entry)
    return tuple(names)


def _parse_tool(where: str, raw: dict) -> ToolBinding:
    if not isinstance(raw, dict):
        raise InvalidAgentManifest(f"{where}: each tool must be an object")
    _reject_unknown(where, raw, _TOOL_KEYS)
    name = _require_str(where, raw, "name")
    reach_url = _require_str(where, raw, "reach_url")
    parsed = urlsplit(reach_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise InvalidAgentManifest(
            f"{where}: reach_url must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidAgentManifest(
            f"{where}: reach_url must not contain credentials")
    try:
        parsed.port
    except ValueError as exc:
        # urlsplit deliberately delays port validation until .port is read.
        # Validate here so a resolution described as launchable cannot later
        # crash the runner while it decomposes routing data.
        raise InvalidAgentManifest(
            f"{where}: reach_url has an invalid port: {exc}") from exc
    authority = raw.get("authority")
    if authority not in _AUTHORITY_MODES:
        raise InvalidAgentManifest(
            f"{where}: authority must be one of {sorted(_AUTHORITY_MODES)}, "
            f"got {authority!r}")
    # resource_id is required even for passthrough, so discovery and audit share
    # one canonical resource name. For managed it MUST be non-empty because it is
    # the authorization audience the mint and the PEP key on.
    resource_id = _require_str(where, raw, "resource_id")
    if not _RESOURCE_ID_RE.fullmatch(resource_id):
        raise InvalidAgentManifest(
            f"{where}: resource_id must be a canonical URI-like identifier")
    # The tool's own workload identity, optional. Validated to a well-formed
    # SPIFFE ID so it can become a data-plane SAN matcher; rejected on a
    # passthrough tool, where there is no Andyur-authenticated connection to
    # pin it against and declaring one would be a claim nothing can honour.
    expected_spiffe_id = raw.get("expected_spiffe_id")
    if expected_spiffe_id is not None:
        if not isinstance(expected_spiffe_id, str) or \
                not _SPIFFE_ID_RE.fullmatch(expected_spiffe_id):
            raise InvalidAgentManifest(
                f"{where}: expected_spiffe_id must be a SPIFFE ID "
                "(spiffe://<trust-domain>/<path>)")
        if authority == "passthrough":
            raise InvalidAgentManifest(
                f"{where}: expected_spiffe_id is only meaningful for a managed "
                "tool; a passthrough leg carries no connection to pin")
    credential_ref = raw.get("credential_ref")
    if authority == "brokered":
        if not isinstance(credential_ref, str) or not _CREDENTIAL_REF_RE.fullmatch(credential_ref):
            raise InvalidAgentManifest(
                f"{where}: brokered tools require a lowercase credential_ref (3-64 chars)")
    elif credential_ref is not None:
        raise InvalidAgentManifest(
            f"{where}: credential_ref is allowed only for brokered tools")
    credential_headers = _parse_credential_headers(
        where, raw.get("credential_headers"), authority)
    mcp_tools = _parse_mcp_tools(where, raw.get("mcp_tools"))
    if mcp_tools is not None and authority == "passthrough":
        # Same refusal as expected_spiffe_id: a passthrough leg carries no
        # managed connection, so a per-tool grant here would be a declaration
        # nothing enforces -- and an unenforced declaration reads as a control.
        raise InvalidAgentManifest(
            f"{where}: mcp_tools is only meaningful for a tool Andyur manages; "
            "a passthrough leg has no enforcement point for it")
    return ToolBinding(name=name, reach_url=reach_url,
                       resource_id=resource_id, authority=authority,
                       expected_spiffe_id=expected_spiffe_id,
                       credential_ref=credential_ref,
                       mcp_tools=mcp_tools,
                       credential_headers=credential_headers)


def _where(bundle: str | None) -> str:
    """Name the holder of a colliding id, whichever kind of holder it is."""
    return f"bundle {bundle!r}" if bundle else "an ungrouped manifest"


def _parse_card(source: str, raw) -> AgentCard | None:
    """Absent and null both mean "this agent ships without a card"."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise InvalidAgentManifest(f"{source}: 'card' must be an object or null")
    where = f"{source} card"
    _reject_unknown(where, raw, _CARD_KEYS)
    summary = _require_str(where, raw, "summary")
    if len(summary) > MAX_CARD_SUMMARY_CHARS:
        raise InvalidAgentManifest(
            f"{where}: summary is longer than {MAX_CARD_SUMMARY_CHARS} characters")
    category = raw.get("category")
    if category is not None and (not isinstance(category, str) or not category.strip()):
        raise InvalidAgentManifest(
            f"{where}: category must be null or a non-empty string")

    requires = raw.get("requires")
    if requires is None:
        parsed: tuple[str, ...] | None = None
    elif not isinstance(requires, list):
        raise InvalidAgentManifest(f"{where}: requires must be null or a list")
    elif len(requires) > MAX_CARD_REQUIRES:
        raise InvalidAgentManifest(
            f"{where}: requires lists more than {MAX_CARD_REQUIRES} prerequisites")
    else:
        for item in requires:
            if not isinstance(item, str) or not item.strip():
                raise InvalidAgentManifest(
                    f"{where}: every prerequisite must be a non-empty string")
        parsed = tuple(item.strip() for item in requires)
    return AgentCard(summary=summary.strip(),
                     category=category.strip() if category else None,
                     requires=parsed)


def _parse_manifest(source: str, raw: dict) -> AgentResolution:
    if not isinstance(raw, dict):
        raise InvalidAgentManifest(f"{source}: manifest must be a JSON object")
    _reject_unknown(source, raw, _MANIFEST_KEYS)

    schema = raw.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise InvalidAgentManifest(
            f"{source}: schema_version must be {SCHEMA_VERSION!r}, got {schema!r}")

    agent_id = _require_str(source, raw, "agent_id")
    name = _require_str(source, raw, "name")
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise InvalidAgentManifest(
            f"{source}: agent_id must be an immutable agt_* identifier")
    if not _NAME_RE.fullmatch(name):
        raise InvalidAgentManifest(f"{source}: name is not a valid agent name")
    instructions = _require_str(source, raw, "instructions")

    # model is the one optional field; absent and null both mean "no override".
    model = raw.get("model")
    if model is not None and (not isinstance(model, str) or not model):
        raise InvalidAgentManifest(f"{source}: model must be null or a non-empty string")

    if "tools" not in raw or not isinstance(raw["tools"], list):
        raise InvalidAgentManifest(f"{source}: 'tools' must be a list")
    if len(raw["tools"]) > MAX_TOOL_BINDINGS:
        raise InvalidAgentManifest(
            f"{source}: tools exceeds the {MAX_TOOL_BINDINGS}-binding limit")
    tools: list[ToolBinding] = []
    seen: set[str] = set()
    for i, t in enumerate(raw["tools"]):
        tb = _parse_tool(f"{source} tools[{i}]", t)
        if tb.name in seen:
            raise InvalidAgentManifest(
                f"{source}: duplicate tool name {tb.name!r}; names must be unique")
        seen.add(tb.name)
        tools.append(tb)

    ceiling_raw = raw.get("ceiling")
    if not isinstance(ceiling_raw, dict):
        raise InvalidAgentManifest(f"{source}: 'ceiling' must be an object")
    _reject_unknown(f"{source} ceiling", ceiling_raw, _CEILING_KEYS)
    missing_ceiling = _CEILING_KEYS - set(ceiling_raw)
    if missing_ceiling:
        raise InvalidAgentManifest(
            f"{source} ceiling: missing required field(s) {sorted(missing_ceiling)}")
    ceiling = AuthorityCeiling(
        actions=_parse_dimension(f"{source} ceiling.actions",
                                 ceiling_raw.get("actions")),
        resources=_parse_dimension(f"{source} ceiling.resources",
                                   ceiling_raw.get("resources")),
    )
    declared_resources = {tool.resource_id for tool in tools}
    unused = set(ceiling.resources or ()) - declared_resources
    if unused:
        raise InvalidAgentManifest(
            f"{source}: ceiling resources not declared by tools: {sorted(unused)}")

    # A granted MCP tool whose required action the agent's own ceiling can
    # never yield is dead on arrival: the reviewer believes the grant means
    # something, and every tools/call for it would 403. `None` and "*" mean the
    # ceiling restricts nothing; ceiling entries may carry an "@" qualifier,
    # and the qualifier narrows WHICH resources an action touches, not whether
    # the action exists, so the comparison is against the base action.
    if ceiling.actions is not None and "*" not in ceiling.actions:
        grantable = {a.partition("@")[0] for a in ceiling.actions}
        for tool in tools:
            dead = sorted(g.name for g in (tool.mcp_tools or ())
                          if g.requires not in grantable)
            if dead:
                raise InvalidAgentManifest(
                    f"{source}: mcp_tools {dead} of tool {tool.name!r} require "
                    "actions above this agent's ceiling; the grant could never "
                    "be exercised")

    return AgentResolution(
        agent_id=agent_id, name=name, instructions=instructions, model=model,
        tools=tuple(tools), ceiling=ceiling,
        card=_parse_card(source, raw.get("card")))


class ManifestAgentRegistry:
    """AgentRegistry backed by JSON manifest fixtures.

    `source` is a single `.json` file or a directory of them. Every manifest is
    parsed and validated NOW, so a broken fixture is an InvalidAgentManifest at
    construction rather than a surprise mid-run.
    """

    def __init__(self, source: str | Path):
        path = Path(source)
        if path.is_dir():
            # A BUNDLE IS A SUBDIRECTORY, and that is the whole mechanism.
            # Loose `*.json` files stay ungrouped, so every registry written
            # before bundles existed keeps loading unchanged. A subdirectory
            # groups its agents under its own name, which is what lets two
            # bundles share one registry without being tipped into a single
            # pile where nothing records which shipped what.
            #
            # ONE level, deliberately. Nesting a bundle inside a bundle makes
            # "which bundle is this agent from" ambiguous, and that question is
            # the only reason the grouping exists.
            files = [(None, f) for f in sorted(path.glob("*.json"))]
            for sub in sorted(p for p in path.iterdir() if p.is_dir()):
                files.extend((sub.name, f) for f in sorted(sub.glob("*.json")))
            # AN EXISTING BUT EMPTY DIRECTORY IS AN EMPTY CATALOGUE, not an
            # error. This used to refuse, which read as a guard against a
            # misconfigured path -- but the guard that actually catches that is
            # the `not a file or directory` refusal below, and a typo rarely
            # lands on a directory that exists. What refusing DID break is
            # uninstalling your last bundle: the files were deleted, the
            # rebuild then failed, and the registry was left empty on disk and
            # stale in memory. `registry list` has always had copy for an empty
            # catalogue; the constructor was contradicting it.
        elif path.is_file():
            files = [(None, path)]
        else:
            raise InvalidAgentManifest(f"{path}: not a file or directory")

        self._by_id: dict[str, AgentResolution] = {}
        # name -> the bundle that already claimed it, so a collision can say
        # WHERE the other one is. "duplicate agent name 'triage'" is a puzzle
        # when two bundles are installed; naming both bundles is the answer.
        names: dict[str, str | None] = {}
        for bundle, f in files:
            try:
                raw = json.loads(f.read_text())
            except json.JSONDecodeError as exc:
                raise InvalidAgentManifest(f"{f}: not valid JSON: {exc}") from exc
            resolution = replace(_parse_manifest(str(f), raw), bundle=bundle)
            if resolution.agent_id in self._by_id:
                held = self._by_id[resolution.agent_id].bundle
                raise InvalidAgentManifest(
                    f"{f}: duplicate agent_id {resolution.agent_id!r}, already "
                    f"held by {_where(held)}")
            if resolution.name in names:
                raise InvalidAgentManifest(
                    f"{f}: duplicate agent name {resolution.name!r}, already "
                    f"held by {_where(names[resolution.name])}")
            self._by_id[resolution.agent_id] = resolution
            names[resolution.name] = bundle

    def resolve(self, agent_id: str) -> AgentResolution:
        try:
            return self._by_id[agent_id]
        except KeyError:
            raise AgentNotFound(agent_id) from None

    def list_agents(self) -> list[AgentResolution]:
        """Convenience for demo setup and inspection. Not part of the harness
        read contract, which is `resolve` alone."""
        return list(self._by_id.values())

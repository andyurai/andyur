# ADR 002: what a token's `aud` names, and why it differs from what MCP asks for

> **SUPERSEDED IN PART — read `docs/authority-architecture.md` first.**
>
> This ADR answers 'which string goes in the `aud` claim of a token Andyur mints
> for a downstream resource'. That question only exists while Andyur issues those
> tokens, and the architecture correction says it must not. The decision is sound
> for the code as it stands and becomes moot when the mint retires. It was written
> AFTER the correction, which is itself the mistake this banner exists to stop.
>
> It is kept because it is TRUE OF THE CODE TODAY, and someone operating or
> debugging the running system needs it. It is not a description of where we are
> going. Do not extend the behaviour it documents.


Status: **accepted 6 Aug 2026 — option B, narrowed.** Implemented. Supersedes nothing.

## Context

Andyur mints a token for exactly one target, and the audience is one of the four
terms in `entitlement AND pin AND ceiling AND audience`. Today an audience is an
opaque string written by an operator in the agent's `mcp.json`:

```json
"ci": { "type": "http", "url": "http://ci.internal:8790/mcp",
        "andyur": { "audience": "tool:ci" } }
```

That value reaches three places: the `aud` claim in the minted token, the per-agent
ceiling in the registry (`audiences: tool:bank`), and the resource server, which
refuses anything whose `aud` is not its own.

Building the resource-server PEP and RFC 9728 discovery surfaced a mismatch that
had been invisible while nothing on the receiving side existed.

**MCP's canonical resource identifier is the server's URL.** The SDK publishes
`{"resource": "http://127.0.0.1:8795/mcp"}` in its protected-resource metadata,
and its `AuthSettings.resource_server_url` is typed `AnyHttpUrl` — it *cannot*
hold `tool:bank`; pydantic rejects it. The MCP authorization spec has a client
send that canonical URL as the `resource` parameter when asking for a token.

So the demo's own tool server currently **publishes one identifier and enforces
another**. Andyur's probe only works because it bypasses discovery and uses the
operator-written value. A spec-following MCP client would request
`resource=http://127.0.0.1:8795/mcp`, receive a token with that `aud`, and be
refused by a PEP expecting `tool:bank`.

**This is not a conformance defect.** RFC 8693 §2.1 defines `audience` as "the
logical name of the target service" and gives non-URI examples; only `resource`
carries the absolute-URI requirement. RFC 8707 §2 explicitly permits an AS to map
a resource URI to "a more general URI **or abstract identifier**". Andyur's `aud`
is conformant. What RFC 8707 §3 adds is the cost: with an abstract identifier
"it is the client's responsibility to validate **out of band** that any network
endpoint to which tokens are sent are the intended audience for that identifier."
Andyur's out-of-band binding is the operator writing the audience next to the URL
in `mcp.json`. That is a real answer, and it is the thing an opaque scheme
obliges you to keep true by hand.

## Decision

**Option B, narrowed to MCP tool audiences.** An MCP tool's audience IS its
canonical resource identifier, derived from the URL the operator already wrote.
The mint stays agnostic — an audience is still just a string to
`tokenexchange.mint`, and the authority demo's `tool:bank` still names a
hypothetical target with no server behind it.

**That narrowing is the one judgement added at implementation time**, and it is
not in the analysis below. Forcing every audience Andyur can issue to be a URL
would have churned the registry, the demo and the runbook for no interoperability
gain, because those targets have no RFC 9728 metadata to agree with. The mismatch
only ever cost something in one place: a tool reached over MCP.

### What it looks like

```json
"bank": { "type": "http", "url": "http://127.0.0.1:8795/mcp",
          "andyur": { "authority": true } }
```

`authority: true` opts the tool in; the audience is derived. Writing
`andyur.audience` explicitly still works when it AGREES with the URL, and is
refused loudly when it does not — the commonest way to hit that is a `tool:ci`
left over from before this ADR, and silently correcting it would be worse than
refusing, because an operator who wrote an audience believes it means something.

Identifiers are canonicalised before comparison (`http://h:80/mcp/` and
`http://h/mcp` are one resource): we ask for this string, the resource declares
it, and a ceiling names it, so trivia must not make one endpoint look like two.

### What it bought, demonstrated rather than argued

A client doing what the MCP spec says now works end to end, which was impossible
before:

```
1. challenge names: http://127.0.0.1:8795/.well-known/oauth-protected-resource/mcp
2. canonical resource id: http://127.0.0.1:8795/mcp
3. minted aud: http://127.0.0.1:8795/mcp
4. the resource ACCEPTED it -> sub=alice act=demo-specialist aud=http://...
```

Discovery also stopped being advisory. It still never *supplies* the audience —
that would let a resource ask to be issued a token for someone else — but it now
**verifies** it: the metadata must declare exactly the identifier we were about
to request, or the tool is withheld. With RFC 9728 §3.3 already forcing the
document to match the URL it was served from, the audience is proven by the
resource rather than asserted by whoever wrote the config.

The demo tool server also stopped contradicting itself. It publishes and enforces
one value, and warns at startup if they are ever configured apart.

### What it cost, as predicted below

A ceiling naming a tool now holds a URL, so a tool that moves host or port
invalidates it. That trade is real. What softens it is that the failure is loud
at mint time (`invalid_target`) rather than silent.

## What running the actor leg against a real AS surfaced (2026-08-07)

`infra/verify-actor-leg.sh` exchanged a real per-run SVID at the reference AS
for the first time, and it exposed an interaction this ADR did not foresee: the
audience-as-URL decision above collides with how an AS derives the PINNED
resource.

The reference AS's `PinOf` reads the resource name from the URL's LAST path
segment (`.../teams/checkout` -> `checkout`), because that is where a
deployment's resource URLs put the thing the run is about. But an MCP tool's
audience, under the decision above, is its endpoint URL — which ends in `/mcp`.
So `PinOf` reduces the audience to `"mcp"`, and a run pinned to team `checkout`
is refused: `user "dana" has no claim to resource "mcp"`. The token never
reaches the tool. Verified live — the AS denied the exchange, correctly by its
own rule, for a reason that is really this mismatch.

The two identifiers a token carries are pulling in opposite directions:

- the **audience** the tool PEP enforces must equal the tool's own URL
  (`AnyHttpUrl`, so `.../mcp`), or the PEP raises `InvalidAudienceError`;
- the **pinned resource** the AS authorizes against is the URL's last segment,
  which for `.../mcp` is `mcp`, not the team.

They can only agree if the tool's resource URL already ENDS in the resource
name — i.e. the tool is served at `.../teams/checkout`, not `.../mcp`, so
audience, PEP and `PinOf` all resolve to `checkout`. The demo tool servers serve
`/mcp`, so they do not, and the actor-leg harness proves the mechanism by
handing the AS a URL whose last segment IS a resource the user holds.

**This is not the actor leg's problem to solve and it is left open here.** It is
the same family as the decision above (what a URL means as an identifier), one
level deeper: not just "opaque vs URL" but "which SLICE of the URL is the
resource". The clean answer is that a tool's resource URL should be its resource
(`.../teams/<team>` served as the MCP endpoint), which makes all three agree and
needs no second mapping — the same shape option B already argues for. The demo
tool servers should move to it before the full AS-backed SRE demo can be green
end to end; tracked with `../ROADMAP.md` gap 8 and the SRE demo plan.

## The analysis, as written before the decision

Three options. None is free.

### A. Keep opaque audiences, and treat the URL as a separate fact

`aud` stays `tool:bank`. Discovery keeps confirming rather than supplying. The
operator's `mcp.json` remains the binding between identifier and endpoint.

- **For:** nothing changes. Ceilings stay readable (`audiences: tool:bank` says
  something to a human; a URL list does not). An audience survives a server
  moving host or port, which a URL does not. Conformant per RFC 8693/8707.
- **Against:** a standard MCP client can never obtain a usable token from Andyur,
  so the audience is only spendable by clients Andyur configures. The out-of-band
  binding is manual and unverified — nothing checks that `tool:bank` really is
  the server at that URL, which is exactly the check RFC 8707 §3 says is now the
  client's job. Discovery can confirm the AS but never the identifier.

### B. Adopt the canonical URL as the audience

`andyur.audience` becomes `http://ci.internal:8790/mcp`, ceilings list URLs,
discovery can then supply the audience because it is verifiable against the
document it came from (RFC 9728 §3.3 already forces that match).

- **For:** interoperable with any MCP client and any RFC 9728 resource. Discovery
  becomes load-bearing rather than advisory. The identifier is self-verifying:
  the resource proves it, rather than an operator asserting it.
- **Against:** touches the registry schema, every ceiling, the authority demo,
  the runbook and the artifact. A tool moving host or port silently invalidates
  every ceiling naming it. Ceilings become much harder to read and review. And a
  URL audience is only as trustworthy as the DNS and network path to it, whereas
  `tool:bank` means whatever the operator says it means.

### C. Carry both — an opaque audience and a resource URL

Mint with `aud: tool:bank` and an RFC 8707 `resource` naming the URL, and have
the PEP accept either. Registry ceilings stay opaque.

- **For:** readable ceilings and standard-client interoperability at once.
  Discovery can verify the URL half without the opaque half moving.
- **Against:** two identifiers for one thing, which is the "one source of truth"
  rule broken deliberately. The mapping has to live somewhere, and whichever
  place holds it becomes a thing that can disagree with itself. Most of the cost
  of B plus a permanent conceptual overhead.

## Recommendation as written at the time (superseded by the decision above)

**B, but not yet.** The interoperability argument gets stronger the moment
anything other than Andyur's own runner talks to these tool servers, and
self-verifying identifiers are worth more than readable ones in a security
control. But B's cost is concentrated in the registry and the ceilings, and the
ceiling is the term with the most careful test coverage in the system — it is not
a thing to change in the same breath as landing a new PEP.

The cheap step that does not prejudge the choice: **make the demo's tool server
publish the identifier it enforces**, so the repo stops shipping a server that
contradicts itself. That is true under A and under B.

## What was true before the change, kept so the reasoning stays legible

- Andyur's `aud` is opaque and operator-written; it is RFC 8693/8707 conformant.
- MCP's canonical resource id is an https URL, and the SDK cannot publish an
  opaque one — `AnyHttpUrl` rejects it.
- The demo tool server publishes `http://127.0.0.1:8795/mcp` and enforces
  `tool:bank`. Only Andyur's own probe works, because it skips discovery.
- Discovery (`ANDYUR_TOOL_DISCOVERY=on`) deliberately never supplies the
  audience, precisely because this is unsettled — a resource naming its own
  identifier could otherwise ask to be issued a token for someone else's.
- RFC 9728 §3.3 already requires the metadata's `resource` to match the URL it
  was served from, and Andyur enforces that. So under option B the identifier
  would arrive already verified.

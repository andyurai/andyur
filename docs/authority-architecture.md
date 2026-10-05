# Where authority comes from, and which parts are ours

> **Egress topology update (2026-08-08):** this document remains authoritative
> for the AS/TTS/PDP/PEP model. Its agentgateway process placement is superseded
> by ADR 003's per-run Andyur sidecar plus shared LiteLLM split.

Decided 6 August 2026, after building the token mint and discovering the design put
one box on the wrong side of the line. This is the reasoning, not just the outcome,
because the outcome looks arbitrary without it.

> ## STATUS: DECIDED, NOT BUILT
>
> **The code does not implement this document.** As of 6 August 2026 Andyur still
> issues audience-bound OAuth access tokens (`typ: at+jwt`), which the section
> "What retires" below says must stop. None of `tctx`, `agentic_ctx`, `purp` or
> `txn` exist anywhere in the codebase, and nothing validates an access token
> arriving from an enterprise AS.
>
> That gap is not an oversight you have just found. It is two days old and it grew
> because this document was read as a description of the system rather than as a
> plan to change it. If you are about to extend `tokenexchange.py`, stop and read
> "What retires" first.
>
> **The migration plan is `authority-architecture.md`, PROPOSED and not yet
> approved.** Nothing should be built against this document until it is. Note the
> plan corrects three things here against draft -11 (this document cites -07):
> `aud` names the TRUST DOMAIN and not a resource, a Txn-Token must never leave
> the trust domain, and the required claim set differs. Anything here that sounds
> like present tense is aspiration.

## The question

Andyur had grown its own authorization server. `tokenexchange.py` minted access
tokens carrying `sub`, `act`, `aud`, a narrowed scope and an
`authorization_details` claim holding the run's pin. It worked, it was well tested,
and it was wrong: **every enterprise brings its own AS**, so a platform that is one
cannot be deployed into an enterprise without fighting it.

The obvious correction, "replace our mint with Keycloak", is also wrong. Keycloak
is itself a placeholder for whatever the customer runs. The requirement is to be
*pluggable against any AS*, which is a different and stricter goal.

That raised the real question: if the AS is always theirs, what is irreducibly
ours? A run's authority depends on facts only the harness knows — which run this
is, who it acts for, which agent, and what the work is about. No external AS can
know those. So something on our side must carry them, and the risk is that
"something" quietly becomes an AS again under a new name.

## The answer, which turned out to be a standard

`draft-ietf-oauth-transaction-tokens` (IETF OAuth WG-adopted, Standards Track)
defines a **Transaction Token Service**: exactly one logical TTS per trust domain,
at its boundary. It validates the access token arriving from the enterprise AS and
issues short-lived signed JWTs carrying *immutable context* for every downstream
hop.

That is the harness. Not an authorization server, a context authority. The
distinction is the whole point:

- signing "alice may transfer on account 447" makes you an AS
- signing "run r-0007 acts for alice, is agent classifier, and is about account
  447" makes you an attestation authority

The first is a decision. The second is a fact about a run, and only we hold it.

The agents extension, `draft-oauth-transaction-tokens-for-agents`, names the claims
we had been hand-designing:

| claim | meaning | what it was in our code |
|---|---|---|
| `sub` | the principal | the run's acting user |
| `act` | the agent performing the action | the delegatee in our `act` chain |
| `tctx` | transaction context, **immutable across the chain** | **the pin** |
| `agentic_ctx` | agent type, version, intent, `allowed_actions` | the agent registry and its **ceiling** |
| `purp` | purpose, for policy evaluation | the run's reason |

Its delegation rule is our multi-agent handoff rule verbatim: on replacement for a
sub-agent, `txn` and `sub` MUST be copied unchanged and `act` MUST NOT be modified.
We derived that independently, which is reassuring about the design and
embarrassing about the reading we did first.

## Why this is the compatible choice as well as the secure one

The TTS pattern asks nothing unusual of the enterprise AS. Their AS issues an
ordinary access token; we validate it and mint the context token. No RAR support,
no custom protocol mapper, no external lookup wired into their token endpoint.

That matters because the alternative was tried and does not survive contact with
real products. Carrying the pin as an RFC 9396 `authorization_details` claim
through a third-party AS requires that AS to support RAR:

- Keycloak: no support, an open discussion, and in some flows it rejects the
  parameter outright
- Curity: experimental, explicitly not for production
- Auth0 and Okta: native support
- Authlete: supported

Adoption outside payments and verifiable credentials is nascent. RAR is a fine
input where it exists and cannot be a requirement.

## Three ways context can travel, and we support all three

**1. Txn-Token `tctx` — the default.** Works against any AS because we mint it.
Signed, immutable across the chain, and present even when every optional piece on
the enterprise side is absent. This is the secure default.

**2. RAR ingest — optional.** Where their AS does emit `authorization_details`, the
TTS folds it into `agentic_ctx`. This is what the draft prescribes, and it makes
richer enterprise policy an input rather than a dependency.

**3. External binding store — optional.** The application owns the session and
decides the pin (the design has always said so: *"entitlement lookup, canonical id,
decides the pin ... all of this is OUTSIDE Andyur"*). Its store is therefore a
**Policy Information Point**, and its attributes reach the decision as AuthZEN
`context`. An earlier flow put this in the application's Redis, which is exactly
right and is the standard home for it.

The three are layered, not alternatives. Andyur carries a reference and its own
context; the enterprise enriches it if it can; the PDP resolves the rest at
decision time.

## Who runs what

| role | who | notes |
|---|---|---|
| Authorization server | **theirs**, any product | issues an ordinary access token, unmodified |
| Transaction Token Service | **ours** | the harness. It already seals the run binding, signs, and publishes JWKS, so the plumbing is reusable. What it signs has to change completely: see "What retires" |
| Egress credential broker | **agentgateway**, Apache 2.0 | per run pod. RFC 8693 exchange + injection |
| PDP | **theirs** | AuthZEN 1.0 (OpenID Final Spec, March 2026); COAZ profile for MCP tools |
| PEP at the tool | **theirs**, on the MCP SDK | the SDK ships `TokenVerifier`, bearer middleware and RFC 9728 metadata |

Only one new process runs: agentgateway, and `toolproxy.py` is deleted.

**No new process is not the same as no new work.** An earlier draft of this
document said "the TTS is a name for what the server already does", and that
sentence did real damage: read alongside the table above it says *rename the box
and carry on*, and two sessions of work then carried on. It is wrong. The TTS
reuses the server's signing key, its JWKS endpoint and its run binding, and
almost nothing else. The claims change, the trigger changes (a TTS mints on
receipt of the enterprise AS's access token, not on an agent's request), and the
audience-bound access token goes away entirely. Same process, different job.

## What survives from the work already done

`registry.narrow` and its four-term intersection survive intact. Their output
changes envelope: `allowed_actions` inside `agentic_ctx`, and the pin as `tctx`,
instead of a custom RFC 9396 `type`. The ceiling, the pin, the never-widening fold
and every test around them keep earning their place.

What retires is the part built most recently: minting *target-audience access
tokens*. That was the AS's job all along.

Concretely, so this cannot be read as a vague direction. These retire:

- the `typ: at+jwt` header and RFC 9068 conformance — that profile is the JWT
  format for OAuth **access tokens**, and issuing one is the act of being an AS
- `aud` naming a downstream resource, and therefore the whole question of which
  string goes in it (`docs/adr-002-audience-identifiers.md` exists only to answer
  that, and dies with it)
- the mint being triggered by an agent asking for a token for a target
- `acting_user` and `ANDYUR_ASSERTED_USER`, added 6 August. They exist because
  Andyur had no authenticated user to put in a `sub` it was signing. A TTS gets
  the `sub` from the enterprise AS's validated access token, so the whole
  question disappears rather than being answered

And these survive, in a new envelope:

- `registry.narrow` and the four-term intersection, as `agentic_ctx.allowed_actions`
- the pin, as `tctx`
- the HMAC run token, which is internal to the harness and never leaves it
- the per-run SPIFFE identity, unchanged

## What is still missing, stated plainly

**`cnf` proof-of-possession.** Every token in this design is a bearer token today.
The audience bounds *where* it can be spent and the pin bounds *what* it touches,
but nothing bounds *who* holds it. Two runs with valid identities in the same
deployment, one holding the other's token, is a real attack: the resource server
sees a valid peer and a valid token and allows it.

It is reachable rather than blocked. agentgateway can present the run's client
certificate to both the AS and the tool. The missing pieces are ours: computing
`cnf.x5t#S256` from the observed leaf certificate, and a PEP that compares it to
the TLS peer and `act.sub` to the peer's SPIFFE ID. The AS also has to sit behind
something that terminates mTLS and reports the peer certificate, which is a
deployment concern and not a thing to hand-roll in uvicorn.

**RFC 9728 discovery.** agentgateway serves protected-resource metadata inbound but
does not consume it on egress. Either we do the 401-then-metadata dance or the
audience stays configuration.

## Sources

- [draft-ietf-oauth-transaction-tokens-07](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-07)
- [draft-oauth-transaction-tokens-for-agents](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/)
- [AuthZEN Authorization API 1.0 final](https://openid.net/authorization-api-1-0-final-specification-approved/)
- [AuthZEN drafts for the agent era, incl. COAZ](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/)
- [Keycloak RAR discussion](https://github.com/keycloak/keycloak/discussions/29340)
- [Keycloak standard token exchange](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)
- [agentgateway](https://github.com/agentgateway/agentgateway)
- [RFC 9396](https://www.rfc-editor.org/info/rfc9396/), [RFC 8693](https://www.rfc-editor.org/info/rfc8693/), [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)

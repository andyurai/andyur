# What you can replace, and what you cannot

Andyur is a framework layer over other people's infrastructure. That is the whole
premise: it does not reimplement an identity provider, a policy engine, a
certificate authority or a proxy, it composes them and owns the seams between.

**The principle, decided 6 August 2026: complete out of the box, and every part
swappable.** Precisely: a feature is off until you turn it on, and turning it on
never leaves you to go and find a component. Andyur starts one for you, and it is
a REAL implementation rather than a stand-in. Someone with none of this
infrastructure gets a working system. Someone who runs their own points at theirs
and drops ours.

"Complete" therefore does not mean everything runs by default. `./run.sh up` still
needs no Docker and no identity provider. It means there is no gap between
"enable the authority features" and "have an authorization server".

That is not a style preference. A stand-in that works becomes load-bearing, stops
looking temporary, and eventually IS the product. Andyur grew its own
authorization server exactly that way (see `docs/authority-architecture.md`), which
is why the default has to be the real thing.

This page is the honest version of that claim. It exists because the promise is
easy to make in a README and expensive to check, and because a reader deciding
whether to adopt needs to know which parts they are committing to.

Every row below is derived from `andyur/config.py` and the code that reads it.
When you change one of those, change this.

## Replaceable today

Most components here are opt-in. Workload authentication and the per-run egress
boundary are mandatory platform controls; the database defaults to embedded
SQLite. Where Andyur can start the component for you, the "Default" column says
so.

| Component | How you point at yours | Default | Verified against |
|---|---|---|---|
| Policy decision point | `ANDYUR_PDP=authzen`, `ANDYUR_PDP_URL` | `builtin`, in-process | OPA behind an AuthZEN shim |
| Identity provider | `ANDYUR_USER_AUTH=on`, `ANDYUR_OIDC_ISSUER` / `_JWKS` / `_AUDIENCE` | off; `./run.sh user-idp` starts ours | Keycloak 26.2 |
| Workload identity | `SPIFFE_ENDPOINT_SOCKET`; `ANDYUR_MTLS=on` also encrypts peer transport | mandatory | SPIRE |
| Per-run egress boundary | Andyur sidecar (lifecycle-owned, not a vendor adapter) | built in | native HTTP/MCP + SPIFFE |
| Shared LLM gateway | native provider base URL via the sidecar | pinned LiteLLM 1.95.0 | Anthropic Messages/SSE + OTLP |
| State store | `ANDYUR_DB_URL` | SQLite file | PostgreSQL |
| Model/provider | manifest model + LiteLLM deployment config | Anthropic through LiteLLM | Anthropic API; Ollama demo mode |
| Tracing backend | `ANDYUR_OTEL_ENDPOINT`; `ANDYUR_OTEL=off` disables | on | Jaeger, over OTLP |
| Memory graph | `ANDYUR_GRAPH`, `ANDYUR_NEO4J_URL` | off | Neo4j |

The PDP interface is the OpenID AuthZEN Authorization API, so any engine that
speaks it works without an Andyur change. The IdP interface is plain OIDC
discovery plus JWKS. Workload identity is the SPIFFE Workload API, so any
conformant implementation substitutes for SPIRE.

### What replacing one costs you

Calls to these components are on Andyur's request path, and Andyur cannot make
them well behaved. Both the PDP and the IdP are reached through
`andyur/boundedhttp.py`, which enforces a TOTAL wall-clock deadline and a size
cap rather than the per-read timeout that `httpx` and `urllib` give you by
default. A component that degrades produces a prompt, logged failure instead of
a stalled request path. The PDP fails CLOSED, so a PDP you cannot reach denies
rather than permits.

## NOT replaceable today

**The authorization server.** This is the significant one, and it is not a design
position. It is a decided change that has not been built.

When it is built, the AS follows the principle above: Keycloak ships as the
default, started by `./run.sh keycloak`, and an adopter points at their own
instead. There will be no Andyur-signs-access-tokens mode to fall back to, in dev
or anywhere else, because the default is a real AS rather than a stand-in.

`docs/authority-architecture.md`, decided 5 August 2026, says the AS is the
adopter's, always, and that Andyur's own token mint must retire. The code has not
followed. Andyur still mints its own delegation tokens: the RFC 8693 exchange
lives in `andyur/server/tokenexchange.py`, signs with Andyur's own key, and
publishes its own JWKS. `ANDYUR_EXCHANGE_ISSUER` renames the issuer string and
nothing more.

So read this row as "not yet", not as "by design". The plan is
`authority-architecture.md`, proposed and awaiting approval.

An adopter who already runs Keycloak, Auth0 or Okta as their AS, and who expects
agent tokens to come from the same place as everything else in their estate,
cannot have that. They would have to trust a second issuer. If your organisation
has a rule that all tokens come from one AS, Andyur does not currently satisfy
it.

### What an adopter's AS can actually carry, measured

Not inferred from vendor documentation. Two harnesses, both asserting a positive
control first: `infra/keycloak/verify-act-delegation.sh` and
`infra/reference-as/verify.sh`, run 7 August 2026.

| | Keycloak 26.7.1 | go-oidc v0.25.0 |
|---|---|---|
| RFC 8693 exchange, `sub` preserved, `aud` rebound | yes | yes |
| RFC 8693 `act` (who acted) | **no** | yes, nested, SPIFFE actor |
| RFC 8707 `resource` | **no** ([#14355](https://github.com/keycloak/keycloak/issues/14355)) | yes |
| RFC 9396 RAR | **no** ([#29340](https://github.com/keycloak/keycloak/discussions/29340)) | yes |
| licence | Apache 2.0 | MIT, OpenID Certified |

Keycloak *does* ship `token-exchange-delegation:v1`, and it works -- it produces
`may_act` in the SUBJECT token. It does not produce `act` in the EXCHANGED token;
that is still open upstream. Configuring it takes a delegation client scope plus
the `impersonation` role, and without both the feature silently does nothing,
which reads exactly like the feature being broken. The harness does all of it.

Entra ID does not speak RFC 8693 at all; its on-behalf-of flow is RFC 7523.

**What this means for an adopter.** Andyur must not require `act` or RAR from the
AS, because the two most widely deployed enterprise IdPs supply neither. Where
they exist they are INGESTED and improve audit; where they do not, attribution
degrades to `azp` (the client, not the run) and the resource constraint is not in
the token at all. Enforcement therefore never depends on either --
`docs/decisions.md` O1 puts it at the gateway and the adopter's PDP.

`infra/reference-as/` exists so the full design can still be demonstrated end to
end. It is the reference AS for the test suite and **not a production
recommendation**; Andyur does not depend on it.

Even there, RAR is a carrier and not a control: the AS allow-lists the RAR type
and refuses an unregistered one, but carries whatever CONTENT the client asks
for, including `identifier: "*"`. Narrowing is Andyur's job before it asks.

**The policy enforcement point.** `demos/authority-tool/pep.py` is worked
example code that verifies an Andyur-minted token and checks action, audience and
pin. It is meant to be copied into your resource server and adapted. It is not a
published library, and it is not versioned. The demos share it through
`sys.path`, which is a demo convenience and not a pattern to copy.

**The ceiling and pin model.** What an agent may ever do, and what a run is
bound to, are Andyur's own concepts stored in Andyur's own tables. There is no
interface for holding them somewhere else. This is deliberate -- it is the part
Andyur is actually for -- but it is worth being explicit that it is not
pluggable.

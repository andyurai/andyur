# The reference authorization server

A standards-complete OAuth authorization server, used **only by the test suite**,
to prove that Andyur's authority design is implementable against a real AS.

It is built on [go-oidc](https://github.com/luikyv/go-oidc) v0.25.0 (MIT, OpenID
Certified). **This is not a production recommendation and Andyur does not depend
on it.** Nothing in `andyur/` imports it.

## Why it exists

`docs/decisions.md` #5 says the delegated token carries `sub` = the user and
`act` = the run, and O1 discusses carrying the resource constraint as RFC 9396.

Keycloak can do none of that (`infra/keycloak/verify-act-delegation.sh` proves
it, with a positive control). Without a server that can, there is no way to
demonstrate the design end to end, and worse, no way to tell a flaw in the design
apart from a limitation of one product. That distinction cost several sessions.

So: two servers, two roles.

| | role | what it proves |
|---|---|---|
| `infra/reference-as` | the ceiling | the design works, fully, against a conformant AS |
| `infra/keycloak` | the floor | how it degrades against what enterprises actually run |

Both belong in CI. A change that breaks either is a real regression: the first
means the design stopped being implementable, the second means Andyur started
requiring something most adopters cannot give it.

## Run it

    ./verify.sh          # builds, starts, asserts the matrix, tears down

Or start it alone:

    ANDYUR_REFAS_ADDR=:8099 go run .

The disposable ADR-007 sender-binding gate additionally sets a paired
`ANDYUR_REFAS_TLS_CERT` / `ANDYUR_REFAS_TLS_KEY` and
`ANDYUR_REFAS_DPOP_REQUIRED=1`. The first pair serves HTTPS directly; setting
only one is a startup error. The latter makes every token issuance require a
valid DPoP proof. These switches define a reference conformance profile; they
do not turn this fixture into a production AS.

Clients: `client_one` / `gateway-secret` (confidential, does the exchange) and
`andyur-cli` (public, PKCE only, loopback redirect). Users are seeded from
`ANDYUR_REFAS_USERS` as `name:password,...`, defaulting to `alice` and `bob`.

Loopback redirects are a fixed candidate list (127.0.0.1:8765-8769) because this
AS matches `redirect_uri` EXACTLY and does not implement the variable-port
allowance RFC 8252 sec 7.3 grants loopback clients. Exact matching is the
stricter behaviour, so this is a CLI constraint rather than a weakness.

## What it demonstrates, and one thing it deliberately does not

Verified 7 August 2026, `verify.sh`, 20 checks:

- **A real interactive login**: authorization code + PKCE against a login form
  this AS serves. Wrong password refused without naming which field; `state`
  echoed; the same code replayed WITHOUT the verifier refused 400. No password
  grant (RFC 9700 sec 2.4 forbids it) and no jwt-bearer fixture.
  **Andyur never renders a password box.** `andyur auth login` is an ordinary
  OIDC client, so standalone opens this page and an enterprise opens Okta's,
  with no different code path on Andyur's side.
- **RFC 8693** `act`, **nested**, actor = the run's SPIFFE id. A missing
  `actor_token` is refused with 400, because without it the token asserts the
  user acted directly, which is impersonation.
- **RFC 8707** `resource` becoming `aud`. Unregistered target refused 400.
- **RFC 9396** the pin as `authorization_details`. Unregistered type refused 400.
- **RFC 9449** DPoP putting `cnf.jkt` in the token, asserted to be the
  thumbprint of the presenting key, with a no-proof-no-cnf control beside it.
- all of them **in a single token**.

It also emits `typ: at+jwt` natively and signs RS256, so
`demos/authority-tool/pep.py` validates its tokens unmodified. Keycloak needs a
client attribute set before it will do the first of those (gap G8).

The exchange callback in `main.go` deliberately **does not narrow**. That is not
an oversight; it is the point of the last assertion in `verify.sh`. Ask for
`identifier: "*"` and the AS carries it, because a token exchange has no prior
granted set to compare against. The AS allow-lists the RAR *type*, never its
*content*.

In a real deployment that callback is where Andyur's four-term intersection
lives — entitlement AND ceiling AND scope AND pin, refusing when empty. The AS
carries the answer; it does not compute it. Which is why `docs/decisions.md` O1
enforces the pin at the gateway and the adopter's PDP rather than trusting the
token to bound it.

## Caveat worth keeping

`main.go` imports upstream's `examples/authutil` for its embedded test keypair
and client fixtures, so the client id must be one upstream ships (`client_one`).
That is fine for a fixture and would not be fine for anything else.

## The local go-oidc patch

`patches/` carries an authored patch and an apply script; the generated tree is
gitignored, because a copy of somebody else's repository does not belong in this
history. Run `./patches/apply.sh` once and `go.mod`'s `replace` picks it up.

It adds two fields to `TokenExchangeRequest` that are already parsed and simply
not passed through. Without them the exchange handler -- the ONLY place that
knows the subject, since it is what resolves the subject token -- cannot see the
requested scope or `authorization_details`, because both are validated before it
runs. A subject-aware policy over either therefore has nowhere to live.

Filed upstream: `patches/UPSTREAM-ISSUE.md`, with the line-numbered ordering
evidence. When it merges, delete `patches/` and the `replace` line.

## Where the ceiling comes from, and the limit that creates

An agent's ceiling is **registry data**. `andyur/server/registry.py` says so in its
first paragraph: *"The agent registry ceiling ... This module owns it:
`agents.ceiling_actions` / `agents.ceiling_audiences`."* An agent's ceiling is
defined when the agent is defined, so this server READS it rather than keeping a
parallel copy that drifts.

    ANDYUR_REFAS_REGISTRY_URL=http://localhost:8080 \
    ANDYUR_REFAS_REGISTRY_TOKEN=... \
      go run .            # ceilings from GET /agents/{name}/ceiling

Unset, it falls back to `data/ceilings.json`, which is the right choice for an
adopter who does not want this server depending on the harness.

The split:

| fact | owner | why |
|---|---|---|
| agent ceilings | Andyur's agent registry | Andyur is where agents exist |
| user entitlements | this server's store | the enterprise's directory; Andyur has no business holding it |
| the run's pin and scope | Andyur | facts no authorization server can know |

**The limit, so it is not overstated.** When the ceiling is fetched FROM Andyur,
this server's refusal is a second opinion against a BUGGY Andyur -- not a
containment boundary against a COMPROMISED one, which would simply serve the
bound it is about to be judged against. In the current threat model the harness
is trusted and the agent is not, so that is the right trade. An adopter who does
not trust the harness configures static ceilings here instead.

Two things fail CLOSED rather than open, both deliberately: a registry that
cannot be reached denies (a stale cache is not served, because a ceiling may have
been TIGHTENED while it was unreachable), and an agent whose registry ceiling is
NULL is denied rather than treated as unlimited.

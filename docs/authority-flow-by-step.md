# The authority flow

What must hold at each step, against the specifications that govern it.

The IETF and OpenID specifications are the authority. Where a requirement is a
design choice rather than a protocol requirement, its source is named inline so a
reader can tell the two apart. A claim with no citation does not belong here.

Current behaviour and the distance from it live in `authority-flow-by-step.md`.

A step marked *not specified* means the requirement has not been written, not that
the current behaviour is correct.

| # | step | status |
|---|---|---|
| 1 | The authorization server authenticates the user and issues a token | specified |
| 2 | The application calls the harness | validation specified; the rest not |
| 3 | The harness establishes the run's context | not specified |
| 4 | The agent calls a tool inside the trust domain | not specified |
| 5 | The agent calls a tool outside it | not specified |
| 6 | The tool authorizes the call | not specified |

---

# Step 1 — the authorization server authenticates the user and issues a token

Alice authenticates and a token exists. The step ends there. Validating that token
is step 2.

## Components

| component | role | supplied by |
|---|---|---|
| Alice | resource owner | the enterprise |
| Browser | front channel; receives the login token | the enterprise |
| Chat gateway | OAuth client, OIDC relying party, audience of the login token | undecided, D2 |
| Authorization server | OIDC provider | the enterprise |
| Session store | holds the resource constraint | the application |

The harness, the agents, the tools and SPIRE take no part. The login token's
audience makes it unspendable at a tool.

## Protocols

| spec | status | governs |
|---|---|---|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | Proposed Std | the authorization code grant, the token endpoint |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | Proposed Std | PKCE |
| [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) | BCP 240 | §2.1.1 code injection, §2.1.2 implicit, §2.2.1 sender-constraining, §2.4 ROPC |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Final | authentication, the ID token, §3.1.2.1 request parameters |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Final | how the client finds the endpoints |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | Proposed Std | the token format |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | Proposed Std | the signature |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | Proposed Std | what an access token must carry: `typ: at+jwt` §2.1, claims §2.2 |
| [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) + [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) / [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | Proposed Std | binding `cnf` at issuance |
| [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | Proposed Std | the `resource` parameter, by which a client asks for a specific `aud` |

None of these are an IETF Internet Standard; "Proposed Standard" is the correct
status label.

## The grant

Authorization Code with PKCE.

RFC 9700 §2.1.1: clients MUST prevent authorization code injection by one of three
options; public clients MUST use PKCE, confidential clients RECOMMENDED. §2.1.2:
the implicit grant SHOULD NOT be used. §2.2.1: servers SHOULD sender-constrain
access tokens. §2.4: the resource owner password credentials grant MUST NOT be
used.

### Authorization request parameters

[OIDC Core §3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html).

| parameter | requirement |
|---|---|
| `scope`, including `openid` | REQUIRED |
| `response_type` = `code` | REQUIRED |
| `client_id` | REQUIRED |
| `redirect_uri` | REQUIRED |
| `state` | RECOMMENDED |
| `nonce` | OPTIONAL |
| `code_challenge`, `code_challenge_method` | MUST for a public client |
| `resource` | MAY, RFC 8707 |
| `max_age`, `acr_values`, `prompt`, `login_hint`, `ui_locales`, `display`, `id_token_hint`, `response_mode` | OPTIONAL |

## The login token

Design source: `Agent_Identity_Token_Flow` p.8.

```
sub     alice@corp
aud     ads-gateway
scope   ads.read ads.write billing.read
exp     +3600
cnf     gateway key
```

| claim | requirement | purpose (design, p.9) |
|---|---|---|
| `sub` | the authenticated principal | "Unchanged across every hop. The root principal never drifts." |
| `aud` | the gateway, and nothing else | "Makes a misdirected token useless. Structural, not policy. The answer to 'how do you stop the raw user token being spent at a tool.'" |
| `scope` | the user's rights, unnarrowed | narrowing happens at the exchange |
| `exp` | one hour | |
| `cnf` | bound to the gateway's key | "Holder-of-key, not bearer. Steal it and you still cannot spend it." |
| `act` | absent | no delegation has occurred |
| the resource constraint | absent | chosen after authentication, so it cannot be in this token |

The authorization server MUST emit `typ: at+jwt` on access tokens (RFC 9068 §2.1)
and MUST include `iss`, `exp`, `aud`, `sub`, `client_id`, `iat` and `jti` (§2.2).

Explicit typing is the specified way to tell an access token from an ID token.
[RFC 9068 §5](https://datatracker.ietf.org/doc/html/rfc9068): "The explicit typing
required in this profile ... helps the resource server to distinguish between JWT
access tokens and OpenID Connect ID Tokens."

### The resource constraint

What the work is *about*: an account, a tenant, a customer, a case, a repository.
The design's examples use an account because its scenario is advertising; the
concept is the deployment's unit of work, named per deployment. **It may be absent
entirely**, for a deployment with no such dimension.

Three requirements, whatever it is called:

- It is chosen **after** authentication, so it MUST NOT appear in the login token.
- It lives in **server-side session state**. It MUST NOT appear in the prompt, in a
  tool argument alone, or in agent memory (design, p.9) — each of those is
  something an injected agent can rewrite.
- Changing it MUST produce a new session, a new spawn, a new exchange and a new
  token. It is never widened, so switching is an audited boundary rather than
  state drift inside the agent.

Where a deployment has no resource constraint, that MUST be distinguishable from a
run that lost one. "This deployment does not constrain by resource" and "this run
is missing its constraint" are different facts and cannot share a representation,
because the second is a defect and the first is not.

## Audit

Session start is a logged event carrying the session, the user, the pinned
resource and the surface (design, p.10). The conversation's log schema carries `trace_id`
(one per conversation), `session_id` (one per pinned session) and
`principal`. One trace per conversation.

---

# Step 2 — the application calls the harness

The holder of the login token calls the harness on Alice's behalf. Only the
validation half is specified; the exchange half depends on D1.

## Protocols

| spec | status | governs |
|---|---|---|
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Proposed Std | `Authorization: Bearer`, `WWW-Authenticate`, `invalid_token` |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | Proposed Std | reading the key set |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Final | `jwks_uri`, REQUIRED in §3 |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | Proposed Std | §4, how a resource server validates |
| [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | Proposed Std | the exchange, once D1 is settled |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Proposed Std | revocation checking |

## Validating a received token

A consumer MUST:

1. Fetch `jwks_uri` from OIDC Discovery at
   `<issuer>/.well-known/openid-configuration`. It MUST NOT be constructed.
2. Verify the `typ` header is `at+jwt` or `application/at+jwt`.
3. Verify the signature per RFC 7515, rejecting `alg: none` and any symmetric
   algorithm.
4. Match `iss` exactly against the configured authorization server.
5. Verify `aud` contains an identifier the consumer expects for itself.
6. Verify the current time precedes `exp`.
7. Require `sub`.
8. Return `invalid_token` with a `WWW-Authenticate` header on any failure
   (RFC 6750 §3.1).

`iss` and `aud` validation MUST NOT be conditional on configuration being present.
A deployment with user authentication enabled and either value unconfigured MUST
refuse to start.

`sub` is unique only within an issuer and MUST be stored qualified by it.

Unknown `kid` values MUST NOT drive an unbounded number of outbound key-set
fetches. A bounded negative cache is required.

RFC 9068 §4 has no subsections and its requirements are an unordered list. OIDC
Core §3.1.3.7 is thirteen steps for an ID token at a client; step 6 permits TLS
server validation in place of signature checking where the token came directly
from the token endpoint.

Forwarding a received token unchanged to a downstream service is forbidden. The
holder exchanges it for one bound to the next audience.

## Not yet specified

What the harness receives beyond the token: the resource constraint, the intent, which agent
to run. How a session maps to a run. Whether the exchange happens here or later,
which is D1.

---

# Steps 3 to 6

Not specified.

---

# Open decisions

**Settled before reading D1: who SIGNS is not open.** The authorization server is
the adopter's, always; Andyur is a client of it and never signs an access token
(`docs/decisions.md` #1). D1 is only about which of *our* components speaks to
their AS.

**D1. Which component presents the exchange -- the agent, or the proxy beside
it.** Every hop is an RFC 8693 exchange at the adopter's AS, each presenter
offering what it holds as `subject_token` and its own SVID as `actor_token`, so
`act` nests and records the chain. The fork is who performs that call.

`docs/decisions.md` #3 says the agent does, presenting its run SVID. The Kagenti /
Red Hat reference does the opposite: **AuthBridge**, an Envoy sidecar, performs the
exchange via an ext-proc filter on both the inbound and the outbound leg, and
["the agent-service code doesn't perform token exchange -- Envoy handles it
transparently"](https://next.redhat.com/2026/06/10/wiring-zero-trust-identity-for-ai-agents-spiffe-token-exchange-and-kagenti/).

What the fork decides: whether a compromised agent can request tokens on its own
behalf. If the proxy presents, the agent never holds a `subject_token` and never
speaks to the AS. agentgateway already occupies AuthBridge's position in our
architecture.

The standard rule is that the party holding the token performs the exchange, and
forwarding an inbound token unchanged to a downstream service is the confused
deputy pattern the MCP authorization specification forbids.

**D2. Whether the chat gateway is shipped or supplied.** The design places it in
the request path rather than the control plane, which suggests the adopter's
application; p.10 makes it an emitter into the platform's log plane and p.8 makes
it the holder of session state the exchange depends on, which suggests otherwise.

**D3. Who holds the refresh token, and for how long.**

**D4. `cnf` via mTLS (RFC 8705) or DPoP (RFC 9449).** DPoP requires no change to
TLS termination; mTLS composes with the SPIFFE identity already present.

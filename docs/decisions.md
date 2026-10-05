# Decided

Read this before touching identity, authority or tokens. These are settled. Do not
re-derive them, do not re-open them, do not "discover" them.

Source: `Agent_Identity_Token_Flow` (28 July 2026), confirmed by
`docs/authority-architecture.md` (5 August 2026).

1. **Andyur is not an authorization server.** The AS is the enterprise's, always.
   Andyur asks it to mint; Andyur does not sign access tokens.

   **CLOSED. This one has been re-opened more than any other, so it gets a fence.**
   Decided 28 July in the artifact, re-decided 5 August in
   `docs/authority-architecture.md`, and "discovered" as an open question at least
   twice since, costing a session each time. It does not need an ADR.

   Anything that looks like this question is one of two things, and neither is a
   decision to make:
   - *the code still mints* -- implementation drift. `tokenexchange.py` signs
     `at+jwt` today. Tracked in `../ROADMAP.md` #8 and
     `docs/replaceable-components.md`. Fixing it is work, not a debate.
   - *which of our components talks to their AS* -- that is the fork under #3
     below, and it is a much smaller question than this one.

   Confirmed against the reference implementation: Keycloak IS the STS in the
   Kagenti / Red Hat pattern, and only the STS mints tokens for agents.

2. **Two credentials, two jobs.** The SVID says *what is running* and is earned by
   attestation at spawn. The delegated token says *who it is acting for* and is
   minted per target service.

3. **The PROXY obtains the delegated token, not the agent.** agentgateway,
   per run, presents the run's SVID as the RFC 8693 `actor_token` and the run's
   stored token as `subject_token`. **The agent never speaks to the authorization
   server and holds neither credential.**

   Every hop is an exchange at their AS: the presenter offers what it holds as
   `subject_token` and its own SVID as `actor_token`, so `act` nests and records
   the chain. `sub` never drifts.

   **DECIDED 7 August 2026, replacing "the agent obtains its own".** Revisited
   once, as this entry required, and closed. Four independent reasons, all
   pointing the same way:

   - The reference implementation does it this way. Kagenti's **AuthBridge**, an
     Envoy sidecar, performs the exchange on both legs, and
     ["the agent-service code doesn't perform token exchange -- Envoy handles it
     transparently"](https://next.redhat.com/2026/06/10/wiring-zero-trust-identity-for-ai-agents-spiffe-token-exchange-and-kagenti/).
   - agentgateway already sits where AuthBridge sits, and `gateway.py:711-722`
     already writes `backendAuth.oauthTokenExchange` into the per-run config.
   - The control plane CANNOT do it. The `actor_token` is the run's JWT-SVID,
     which lives in the run's container. `tokenexchange.mint()` has no access to
     it and should not.
   - `cnf` binds per-run only if the per-run proxy presents the proof. That is
     the answer to O2 falling out of this decision rather than being chosen
     separately.

   **What follows, so it is not re-derived:** the four-term intersection still
   runs in Andyur, at gateway-config time, and its result lands in the per-run
   agentgateway config as scope, resource and `authorization_details`. The agent
   cannot alter any of it because it never sees the config. For a deployment with
   an external AS, `tokenexchange.mint()` is not called at all, which is what
   makes the local signer deletable rather than a second mode to maintain.

4. **The login token** carries `aud` = the gateway, no resource constraint, and
   `cnf` bound to the gateway key. It is not spendable at a tool.

5. **The delegated token** carries `sub` = the user, `act` = the run, `aud` = one
   target service, a narrowed scope, the resource constraint, five minutes, and
   `cnf` bound to the agent key.

   **Achievable, but not against every AS. Measured 7 August 2026.**

   | | Keycloak 26.7.1 | go-oidc v0.25.0 |
   |---|---|---|
   | `act` in the exchanged token | **absent** | **present, nested** |
   | actor as a SPIFFE id | n/a | yes |
   | `aud` rebound to the target | yes | yes (RFC 8707) |
   | resource constraint as RFC 9396 | no | yes |

   Reproduce: `infra/keycloak/verify-act-delegation.sh` and
   `infra/reference-as/verify.sh`. Both assert a positive control first, because
   a refusal proves nothing on its own.

   Keycloak's `token-exchange-delegation:v1` produces **`may_act`** (who MAY act)
   in the SUBJECT token. Emitting `act` in the EXCHANGED token is a different
   thing and is still open upstream:
   [#12076](https://github.com/keycloak/keycloak/issues/12076),
   [#38279](https://github.com/keycloak/keycloak/issues/38279). Against Keycloak
   the only trace of the acting party is `azp`, which names the OAuth **client**,
   not the run. Kagenti lives with this: their identity guide shows an `act`
   claim, and their charts ship no mapper that could produce one.

   So this decision holds where the AS supports it and degrades to agent-level
   attribution where it does not. The run's identity is therefore not safe to
   rely on from the token alone, which is one more reason O2 matters: `cnf` bound
   to the per-run SVID is what PROVES the run rather than asserting it.

6. **The resource constraint** lives in server-side session state. Never the
   prompt, never a tool argument alone, never agent memory. Changing it makes a
   new session, a new spawn, a new exchange and a new token. It is never widened.
   It may be absent for a deployment that has no such dimension.

7. **The harness owns control.** Agents never hand off to each other. The harness
   updates control, so enforcement and audit happen at one chokepoint.

8. **Identity is scoped to the run**, not to the user. The user lives in `sub` and
   `act`, never in the SPIFFE ID.

9. **A stock OSS agent may reach a third party, and never holds the credential
   for it.** Decided 2026-08-26 after the question was asked of the `exec/v1`
   lane and found to have no recorded answer. Reach is a property of a binding
   an approver accepted, never of the image and never of the input: undeclared
   reach stays impossible by construction (no DNS, one egress peer), declared
   reach goes through the run's OWN sidecar, which holds the leased credential
   and signs or injects at the boundary, and out through an egress gateway that
   authenticates the caller and enforces the grant but NEVER holds a vendor
   credential. One custodian, scoped to one run. A shared component holding
   every binding's credential would be a single blast radius and is refused. "The workload cannot reach
   anything" is not the decision and never was; it is what the surface happened
   to do before anyone chose. ADR-011 D11 states the position, ADR-013 builds
   it, ADR-012 gates it.

---

# Open

**Two genuinely open: O3 (revocation) and O5 (switching the pin in standalone).**

O1, O2 and O4's shape are ANSWERED and kept below with their reasoning, because a
decision without its rejected alternatives gets re-opened -- that is the failure
this file exists to stop. If something feels open and is not on this list, it is
on the Decided list above instead.

Quick index:

| | question | state |
|---|---|---|
| O1 | where the pin is enforced | ANSWERED: the PDP at tool-invoke, gateway as PEP |
| O2 | `cnf` binding | ANSWERED: DPoP inside the trust domain, mTLS at the edge |
| O3 | revocation | **OPEN** |
| O4 | per-user entitlements | shape settled; where they are read from is open |
| O5 | switching the pin in standalone | **OPEN** |

**O1. ANSWERED, 6 August 2026. The pin is not carried in a token. It is decided by
the PDP at tool-invoke time, with agentgateway as the PEP.**

The question was asked for four sessions as "how does the pin get INTO the
delegated token". That framing is the trap: it assumes the constraint must be
carried, which makes the adopter's authorization server responsible for a fact
only the harness holds. The third option already listed below was the answer.

## The decision

```
agent calls a tool
  -> agentgateway extracts {action, resource} from the call
  -> AuthZEN request to THEIR PDP:
        subject  = sub (the user), act (the run)
        action   = the tool action
        resource = what this call actually touches
        context  = { pin: sealed on the run,
                     authorization_details: their RAR, when present }
  -> the PDP decides; the gateway enforces the answer and refuses otherwise
```

Three properties this has and the carrying options do not: it needs **no change to
the adopter's authorization server**, it puts the policy in **their** PDP rather
than in our code, and it is evaluated at the only moment the answer can be known.

**RAR is an input, never a requirement.** Where their AS emits
`authorization_details` (Auth0, Okta, Authlete) it is ingested into `context` and
the tool can independently enforce it as well. Where it does not (Keycloak, and
most), the run record supplies the constraint and enforcement is single-point.

## Why not the alternatives

- **RFC 8707 `resource` + a protocol mapper.** Does not work. Keycloak discards the
  parameter before any mapper sees it -- ["cannot currently recognize the resource
  parameter"](https://github.com/keycloak/keycloak/issues/14355),
  [PR #35711](https://github.com/keycloak/keycloak/pull/35711) open,
  [#41526](https://github.com/keycloak/keycloak/issues/41526) filed because MCP
  clients send it and it is dropped. Their documented workaround is to use `scope`.
- **A custom `TokenExchangeProvider` SPI for true RAR.** Works, and is roughly 80
  lines -- *per AS product*, written by us, deployed inside the adopter's identity
  infrastructure. That breaks the one promise this architecture exists to keep.
  Filed as a track only if an adopter demands spec-pure RAR and runs Keycloak.
- **Structured scope** (`payments:read:account:447`). Portable and it is Keycloak's
  own documented workaround, but it is a naming convention, not a mechanism, and it
  makes every tool author responsible for parsing it correctly. Available opt-in as
  an audit carrier so the adopter's SIEM sees the pin. Never the enforcement point.
- **An Andyur-signed context token beside the AS's token.** Portable, and it makes
  Andyur sign a fact about a run that crosses a boundary. Closed by #1.
- **Enforcing the comparison in Andyur rather than asking the PDP.** Rejected for
  the same reason as #1 one layer down: we are not the policy author.

## What this forces, and it is not optional

**A PDP call site that does not exist today.** The PDP is currently consulted at
run creation (`_grant_scope`, `app.py:920`), where the specific call has not
happened and the resource is unknown. The pin cannot be enforced there by any
design. Tool-invoke is the only moment it can be.

**The gateway must know which argument of which tool names the resource.** A
declared per-tool mapping, written once by the adopter, in our configuration and
not in their IdP. When a run is pinned and the mapping is absent, the gateway
**withholds the tool** rather than passing the call through.

**O2 is load-bearing, not deferred.** Without RAR the tool cannot check the pin
itself, so a token replayed *directly* at the tool, around our gateway, carries
`sub`/`act`/`aud`/`scope` and nothing about the pinned resource. RAR narrows that
gap; only `cnf` closes it. Decide O2 knowing this depends on it.

## Tested afterwards, and it CONFIRMS the decision

Measured 7 August 2026 against go-oidc v0.25.0, the most capable AS found
(`infra/reference-as/verify.sh`). RAR through a token exchange behaves like this:

| asked for | result |
|---|---|
| the honest pin, `identifier: 447` | carried |
| an unregistered RAR *type* | **refused**, 400 `invalid_authorization_details` |
| an unregistered *resource* | **refused**, 400 `invalid_target` |
| a different account, `identifier: 999` | **carried** |
| a broader action, `["read","transfer"]` | **carried** |
| `identifier: "*", actions: ["*"]` | **carried** |

**RAR is a carrier, not a control.** The AS allow-lists the TYPE and never the
CONTENT, because a token exchange has no prior granted set to narrow against. So
even against the best available AS, the pin's content is not enforced by the AS.

That is the whole argument for this decision, now measured rather than reasoned:
carrying the pin buys audit visibility in the adopter's plane and lets a tool
check independently, and it never buys enforcement. Narrowing has to happen in
Andyur's four-term intersection before it asks, and enforcement at the gateway
and the PDP.

Note the shape: a token can legitimately carry `actions: ["*"]`. A PEP that reads
absent or wildcard as permissive has the same fail-open defect as
`../ROADMAP.md` #1, now reachable through a fully
standards-compliant path.

## For the record

No reference implementation carries an object-level constraint. The Kagenti /
Red Hat intersection is over *departments*, which is role-shaped and coarse; the
Red Hat articles, the protocol-explorer agent-auth flow and the WIMSE drafts were
all checked and none carries one. Nothing was available to borrow, which is why
this took four sessions -- and why the answer had to be designed rather than found.

**O5. How the pin is switched in STANDALONE, where it rides in the login token.**

Standalone has no application session, so the login IS the session and the pin is
chosen there as an RFC 8707 `resource`. That is stronger than the alternative --
a pin in the token is attested by the authorization server, where a pin in the
trigger body is asserted by whoever called the trigger.

What is open is only what happens when the user switches. Today it means logging
in again, because the pin is bound into the credential. That is normal for a CLI
(`aws sso login` behaves the same way), and it may not be the right answer here:
the run may be the better unit, with the pin attached to a run identity rather
than to a stored credential.

Do NOT re-derive the part that is settled: with an application in front, the pin
is chosen after authentication in that application's session and does not belong
in the login token at all (`docs/authority-flow-by-step.md`, step 1). This
question is about standalone only.

**O2. ANSWERED, 7 August 2026. BOTH, split by trust boundary: DPoP inside the
Andyur trust domain, mTLS at the edge.**

Not either/or. The two mechanisms prove the same thing at different layers, and
each is the only one that works where it is used.

```
chat-app --DPoP--> Andyur --DPoP--> run r-7
                                       |
                                       +--mTLS (via agentgateway)--> ads-api
                                                                     telemetry.internal
```

So **T0, T1 and T2 are DPoP-bound** (`cnf.jkt`) and **T3, the token that reaches
the tool, is mTLS-bound** (`cnf.x5t#S256`) after agentgateway re-binds it.

## Inside the trust domain: DPoP (RFC 9449)

chat-app to Andyur, and Andyur to the run.

- Public clients, no certificates, fast rotation.
- The token carries `cnf: {jkt: <thumbprint of the DPoP key>}`.
- **Every hop presents a NEW proof**, bound to `htm` and `htu`, so a proof
  captured on one request cannot be replayed on another.
- The authorization server validates `cnf` and the DPoP nonce.
- Works on localhost with no PKI at all, which is what makes the standalone path
  and the CLI possible.

Proof of key possession at the APPLICATION layer. It can run in a browser, in a
CLI, and in Python without certificates.

## At the edge: mTLS (RFC 8705)

Andyur to agentgateway to an external tool. **Required the moment you leave your
SPIFFE trust bundle.**

- Confidential clients, SPIFFE SVID certificates.
- The token carries `cnf: {x5t#S256: <certificate thumbprint>}`.
- agentgateway terminates mTLS and forwards the token together with the client
  certificate.
- The resource server validates that the token's `cnf` matches the mTLS client
  certificate it actually sees.

Proof at the TLS layer. It needs SPIRE-issued certificates and only works
service to service, and in exchange it gives a hardware-bound guarantee across
domains.

## Both halves are already demonstrated

- DPoP producing `cnf.jkt`: asserted in `infra/reference-as/verify.sh`, with a
  no-proof-no-cnf control beside it, and the thumbprint checked against the
  presenting key.
- mTLS: agentgateway presents a client certificate to a backend through its TLS
  policies.

## A correction, so the reasoning is not re-run

An earlier version of this entry recorded the answer as "mTLS", on the grounds
that agentgateway 1.4.1 has **zero** DPoP support anywhere in its crate tree.
That fact is true and was verified against the pinned tag. It is also about the
wrong leg: agentgateway sits at the EDGE, which is exactly where mTLS belongs.
DPoP is used INSIDE the trust domain, where Andyur's own code makes the proof and
agentgateway is not involved.

The other recorded objection -- that transport binding dies at the first TLS
termination and would bind to the gateway rather than the run -- was written for
a SHARED gateway. Andyur runs one agentgateway per run, so a per-run client
certificate binds per run.

Also found while checking: agentgateway's `actor_token` spec carries
`enforce_may_act`, so it can require the subject token's `may_act` claim to
authorize the actor before it will exchange at all.

**O3. Revocation.** Not mentioned in the design, and not addressed by any of the
four external sources checked. A run carries one validation for
up to six hours while minting downstream tokens throughout, so the exposure is the
run's lifetime rather than the token's.

**O4. Per-user entitlements.** Not mentioned in the design. Today entitlements
come from one global variable applied to every user, so the user identity path
gives audit attribution rather than access control.

The shape is settled by the reference implementation, which names it the
**permission intersection pattern**: "an agent's effective permissions are the
intersection of the user's permissions and the agent's own capabilities. Agents
can only reduce your access, never expand it"
([source](https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/)).
That is our entitlement ∩ ceiling. What remains open is only where per-user
permissions are read from, since ours is currently one global value.

---

# Rule

A session that finds a "problem" with anything in **Decided** has misread it. Check
this file and the artifact before writing anything down.

Current behaviour and the distance from it: `authority-flow-by-step.md`.
What must hold, step by step: `docs/authority-flow-by-step.md`.

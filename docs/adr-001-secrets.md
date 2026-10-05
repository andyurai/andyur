# ADR 001: Andyur holds almost no secrets, and does not manage the ones it has

Status: accepted. Supersedes nothing.

## Context

An agent platform looks like it should need a secrets manager. It runs untrusted
code, calls paid APIs, talks to databases, and hands authority between
components. The instinct is to add Vault (or a cloud equivalent) and route
everything through it.

That instinct answers the wrong question first. A secrets manager solves
*distribution*: how a long-lived credential reaches many workloads, rotated and
audited. Before solving distribution, it is worth asking how many long-lived
credentials need to exist at all.

## Decision

**Andyur minimises what a vault would hold, and does not implement secret
management itself.** Three substitutions do the work:

**Attestation instead of stored identity.** The classic bootstrap problem is
secret zero: the credential a workload presents to obtain its other credentials.
Andyur does not store one. SPIRE issues a short-lived SVID based on what a
workload verifiably IS -- its path and uid on a host, its labels as a container.
There is nothing at rest to steal and rotation is automatic. (See
`threat-model.md`.)

**Minting instead of stored authority.** Agents hold no standing credentials.
The control plane mints a per-run token, scoped to one agent and one run, TTL
bound, delivered through the trusted spawn channel and worthless when the run
ends. Delegation works the same way: RFC 8693 mints a short-lived,
audience-bound, never-widening token on demand. Authority that is minted has no
storage problem, because there is nothing at rest to protect.

**Confinement instead of managed distribution** for the one genuinely long-lived
secret, the model provider key. It lives in a single small process (the broker),
which injects it upstream; the agent never holds it. The blast-radius question a
vault answers with policy, Andyur answers with a process boundary.

User credentials are never touched at all: OIDC tokens are validated against the
IdP's published JWKS and discarded. Verification needs public keys only.

## What is left, and where it belongs

A residual set remains, and the production profile refuses to start without real
values for it (`config._secret_problems`):

| Secret | Why it exists |
|---|---|
| `ANDYUR_RUN_TOKEN_SECRET` | HMAC key for run and broker tokens; shared by every replica AND the broker, which verify what the server signs |
| `ANDYUR_EXCHANGE_KEY` | RSA PEM for downstream delegation; shared, or replicas mint tokens only they can validate |
| `ANDYUR_S3_*` | object storage holding every agent's mind |
| `ANDYUR_NEO4J_PASSWORD` | the memory graph |
| `ANDYUR_DB_URL` | credentials inside a connection string |
| the provider API key | held by the broker |

These are operator-level secrets, not agent-level ones, and that distinction is
the point: no agent ever sees any of them.

**A secrets manager is the right home for this list, and Vault sits BEHIND
SPIRE, not instead of it.** Vault's JWT auth method accepts a SPIFFE SVID as the
login, so the attested identity Andyur already issues becomes the credential
that fetches the rest -- and dynamic database credentials remove the DB password
from the list entirely. That composition is deliberate: SPIRE answers "who is
this workload", Vault answers "what may it fetch". They are not competitors, and
a design that treats them as alternatives has usually confused identity with
storage.

## What Andyur will NOT do

Implement its own secret storage, rotation, or encryption at rest. Every
credential above is a standard deployment secret with excellent existing homes
(Vault, cloud secret managers, Kubernetes secrets with a CSI driver). A platform
that writes its own is offering a worse version of a solved problem while
enlarging its own trust boundary.

## Consequences

- Compromising a running agent yields no long-lived credential, because it holds
  none: a scoped run token that dies with the run, and a broker credential
  usable only for inference.
- Compromising the broker yields the provider key. That is the concentration the
  design accepts in exchange for keeping the key out of every agent, and it is
  why the broker authenticates its callers, allowlists upstream paths, and stays
  deliberately small.
- An operator must still manage the residual list properly. Andyur refuses to
  start in production with development defaults or per-process randomness, which
  converts the most common failure (nobody changed `minioadmin`) from a silent
  weakness into a boot error.

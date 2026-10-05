# Curity production-candidate integration

This directory qualifies one exact Curity tenant for Andyur's delegated
authorization route. A provider name is never certification. Production stays
blocked until the signed tenant overlay and every row of
`andyur/server/as-certification-matrix.json` are green.

## Compose versus build

Curity 11.4 supplies RFC 7523 assertion validation, RFC 8693 token exchange,
JWT access-token issuance, DPoP nonce challenges, and `cnf.jkt`. Those protocol
and cryptographic functions remain Curity's responsibility. Andyur's only
custom AS logic is `token-exchange.js`: after Curity has introspected both
tokens, it copies the verified actor subject into the issued token's RFC 8693
`act.sub`. Curity's built-in exchange did not emit that claim in the live
Community 11.4 test.

The script procedure is acceptable for conformance and a demo. For production,
package the same small policy as a versioned Curity Token Procedure Plugin so
it has a build, artifact digest, tests, rollout and rollback. Do not paste an
unversioned script into a production tenant.

`plugin/` is that versioned production replacement. It validates the raw
SPIRE JWT-SVID actor inside Curity's OAuth token-exchange procedure, so the
subject token and actor assertion travel in one RFC 8693 request and no bearer
actor token is minted. The exact issuer, audience, static source-controlled
JWKS, RS256 algorithm, `jti`, `iat`, `exp`, SPIFFE subject form, and a maximum
300-second original lifetime are checked before `act.sub` is issued. Curity's
SDK performs normal subject-token and DPoP processing; jose4j performs JOSE.

Build and unit-test it with:

```sh
docker run --rm -v "$PWD/infra/curity/plugin:/workspace" -w /workspace \
  maven:3.9.11-eclipse-temurin-21 mvn clean package
```

The live single-leg gate is:

```sh
PYTHON=.venv/bin/python bash infra/curity/verify-single-exchange.sh
```

As tested on 2026-08-20, Curity 11.4 Community loads and configures the plugin
but refuses its enforcement point with HTTP 503 and the server-side exact
classification `Feature not allowed: 'token-procedure-plugins'`. Therefore the
Community license is demo-only for this architecture. A trial or paid license
that enables token procedure plugins is a hard prerequisite; the live gate
must then be rerun and must generate its own evidence before this provider can
be certified. The gate always restores the JavaScript procedure and removes
its disposable clients/plugin configuration on either success or failure.

The client side will compose a maintained RFC 9449 implementation. It must own
one non-exported key per run, honor Curity's `use_dpop_nonce` challenge with one
bounded retry, generate a fresh proof for each resource request, and tear the
key down with the run. The disposable code under `sender-binding-spike/` is
evidence, not production code, and must not be imported.

## Required Curity shape

- HTTPS issuer, token endpoint, discovery and JWKS URLs.
- JWT access tokens with a maximum 300-second lifetime.
- Global RFC 7523 asymmetric assertion support restricted to the SPIRE signing
  algorithm and the exact trust-domain bundle.
- A subject client representing the real user/application authorization path.
- A confidential broker client with RFC 7523 assertion and OAuth token exchange
  capabilities. Its assertion trust pins the SPIRE issuer and JWKS.
- DPoP required on the broker client.
- `token-exchange.js` bound only to the demo OAuth token-exchange flow, or the
  versioned plugin bound there for the production candidate.
- Exact audience and scope allowlists; no wildcard audience or scope.

The Community/demo flow is deliberately two-legged:

1. The broker presents the run JWT-SVID as an RFC 7523 JWT bearer assertion.
   Curity validates it and returns a short-lived DPoP-bound actor access token
   whose `sub` is the exact run SPIFFE ID.
2. The broker exchanges the user's access token plus that Curity-issued actor
   token. Curity introspects both, and the procedure emits the final
   DPoP-bound token with exact `sub`, `act.sub`, audience and scope.
3. The resource verifies the access-token signature and claims, then validates
   `cnf.jkt`, proof signature, `ath`, `htm`, external `htu`, freshness and
   single-use `jti` before executing.

Curity's default/JavaScript procedure path expects an actor token it can
introspect, so directly sending a JWT-SVID there must remain a denial. The
production plugin is a separate, explicit profile: it validates that raw
JWT-SVID itself and eliminates leg 1. Community cannot execute that profile.

## Current closure status

The repeatable `verify-rfc7523.sh` gate now proves both issuance legs on live
Curity Community 11.4. It uses disposable JWKS-authenticated clients, accepts a
trusted SPIFFE-shaped RFC 7523 assertion, preserves its exact subject in
`act.sub`, binds the final token to `cnf.jkt`, denies an attacker signature and
wrong audience, removes the exact `act` assignment to turn the live semantic
assertion red, restores it to green, and deletes both clients before emitting
evidence.

The gate also records that Curity's intermediate assertion-grant actor access
token is bearer even when the client requires DPoP. It never leaves the trusted
broker and is immediately consumed, but this residual must be accepted in the
tenant threat model or removed by a versioned assertion token procedure before
certification.

This is not yet production certification: the gate currently uses an ephemeral
test signer rather than the real SPIRE Workload API. The same gate now sends the
real Curity-issued token to a separate HTTPS resource using the production-owned
`andyur.resource_dpop` verifier. The resource executes one positive request and
denies replay, wrong holder, wrong `ath`, method, target, stale proof and future
proof before execution. Replay and `ath` source mutations independently make
their exact regression tests red, then restore green.

The remaining closure starts with a token-procedure-plugin-capable license and
a green `verify-single-exchange.sh`, then integration into the managed resource/Envoy route,
eight-run partition and aggregate-capacity live evidence, non-exporting key
custody in the sidecar, lifecycle, rotation/revocation, Kubernetes composition,
signed overlay and operational TLS configuration.

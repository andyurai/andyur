# Sender-binding reference spike

This directory is the disposable, structurally non-production experiment
authorized by ADR-007. Production packages, manifests, and imports must not
reference it.

Run Phase 1:

```bash
./infra/sender-binding-spike/verify.sh
```

The gate installs the existing hash-pinned OAuth bake-off graph plus pinned
PyJWT in a temporary virtual environment, starts a local TLS AS/resource
fixture, and proves:

- `requests-oauth2client` emits the closed token-endpoint DPoP proof shape;
- a DPoP token response is verified with exact `cnf.jkt` continuity;
- the `NoNonceDPoPKey` confinement stops AS and RS nonce paths after one wire
  attempt and stores no nonce;
- restoring the library defaults produces three AS requests and two resource
  requests whose proofs carry the challenge nonce, distinct `jti`, and exact
  resource `ath`, proving the hidden-retry/replay mutation;
- 32 AS plus 32 resource refusals close responses with no observed FD growth;
- PyJWT/Andyur validation rejects 20 exact signature, issuer, audience,
  algorithm, time, required-claim, `cnf.jkt`, and token-type mutations; and
- the library's token serialization includes the private JWK, preserving that
  custody limitation as an explicit red signal rather than hiding it.

It also runs a mutation-tested current-tree guard for production Python,
Kubernetes manifests, and broad Docker `COPY`/`ADD` sources. This is not a
substitute for Phase-2 inspection of the built image contents.

The result is written atomically only after bounded fixture teardown succeeds
and records hashes of the gate plus both dependency locks.

Phase 1 does not prove Envoy integration, resource-side DPoP enforcement,
non-exporting key custody, provider support, concurrency, or production
readiness. Spike client/proxy glue is deleted rather than promoted.

Checked-in evidence from 2026-08-14 is
`result-2026-08-14-macos-arm64.json`, SHA-256
`aefc7f08c7cd41978f54b620b87e4813f4419a58d55e225bf8694c020d5a051d`.

Run the separately authorized Phase 2a gate:

```bash
./infra/sender-binding-spike/verify-phase2a.sh
```

It builds the reference AS pinned to `go-oidc v0.25.0`, starts that AS directly
on locally trusted HTTPS with DPoP required, and uses the Phase-1 selected
`requests-oauth2client` path for a real RFC 8693 exchange. The result verifies
the signed access token through the AS JWKS, exact issuer/audience,
`token_type=DPoP`, and `cnf.jkt` continuity. At the AS enforcement point it
also denies missing proof, wrong `typ`, mismatched signing/public key, a private
JWK member, wrong `htu`/`htm`, out-of-window `iat`, and replayed `jti` after a
working first presentation.

Phase 2a still does not prove resource-side `ath`, Envoy header transport,
broker concurrency/lifecycle, non-exporting custody, or an enterprise tenant.

Run Phase 2b:

```bash
./infra/sender-binding-spike/verify-phase2b.sh
```

This starts a separate disposable HTTPS resource PEP and sends the exact
reference-AS token using the selected client's real resource-proof path. The
PEP verifies the AS signature/issuer/audience, closed `cnf.jkt`, proof JOSE and
holder key, `ath`, method, external URI, ten-second freshness window, bounded
`jti`, and a bounded replay cache before incrementing its execution counter.
The live matrix attacks every field and includes exact red/restore/green
mutations that remove `ath` and replay enforcement.

This remains a conformance harness, not reusable production PEP code. Phase 2b
does not prove Envoy transport, cancellation/queueing, halt/fencing, concurrency
capacity, non-exporting key custody, or an enterprise resource implementation.

# OpenSRE on Andyur (exec/v1)

An unmodified upstream image, `ghcr.io/tracer-cloud/opensre` (the digest the
2026-08-23 compatibility audit ran), governed by a manifest alone. Nothing in
the image knows Andyur exists: it reads its alert from stdin
(`opensre investigate -i -`), talks to its model through
`services.model.base_url` on the run's proxy Pod (the sidecar's front forwards
`/llm` to the platform's model leg -- Ollama in local-model mode), and writes
its JSON report to stdout, which the daemon captures as the run's summary.

`agent.json` is the governed manifest. It compiles and packages through the
real tooling (`tests/test_opensre_manifest.py` proves that on every run), and
its runtime is the audited shape from ADR-011 D5.

Status:
- The runtime path is proven with a stock process on Kubernetes
  (`infra/kubernetes/verify-exec-tool-call.py`).
- THIS image ran to completion under the platform's launch primitives on the
  docker path through the exec/v1 conformance gate (ADR-011 D8):
  `evidence/result-exec-v1-*.json`, 8/8 -- input by stdin, four model calls
  observed only at the proxy path, no credential anywhere, output captured by
  the daemon's own bound, a killed run failing closed, scratch writable as
  uid 1001. Reproduce with
  `andyur agents conformance demos/opensre/agent.json --evidence <new.json> --input demos/opensre/alert.json`
  (Docker Desktop's context: the harness is reached through
  `host.docker.internal`).
- That evidence is what governed publication requires: `andyur agents package
  demos/opensre/agent.json --policy-resolution demos/opensre/policy.json ...
  --conformance-evidence evidence/result-exec-v1-*.json` packages, pushes and
  cosign-signs the snapshot, and the governed registry loads it back.
- Done in the cluster too: the same image ran to `done` through the in-cluster
  control plane (governed registry, worker under its Role, SPIRE registration)
  -- `infra/kubernetes/result-exec-opensre-*.json`, `verify-exec-opensre.sh`.

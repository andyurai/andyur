# Kubernetes run isolation

`run-isolation.yaml` is the reference cluster contract for Andyur run groups.
It assumes the enterprise already operates Kubernetes, SPIRE, the SPIFFE CSI
driver (`csi.spiffe.io`), and SPIRE Controller Manager. Andyur does not install
or own those enterprise control planes.

Apply the namespaced resources and, after replacing the example trust domain,
the `ClusterSPIFFEID`. The worker uses in-cluster Kubernetes authentication by
default. Host development must explicitly set `ANDYUR_KUBECONFIG`; Andyur never
silently adopts a developer's current kubectl context.

`control-plane.yaml` packages the installation: the control-plane server, the
worker daemon, and the durable engine's execution worker. With `temporal.yaml`
(the engine, behind its SPIFFE-ID authorizer) the engine DISPATCHES admitted
runs to the execution worker, which launches them through the same governed
launcher as the daemon; the daemon's reconciler still destroys any run the
server condemns, engine or not (ADR-014 D11, `infra/temporal/RUNBOOK.md`).
Before applying it, replace all `registry.example` digest placeholders, create
the referenced `andyur-secrets` Secret, and render the worker NetworkPolicy's
Kubernetes API address and port from the `kubernetes.default` Endpoints object.
Kubernetes NetworkPolicy cannot select a Service by name, and many CNIs enforce
the post-DNAT endpoint rather than its ClusterIP. Leaving another cluster's
endpoint in place correctly prevents API access instead of opening ambient HTTPS
egress. The checked-in endpoint is the local Rancher Desktop gate, not an AWS or
Azure assumption; a multi-endpoint API needs one narrow rule per endpoint.

`observability.yaml` is the telemetry path the control plane and every run
sidecar export to (the deployed profile runs with `ANDYUR_OTEL=on`). Apply it
with `apply-observability.sh`, which generates the two ConfigMaps from
`infra/observability/otel-collector.yaml` and `infra/observability/jaeger.yaml`
(validate them first with `infra/observability/verify-config.sh`). Jaeger is a
bounded in-memory development backend; the Collector's `otlp_http/backend`
exporter is where a durable backend is configured. The Collector's ingress
NetworkPolicy is load-bearing (OTLP ingest is unauthenticated): it admits the
control plane and the run proxy sidecars only. See `docs/observability.md`.

Select this runtime explicitly:

```bash
ANDYUR_DEPLOYMENT=kubernetes
ANDYUR_KUBERNETES_NAMESPACE=andyur-runs
ANDYUR_WORKER_ID=andyur-worker-0
ANDYUR_KUBERNETES_PROXY_IMAGE=registry.example/andyur-proxy@sha256:<digest>
ANDYUR_KUBERNETES_AGENT_IMAGE=registry.example/andyur-agent@sha256:<digest>
LITELLM_MASTER_KEY=<sidecar-service-key>
```

Broker-enabled assignments additionally require an immutable Envoy image and
one explicit broker-state destination. These settings do not widen ordinary
runs: the destination is added to a run's NetworkPolicy only when its sealed
assignment enables the broker.

```bash
ANDYUR_KUBERNETES_BROKER_ENVOY_IMAGE=docker.io/envoyproxy/envoy@sha256:<digest>
ANDYUR_KUBERNETES_BROKER_STATE_HOST=andyur-server.andyur-system.svc
ANDYUR_KUBERNETES_BROKER_STATE_PORT=9443
ANDYUR_KUBERNETES_BROKER_STATE_PEER='{"namespace":"andyur-system","labels":{"app":"andyur-server"},"port":9443}'
```

Broker mode requires Kubernetes 1.29 or newer because it uses the native
sidecar contract (`initContainers[*].restartPolicy: Always`). It creates a
three-container trusted Pod: the runner, the state-bound deny broker, and an
Envoy that presents the run SVID to the
control-plane broker-state ingress. The agent Pod receives none of their
sockets, configuration, identity, or broker credential. The broker's readiness
probe traverses its private UDS and the Envoy mTLS state path, so the controller
does not create the agent while that composition is unavailable. The broker
retries explicitly transient SPIFFE identity, local transport and Envoy
502/503/504 warm-up failures for at most 55 seconds; authorization, terminal
run and malformed-state failures remain single-attempt. Kubernetes stops the
two native sidecars after the runner exits, allowing the Pod to reach a terminal
phase. Credential issuance and production tool-route promotion remain disabled.

`ANDYUR_WORKER_ID` must be stable across controller restarts and unique within
the run namespace. A StatefulSet identity supplied from the Pod name is the
intended production shape. Adoption is scoped to the hash of this identity, so
one worker cannot report or delete another worker's run groups. Changing it
abandons the old generation for control-plane reconciliation; sharing it lets
two controllers contend for the same generation and is unsupported.

The selector is fail closed. Missing configuration, invalid digest-pinned
images, isolation-preflight failure or Kubernetes API setup failure stops the
worker; it never falls back to Docker or host execution.

The worker refuses the namespace until an active cluster preflight has proven
NetworkPolicy enforcement and set `andyur.network-policy/verified=true`. Merely
creating a NetworkPolicy object is not evidence that the installed CNI enforces
it. The shipped namespace starts with the marker set to `false` deliberately.

The worker has no cluster-wide write permissions. It creates two immutable,
generation-labelled Secrets from the already-issued assignment and deletes them
with the run group:

- channel Secret: key `token`;
- trusted runtime Secret: keys `run-token` and `litellm-key`; for an `exec/v1`
  run also the dedicated per-run MCP bearer, as one minted value in two
  spellings: `mcp-token` (the bare token the serve-only proxy's tool service
  compares) and `mcp-authorization` (`Bearer <token>`, the complete header
  value the workload sends).

The proxy Pod references the trusted runtime Secret and mounts the SPIFFE
Workload API. A runtime-v1 agent Pod receives the channel token only. An
`exec/v1` agent Pod receives NEITHER the channel token nor `run-token`: the only
Secret key it can read, by any Pod shape (env, envFrom, volume), is
`mcp-authorization` -- by `secretKeyRef` on the environment variables its
manifest declared and on its config-render init container. The dedicated
`andyur-runs` namespace must contain no unrelated Secrets; this keeps the
worker's namespaced Secret list/delete-collection permission from crossing
another application's boundary. Secret values never appear in Pod specs, logs,
labels, or annotations.

The two run Pods are deliberately separate. Kubernetes NetworkPolicy cannot
give two containers in the same Pod different egress permissions because they
share one network namespace.

Run `./run.sh kubernetes-verify` after rendering and deploying the manifests on
Rancher Desktop. It performs a registry-backed model run, operator halt with
exact-generation cleanup, server/PVC restart proof, and focused TTL/isolation
regressions. It refuses a different kubectl context, example images, mutable
images, multiple control-plane replicas, or a namespace whose CNI has not been
actively verified. See `infra/kubernetes/README.md` for
the latest live evidence and remaining cloud portability boundary.

To refresh the broker lifecycle evidence, build a unique image from the
current checkout directly into Rancher Desktop's image store. The live gate
uses `imagePullPolicy: Never` so it cannot silently substitute a registry image
or an old evidence image:

```bash
tag="andyur-broker-lifecycle:$(git rev-parse --short HEAD)-$(date -u +%Y%m%dT%H%M%SZ)"
docker --context rancher-desktop build -f Dockerfile.server -t "$tag" .
ANDYUR_KUBECONFIG="$HOME/.kube/config" \
ANDYUR_BROKER_LIFECYCLE_IMAGE="$tag" \
  bash infra/kubernetes/verify-broker-lifecycle.sh
```

The verifier refuses to run without `ANDYUR_BROKER_LIFECYCLE_IMAGE` and checks
the executing container's broker source hashes against the current checkout.


## Refreshing the exec/v1 evidence (input delivery and the tool call)

Both gates drive the real controller under the worker's ServiceAccount against
a digest-pinned image built from the current checkout and pushed to a registry
the k3s node can pull from (the local `registry:2` on `localhost:5000` that
Rancher Desktop's node reaches). Build in the `rancher-desktop` docker context
-- Docker Desktop's daemon cannot reach `localhost:5000` -- and pin the
REGISTRY's manifest digest, not `docker inspect`'s:

```bash
tag="localhost:5000/andyur-exec-tool-call:$(git rev-parse --short HEAD)-$(date -u +%Y%m%dT%H%M%SZ)"
docker --context rancher-desktop build -f Dockerfile.runner -t "$tag" . && docker --context rancher-desktop push "$tag"
digest=$(curl -sI -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  "localhost:5000/v2/andyur-exec-tool-call/manifests/${tag##*:}" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' | tr -d '\r')
ANDYUR_KUBECONFIG="$HOME/.kube/config" ANDYUR_EXEC_TOOL_CALL_IMAGE="localhost:5000/andyur-exec-tool-call@$digest" \
  bash infra/kubernetes/verify-exec-tool-call.sh > /tmp/tool-call.json
```

`verify-exec-input.sh` is the same recipe with `Dockerfile.daemon`, the
`andyur-exec-input` repository and `ANDYUR_EXEC_INPUT_IMAGE`. Each gate prints
its result as one JSON line on stdout; the committed
`result-exec-tool-call-*.json` / `result-exec-input-*.json` are that line
re-serialised with `indent=1, sort_keys=True`. Run the k3s gates one at a time.
The tool-call gate's `not_covered` field names the leg it cannot prove here
(the server-side scope refusal needs the in-cluster control plane and a SPIRE
registration for the run).

The exec/v1 workload's `services.model.base_url` resolves to the proxy Pod's
`/llm`, which the serve-only sidecar forwards to its model proxy. That proxy
exists only when the sidecar has a model leg to hold: set `ANDYUR_LITELLM_URL`
(the LiteLLM service the tool gateway fronts) alongside `LITELLM_MASTER_KEY`, or
every model call answers `503 this run has no model proxy to forward to`.

## The governed registry in the cluster, and the OpenSRE end-to-end gate

Kubernetes assignment requires a pinned governed registry: `assign_runs` refuses
a run bound to no `registry_digest`, and the directory registry the first
verification used can carry no container runtime. The server therefore runs
with `ANDYUR_REGISTRY=governed` (see `control-plane.yaml`): it cosign-verifies
and oras-pulls the snapshot named by `ANDYUR_REGISTRY_REF` (both tools are in
the server image, pinned by checksum), with the public key mounted from the
`andyur-registry-cosign` Secret and an egress rule to the registry. Publish the
snapshot with `andyur agents package … --publish-ref <registry>/andyur-registry:<tag>
--cosign-key … --conformance-evidence <exec/v1 or runtime-v1 evidence>`; the
digest it prints is the value to render. From Pods on Rancher Desktop the local
registry is `host.lima.internal:5000` (`192.168.5.2`); from the host it is
`localhost:5000`; the digest is the same.

Two operational rules this gate learned the hard way (2026-08-26):

- The worker refuses to START, and to launch, unless `andyur-runs` carries a
  NetworkPolicy verification stamp younger than 600 s. Run
  `verify-network-policy.sh` (with `ANDYUR_NETWORK_POLICY_EVIDENCE` pointed at a
  scratch path if today's artifact already exists), then restart a worker that
  crashed on a stale stamp, then trigger. `verify-exec-opensre.sh` does this.

  Since 2026-08-30 `control-plane.yaml` also deploys `andyur-netpol-reconciler`,
  which re-proves containment inside the run namespace every 240 s and stamps
  only when every expectation holds -- withdrawing the stamp when one does not.
  So a DEPLOYED cluster keeps its own stamp fresh and a partner is no longer
  handed a control plane that serves and never launches. It deliberately does
  not run the release gate's allow-all mutation proof (that breaks containment
  on purpose, which is not something to do unattended), and the stamp it writes
  records exactly which checks it ran.
- The checked-in Role (`run-isolation.yaml`) must be the one deployed: the
  2026-08-13 Role lacked `pods/log`, `pods/attach get` and `configmaps`, and
  every exec/v1 launch failed on attach, then 403'd on rollback. Re-apply the
  Role and RoleBinding documents after pulling.

The shipped `control-plane.yaml` stays `ANDYUR_PROFILE=prod`, which on current
`main` requires `ANDYUR_USER_AUTH=on` (an OIDC IdP) and
`ANDYUR_REQUIRE_RUN_SVID=on`. The Rancher Desktop cluster has no IdP, so it runs
with `ANDYUR_PROFILE=dev` and `ANDYUR_REQUIRE_RUN_SVID=on` set on the server,
worker and operator -- a documented deviation, not the production posture.

```bash
ANDYUR_KUBECONFIG="$HOME/.kube/config" bash infra/kubernetes/verify-exec-opensre.sh > /tmp/opensre.json
```

drives an unmodified OpenSRE image (the governed `agt_opensre` resolution) to
`done` through the whole path and prints one JSON line: run id, state, the
captured report's head, elapsed time, image and registry digests, the worker's
log lines for the run. The committed `result-exec-opensre-*.json` is that line
re-serialised with `indent=1, sort_keys=True`. `verify-exec-goose.sh` and
`verify-exec-hermes.sh` run the same generic script
(`verify-exec-workload.sh`) with their own demo as data.

WHAT THESE THREE PROVE, AND WHAT THEY DO NOT. Each proves a governed launch: the
pinned image, the governed resolution, the model reached only through the front,
completion, the trace, and cleanup. None of them proves tool use. A tool call is
recorded as observed-not-required, and all three committed artifacts record
`tool_calls_observed: []`: whether the model calls a tool is the model's
decision. Tool use by a stock workload is proven by `verify-exec-tool-call.py`
and by the agent-requested-action gates below.



## Did the AGENT ask? (`verify-agent-requested-action.sh`)

`verify-consequential-action.py` proves the DECISION against a real cluster --
deny, allow, approve -- by driving `andyur.server.actionrequests` in-process
with a hand-minted grant. It is silent about who asked, which is what the
2026-08-30 readiness review named: nothing showed an agent initiating a
consequential action through the generic tool path.

This gate does. A stock upstream agent at its pinned digest -- Goose by default,
Hermes Agent through `verify-hermes-requested-action.sh`, each with its own
artifact -- is triggered with a `deployments:rollback` scope and a pin to a
disposable `checkout-service` in a namespace the gate creates and owns, and
calls `request_rollback` over the run's own MCP tool service. The gate then
asserts the `action_requests` row, that the API server's view of the pod
template actually moved back a revision, and that `mcp.tool request_rollback` is
in the run's trace.

WHY THE ROW IS THE PROOF. `POST /runs/{id}/actions` refuses an operator with a
403 -- the endpoint records that THE AGENT asked, and an operator posting there
would forge that record. This gate holds an operator credential and nothing
else, so it is structurally incapable of writing the row it reads back.

NOTHING WORKLOAD-SPECIFIC WAS ADDED. `request_rollback` is a tool of the one
platform tool server (`driver.build_platform_server`), which `toolservice.build_app`
serves verbatim over streamable HTTP; the in-process path and the stock-workload
path are the same object. Goose reaches it through the generic
`configuration.files` mechanism every exec/v1 agent has.

The review named OpenSRE. Unmodified OpenSRE cannot be handed an arbitrary
tool -- its surface is a fixed registry of named `IntegrationSpec` entries and
its only MCP clients are hard-wired to GitHub and X -- so proving the generic
path with it would require upstream MCP support or the workload-specific adapter
the review forbids. The artifact records the substitution as
`workload_substitution` rather than glossing it.

    bash infra/kubernetes/verify-agent-requested-action.sh
    bash infra/kubernetes/verify-hermes-requested-action.sh

It never changes the control plane's credentials or shared RBAC. An authorized
operator must already have enabled `automountServiceAccountToken` on the
`andyur-server` StatefulSet (see `rbac-consequential-action.yaml`), and the gate
refuses to start otherwise. It renders the example RBAC into the one namespace
it creates, and teardown deletes only that namespace, by its API-server UID,
however the gate exits. A gate that patched the shared credential would have
changed the deployment it was measuring.

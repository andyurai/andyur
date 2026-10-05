# Observability contract

Andyur uses OpenTelemetry as the vendor-neutral carrier for traces and metrics,
and structured JSON on stdout for logs. Components call the shared
`andyur.otel` and `andyur.observability` hooks; they do not construct Jaeger,
Prometheus, Grafana or vendor clients directly.

## Current coverage

- Run-rooted traces cross the server, daemon, runner and sidecar through trusted
  W3C `traceparent` context. Authentication, model and tool spans are included.
- `setup_tracing(service_name)` configures tracing, an OTLP meter provider and a
  trace-correlated JSON logger. Existing callers therefore share one telemetry
  bootstrap.
- `ObservedASGI` records bounded request count, duration and in-flight metrics in
  addition to its server span. It classifies endpoints as `api`, `health` or
  `metrics`; it never records raw request paths or uses them as metric labels.
  It ignores inbound trace context by default. The compatibility `TracedASGI`
  wrapper is restricted to existing SRE fixtures behind the sidecar boundary
  that removes caller trace headers and injects the authenticated run context;
  do not mount that wrapper on a public/unfiltered listener.
- `record_metric` exposes a fixed vocabulary for run outcomes, dependency RED
  signals and authorization decisions. Unknown metrics and dimensions fail at
  the caller boundary. `observe_dependency` composes a CLIENT span, calls,
  failures and duration without allowing telemetry failure to alter the
  observed operation.
- The production OpenBao client uses that dependency hook for bounded
  `exchange`, `fetch`, `call` and `cleanup` operations. Its outcome vocabulary
  uses `success` or `failure`, with bounded failure reasons `refused`,
  `timeout`, `unavailable` or `invalid`; paths,
  credential references, tokens and response content are never signal fields.
- The Collector configuration accepts OTLP on 4317/4318, applies memory and
  batch limits, exports Prometheus metrics on 9464, and forwards traces and metrics to
  the operator-selected OTLP backend. `infra/observability/verify-config.sh`
  validates the configuration and alert rules with digest-pinned Collector
  0.157.0 and Prometheus 3.5.5 images.

### The console (`andyur console`)

Service `andyur-console`, on by default. Every request (static files,
`/healthz`, `/session`, `/api/*`) is a `console.request <METHOD>` server span
with `andyur.http.server.*` metrics. Inside it, every decision is named:

- `console.proxy`: `andyur.console.route` (the allowlist entry name, never a
  path), `andyur.console.outcome` = `forwarded` or `refused`,
  `andyur.console.reason` (the same word as the response body's `reason` and
  the `console.refuse` log line, e.g. `bad_session`, `cross_origin`,
  `upstream_timeout`), `andyur.console.upstream_status`, and `andyur.run_id`
  when a run was started from the console.
- `console.session.issue` (`issued` or `refused` + reason),
  `console.session.refresh` (`refreshed`, `expired`, `idp_error`),
  `console.login` (`signed_in`, `failed`), and `identity.fetch` (a
  dependency span in the platform vocabulary, with `andyur.dependency.*`).
- Refusals count on `andyur.authorization.decisions` with the reason bucketed
  to the platform set (`refused`, `invalid`, `unavailable`, `timeout`,
  `exhausted`); the exact console word stays on the span.

Where to look: a 401 or 403 in the browser is a `console.proxy` span with
`andyur.console.reason`; a 502/503/504 is the same span plus, for 503, an
`identity.fetch` span with its failure reason; a page that says "control plane
unreachable" is a run of `upstream_unreachable` or `upstream_timeout` spans.
The console gate (`infra/verify-console.sh`) provokes each refusal and reads
it back from the collector by that attribute; its trace ids are written to
`data/logs/console-gate-traces.txt`. The control plane does not honour the
`traceparent` the console sends (see above), so a console-started run is
correlated by `andyur.run_id`, not by parent span.

## Safety and cardinality

Metrics may not contain run, workflow, agent, user, tenant, request or URL
identifiers. Allowed values are bounded enums or short machine-defined reason,
dependency and operation codes. Raw paths are span attributes only; operators
must apply their backend's retention and access policy to traces.

Declared structured events use the `andyur.log.v1` envelope with timestamp, severity,
service, logger, event, message and the active trace/span IDs. Event fields are
an exact per-event schema with bounded enums. Free-form messages are not
accepted by the structured-event API. Existing legacy Python log calls are
placed in the JSON envelope but are not thereby proven content-safe; migration
and leak testing remain required. Application code must log outcome codes,
never credential material or request/response content.

Telemetry is operational evidence, not an enforcement dependency. Export and
flush failure must not change request authorization, run lifecycle or cleanup.
Collector queues and memory are bounded so backend outage cannot create an
unbounded platform queue.

## Configuration

- `ANDYUR_OTEL=on|off` controls trace and metric export. Invalid values fail
  startup rather than silently disabling telemetry.
- `ANDYUR_OTEL_ENDPOINT` is the OTLP/HTTP receiver base, normally the Collector
  service at `http://otel-collector:4318`.
- `ANDYUR_TELEMETRY_BACKEND_OTLP_ENDPOINT` configures the Collector's upstream
  trace/metric vendor or self-hosted backend. JSON stdout log collection is a
  separate deployment responsibility and is not wired by this Collector file.
- An operator-installed Python logging handler takes precedence over Andyur's
  JSON stdout handler.

## Kubernetes deployment

`infra/kubernetes/observability.yaml` deploys the telemetry path into
`andyur-system`: an OpenTelemetry Collector (`otel-collector`, contrib
0.159.0, digest-pinned) that every control-plane component and every run
sidecar exports to, and Jaeger v2 (`andyur-jaeger`, 2.20.0, digest-pinned)
as the DEVELOPMENT backend the Collector forwards traces to. Apply order:

```bash
kubectl apply -f infra/kubernetes/control-plane.yaml   # creates andyur-system; ANDYUR_OTEL=on + endpoint on every component
bash infra/observability/verify-config.sh          # both configs, in the pinned images
bash infra/kubernetes/apply-observability.sh       # ConfigMaps from the two files + the manifests (refuses without the namespace)
kubectl -n andyur-system port-forward svc/andyur-jaeger 16686:16686   # UI at http://localhost:16686
```

- The deployed profile ships with telemetry ON: `control-plane.yaml` sets
  `ANDYUR_OTEL=on` and `ANDYUR_OTEL_ENDPOINT=http://otel-collector.andyur-system.svc:4318`
  on the operator, the server, the broker-state backend and the worker, and
  the worker's values are what every run's proxy sidecar inherits. The
  sidecar's NetworkPolicy admits the Collector through the
  `ANDYUR_KUBERNETES_PROXY_EGRESS` peer list.
- **The one seam.** The Collector's `otlp_http/backend` exporter
  (`infra/observability/otel-collector.yaml`, fed by
  `ANDYUR_TELEMETRY_BACKEND_OTLP_ENDPOINT` on the Deployment) is where an
  adopter points at Tempo, Honeycomb, or any OTLP/HTTP backend. The platform
  never changes; only that block does.
- **Jaeger here is a dev backend.** `infra/observability/jaeger.yaml`
  configures in-memory storage bounded by `max_traces` — a bound in trace
  COUNT, not bytes: Jaeger's memory store appends to an existing trace id
  without limit, so one long run can grow one trace without bound. A dev
  backend; traces do not survive a restart. The same file and the same image run under `./run.sh jaeger`
  locally, so Docker and Kubernetes read traces from the same backend.
- **The Collector trusts its network.** OTLP ingest is unauthenticated: any
  process that can open `otel-collector:4318` can write spans into any run's
  trace. Its NetworkPolicy is therefore load-bearing: ingress from the
  control-plane components and from the run PROXY sidecar
  (`app.kubernetes.io/component: proxy`, in a namespace carrying the
  isolation stamp `andyur.network-policy/verified`) only -- never the
  agent/workload selector, whose rendered policy stays proxy-only
  (`tests/test_kubernetes_manifests.py`; probed live by
  `verify-network-policy.sh` and `verify-exec-tool-call.py`). Jaeger accepts
  spans from the Collector only and queries from the operator only.
- **Reading a trace back.** The run record carries `trace_ctx`; the gates
  and an operator take its trace id and fetch
  `GET /api/v3/traces/{traceId}` on `andyur-jaeger:16686` -- from the
  operator Deployment (`kubectl exec -i deployment/andyur-operator -- python -
  http://andyur-jaeger:16686 <trace_ctx> < infra/observability/trace_readback.py`)
  or through the port-forward above. `infra/observability/trace_readback.py`
  is the shared helper; the tool-call, OpenSRE and Docker full-trace gates
  all use it and record the trace id and span names in their evidence.

## Runbook: the exec/v1 run path

One run is one trace; read it back by the run record's `trace_ctx` (above).
For each failure mode, the FIRST signal to look at, by the name it carries.
Every refusal code below is the same string in the error body the workload
saw, the span attribute, the log line and the gate artifact
(`modelpolicy.REFUSAL_CODES`).

| Failure mode | First signal |
|---|---|
| Queued approval refused by current policy or PDP failure | `action.approve` on the stored run trace, with child CLIENT span `pdp.authorize`; its propagated `traceparent` matches the PDP wire request. `pdp.decision` reports permit/refusal; `dependency.failure` names invalid/unavailable/timeout. Metrics `andyur.authorization.decisions` and dependency calls/failures/duration. Each action span carries run and agent identity. |
| Action-gate namespace cleanup failed | CLIENT span `kubernetes.cleanup`, event `action_gate.cleanup.decided` with conflict/invalid/timeout/unavailable; deleted/already_absent/replacement_untouched are bounded completion outcomes. Dependency counters and duration histogram; the gate must observe cleanup before exporting PASS evidence. Loss of create response or SIGKILL can leave an orphan; never delete it by an unverified name. |
| Consequential rollback did not restore the intended deployment | `action.perform` on the run trace, `andyur.rollback_reason=deployment_replaced|rollback_target_changed|controller_not_observed|no_previous_revision|cluster_error`. Event `rollback.observed` and histogram `andyur.action.observation_seconds{rollback_reason}` report bounded observation duration; structured `action.observed` names the same reason. `rollback_applied` means exact template on the original UID and controller-observed generation, NOT application health. |
| The workload's model call was refused | span `execfront POST` (service `andyur-runner`), `andyur.decision=refused`, `andyur.refusal` = `model_not_granted` / `model_key_variant` / `model_missing` / `duplicate_model_key` / `body_not_json` / `no_model_granted`; `andyur.model.requested` names what it asked for. Counter `andyur.execfront.decisions{refusal}`. |
| The workload called a model endpoint that is not a model call (`/api/tags`, `/api/delete`, …) | `execfront GET|DELETE|POST`, `andyur.refusal=path_not_model_call` (or `path_refused` for dot/empty segments) |
| The model leg is missing or dead | `execfront POST`, `andyur.refusal=no_model_proxy` (503: this run has no model leg) or `upstream_unreachable` (502) |
| The workload cannot reach `/mcp` | `mcp POST`, `andyur.refusal=bearer_rejected` (the declared bearer was not presented); a `mcp.tool <name>` child span means the call got through and names the tool and its outcome |
| Readiness timeout / launch rolled back | `controller.wait_ready` `andyur.outcome=timeout` or `phase:<Failed|Succeeded>`, then `controller.rollback` `andyur.outcome=rolled_back|rollback_failed`; event `launch_failed` on `daemon.launch` with `andyur.reason=<exception type>`. Histogram `andyur.controller.wait_seconds{operation,outcome}`. |
| Input delivery failed | `controller.attach` outcome ≠ `delivered` (`andyur.input_mode`, `andyur.input_bytes`) |
| The run's completion never confirmed | `daemon.exec_completion` `andyur.finish=unconfirmed:<reason>`, `andyur.exit_code`, `andyur.captured_bytes`; `andyur.daemon.finish_attempts{outcome=failure}` |
| The sidecar left early / the Pod delete was slow | `runner.serve` `andyur.serve.exit=ttl_expired|sigterm` and its duration; a serve-only exit is bounded (`ANDYUR_SERVE_ONLY_FLUSH_SECONDS`, 2 s) and logs `telemetry export cut` when the collector was unreachable |
| The sidecar failed to start its services | event `serve.start_failed` on `runner.execute`, `andyur.reason=no_declared_bearer|front_failed_to_start` |
| Publication refused evidence | `publisher.evidence` `andyur.outcome=refused`, `andyur.refusal=evidence_not_green|evidence_stale_source|evidence_unbound_workload|evidence_unknown_gate|evidence_missing_binding|evidence_no_inputs`; `publisher.publish` carries the pinned snapshot ref |

Logs from the daemon and the serve-only runner are the `andyur.log.v1`
envelope on stdout with `trace_id`/`span_id`, redacted, so `kubectl logs`
lines can be joined to the trace by id.

**What a span may carry from an untrusted caller.** The exec/v1 front records
a CLOSED route vocabulary (`andyur.execfront.route`: an allow-listed model
call by name, `not-a-model-call`, or `refused-path`) and two numbers, never
the caller's raw path. The one free-text value that remains is
`andyur.model.requested` on a refused call, because "which model did it ask
for" is the diagnosis; it passes the same redaction as logs and captured
output, and the residual is the one `redact.py` states: a bare third-party
secret carrying `/` or `+`, with no `KEY=` and no vendor prefix, is not
scrubbed by shape.

## Runbook: an extension's authorization policy

Only present when an extension installs a policy ([extensions.md](extensions.md)).
Each consultation is one `authz.policy` span under the request's span, one
`extension_policy.decision` log event, and one count on
`andyur.extension_policy.decisions`; `andyur.extension_policy.duration` times it.

| What you see | Signal | What it means, and what to do |
|---|---|---|
| Users get `403 refused by authorization policy` | span `andyur.authz.decision=refuse` with an `andyur.authz.refused` event; metric `andyur.outcome=denied` | The policy is doing its job. The event's `andyur.authz.reason` is the policy's own text; `andyur.authz.action` and `andyur.user` say what and who. |
| Users get `403 ... failed to evaluate` | span `decision=error`, status error, an `exception` event; metric `outcome=failure, reason=invalid`; an ERROR log naming the exception type and its redacted message | The policy raised or returned something that is neither `None` nor a string. It is a bug in the extension. Every user request it fails on is refused. The traceback is deliberately not recorded; reproduce it against the extension. |
| Users get `503 ... did not answer in time` | span `decision=timeout`; metric `outcome=timeout`; `andyur.extension_policy.duration` at the deadline | The policy is slow, usually a decision service behind it. Each such call still holds a slot until it returns. |
| Users get `503 ... too many calls outstanding`, instantly | span `decision=saturated`; metric `outcome=failure, reason=exhausted` | Every slot is held by a call that has not returned. Follows a run of timeouts. The operator path (no user token) still works: use it. Fix or disable the extension and restart the server; a hung call does not block shutdown. |
| Requests carrying a user token get `401` on routes that used to ignore it | `server.request` with status 401 and no `authz.policy` span | With a policy enabled, the workload's SVID and then the user token are validated on every API route before the policy is asked. The token is expired or forged, or the caller sent no SVID. A `403 a user token is accepted only from the operator workload` is the same check refusing a workload that is not the operator. There is no policy decision to record, so there is no policy span. |
| A replica answers differently from the others | its startup log has no `extension enabled:` line | That replica was started without `ANDYUR_EXTENSIONS`, or without the package. It is serving with no policy. |

## Runbook: the heartbeat's drain

The drain is the platform's self-healing path. Work handed to an agent that is
already running is re-driven from here, so a drain that quietly stops is work
that silently never runs. It is also the one place a run is created with no
human or schedule behind it, which is why its attribution matters.

**The signal is the `heartbeat.drain` span**, one per agent with waiting work,
per tick. It continues the trace of the run that CREATED the work, so a
delegation and the run that performs it are one trace even when they are thirty
seconds and two processes apart.

| attribute | what it answers |
|---|---|
| `andyur.agent` | whose waiting work this is |
| `andyur.workflow_id` | which workflow the run joined (absent if it minted its own) |
| `andyur.run_id` | the run created, on success |
| `andyur.decision` | `joined`, `joined_rootless`, or `fresh_workflow` |
| `andyur.outcome` | `success`, `denied`, `failure` |
| `andyur.reason` | which control refused: `refused` (halted or paused), `invalid` (depth, or a manifest that needs an input), `exhausted` (work-item cap), `conflict` (a concurrent claim, or a parent pruned mid-drain) |

**"Why did this workflow stop draining?"** Filter `heartbeat.drain` by
`andyur.outcome = denied` and read `andyur.reason`. `exhausted` is the
work-item cap and clears itself as the workflow finishes. `refused` is a
deliberate act -- someone halted the workflow or paused the agent -- and will
not clear on its own. `invalid` on repeat is permanent: the agent's manifest
requires an input and delegated work carries none, so the work must be closed
or reassigned.

**"Why is this run drawn as a root inside a workflow?"** `andyur.decision`.
`joined_rootless` means the waiting work had several creators, so no single
parent is honest; the span carries a `drain.attribution_degraded` event with
the count. `fresh_workflow` means the work spanned several workflows and
belongs to none of them.

**The counter** is `andyur.run.outcomes{andyur.operation="claim"}`, split by
outcome. A rising `denied` rate with a flat `success` rate is the shape of a
platform whose work is arriving faster than it drains.

**The logs** are the `heartbeat.drain` declared event (bounded fields only:
outcome, reason, decision) plus the tick's free-text lines through the JSON
logger at `andyur.server.heartbeat`. Both carry trace context. Nothing in this
path uses `print`.

## Pilot alerts

`infra/observability/prometheus-alerts.yaml` provides initial service-error,
dependency-failure and run-failure alerts. `verify-alerts.sh` loads those
shipped rules as its source of truth and, against digest-pinned Prometheus
3.5.5, proves all three move through inactive, pending, firing and recovered
states with bounded waits and verified teardown. This is deterministic rule
evaluation evidence; application-produced signal and operator notification
delivery still require composed deployment proof.

## Remaining RC1 work

This foundation does not by itself close the readiness report's 45% Operations
score. The following remain required:

1. Wire lifecycle, heartbeat, AS/PDP, model and tool boundaries to the stable
   metric vocabulary, with component-specific tests. OpenBao is wired; its live
   service-credential gate proves the underlying positive/negative credential
   composition, while telemetry export remains to be exercised in that stack.
2. Deploy central stdout log collection with retention, deletion and access
   policy; prove secrets are absent under positive and failure paths.
3. Add stuck-run, heartbeat-loss, token-exchange, vault, tool-refusal and budget
   alerts, then exercise their application-produced signals and notification
   delivery. The three initial Prometheus rule transitions are exercised.
4. Define SLOs and supported capacity/cardinality limits; run load and soak
   tests while the telemetry backend is slow or unavailable.
5. Enforce per-agent/model/workflow/tool budgets at trigger and broker
   boundaries. Metrics alone are not budget enforcement.
6. Perform PostgreSQL/object-store restore and control-plane recovery drills and
   publish the corresponding runbooks.

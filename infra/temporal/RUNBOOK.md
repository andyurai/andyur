# Operating the workflow engine

Self-hosted Temporal, deployed by `infra/kubernetes/temporal.yaml`. This is the
operator's page: what it is, how to upgrade it, how to get it back, and what its
failures actually look like.

Every failure mode below was observed while building this, not imagined for the
document. Where a symptom points somewhere other than its cause, that is said.

## What it holds, and what it does not

Temporal's two databases are the engine's memory of **in-flight work** — open
executions, their histories, timers and task queues.

They are **not** Andyur's system of record. The coordinator's tables decide what
a run is, whether it is live, and what its outcome was; those are backed up with
the control plane's database and are the authority in any disagreement. Losing
Temporal's persistence costs the ability to resume workflows that were mid
flight. It does not lose a decision.

**Payloads carry identifiers, by design and by a guard with a known limit.**
Workflow and activity payloads carry `run_id`-style identifiers, and
`orchestration/models.py` refuses at import time to define a boundary type
that names a token, scope, subject or key. That guard matches field NAMES
(ADR-014 D3): a free-text field could still carry a secret, so a history
export is to be treated like a log, not handed on as if it were known clean.
The same goes for a backup, which contains every history.

## Retention

The `andyur` namespace is registered with a 7-day retention
(`WorkflowExecutionRetentionTtl 168h0m0s`), set by the `andyur-temporal-namespace`
Job, which reconciles it rather than only creating it.

**Seven, not thirty, and the volume is sized with it.** A live run hands off
about 72 times a day and each closed execution is roughly 675KB on disk, so
storage grows with run-SECONDS. At 30 days on 10Gi the database filled at about
seven concurrently live runs; at 7 days on 50Gi the ceiling is roughly 150. The
arithmetic is in the volume's comment in `temporal.yaml`.

**The Job reconciles only when it runs.** A Job's pod template is immutable, so
`kubectl apply -f temporal.yaml` with a changed admin-tools digest while the
last Job still exists fails for the Job with `field is immutable`: kubectl
applies the other objects and exits non-zero, and retention is not
reconciled. The finished
Job deletes itself after 60 seconds; `infra/rc/deploy.sh` deletes it before
applying. By hand:

```
kubectl delete job andyur-temporal-namespace -n andyur-system --ignore-not-found
kubectl apply -f infra/kubernetes/temporal.yaml
```

Retention bounds **closed** executions. It does nothing for a long-running one:
a workflow that never closes is never collected, and what stops its history
growing is `continue_as_new` in `orchestration/temporal/workflows.py`, not this.

## Upgrading

The schema step runs as an init container on every rollout, so an upgrade is a
digest change and a rollout. **A schema migration does not run backwards**, so
the backup comes first and is the rollback:

1. `infra/temporal/backup.sh <dir>` — and check it reports both dumps complete.
2. Resolve the new digests and edit `infra/kubernetes/temporal.yaml`. Pin by
   digest; the tags in the comment are there to say what the digest was.
3. Delete the registration Job (see Retention), then
   `kubectl apply -f infra/kubernetes/temporal.yaml`.
4. Watch the init container: `kubectl logs -n andyur-system deploy/andyur-temporal -c schema`

**Rolling back** is not reverting the digest: the old server against the new
schema is the one combination that is never supported, and the NEW server's
schema step migrates a restored database forward again. So the database goes
back before any server starts:

```
kubectl scale deployment/andyur-temporal -n andyur-system --replicas=0
infra/temporal/restore.sh <step-1 backup>
# revert the digests in temporal.yaml, then:
kubectl delete job andyur-temporal-namespace -n andyur-system --ignore-not-found
kubectl apply -f infra/kubernetes/temporal.yaml     # starts the old server
```

Executions that ran between the backup and the rollback are lost to the engine;
Andyur's own tables still record those runs.

`update-schema` is the step that matters and it is deliberately **not** allowed
to fail silently — `create-database` and `setup-schema` may fail harmlessly on
every start after the first, because "already there" is the expected answer, but
a failed `update-schema` stops the rollout rather than starting a server against
a schema older than itself.

**Order matters across a version jump.** Temporal supports upgrading one minor
version at a time; skipping versions is not supported and the schema step will
not protect you from it. Upgrade in steps, letting each roll out fully.

## Backup and restore

```
infra/temporal/backup.sh  <output-directory>
infra/temporal/restore.sh <backup-directory>
```

`backup.sh` dumps both databases and **verifies each dump is complete** before
accepting it. The files are written owner-only (`umask 077`), because a dump
holds every execution history. A truncated dump that looks plausible is the failure that matters,
because it is discovered during a restore, which is the worst possible time.

`restore.sh` **refuses while the engine is running**, and that refusal is the
feature: a running Temporal holds shard leases and writes continuously, so
restoring underneath it yields a mixture of two states rather than the one you
backed up. The full cycle:

```
kubectl scale deployment/andyur-temporal -n andyur-system --replicas=0
infra/temporal/restore.sh <backup-directory>
kubectl scale deployment/andyur-temporal -n andyur-system --replicas=1
```

Resumed executions replay from the dump's moment. The engine performs no run
lifecycle transition — a run starts and finishes through its own
SVID-authenticated endpoints, never through an activity — so a replay cannot
start or finish a run a second time. What a replay CAN repeat is a scheduled
admission: an agent admits one live run at a time, so a replayed admission is
refused while the original run is live, and admitted as a new run if the
original has already finished.

## Rotating the database password

The password lives in `andyur-temporal-secrets` and is read by the database
only at FIRST initialisation; changing the Secret alone changes nothing in
Postgres and locks the engine out at its next restart. Change it in the
database first, then the Secret, then restart the engine:

```
NEW="$(openssl rand -hex 24)"
# Over stdin, not `-c`: an argument is visible in the pod's process table.
printf "ALTER USER temporal PASSWORD '%s';\n" "$NEW" | \
  kubectl exec -i -n andyur-system andyur-temporal-db-0 -- psql -U temporal -d temporal
kubectl create secret generic andyur-temporal-secrets -n andyur-system \
  --from-literal=db-password="$NEW" --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/andyur-temporal -n andyur-system
```

The database pod keeps the old value in its environment, and nothing reads it
there after first initialisation: `pg_isready` sends no password, and
`backup.sh`, `restore.sh` and the `psql` above connect over the pod's Unix
socket, which the image trusts. So the database needs no restart.

## Resizing the database volume

A StatefulSet's `volumeClaimTemplates` cannot be changed in place, so an
existing deployment keeps the claim it was created with. `infra/rc/deploy.sh`
handles the template: when it differs, it re-creates the StatefulSet with
`--cascade=orphan` (Pod and claim keep running) and says the claim still needs
resizing. With a StorageClass that allows expansion, grow the claim directly;
applied by hand, the StatefulSet is re-created without its pods the same way:

```
kubectl patch pvc data-andyur-temporal-db-0 -n andyur-system \
  -p '{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'
kubectl delete statefulset andyur-temporal-db -n andyur-system --cascade=orphan
kubectl apply -f infra/kubernetes/temporal.yaml
```

Without expansion support the volume is replaced and the data restored into
it. The engine must stay stopped from the backup to the restore, and applying
the whole manifest would start it, so only the database is applied:

```
infra/temporal/backup.sh <dir>
kubectl scale deployment/andyur-temporal -n andyur-system --replicas=0
kubectl delete statefulset andyur-temporal-db -n andyur-system
kubectl delete pvc data-andyur-temporal-db-0 -n andyur-system
python3 -c 'import sys,yaml; print(yaml.safe_dump_all([d for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["metadata"]["name"]=="andyur-temporal-db"]))' \
  infra/kubernetes/temporal.yaml | kubectl apply -f -
kubectl rollout status statefulset/andyur-temporal-db -n andyur-system
infra/temporal/restore.sh <dir>
kubectl apply -f infra/kubernetes/temporal.yaml
```

The control plane reports the engine unavailable while it is stopped; runs
admitted in that window fail to start and are recorded as failed by Andyur,
not lost.

## Who may call the engine

The engine's only listener on the pod network is an Envoy sidecar
(`authz` container). It terminates mTLS with the engine's SVID, requires a
client certificate, and admits exactly three SPIFFE IDs:

| identity | who holds it | may call |
|---|---|---|
| `spiffe://andyur.local/control-plane` | the andyur-server Pod: the provider and the workflow worker | the whole API |
| `spiffe://andyur.local/workflow-engine-admin` | the namespace-registration Job | the whole API |
| `spiffe://andyur.local/temporal-execution-worker` | the execution worker | a worker's calls only: poll, respond, heartbeat |

The execution worker's limit is checked per request, by gRPC method: it cannot
start, signal, cancel or terminate a workflow, or touch a schedule. A refused
method is logged with the method named:

```
kubectl logs -n andyur-system deploy/andyur-temporal -c authz | grep engine-authz-rpc
engine-authz-rpc peer=spiffe://andyur.local/temporal-execution-worker method=/temporal.api.workflowservice.v1.WorkflowService/StartWorkflowExecution detail=rbac_access_denied_matched_policy[none]
```

If an SDK upgrade makes the worker call a method the allowlist does not name,
that line appears for it and the worker fails its call; add the method to the
`execution-worker` policy in the `andyur-temporal-authz` ConfigMap.
`tests/test_engine_authorizer.py` runs a real SDK worker under this identity
through the shipped config and fails if any of its calls is refused.

Every other SVID in the trust domain — the run-launching daemon, the operator,
the run proxy — is closed after the handshake. Temporal's own services bind
`127.0.0.1`, so nothing but the authorizer is reachable from the Pod network
except metrics on 9090. Adding a caller is a change to the allowlist in the
`andyur-temporal-authz` ConfigMap, and `tests/redteam/test_iteration_02.py`
requires that caller to be an identity the cluster actually issues.

Every refusal is logged:

```
kubectl logs -n andyur-system deploy/andyur-temporal -c authz | grep rbac_access_denied
engine-authz peer=spiffe://andyur.local/worker ... detail=rbac_access_denied_matched_policy[none]
```

A client without a certificate is refused during the handshake and logs
`tls_failure=...PEER_DID_NOT_RETURN_A_CERTIFICATE...` instead.
`tests/test_engine_authorizer.py` runs the shipped config in front of a real
Temporal for every one of these cases, and `infra/kubernetes/verify-engine-authz.sh`
proves the refusal in the cluster with a SPIRE-issued identity the network
admits.

**What else the authorizer does.** It sends Temporal nothing for a connection
that has not been admitted and made a request, so idle or unauthenticated
connections hold nothing on the engine; task-queue long polls are not cut by a
route timeout; it closes a handshake that has not finished in ten
seconds; it speaks TLS 1.3 only; and it does not open its listener until SPIRE
has delivered its certificate. A bare TCP connect — the kubelet's readiness
probe — is not logged.

**`kubectl port-forward` to the engine Pod is engine administration.** Port
forwarding dials 127.0.0.1 inside the Pod, where Temporal listens without TLS,
so it goes around both the NetworkPolicy and the authorizer — exactly as
`kubectl exec` into the Pod does. Grant `pods/portforward` in `andyur-system`
only to those who may administer the engine.

## Engine dispatch and the execution worker

In the production deployment the engine DISPATCHES admitted runs
(`ANDYUR_TEMPORAL_DISPATCH=engine`, ADR-014 D11): the server starts
`AndyurExecution(run_id)` on the `andyur-runs` queue, and the
`andyur-temporal-execution-worker` Deployment claims the run from the server
and launches it through the same governed launcher the worker daemon uses.

**Capacity is replicas.** Each replica runs `ANDYUR_EXECUTION_CONCURRENCY`
executions at once; there is no worker registration row to add.

```
kubectl -n andyur-system scale deployment/andyur-temporal-execution-worker --replicas=3
```

**Which worker has a run**, and under which generation:

```
kubectl -n andyur-system logs deploy/andyur-temporal-execution-worker -c execution-worker \
  | grep "<run-id>"          # "launched under generation exec-..." / "adopted under ..."
```

**A worker lost mid-run is not an incident.** The engine retries the execution
after the heartbeat timeout (60 s) on another replica, which adopts the run's
runtime under its recorded generation; the run's Pods are not replaced.
`infra/kubernetes/verify-bplus-adoption.sh` proves it by deleting a worker Pod
mid-run.

**A halt does not need the engine.** Andyur writes its governance record first;
the engine's cancellation, the executor's condemnation poll and the worker
daemon's reconciler each destroy the runtime.
`infra/kubernetes/verify-bplus-containment.sh` proves the last one with the
engine and every execution worker scaled to zero.

**A rolling restart is not an incident either.** A worker shutting down
cancels its executions, and a cancellation destroys a runtime only if Andyur
has condemned the run; otherwise the execution detaches and the retry adopts
it. The same holds for an attempt the engine has superseded.

**Switching dispatch strands pending engine runs.** A run's dispatcher is
fixed at admission. With `ANDYUR_TEMPORAL_DISPATCH` changed away from
`engine`, no execution worker serves `andyur-runs`, and a run admitted for the
engine but not yet launched holds its agent until the stranded-run reaper
takes it. Drain first: pause triggers and schedules, wait until no engine run
is `pending`, then switch. Engine schedules keep firing through the engine
after a switch to native dispatch; delete them with the Temporal provider
still configured.

**The worker refuses to start** until the run namespace carries a fresh
isolation stamp (the reconciler refreshes it every 240 s), exactly as the
daemon does; a restart or two after a fresh install is that check, not a fault.

## Failure modes

**A caller that should work gets `error reading from server: EOF` or
`transport is closing`.** That is the authorizer closing a connection whose
SPIFFE ID is not on its list, and it reads like a network fault. The `authz`
container's log names the peer that was refused.

**The engine crash-loops with `failed to start service worker: context deadline
exceeded`.** The system worker cannot reach the frontend. When the frontend
itself did TLS, the cause here was `TEMPORAL_TLS_SERVER_CA_CERT` being set: it
is the **internode** setting and also feeds the internode client's
`rootCaFiles`, so it turned the system worker into a TLS client dialling a
plaintext internal frontend. TLS now ends at the authorizer and no
`TEMPORAL_TLS_*` variable is set; if one is reintroduced, this is what it
does.

**`tls: either ServerName or InsecureSkipVerify must be specified`.** A Temporal
client with no server name. Name it rather than skipping verification; the
authorizer serves an SVID carrying the Service's DNS names, so it verifies
whatever address it dialled.

**A new component hangs with no output at all.** `default-deny` in
`andyur-system` selects every pod, so anything without its own NetworkPolicy has
no route anywhere, DNS included. This cost six silent minutes during the build;
the registration Job now logs while it waits, and a new component needs a policy
of its own.

**The drain and the schedules both say "paused: the workflow engine was
unreachable".** One breaker covers every heartbeat phase that admits runs
through the engine. The first start that cannot reach it trips the breaker;
nothing is claimed or admitted until it closes, 30 seconds after the first
failure and doubling to five minutes. Due schedules stay due and fire on the
first tick after the engine answers. Only an admitted run closes the breaker.

**The schema step crash-loops at first deploy.** It started before the database
had endpoints, DNS answered NXDOMAIN, and Kubernetes retried it into eventual
success — which is worse than failing, because a deploy that arrives by
restarting cannot be told from one that is broken. It waits on `pg_isready` now;
a cold start should show **zero** restarts, and a non-zero count is a real
signal.

**`unknown flag: --tls` from the CLI.** Its TLS flags are subcommand-level:
`temporal operator cluster health --tls ...`, not `temporal --tls operator ...`.
The environment variables are `--tls-cert-path` style names, not the server's
`TEMPORAL_TLS_*` ones, and an unrecognised export is silent — the client simply
connects without a certificate and is refused, which reads as the server being
unreachable.

**Workflows fail with a history-size or history-count error.** The poll loop
should hand off long before this: `MAX_POLLS_PER_EXECUTION` in
`orchestration/temporal/workflows.py` is carried as a workflow argument from
the first continuation on, so each continued execution records its bound in
its own history; the first execution takes the code's default. If this appears, check that
continuations are happening — a `WorkflowExecutionContinuedAsNew` event in the
first execution's history is the proof.

## What to watch

Metrics are scraped by the OTel collector as job `andyur-temporal` and exported
under the `andyur_` prefix. The engine exposes roughly 7,500 samples; the ones
worth an alert are task-queue backlog, persistence latency and error rates.
There is no alert rule for them yet — `infra/observability/prometheus-alerts.yaml`
is where one would go.

# Observability exit criteria

Observability, traceability and OpenTelemetry are not a feature of this
platform; they are an exit criterion for every feature of it. A change is not
done until an operator can answer, from the platform's own signals and
without reading code, what a run did, which control decided each outcome, and
why. This page is the checklist a change is reviewed against, beside the
security change gate. It is deliberately short so it can be applied to every
pull request, and every line is testable.

The baseline it extends is `observability.md`: one run is one trace, anchored
on the run record, spanning every process the run touches.

## The checklist

A change passes when every line below is true for every code path it adds or
alters. "Decision" means any point where the platform allows, refuses,
routes, launches, finishes, retries or gives up.

1. **Every decision is a span or a span event**, carrying the run id, the
   agent id, the component, the outcome, and the reason BY NAME (the same
   name the error message uses). A refusal an operator sees as a 4xx in a
   client must be findable in the trace by that reason.
2. **Trace context crosses every hop the change introduces.** Workload to
   front, front to model leg, sidecar to tool, daemon to control plane,
   controller to cluster: each is a child span of the run's trace, or the
   change documents why it cannot be and what correlates it instead.
3. **Identity is on the span, secrets never are.** Which principal (SPIFFE
   ID, worker id, agent id, granted model, audience) made or received the
   call is recorded; tokens, keys and bearer values are not, and the
   redaction path covers span attributes and events exactly as it covers
   logs.
4. **Failures are observable at the boundary where they happen.** A
   teardown that took the whole grace period, a launch that rolled back, a
   finish that could not confirm, a gate that expired: each is a span with
   its duration and its cause, not only a log line inside a process.
5. **Metrics exist for what the change makes countable**: decisions per
   outcome and reason, latency of every bounded wait the change adds or
   relies on (readiness, delete, finish, attach), and the resource the change
   caps (body bytes, output bytes, calls per run). Names follow the existing
   `andyur.*` conventions.
6. **Logs are structured, redacted and correlated**: each line the change
   emits carries the trace id and the run id where one exists, and passes
   through the same redaction as user-visible errors.
7. **Telemetry off is safe and telemetry on is the default.** Exporter
   failure never changes a control's outcome (telemetry fails open;
   controls fail closed), and the deployed profiles ship with telemetry on.
   A gate or evidence run executes with telemetry ON unless the gate exists
   to test the off posture, and its artifact records the trace id(s) it
   produced.
8. **A test reddens when the instrumentation is removed.** For each decision
   the change adds, a test asserts the span or event with its name and
   attributes, and the mutant that deletes the instrumentation turns it red
   (mutation-checked like every other regression test).
9. **The runbook names the signal.** For each failure mode the change
   introduces or touches, `observability.md` or the feature's own doc says
   which span, metric or log the operator looks at first.

## What review does with it

The review fan-out includes an observability lens beside security,
concurrency, protocol, test-quality, operations, scale and code quality. Its
verdict is decided by running: start the feature with telemetry on, exercise
the positive path and each refusal, and read the trace back from the
collector. A feature whose decisions cannot be found in that trace is
CHANGES REQUESTED, whatever else it proves.

## Retroactive scope

Features that landed before this page are not exempt; they are debt, listed
in `../ROADMAP.md` with the paths that are dark, and closed lane by
lane against this same checklist.

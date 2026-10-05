# The red-team regression suite

Red-team agents are non-deterministic: a run finds what it happens to find, and
the next run over the same code may find something else. That makes them a good
way to DISCOVER an attack and a bad way to know an attack stays closed.

So every attack a red team runs gets frozen here as an ordinary test. The agents
stay exploratory; this suite is the deterministic part, and it only grows.

## Convention

    tests/redteam/test_iteration_NN.py

One file per red-team round, never edited afterwards except to fix a test that
was itself wrong. A later round that re-finds an old attack does not move it --
that would hide that the control regressed.

Every test records, in its docstring:

- **LANDED** or **held**. An attack that landed is a regression test for a real
  defect. One that held is kept so a later change cannot silently re-open it,
  and those are the ones most likely to be deleted by someone tidying up.
- What was actually sent, when the shape is not obvious from the code.

Every landed attack is paired with a **positive control** in the same file. A
refusal proves nothing on its own: a function that refuses everything passes
every negative test in here.

## Running it

    ./run.sh redteam              # this suite alone
    .venv/bin/python -m pytest tests/redteam -q
    .venv/bin/python -m pytest -m redteam -q      # includes any marked elsewhere

It is part of the normal `pytest tests/` run, so CI already covers it.

## What is NOT here

Attacks that need a LIVE process rather than an import:

| where | what it attacks |
|---|---|
| `./run.sh spire-redteam` | the identity plane, with real SVIDs and tokens |
| `infra/reference-as/verify.sh` | the authorization server: policy, PKCE, DPoP replay, RAR |
| `tests/test_s1_attacks.py` | the pre-existing S1 attack set |
| `tests/test_engine_authorizer.py` | the workflow engine's SPIFFE-ID authorizer: the shipped Envoy config in front of a real Temporal, one certificate per identity |

Same rule applies in all of them: every finding becomes an assertion, and every
denial sits beside a positive control.

## Iterations

| file | round | landed | held |
|---|---|---|---|
| `test_iteration_01.py` | 7-persona review of the external-AS work, 7 Aug 2026 | credentials-file symlink; discovery endpoint origin not pinned | CEL literal breakout; authorization-code injection into the loopback listener; discovery issuer mismatch, oversized document, redirect. The former URL-reconstruction tests retired with agentgateway; the current AS client sends the configured URL intact. |
| `test_iteration_02.py` | 7-persona review of the workflow-engine lane, 21 Sep 2026 | a registered activity could record any run's outcome; the run-launching daemon held a route to the engine; every SVID in the trust domain administered the engine; Temporal's services, the unauthenticated internal frontend among them, listened on the pod IP | the run namespace has no route to the engine |

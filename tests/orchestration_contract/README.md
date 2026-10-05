# The orchestration contract

What any workflow provider must do, stated without saying how.

Andyur's orchestration semantics are currently implemented by one provider: the
native coordinator, worker daemon and server heartbeat loop. That implementation
is thoroughly tested elsewhere in `tests/`, and those tests are deliberately
specific -- they pin compare-and-swap ordering, worker slot accounting, kill
lists on the heartbeat wire, and process groups. They should stay that way.

This suite is the other half, and it exists because those tests cannot answer
the question a second provider asks:

> Which of these behaviours am I required to reproduce, and which are just how
> the native engine happens to work?

**The rule this suite is written under: assert the observable semantics, never
the mechanism.** A test here may say "an agent already holding a live run
refuses a second". It may not say "the second INSERT raises IntegrityError",
because a provider that serialises admission some other way would still be
correct and this suite would wrongly fail it.

Concretely, nothing in this directory may assert:

- SQL, table shape, or the `agent_status` view
- worker ids, slot counts, or the heartbeat request/response wire
- process groups, signals, or container handles
- polling intervals, tick cadence, or sleep durations
- which component performed a transition

and everything in it must assert only what a caller or an operator can observe:
run states, refusals, which agent is free, what authority a run carries, and
what survives a restart.

## The gate

The native implementation passes this contract unchanged. No production code was
modified to make these pass; where the contract wanted a behaviour the native
engine does not have, the test is marked `xfail` with the reason, rather than
the engine being changed to suit it. That is the point of characterization: the
contract records what is true today, including the parts that are awkward.

## Two kinds of test live here

**Andyur's semantics** -- `test_admission.py`, `test_run_lifecycle.py`,
`test_halt_and_containment.py`, `test_dispatch.py`, `test_scheduling.py`,
`test_deferred_work.py`, `test_authority_inheritance.py`. These hold whoever is
running the work. Admission, the drain, the caps and the reaper are not a
provider's to implement, so these drive the platform directly.

**The provider contract** -- `test_provider_conformance.py`, parameterised over
every provider, running identical bodies against each. This is the part a
provider answers for, and it is the only thing that makes the interface mean
anything: an SPI nobody has run two implementations against is a guess.

`test_local_provider.py` is the third, smaller category: behaviour that is real
and worth pinning but could not be asked of every provider. The native engine
refuses to start a workflow whose run was never admitted, because it can see
Andyur's own tables; a durable engine has no view of those, so requiring it of
everyone would be requiring the impossible -- and a conformance suite that asks
for the impossible gets weakened until it asks for nothing. Telling those two
apart is most of the value of having written a conformance suite at all.

## What the fake does and does not prove

`fakes.py` holds a provider with no engine behind it. It establishes that the
contract is satisfiable without importing any engine SDK, and that the types
crossing the boundary are constructible from plain data.

It cannot establish that a REAL durable engine fits, because a fake can
implement any interface. That question was answered a different way, by running
a disposable spike against a real Temporal server before the interface was
fixed -- which is where the absence of `cancel` came from.

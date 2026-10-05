# Support

Andyur has **one maintainer**. This document says what that means in practice, so
you can decide whether to depend on the project with your eyes open rather than
discover the answer by waiting.

## Where to go

| You have | Use |
|---|---|
| A bug, with steps to reproduce | a GitHub issue |
| A question about how something works | a GitHub issue — if the docs did not answer it, that is a documentation bug and worth filing |
| A security vulnerability | **not** an issue. See [`SECURITY.md`](SECURITY.md) |
| A change you have already written | a pull request, but read [`CONTRIBUTING.md`](CONTRIBUTING.md) first — the bar for changes is specific |
| A question about whether Andyur fits your use case | an issue. [`ROADMAP.md`](ROADMAP.md) states the known limits plainly; start there |

## What to expect

**Triage twice a week, batched.** Not daily. An issue filed on Saturday is
normally seen early in the following week.

**A first response within about a week**, usually sooner. A response may be a
question, or "this is real and here is where it sits", rather than a fix.

**Security reports are different**, and are acknowledged within 7 days — see
[`SECURITY.md`](SECURITY.md).

**No SLA, because there is no support contract.** Nothing here is a commitment;
it is a description of how the project actually runs, written so the gap between
expectation and reality is small.

## What is likely to get fixed

Honest ordering, because a maintainer who pretends everything is equally likely
wastes your time:

1. **Anything that makes a documented claim false.** Claims in this repository
   are bound to evidence, and a claim that has stopped holding is the highest
   priority bug there is.
2. **Anything that breaks the first-run path.** If a stranger cannot get to a
   working agent, nothing else matters.
3. **Security issues**, weighted by whether the default configuration is
   affected.
4. **Bugs with a reproduction.** A reproduction roughly triples the chance of a
   fix, because most of the work in a fix is establishing what is happening.
5. **Features on [`ROADMAP.md`](ROADMAP.md).**

## What is unlikely to get fixed

- Requests to make Andyur an agent framework. See *Not planned* in
  [`ROADMAP.md`](ROADMAP.md).
- Support for configurations the project does not test. The supported shapes are
  `ANDYUR_DEPLOYMENT=docker` and `kubernetes`; `native` is development only.
- Anything requiring a credential, tenant or cluster the maintainer does not
  have. Say so in the issue and it can at least be recorded accurately.

## If you need more than this

Andyur is Apache 2.0. You can fork it, vendor it, or carry patches, and nothing
about this project's pace constrains yours. If you are evaluating it for
something load-bearing, read [`docs/threat-model.md`](docs/threat-model.md) and
the known-limits table in [`ROADMAP.md`](ROADMAP.md) first — they are written to
help you say no.

# ADR-012: Certification — an approval step between "proven" and "publishable"

Status: accepted (2026-08-26, operator), amended the same day (Amendment 1,
below: request states, report honesty, and the failure-triggered review).
Nothing in this ADR is built yet;
it is tracked as production-gaps row 20 and sequenced after the `exec/v1`
lane's open items (see Sequencing). It was written after the
`exec/v1` lane put a real third-party image (an unmodified upstream SRE agent)
through governed publication for the first time, which made the gap visible:
the platform can prove what an image does, and it can refuse to publish an
image that has not been proven, but nobody with authority ever says "this
organization accepts this agent". Proof and acceptance are different
decisions made by different parties, and today the second one does not exist.

## Context

Governed publication (ADR-008, ADR-011 D8) is the platform's supply-chain
gate. `andyur agents package` compiles a manifest against the platform policy
(`PlatformPolicy`: tool catalog, authority ceiling, approved models, lifetime
ceiling, revision) into a sealed snapshot, and `publish_snapshot` refuses to
sign and push that snapshot unless every container runtime in it has GREEN
conformance evidence bound to the exact `image@digest` and command
(`publisher.load_conformance_evidence`, one gate per interface in
`CONFORMANCE_GATES`), the evidence is signature-verified before it is read,
and the gate that produced it hashes to the tree. The worker launches only
from a digest-pinned, cosign-verified snapshot (`registry/governed.py`).

That chain answers one question well: *does this artifact behave, on this
runtime, as the contract requires?* It does not answer the question every
enterprise asks before a third-party component reaches production: *have we,
as an organization, looked at it and accepted it?* Today the answer is
implicit. Whoever holds the publishing key and a green gate can publish, and
the only record that a human considered the image is the operator's memory.

This is a solved problem elsewhere, and the shape is the same at every layer:
an automated report, an attestation by a trusted party bound to an exact
artifact identity, and a consumer that refuses anything lacking it.
Container admission (Binary Authorization's attestors; Sigstore attestations
verified by Kyverno or the policy-controller), curated package repositories
(Sonatype Repository Firewall's quarantine-review-waive loop, JFrog Xray),
model registries (stage-transition requests approved by a permitted user),
and app-store review all work this way. The platform's contribution is not
the workflow, which it should copy, but the report: behavioral conformance
evidence from a governed runtime, which none of those systems have.

Evidence since acceptance (2026-08-26): a second, unrelated OSS agent —
Block's Goose — ran on the exec/v1 contract with **no change under
`andyur/`** (manifest, rendered config file, the unchanged conformance gate,
governed publication, the in-cluster control plane; `adr-011-exec-v1-stock-process-contract.md`,
`demos/goose/`). The certification this ADR describes therefore has two real
subjects (OpenSRE, Goose) and one unchanged gate to bind them to.

A third followed on 2026-09-13: Nous Research's Hermes Agent, again with no
change under `andyur/` (`demos/hermes/`). It changed the GATE once, and that is
worth recording because it is the kind of defect only a new workload finds: the
conformance stub answered a streamed model call with a single JSON body, so a
workload that streams -- Hermes does by default -- failed E1 while the platform
front it would meet in production forwards streams correctly. The stub now
streams, and the OpenSRE and Goose conformance evidence was re-recorded against
it. Hermes is also the first subject granted a different model
(`gemma4-andyur`), because it refuses a context window below 64K tokens.

## Decision

Introduce **certification**: a signed approval, issued by an authorized
approver for one exact `(image@digest, command, manifest)` triple after
reviewing a platform-generated report bundle, which governed publication
requires in addition to conformance evidence. Certification is an
attestation, not a database row: it is verified the same way and at the same
point as conformance evidence, so it cannot drift from it, and it travels
with the artifact.

The parts, in the order a request moves through them:

1. **Request.** A user submits a manifest for certification. The platform
   resolves it to the triple it would publish (the compiled runtime document:
   image ref, digest, command, interface, process and configuration blocks,
   granted model) and records the request against that triple. A request for
   a triple that is already certified and unexpired is answered from the
   record.
2. **Report.** The platform produces one report bundle for the triple. Every
   report is an in-toto statement whose subject is the image digest, signed
   with `cosign attest --type custom`, one predicate type per report:
   - the conformance evidence the interface's gate already produces
     (runtime-v1 G1–G6, or exec/v1 E1–E7), unchanged;
   - the behavior the conformance run OBSERVED: model requests (endpoint,
     model, count), tool calls at the MCP boundary, output size, exit path,
     and every refused request the front or sidecar answered by name;
   - the image: SBOM (Syft), vulnerability scan against that SBOM (Grype or
     Trivy), license inventory, entrypoint versus the manifest command,
     runtime uid, writable paths, and any provenance the image publishes
     (SLSA, if present);
   - the manifest: the compiled resolution, and the diff against the last
     certified version of the same agent, if any.
3. **Review.** An approver reads the bundle. Approval is itself an in-toto
   statement (predicate: approver identity, the triple, policy `revision`,
   issued-at, expires-at, the digests of the reports it was based on),
   signed with the approval key. Rejection is recorded with a reason and is
   not signed as an attestation; a rejected triple simply has no approval.
4. **Enforce.** `publish_snapshot` requires, for every container runtime, a
   valid approval attestation whose triple matches the runtime document
   being sealed and whose report digests match the reports on disk, in
   addition to the conformance evidence it requires today. The check is a
   policy evaluation (`cosign verify-attestation --policy`, Rego or CUE):
   approver in the approver set, unexpired, revision compatible, triple
   equal. The worker changes nothing: it already launches only from
   published snapshots.
5. **Re-certify.** Because the approval is bound to the triple and the
   policy revision, a new digest, a changed command or manifest block, or a
   policy revision that narrows the grant invalidates it without any
   bookkeeping. Expiry forces periodic re-review. Revocation is a signed
   statement naming the approval it revokes; the policy treats a revoked
   approval as absent.

## Compose versus build

- **Attestation format and signing: in-toto statements via cosign.** The
  platform already signs conformance evidence with `cosign sign-blob` and
  verifies snapshots with `cosign verify`; approvals and reports use the same
  tool and the same key custody. No signature code is written here.
- **Decision rule: policy, not Python.** "Approved by an authorized approver,
  unexpired, matching triple and revision" is a Rego (or CUE) policy evaluated
  by `cosign verify-attestation --policy`. The approver set and expiry window
  are policy inputs, not constants.
- **Image reports: Syft, Grype/Trivy.** Off-the-shelf, pinned by digest in
  the tooling image like cosign and oras are today, run by the report
  assembler, their output wrapped as predicates.
- **Behavioral report: the existing gates.** Nothing new is proven; the
  observation the gates already make is written down as a predicate instead
  of a log line.
- **Built by the platform, because nothing else can:** the request record
  and its states; the report assembler that runs the tools in order and
  signs each output; the approval command; the publisher check; the policy
  file; the re-certification triggers. This is the framework layer.

Rejected: a certification table in the server database as the source of
truth. A row can say "approved" while the artifact it refers to has changed;
an attestation bound to the digest cannot. The database may cache and index
attestations for the request UI; it does not decide.

Rejected: putting approval inside conformance evidence. They are produced by
different parties at different times with different authority, and one
signature covering both would let the gate's key certify on the approver's
behalf.

## D1 — Certification is bound to the triple, never to a name or a tag

An approval names `image@digest`, the exact command, and the digest of the
compiled runtime document. It does not name the agent, the manifest file, or
a tag. This is the same rule the publisher applies to conformance evidence
("production overrides the image entrypoint with the manifest command, so an
image proven under a different command was never actually tested") and it
closes the gap the review of the `exec/v1` gate found: evidence for one
process/configuration block must not certify another with the same image.

## D2 — The report is generated by the platform, never supplied by the requester

A requester submits a manifest. The platform resolves it and runs the tools.
A requester who could attach their own report bundle could attach a green
one. The one exception is provenance the image itself publishes (SLSA,
signed SBOMs), which the assembler fetches and verifies, and records as
"published by the image's builder", distinct from "observed by this
platform".

## D3 — Approval is a human act with a recorded identity, and the key is not the identity

Phase 1 signs approvals with a platform-held approval key and puts the
approver's identity in the predicate. That is enough to enforce and to audit
but it makes the key holder able to sign as anyone. The seam for phase 2 is
explicit: Sigstore keyless signing binds the signature to the approver's
OIDC identity and puts it in the transparency log, and the policy then checks
the certificate identity rather than a predicate field. The predicate schema
does not change between phases.

## D4 — The approver set is policy, and the requester is never in it for their own request

`PlatformPolicy` gains `approvers` (identities allowed to certify) and
`certification_max_age`. The policy refuses an approval whose approver is the
requester of that triple. Two approvers for an image that requests any tool
or a model outside the platform default is a policy option, not a code path.

## D5 — What the report must contain is fixed by the interface, not by the requester

Runtime-v1 agents and `exec/v1` workloads have different gates and different
observable behavior, so the report types required for each are part of
`CONFORMANCE_GATES`' sibling table, not chosen per request. A report bundle
missing a required predicate type is not reviewable and is refused before it
reaches an approver.

## D6 — Certification does not replace conformance, policy, or the run-time controls

An approval says an organization accepted the artifact after reading the
evidence. It does not widen what the artifact may do: the compiled authority
(tools, ceiling, model, lifetime) is still narrowed by policy, and the
run-time controls (bearer-gated MCP, pinned model leg, no direct egress,
bounded output) still enforce it. An approved image that misbehaves is
refused by the same controls as an unapproved one; certification only
decides whether it may be published at all.

## D7 — Requests, reviews and decisions are records the platform keeps

Every request, report, approval, rejection and revocation is stored with the
triple, the actor, the time and the reason, and is queryable by agent, by
digest and by approver. This is the audit trail an enterprise asks for and
the input to the request UI. It is a cache of attestations plus the
non-attested facts (requests, rejections), never the authority.

## Amendment 1 (2026-08-26) — asking for inputs, and what a failure may trigger

The flow above is request, report, review, approve or reject. Two things are
missing from it, both found by asking what happens when an OSS agent needs
something the platform has not granted (ADR-013), and one of them was raised by
the operator directly: a review should be requestable from a run that failed.

### D8 — Review can ask for inputs without rejecting

The flow gains one non-terminal state, `changes_requested`: an approver holds
the request open and records what the requester must supply or change. Like
rejection it is a record, not an attestation, and like rejection it is not
signed. The requester amends the manifest, which produces a new triple (D1), and
the new request carries the id of the request it answers.

Without this the only way to say "declare the binding you need and come back" is
a rejection plus an out-of-band conversation, which is exactly the part of the
decision the audit trail in D7 should keep and would lose. A request that ends
in an approval after two rounds of `changes_requested` is a better record of why
an organization accepted an agent than a request that was approved first time.

### D9 — A failed run may request a manifest review, and requesting one changes nothing by itself

Any principal who can read a run may file a review request against that run's
triple. It creates a certification request, or reopens one, with the run
attached.

- **The platform attaches the run-derived facts, never the requester.** Run id,
  final state, exit code, the recorded error, every refusal the front, sidecar
  or gateway answered by name, the trace id, and the bounded summary. This is
  D2 applied to a new input: a requester who could attach their own account of
  what the run did could attach a flattering one.
- **The requester supplies free text only, recorded as a claim attributed to
  them.** It never lands in a structured field of the report.
- **The workload's output is untrusted content in a document a human uses to
  decide.** The summary is bytes the agent chose, and an approver reading it is
  the exact reader an injected instruction wants. It is rendered as untrusted
  workload output, is never interpolated into a policy input, a structured
  predicate field, or an approver-facing instruction, and its provenance is
  stated where it is shown.
- **Filing a request does not suspend anything.** The existing approval stands
  until an approver revokes it or the manifest changes. Otherwise anyone able to
  read a run could take an approved agent out of production by filing.
- **So there must be a separate, authorized SUSPEND action**, available to the
  approver set and not to every reader. Without it an operator who has just found
  a bad image has only two levers, do nothing or revoke, and a manifest under
  review keeps launching until the review concludes. Suspension is recorded like
  every other state change and, like emergency revocation, says explicitly
  whether it reaches active runs.
- **"Marked untrusted" is a rendering convention, not a control.** It shapes what
  a human sees; it does not stop the summary being persuasive. The actual control
  is that an approval must not be DERIVABLE from the summary alone: the decision
  rests on the measured evidence fields, which is exactly why D10 has to hold
  before any of this is authoritative.
- **Three outcomes, all recorded:** no change with a reason, `changes_requested`
  to the manifest owner, or revocation.

The value is that the two questions an operator actually asks after a failure,
"is this agent still one we accept" and "does its manifest need to change", get
asked against the artifact and answered on the record, instead of in a terminal.

### D10 — An empty observation is only evidence if something measured it

The behavioral report records what the conformance run observed. An empty list
is ambiguous exactly where it matters: `tool_calls_observed: []` reads the same
whether the workload made no tool calls or nothing counted them. In an artifact
that is a presentation defect. In a document a human approves on, it is a defect
in the evidence.

Every observation the report carries states positively what was measured, in one
closed five-state vocabulary per declared capability, so that no reader has to
infer anything from an empty list:

    DECLARED       the manifest asked for it
    OBSERVED       the run exercised it, with counts
    REFUSED        an enforcement point denied it, by name, with counts
    NOT EXERCISED  measured, and the workload never used it
    NOT MEASURED   this run did not bound the question at all

`NOT EXERCISED` and `NOT MEASURED` are the two states the artifacts of the time
could not distinguish, and they are the whole finding. Containment carries the
last of those states until something constrains the workload's route and records
where it went. Beside the states: the per-method MCP counts, the model requests
by endpoint, the destinations reached, and the observation window. A report that
cannot say whether a thing was measured does not carry that thing.

The same rule condemns an absence the platform never bounded. The `exec/v1`
conformance gate USED TO run the workload on a network with a route out, so
"made no other network calls" was not a property those runs established; it now
constrains the route and records what was reached, so containment on that gate
is **OBSERVED**. The rule is unchanged by that: a report names the state it
actually established, or it says plainly that it established none. It does not
get to imply the stronger one by staying quiet. (The alternative state is described rather than named, because
a paragraph carrying both tokens tells a substring check nothing about which one
it asserts -- the same describe-rather-than-quote rule this lane has now needed
four times.)

### D11 — Declared versus observed, stated rather than inferred

For every capability the manifest requests, the report states what the run
observed for it: a binding requested and never called, a model granted and never
used, an input mode declared and exercised. An approver should not have to
notice an absence.

This is also the honest counterweight to the closed-loop limitation this ADR
already admits. A binding requested and never exercised during conformance is a
grant approved on the manifest's word, and the report should say so in those
terms.

### D12 — Third-party reach raises what the report must contain

A manifest that requests a binding under ADR-013 adds to the required predicate
set (D5): the binding's destination and transport, the ENUMERATED actions and
resources it grants in the vendor's own vocabulary together with the policy or
permission set that enforces them, the credential's custody path, and the egress
allowlist entry it implies. Never a read/write flag: ADR-013 D5 kills that axis
with its reason, since `secretsmanager:GetSecretValue` is classified as a Read
and a grant of it is a grant of exfiltration. Two approvers for a state-changing binding is a
policy option, alongside the one D4 already defines.

The public work on agentic supply chains is converging on the same inputs. A
risk-scoping bill of materials for agentic systems scores autonomy, maximum
tool-risk tier, data sensitivity, external exposure, memory persistence and
governance weakness. Four of those are facts the platform already holds at
certification time: external exposure (whether any binding reaches outside the
cluster) and governance weakness (whether an approval exists at all, and whether
it has expired), both readable from the compiled resolution today.

Two more become available only when something builds them, and saying so is the
point of listing them. **Maximum tool-risk tier** needs the binding to enumerate
actions, and `ToolBinding` carries no action field at all today, which is a
field ADR-013 D5 must build. **Memory persistence** is per-interface, not
per-platform: for `exec/v1` the workspace really is per-run and destroyed, but
`CONFORMANCE_GATES` covers runtime-v1 too, whose `AGENT_WRITABLE_PREFIXES` is a
cross-run store by design, and `workspace.py` says in its own words that it does
not stop a compromised run writing a persuasive memory for its successor. A
report that stated persistence as absent for such an agent would state a real
risk dimension as a non-risk. Autonomy and data sensitivity the platform does
not hold at all, and should not guess. Third-party reach is what moves external
exposure and, once it exists, the tool-risk tier. The
report's job is to state them, not to score them: a score is a policy opinion
and belongs where the approver set lives.

### D13 — Revocation must reach launches, not only publications

As this ADR specifies it above, `publish_snapshot` would check the approval at
publication and nowhere else (the function has no approval concept today), so
revocation would stop the next publication and nothing more. A snapshot already published and pinned in a
schedule keeps launching a revoked agent indefinitely, which makes revocation a
label rather than a control.

The worker re-evaluates the approval policy at launch against a bounded cache,
and refuses with the reason by name when the approval is absent, expired or
revoked. Two consequences are accepted deliberately: an unreachable attestation
store fails runs closed rather than launching unverified, and the cache bound is
the true revocation latency, so it is a documented deployment knob rather than a
constant.

Failing closed is only defensible with three things beside it, because the first
store outage is otherwise a total launch outage with an ambiguous cause, and
someone will add a silent fallback under pressure:

- `revocation_unavailable` is a DISTINCT refusal reason from `revoked`. "We could
  not ask" and "the answer was no" must never render the same to an operator.
- the check is a span with its duration and outcome, since the first outage will
  be diagnosed from the trace and not from a support ticket.
- a documented, time-bounded operator override exists, so the pressure that would
  otherwise produce an undocumented fallback has a supported path with an expiry.

**Two revocation semantics, not one.** Normal revocation blocks new launches and
lets active runs finish, because most revocations are hygiene. Emergency
revocation blocks launches AND terminates matching active runs, which composes
with the kill switch the platform already has rather than needing new machinery:
the server condemns and the daemon destroys the container or the process group
(`tests/test_kill_switch.py`). Without the distinction, "revoked" can still mean
"keeps operating until it finishes", which is the same class of defect as
revocation only reaching publication.

### D14 — What an approval means outside this repository, stated narrowly

An agent is stochastic and environment-dependent, so no approval may be read as
"this agent is safe" or "this agent will behave this way in production". The
defensible claim, and the only one the platform's evidence supports:

> This exact artifact, command and compiled configuration was accepted by
> organization X under governance profile Y, on evidence Z measured at time T.

Anywhere this is surfaced to a person, the behavioral section says in words that
it is **observed behavior, not a guarantee of future behavior**. If an external
name is ever needed, "approved workload" carries that meaning. Pairing the word
certified with the word agent does not, because it ascribes the decision to the
thing that runs rather than to the artifact that was judged. (Whether to adopt
that name externally is a product call and is deliberately left open here.)

That formulation is therefore banned from this lane's documents by DESCRIPTION
rather than by quotation, including here. A substring rule cannot tell rejecting
a phrase from requiring one, so quoting it in order to reject it puts it back in
the corpus. The regression test that enforces this caught exactly that mistake
in its own first run, in an earlier draft of this paragraph.

### D15 — Bind to a certification profile digest, not to a global revision

`PlatformPolicy.revision` is a single global number, so binding approvals to it
means an unrelated policy edit invalidates every approval at once. The simple
revision check is fine to ship first, but the seam belongs in the predicate
schema now: an approval binds the digest of the **certification profile** it was
judged under, meaning the authority ceiling, the required predicate set, the
runtime contract version and the applicable constraints. Then a policy change
invalidates the approvals it actually affects.

### D16 — What the report binds, enumerated

A report that does not name what it is about cannot be checked against anything
later. Each bundle binds, at minimum: the image digest; the exact command; the
compiled runtime-document digest; the runtime and interface contract version; the
conformance gate version and hash; the platform build identity; the certification
profile digest (D15); the generated configuration digest and never its secret
values; the test environment and profile; the observation window; and the schema
version of every predicate it carries.

### Amendment acceptance

7. An approver moves a request to `changes_requested` with a recorded question;
   the requester amends the manifest; the resulting request references the
   first, and both are queryable by triple.
8. A failed run produces a review request whose run-derived facts match the run
   record, whose requester text is attributed and confined to a claim field, and
   whose attached summary is marked as untrusted workload output.
9. Filing a review request against a certified triple does not prevent a launch;
   revoking its approval does, with the reason by name, and a positive control
   shows the same launch succeeding before the revocation.
10. A report whose behavioral predicate carries an unmeasured absence is refused
    before it reaches an approver, with a positive control for a report that
    states its measurement.
11. A manifest requesting a third-party binding without the ADR-013 predicates
    is refused as unreviewable, and with them present is approvable.
12. Each negative above has a mutant (accept the unmeasured absence, let the
    requester write an observation field, skip the launch-time policy check)
    that turns its test red, with the mutation asserted to have applied.

## What this gives up

- **Speed.** A new digest of an already-approved artifact needs a new
  approval. That is the point, and the report diff (D2, "against the last
  certified version") is what keeps the second review short.
- **Self-service publication.** A developer can package and prove their own
  agent but cannot publish it into a registry the workers trust without an
  approver. Deployments that do not want this leave `approvers` unset, and
  the publisher then behaves exactly as it does today; the feature is
  opt-in and off by default, like every other addition.
- **A closed loop on behavior.** The behavioral report covers what the
  conformance run observed, not everything the image could do with a
  different input. Certification is a judgment on evidence, not a proof of
  absence.

## Acceptance

1. A manifest for an unmodified third-party image is requested, reported,
   approved and published through the real tooling, and the worker launches
   it from the published snapshot.
2. The same triple with one byte changed in the command, the manifest's
   process block, or the image digest is refused by `publish_snapshot` by
   name, with the approval it found and the triple it did not match.
3. A report bundle the requester edits after generation fails verification
   before it reaches an approver.
4. An approval signed by an identity outside `approvers`, an expired
   approval, and a revoked approval are each refused by the policy, with a
   positive control that the valid approval passes.
5. With `approvers` unset, publication behaves exactly as before this ADR:
   conformance evidence alone suffices, and no certification code runs.
6. Every negative above is a regression test whose mutant (drop the triple
   match, drop the expiry, accept the requester as approver) turns it red.

## Sequencing

**Production-gaps 24, "the conformance report states absences it never
measured", blocks phase 1.** Two independent reviews reached this
separately, and the second reason is the stronger one: D9 deliberately redirects
an approver's trust AWAY from the workload's summary, on the correct grounds that
an approver is exactly the reader an injected instruction wants. That redirect
only works if there is somewhere trustworthy to send the trust, and it sends it to
the evidence fields. That gap says those fields assert absences nobody measured. So
phase 1 as written would take an unmeasured claim, make it load-bearing for a
human decision, and tell the human it is the reliable half. D9 and gap 24 are the
same defect from two ends.

The unblock condition is narrow, and either half suffices: the gate bounds the
network and the evidence is re-recorded so the sentence becomes true, or D10's
five-state labelling is applied to the EXISTING artifacts before any human
approves against them. Note that `infra/rc/evidence_currency.py` binds artifacts
by source hash and has no notion of measured versus unmeasured, so nothing
currently flags an artifact that needs it.

Also not before the `exec/v1` lane's open items close: the model pin must be the
grant (not the driver default), the conformance gate must certify against
the production front, and publication must bind evidence to the manifest.
Those are the report and the binding this ADR depends on; building the
approval on top of them while they are open would certify the wrong thing.
Phase 1 is CLI-only (`andyur agents certify request|report|approve|revoke`)
with the platform approval key; phase 2 adds the request queue and the
keyless approver identity.

The buildable form of phase 1 -- predicate schemas, the request state machine,
the decision rule, the record store and the two integration points -- is
`adr-012-oss-agent-certification.md`. One correction it makes to this ADR's
wording is worth carrying here: D1's "compiled runtime document" digest does
NOT exist in the tree today, and the existing `manifest_digest` is not it,
because it is taken from the developer manifest before the compiler narrows it
against policy.

## References

- ADR-008 (BYOA runtime), ADR-011 D7–D8 (why the digest carries the weight,
  and conformance as observed properties).
- Sigstore cosign attestations and policy verification:
  https://docs.sigstore.dev/cosign/verifying/attestation/
- Binary Authorization attestors and attestations:
  https://docs.cloud.google.com/binary-authorization/docs/key-concepts
- Sonatype Repository Firewall quarantine and waiver:
  https://help.sonatype.com/en/firewall-quarantine.html
- in-toto attestation framework: https://github.com/in-toto/attestation
- SLSA provenance: https://slsa.dev/spec/latest/provenance
- SLSA Verification Summary Attestation, the same shape as this ADR's approval
  (a verifier's decision about an artifact, consumable without re-reading every
  underlying attestation): https://slsa.dev/spec/v1.0/verification_summary
- A policy-agnostic verification attestation, discussed upstream:
  https://github.com/in-toto/attestation/issues/277
- AgentRiskBOM, risk scoping for agentic systems (autonomy, tool-risk tier, data
  sensitivity, external exposure, memory persistence, governance weakness):
  https://arxiv.org/html/2606.21877v1
- ADR-013 (third-party reach for stock workloads), the change that made the
  amendment's gaps visible.

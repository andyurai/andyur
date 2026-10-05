"""A provider with no engine behind it.

Lives here rather than in a test module because two suites need it: the SPI
tests, which use it to show the interface is satisfiable without any engine, and
the conformance suite, which runs the same bodies against it and against the
native engine.

It is a TEST DOUBLE, not a reference implementation. Where the contract leaves a
provider room, this one takes the simplest option; where the contract is
specific, it is specific, because a double that quietly violates the contract
would make the conformance suite pass for the wrong reason.
"""

from andyur.orchestration import capabilities, errors, models


class FakeProvider:
    def __init__(self, name="fake", **caps):
        self._name = name
        self._caps = capabilities.ProviderCapabilities(provider=name, **caps)
        self._started: dict[str, models.WorkflowHandle] = {}
        self._halted: set[str] = set()
        self._schedules: dict[str, models.ScheduleSpec] = {}

    @property
    def name(self):
        return self._name

    @property
    def dispatches_runs(self):
        return False

    def capabilities(self):
        return self._caps

    def health(self):
        return models.ProviderHealth(provider=self._name, reachable=True)

    def start(self, request):
        if request.workflow_id in self._started:
            return self._started[request.workflow_id]       # idempotent, per the SPI
        handle = models.WorkflowHandle(
            workflow_id=request.workflow_id, provider=self._name,
            provider_ref=f"fake-{len(self._started)}")
        self._started[request.workflow_id] = handle
        return handle

    def signal(self, workflow_id, signal):
        if workflow_id not in self._started:
            raise errors.WorkflowNotFound(workflow_id)

    def halt(self, request):
        # An unknown workflow is accepted, not refused: there is no durable
        # progress to stop, so the request is already satisfied.
        self._halted.add(request.workflow_id)
        return models.HaltOutcome(
            workflow_id=request.workflow_id, accepted=True,
            state=models.WorkflowState.HALTED,
            detail="nothing was destroyed; this provider runs nothing")

    def describe(self, workflow_id, run_ids=()):
        if workflow_id not in self._started:
            raise errors.WorkflowNotFound(workflow_id)
        state = (models.WorkflowState.HALTED if workflow_id in self._halted
                 else models.WorkflowState.RUNNING)
        return models.ProviderWorkflowState(
            workflow_id=workflow_id, state=state, provider=self._name)

    def create_schedule(self, spec):
        # Refuses an overlap rule it does not implement rather than substituting
        # the one it has -- the contract, not a courtesy.
        if spec.on_overlap != "skip_and_retry_soon":
            raise errors.ProviderCapabilityMissing(
                f"schedule overlap:{spec.on_overlap}", self._name,
                frozenset({"schedules"}))
        self._schedules[spec.schedule_id] = spec
        return models.ScheduleHandle(schedule_id=spec.schedule_id, provider=self._name)

    def update_schedule(self, spec):
        self._schedules[spec.schedule_id] = spec

    def delete_schedule(self, schedule_id):
        self._schedules.pop(schedule_id, None)              # idempotent, per the SPI

"""Governed BYOA launch adapter for the existing Kubernetes orchestrator.

This module is intentionally narrow. Kubernetes lifecycle, rollback, adoption,
network policy and Secret creation remain owned by KubernetesRunController. The
only new responsibility here is translating the control-plane's frozen runtime
envelope into the existing RunGroupSpec without consulting worker-local agent
image or command configuration.
"""

from __future__ import annotations

import os
import secrets

from .. import config, runinput
from ..agentspec.parser import _MODEL_RE
from ..config import LITELLM_URL, SERVER_URL
from ..registry.models import (RUNTIME_PROTOCOL_EXEC_V1, RUNTIME_PROTOCOL_V1,
                               RuntimeResolution)
from ..registry.runtime_wire import decode_runtime
from .kubernetes_controller import RunCredentials
from .kubernetes_manifests import (RunGroupSpec, run_group_names,
                                   run_group_names_for_identity)
from .orchestrator import (
    KubernetesOrchestrator, RunSpec, _ExecRun, _read_as_evidence)

# The worker serves exactly the protocols it can actually launch. The registry
# overlay admits the same two, but being packageable and being launchable here
# are different questions, and answering them in one place is what made the
# difference invisible -- so the set stays here, beside the launcher.
#
# exec/v1 entered this set (the flip) only once M1 held: the stock workload
# carries no runtime channel token by ANY Pod shape, and the bearer it declares
# is exactly what the serve-only proxy's /mcp accepts. That is not a sentence
# but a test -- tests/test_kubernetes_controller.py::
# test_exec_v1_is_not_launchable_unless_M1_holds reddens if exec/v1 is in this
# set while any clause of M1 is broken -- and a live gate,
# infra/kubernetes/verify-exec-tool-call.py, in which a real exec/v1 workload
# makes the call through the real serve-only services under the worker SA.
LAUNCHABLE_PROTOCOLS = frozenset({RUNTIME_PROTOCOL_V1, RUNTIME_PROTOCOL_EXEC_V1})


def validate_runtime_envelope(raw) -> RuntimeResolution:
    """Validate the assignment again at the WORKER trust boundary.

    The control plane already parsed this object from a cosign-verified
    artifact. Revalidation here is deliberate: an HTTP assignment is still
    untrusted input to the worker, and malformed transport must fail closed
    rather than causing a fallback to local image/command settings.

    An explicit command is REQUIRED here and optional at the registry. Falling
    back to the platform's `python -m andyur.agent` would make a third-party
    image execute a platform-specific entrypoint it never approved, which is a
    launch-time concern and belongs to the launcher.

    Returns the typed resolution rather than a dict. The dict it used to
    return restated EIGHT of the nine field names, sitting directly beneath a
    key set that had been derived specifically to stop this. The ninth was
    `lifecycle`: admitted by the derived key set, then dropped on the floor by
    the hand-written return. The missing one was the entire bug, so the count
    is the point.
    """
    if raw is None:
        # "Nothing was sent" and "what was sent is malformed" are different
        # field events and must not read alike. The reachable cause is an
        # assignment carrying no runtime at all -- a server that predates C2,
        # or one that did not treat this worker as registry-bound -- and the
        # generic "must be an object" sends the operator hunting transport
        # corruption instead of missing governance.
        raise config.InsecureProfile(
            "Kubernetes BYOA launch requires a governed runtime envelope; the "
            "assignment carried none, so there is no approved executable "
            "identity to launch under")
    return decode_runtime(
        raw,
        where="Kubernetes runtime envelope",
        error=config.InsecureProfile,
        protocols=LAUNCHABLE_PROTOCOLS,
        require_command=True,
    )


def _exec_input_delivery(spec: RunSpec, runtime: RuntimeResolution):
    """Decide how this run's input reaches the stock process, fail-closed.

    Returns ``(agent_args, mode, payload, max_bytes)``: the command to launch
    (the input appended for mode 'argv'), and what the controller must deliver
    by attach after the Pod exists ('stdin' to the workload, 'file' to the
    init container that persists it), or "" when there is nothing to deliver.

    The door already checked deliverability with the manifest in hand. It is
    checked AGAIN here with the envelope in hand, because an assignment is
    untrusted input at the worker and the two checks share one implementation
    (runinput.check_against_process), so they cannot disagree.
    """
    process = runtime.process
    if process is None:
        raise config.InsecureProfile(
            f"exec/v1 envelope for run {spec.run_id} carries no process block; "
            "nothing says how the task is delivered")
    runinput.check_against_process(
        spec.run_input, process, where=f"run {spec.run_id}",
        error=config.InsecureProfile)
    if process.input_mode == "none":
        return runtime.command, "", b"", 0
    payload = runinput.delivery_bytes(spec.run_input)
    if process.input_mode == "argv":
        # Appended as ONE argument, last, so the manifest's own arguments keep
        # their positions. Visible in the Pod spec and the process's cmdline,
        # the same exposure class as a literal in configuration.env.
        return (*runtime.command, payload.decode("utf-8")), "", b"", 0
    return runtime.command, process.input_mode, payload, process.input_max_bytes


class GovernedKubernetesOrchestrator(KubernetesOrchestrator):
    """Kubernetes launch where executable identity comes only from assignment."""

    def launch(self, spec: RunSpec, logfile):
        # Make accidental use of the legacy entry point fail closed. The daemon
        # must supply the runtime envelope separately via launch_governed().
        raise config.InsecureProfile(
            "governed Kubernetes launch requires the assignment runtime envelope")

    def adopt_governed(self, run_id: str, generation: str, runtime_raw):
        """Adopt a run launched by another execution worker, and re-record
        what reaping an exec/v1 run needs -- the launch recorded it in THAT
        process's memory, which died with it. The bounds come from the same
        validated runtime envelope the launch used; the Pod name is derived
        from the run and generation exactly as the launch derived it."""
        handle = self.adopt(run_id, generation)
        if runtime_raw is not None:
            runtime = validate_runtime_envelope(runtime_raw)
            if runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1 and runtime.process:
                process = runtime.process
                self._exec_runs[run_id] = _ExecRun(
                    pod=run_group_names_for_identity(run_id, generation)["agent"],
                    container="agent",
                    output_max_bytes=process.output_max_bytes,
                    capture_stdout=process.stdout,
                    capture_stderr=process.stderr,
                )
        return handle

    def launch_governed(self, spec: RunSpec, runtime_raw, logfile):
        runtime = validate_runtime_envelope(runtime_raw)

        required = {
            "assignment generation": spec.generation,
            "registry agent id": spec.registry_agent_id,
            "run token": spec.run_token,
            "channel token": spec.channel_token,
            "LiteLLM service key": self.litellm_key,
            "proxy image digest": self.proxy_image,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise config.InsecureProfile(
                "Kubernetes run launch requires " + ", ".join(missing)
                + "; refusing to fall back or launch a partially credentialed run")

        exec_v1 = runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
        if exec_v1 and spec.model is not None and not _MODEL_RE.fullmatch(spec.model):
            # The granted model becomes an environment value in the workload
            # Pod; the assignment is untrusted input at the worker, so the same
            # charset the manifest parser enforces is enforced again here.
            raise config.InsecureProfile(
                f"run {spec.run_id}: granted model {spec.model!r} is not a valid "
                "model identifier")
        exec_input_mode, exec_input, exec_input_max = "", b"", 0
        if runtime.runtime_type == "container":
            agent_image = f"{runtime.image_ref}@{runtime.image_digest}"
            agent_args = runtime.command
            resources = runtime.resources
            agent_cpu = (resources.cpu if resources else None) or "2"
            agent_memory = (resources.memory if resources else None) or "2Gi"
            if runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1:
                agent_args, exec_input_mode, exec_input, exec_input_max = \
                    _exec_input_delivery(spec, runtime)
        else:
            # Builtin is an explicit platform runtime selection, not a BYOA
            # fallback. It may therefore use the platform-owned agent image.
            if not self.agent_image:
                raise config.InsecureProfile(
                    "builtin-claude Kubernetes runtime requires the platform "
                    "agent image digest")
            agent_image = self.agent_image
            agent_args = ()
            agent_cpu = "2"
            agent_memory = "2Gi"

        run_group = RunGroupSpec(
            namespace=self.namespace,
            run_id=spec.run_id,
            generation=spec.generation,
            agent_id=spec.agent,
            registry_agent_id=spec.registry_agent_id,
            proxy_image=self.proxy_image,
            agent_image=agent_image,
            agent_args=agent_args,
            agent_runtime=runtime.runtime_type,
            # The interface, which the runtime type cannot tell you: a
            # runtime-v1 BYOA container and an exec/v1 one are both "container".
            agent_interface=runtime.interface_version or "",
            # UNRESOLVED, on purpose. The controller resolves it once the proxy
            # Pod IP exists; see _bind_exec_configuration.
            exec_configuration=runtime.configuration,
            # services.model.name for a stock workload: the granted model the
            # assignment carried (empty for runtime-v1, which reads /context).
            exec_model_name=((spec.model or "")
                             if runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
                             else ""),
            exec_input_mode=exec_input_mode,
            exec_input=exec_input,
            exec_input_max_bytes=exec_input_max,
            agent_cpu=agent_cpu,
            agent_memory=agent_memory,
            server_url=SERVER_URL,
            litellm_url=LITELLM_URL,
            llm_mode=os.environ.get("ANDYUR_LLM", "api"),
            ollama_url=os.environ.get("ANDYUR_OLLAMA_URL", ""),
            trust_domain=os.environ.get("ANDYUR_TRUST_DOMAIN", "andyur.local"),
            otel_mode=os.environ.get("ANDYUR_OTEL", "on"),
            otel_endpoint=os.environ.get("ANDYUR_OTEL_ENDPOINT", ""),
            as_token_endpoint=config.AS_TOKEN_ENDPOINT,
            as_issuer=config.AS_ISSUER,
            as_jwks_url=config.AS_JWKS_URL,
            as_client_id=config.AS_CLIENT_ID,
            as_provider=config.AS_PROVIDER,
            as_capability=config.AS_CAPABILITY,
            as_resource_scope=config.AS_RESOURCE_SCOPE,
            as_product_version=config.AS_PRODUCT_VERSION,
            as_certified=bool(config.AS_CERTIFICATION_FILE and
                              config.AS_CERTIFICATION_PUBLIC_KEY_FILE),
            broker_enabled=spec.broker_enabled,
            run_ttl_seconds=int(spec.server_run_ttl or 0),
            proxy_egress=self._proxy_egress(),
            # Local-model mode lets a builtin/runtime-v1 AGENT reach the model
            # service directly (its own credential-less client). A stock exec/v1
            # workload reaches the model ONLY through its proxy Pod's front,
            # which pins the endpoint set and the model -- so it gets no model
            # egress of its own (R MED-A, PR #22).
            agent_model_egress=(None if exec_v1 else self._agent_model_egress()),
        )

        certification = ""
        certification_public_key = ""
        if run_group.as_certified:
            certification = _read_as_evidence(
                config.AS_CERTIFICATION_FILE, "AS certification")
            certification_public_key = _read_as_evidence(
                config.AS_CERTIFICATION_PUBLIC_KEY_FILE,
                "AS certification public key")

        # exec/v1 (M1): a dedicated per-run MCP bearer, distinct from the channel
        # token, minted here for the stock workload to present to /mcp and for the
        # serve-only proxy's tool service to accept. Empty for runtime-v1, whose
        # runner mints its own MCP token over the channel.
        mcp_bearer = (secrets.token_urlsafe(32)
                      if runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
                      else "")
        handle = self.controller.launch(
            run_group,
            RunCredentials(
                spec.channel_token, spec.run_token, self.litellm_key,
                config.AS_CLIENT_SECRET, certification,
                certification_public_key, spec.broker_token or "",
                mcp_bearer=mcp_bearer),
        )
        self._generations[spec.run_id] = spec.generation
        if run_group.agent_interface == RUNTIME_PROTOCOL_EXEC_V1:
            # The daemon owns this run's completion: a stock process reports
            # nothing, so its container exit IS the run's outcome. Record what
            # reap() needs to read that exit and bound the captured output,
            # before cleanup deletes the run group and both become unreadable.
            process = runtime.process
            self._exec_runs[spec.run_id] = _ExecRun(
                pod=run_group_names(run_group)["agent"],
                container="agent",
                output_max_bytes=process.output_max_bytes,
                capture_stdout=process.stdout,
                capture_stderr=process.stderr,
            )
        return handle

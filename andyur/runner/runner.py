"""Agent runner: one OS process per run, five phases.

    1. prepare   load the run record and the agent's files
    2. prompt    assemble the sectioned prompt, save it for inspection
    3. execute   drive Claude through the SDK under a hard TTL
    4. process   extract summary, save transcript and summary.json
    5. finalize  report the outcome to the server (agent returns to idle)

The runner reports failure rather than crashing silently: any exception is
captured into the run's error field so the server never leaks a stuck agent.

Launched as:  python -m andyur.runner --agent <name> --run-id <id>
"""

import argparse
import asyncio
import dataclasses
import inspect
import json
import logging
import os
import secrets
import signal
import subprocess
import sys
import time
import tempfile

import httpx
import jwt

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from .. import config, identity, runinput
from ..config import SERVER_URL
from .. import observability, otel
from ..redact import redact as _redact
from ..runfinish import post_finish
from ..agentspec import PROTOCOL_V1
from .agentchannel import AgentChannel, _MAX_LINE, _MAX_STREAM
from .driver import (BROKER_URL, DEFAULT_MAX_TURNS, DEFAULT_MODEL, LLM_MODE,
                     OLLAMA_URL,
                     embed_text, extract_graph, open_conversation, run_agent)
from .execfront import ExecFront
from .modelproxy import ModelProxy
from . import gateway, registry_consumption, toolsidecar
from ..proxy import sidecar as proxy_sidecar
from .prompt import build_conversation_preamble, build_prompt
from .toolservice import ToolService


def describe_failure(message) -> str:
    """What to record as a failed run's error.

    Named and separate so it can be tested. It used to be an inline f-string
    over message.subtype, which produced `agent run ended with success` on a
    run that had failed: the SDK sets is_error independently of subtype, so a
    failure can carry subtype="success". Worse, it discarded the only
    diagnostic present -- the real cause ("API Error: Failed to parse JSON", a
    refusal, a tool crash) is in `result`.

    Reading `result` alone was not enough, and the reason is written into the
    SDK: `api_error_status` is documented as carrying the HTTP status "when
    is_error is True and subtype is 'success'". That is precisely the case this
    function exists for, so the first fix still emitted
    `agent run failed (subtype=success)` for the failures most likely to hit it
    -- a 429 or a 529 from the provider, where `result` is empty.

    So: try every field the SDK can put a cause in, and only fall back to the
    subtype when all of them are empty. When it does fall back on subtype
    "success", say so in words that do not read as a contradiction.
    """
    return describe_failure_fields({
        "result": getattr(message, "result", None),
        "api_error_status": getattr(message, "api_error_status", None),
        "errors": getattr(message, "errors", None),
        "permission_denials": getattr(message, "permission_denials", None),
        "stop_reason": getattr(message, "stop_reason", None),
        "subtype": getattr(message, "subtype", "unknown"),
    })


def describe_failure_fields(fields: dict) -> str:
    """describe_failure over a plain dict of the SDK's cause-bearing fields.

    Factored out so the container-split sidecar can build the identical error
    string from the fields the agent process FORWARDS -- it holds SDK dicts, not
    live ResultMessage objects. One precedence, one place, so the split and
    in-process paths cannot disagree about why a run failed.

    EVERY VALUE HERE MAY HAVE BEEN CHOSEN BY THE UNTRUSTED HALF. The split path
    hands this B's raw result dict, and protocol.sanitize fixes the EVENT's shape,
    not this dict's interior -- so a forged {"result": {...}} reached .strip() and
    raised AttributeError, and a forged {"errors": "boom"} iterated per character
    into "b; o; o; m". Type-check rather than coerce with str(), so a forged
    object cannot smuggle its repr into the run record, and bound the lengths so
    the error text stored on the run cannot be a megabyte the agent chose.
    """
    def _txt(v, limit: int = 4096) -> str:
        return v.strip()[:limit] if isinstance(v, str) else ""

    def _seq(v) -> list:
        return list(v) if isinstance(v, (list, tuple)) else []

    detail = _txt(fields.get("result"))
    if detail:
        return f"agent run failed: {detail}"
    status = fields.get("api_error_status")
    if isinstance(status, int) and not isinstance(status, bool):
        return f"agent run failed: provider returned HTTP {status}"
    if _txt(status, 32):
        return f"agent run failed: provider returned HTTP {_txt(status, 32)}"
    joined = "; ".join(_txt(e, 512) for e in _seq(fields.get("errors")) if _txt(e, 512))
    if joined:
        return f"agent run failed: {joined[:4096]}"
    denials = _seq(fields.get("permission_denials"))
    if denials:
        return f"agent run failed: {len(denials)} tool permission denial(s)"
    stop = _txt(fields.get("stop_reason"), 128)
    if stop:
        return f"agent run failed: stopped ({stop})"
    subtype = fields.get("subtype")
    subtype = subtype if isinstance(subtype, str) else "unknown"
    if subtype == "success":
        # The honest sentence. The SDK is telling us the turn structure
        # completed and the run still failed, and it gave us nothing else.
        return ("agent run failed: the SDK reported an error with no cause "
                "attached (subtype=success)")
    return f"agent run failed (subtype={subtype})"


def _advertise_host() -> str:
    """The host the agent should address this sidecar by, or "" for loopback.

    Two isolated-pod shapes need the sidecar's services bound on all interfaces
    and advertised by a name/IP the agent can resolve from ITS OWN network
    namespace: Kubernetes (separate Pods, reached by the proxy Pod IP) and the
    O1 Docker per-run network (separate netns, reached by the `sidecar` alias,
    passed as ANDYUR_ADVERTISE_HOST). Every other shape shares loopback with the
    agent, so "" selects 127.0.0.1 and nothing is exposed beyond the run."""
    if config.DEPLOYMENT == "kubernetes":
        pod_ip = os.environ.get("ANDYUR_POD_IP", "").strip()
        if not pod_ip:
            raise RuntimeError(
                "Kubernetes proxy Pod has no ANDYUR_POD_IP; cannot advertise "
                "the cross-Pod services to the agent")
        return pod_ip
    return os.environ.get("ANDYUR_ADVERTISE_HOST", "").strip()


_serve_logger = logging.getLogger("andyur.runner")


def _serve_log(message: str) -> None:
    """A serve-only log line through the `andyur.log.v1` envelope: redacted,
    stamped with the active trace/span ids (observability-exit-criteria.md 6).
    Also printed while no JSON handler is installed (a test, a bare process)."""
    text = _redact(message)
    if _serve_logger.handlers or logging.getLogger("andyur").handlers or logging.getLogger().handlers:
        _serve_logger.info(text)
    else:
        print(text, flush=True)


def _serve_event(name: str, **fields) -> None:
    """A decision on the current span, by name; telemetry changes nothing."""
    try:
        from opentelemetry import trace
        trace.get_current_span().add_event(
            name, {f"andyur.{k}": str(v) for k, v in fields.items()})
    except Exception:
        pass


# The serve-only exit's telemetry bound (seconds): well under the tool-call
# gate's PROMPT_DELETE_SECONDS (5 s) so a Pod delete stays prompt with the
# collector gone.
SERVE_ONLY_FLUSH_SECONDS = float(os.environ.get("ANDYUR_SERVE_ONLY_FLUSH_SECONDS", "2"))


def _serve_only_mcp_token() -> str:
    """The exec/v1 serve-only tool-service bearer, fail-closed.

    M1: the DEDICATED per-run MCP token the controller minted and delivered to
    this sidecar by secretKeyRef (ANDYUR_MCP_TOKEN) -- the same value the
    workload presents. It is NOT minted here: a token minted in this process
    could never reach the workload, which gets its bearer from a Secret. So
    the serve-only tool service accepts exactly the declared bearer.

    Absent is a REFUSAL, not a pass-through. ToolService(token=None) is the
    loopback posture, where the network namespace is the control; a serve-only
    sidecar binds the Pod IP for a workload in ANOTHER Pod, so token=None there
    would accept every bearer from anything the NetworkPolicy admits. Same
    shape as _advertise_host refusing a missing ANDYUR_POD_IP.
    """
    # Popped, not read: like the broker token and the LiteLLM key, it is held
    # in this process from here on and inherited by no subprocess.
    token = os.environ.pop("ANDYUR_MCP_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "exec/v1 serve-only sidecar has no ANDYUR_MCP_TOKEN; refusing to "
            "serve /mcp without the run's dedicated bearer")
    return token


# The run's stop signal, installed at execute() level so a SIGTERM that arrives
# while services are still starting is remembered rather than dropped (R LOW,
# PR #21 round 2); _serve_only_park waits on it.
_stop_state: tuple[object, asyncio.Event] | None = None   # (loop, event)


def _install_stop_handler(loop) -> asyncio.Event:
    """SIGTERM/SIGINT -> this run's stop event. The runner is the container's
    PID 1, so without a handler the kubelet's SIGTERM is not delivered at all
    and every Pod delete pays the full grace period. Recorded WITH its loop:
    an asyncio.Event binds to the loop that first waits on it, and a process
    that runs several loops in turn (the test suite) must not inherit one."""
    global _stop_state
    event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, event.set)
    _stop_state = (loop, event)
    return event


def _exec_granted_model() -> str | None:
    """The model the ASSIGNMENT granted this exec/v1 run, delivered to the
    sidecar as ANDYUR_EXEC_MODEL by the controller (the same value the
    workload's services.model.name resolved to). ONE source: the front is
    pinned to it, never to the run's context or DEFAULT_MODEL -- a model-less
    grant used to pin the platform default, a model the policy never approved
    (R MED-1). Popped, like the other per-run values. None when no model was
    granted, which the front turns into a refusal of every model call."""
    return os.environ.pop("ANDYUR_EXEC_MODEL", "").strip() or None


async def _serve_only_park(ttl_seconds: float) -> str:
    """Hold the serve-only sidecar up until the run TTL fires or the container
    is asked to stop; returns "stopped" or "ttl".

    THE RUNNER IS THE CONTAINER'S PID 1 (exec-form ENTRYPOINT), and init gets no
    default signal disposition: a SIGTERM from outside the pid namespace is
    simply not delivered unless a handler is installed. Parked on a bare
    Event().wait(), every proxy Pod delete therefore ran the full
    terminationGracePeriod (20 s) before the kubelet's SIGKILL -- paid by the
    DAEMON'S loop, inline in reap, on every exec/v1 completion (R MED-0, PR
    #21). With the handler the Pod goes in ~1 s. The park is the only long wait
    on this path, so this is where the stop is honoured; the teardown that
    follows the return is the ordinary serve-only finally.
    """
    loop = asyncio.get_running_loop()
    stop = (_stop_state[1] if _stop_state is not None and _stop_state[0] is loop
            else _install_stop_handler(loop))
    _serve_log("[runner] serve-only: parked until the workload exits, the container "
               "is stopped, or the run TTL fires")
    # `runner.serve` is the sidecar's life: how long it served and why it left
    # (observability-exit-criteria.md 1, 4). The exit reason names the same
    # values the log line carries.
    with _tracer.start_as_current_span("runner.serve") as span:
        span.set_attribute("andyur.serve.ttl_seconds", float(ttl_seconds))
        try:
            async with asyncio.timeout(ttl_seconds):
                await stop.wait()
            why = "sigterm"
        except TimeoutError:
            why = "ttl_expired"
        span.set_attribute("andyur.serve.exit", why)
    return why


def _tool_service_network() -> dict:
    """Bind + advertise for the isolated-pod shapes (Kubernetes, and the O1
    Docker per-run network); loopback everywhere else. One decision,
    `_advertise_host()`, drives the tool service, the channel, and the model
    proxy so they cannot disagree."""
    advertise = _advertise_host()
    if not advertise:
        return {}
    return {
        "host": "0.0.0.0", "advertise_host": advertise,
        # Kubernetes pins the port because its NetworkPolicy allow-lists it;
        # Docker's per-run network has a single peer, so a dynamic port (0) is
        # fine and is returned in the advertised URL.
        "port": (int(os.environ.get("ANDYUR_MCP_PORT", "8766"))
                 if config.DEPLOYMENT == "kubernetes" else 0),
    }


def _start_serve_only_services(agent: str, run_id: str, origin_trace,
                               proxy_url: str | None,
                               enforced_model: str | None = None):
    """exec/v1 (serve-only): every listener the stock workload is handed a URL for.

    Two, in start order, returned with the MCP URL: the ToolService -- the SAME
    object the runtime-v1 path serves, keyed on the DECLARED bearer
    (_serve_only_mcp_token, fail-closed) -- and then the ExecFront on the
    proxy port, which answers the Pod's readiness probe and forwards
    `/llm/*` to this sidecar's model proxy. The front starts LAST so readiness
    cannot answer before /mcp is up. Nothing here constructs a channel.

    A function rather than inline in _run_split so that the live gate
    (infra/kubernetes/verify-exec-tool-call.py) can run the REAL sidecar
    services in the real proxy image: the readiness the controller waits on
    and the /mcp the workload calls are then this code, not a stand-in.
    """
    try:
        mcp_token = _serve_only_mcp_token()
    except RuntimeError:
        _serve_event("serve.start_failed", reason="no_declared_bearer")
        raise
    tool_svc = ToolService(agent, origin_trace, run_id, token=mcp_token,
                           **_tool_service_network())
    mcp_url = tool_svc.start()
    # LOCAL-MODEL MODE (ANDYUR_LLM=ollama): there is no credential for a model
    # proxy to hold, so _start_model_proxy returns nothing -- but the workload
    # was still handed services.model.base_url on THIS Pod's proxy port. The
    # front forwards it to the cluster's Ollama itself: the model leg stays
    # observed at the proxy (ADR-011 D8) and the workload never learns the
    # model service's address (its NetworkPolicy admits only this Pod).
    upstream = proxy_url
    if upstream is None and LLM_MODE == "ollama" and OLLAMA_URL:
        upstream = OLLAMA_URL
    try:
        # Pod mode: the proxy port is FIXED (the readiness probe and the
        # workload's resolved model URL both name it); process mode: dynamic.
        # Pinned to the run's GRANTED model (services.model.name): the front
        # refuses any other model by name, as the api-mode sidecar does -- and
        # with no grant it refuses every model call (require_model): a stock
        # workload cannot learn a model any other way, and a default would be
        # one the policy never approved.
        front = ExecFront(
            upstream, host="0.0.0.0" if _advertise_host() else "127.0.0.1",
            port=config.CHANNEL_PORT if config.AGENT_SPLIT_POD else 0,
            enforced_model=enforced_model, require_model=True,
            run_id=run_id, agent=agent, origin_trace=origin_trace)
        front_url = front.start()
    except BaseException as exc:
        _serve_event("serve.start_failed", reason="front_failed_to_start",
                     error=type(exc).__name__)
        tool_svc.stop()
        raise
    _serve_log(f"[runner] serve-only: tool service on {mcp_url}, front on "
               f"{front_url} (/ready, /llm -> {upstream or 'no model proxy'})")
    return front, tool_svc, mcp_url


def _start_model_proxy():
    """Serve the agent's model calls from THIS process, holding the credential.

    Returns (base_url, proxy) or (None, None) when there is nothing to hold --
    a local model, a subscription login, or no broker configured, in which case
    the agent talks to its backend directly as before.
    """
    # Read the credential, then remove it from this process's environment in
    # EVERY mode: the daemon delivers it whenever the server minted one, and
    # anything left in os.environ is inherited by every subprocess this process
    # spawns (the SDK merges os.environ under its overrides). The proxy holds it
    # in memory from here on. This does not rewrite /proc/<pid>/environ -- the
    # uid split is what keeps that from the agent -- it stops inheritance.
    token = os.environ.pop("ANDYUR_BROKER_TOKEN", "")
    if LLM_MODE != "api" or not BROKER_URL or not token:
        return None, None
    advertise = _advertise_host()
    # Bind all interfaces only when the agent is in a separate netns/Pod and must
    # reach us by an advertised name; otherwise keep the proxy on loopback.
    proxy = (ModelProxy(BROKER_URL, credential=token, host="0.0.0.0",
                        advertise_host=advertise)
             if advertise else ModelProxy(BROKER_URL, credential=token))
    url = proxy.start()
    # Logged because "is the agent talking through the proxy or straight to the
    # broker?" is otherwise invisible, and the two look identical from outside.
    print(f"[runner] model proxy on {url} -> {BROKER_URL}", flush=True)
    return url, proxy

async def _stop_all(*stops) -> None:
    """Run every teardown, even when one of them fails.

    ORDERING IS NOT ENOUGH, which is what an earlier fix tried. Each of these
    holds a different credential -- the gateway holds the run token, the model
    proxy holds the provider credential -- and `channel.stop()` awaits the serve
    task and RE-RAISES whatever it raised (agentchannel.py catches only
    TimeoutError and CancelledError). A port already held by a leftover pod is
    enough to make it raise, and with a plain sequence that exception escapes the
    `finally` entirely: every later stop is skipped, the run is left `running`
    until the reaper, and a live credential holder outlives it.

    Each entry is (name, callable). A callable that blocks is the caller's
    problem to wrap in to_thread; this only guarantees that all of them run.
    """
    for name, stop in stops:
        if stop is None:
            continue
        try:
            result = stop()
            if inspect.isawaitable(result):
                await result
        except Exception as exc:                       # noqa: BLE001
            try:
                print(f"[runner] {name} did not stop cleanly "
                      f"({type(exc).__name__}: {exc}); continuing teardown",
                      flush=True)
            except Exception:                          # noqa: BLE001
                # The REPORT must not be able to break the guarantee. With an
                # ENOSPC print this raised out after the first stop and skipped
                # every later one -- the precise failure this helper exists to
                # prevent, reintroduced by its own logging. `withhold()` below
                # already guards its print for the same reason.
                pass


def _claim_of(run_token: str | None, key: str):
    """Read one claim out of this run's OWN grant, without verifying it.

    Not a trust decision. The server signed this token and is about to be shown
    it again; verifying here would need the signing secret, which is exactly what
    a runner must not hold. What travels onward is the RESULT of the four-term
    intersection the server already computed, so this reads a decision rather
    than making a second one.
    """
    import base64
    if not run_token:
        return None
    try:
        payload = run_token.split(".")[0]
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(raw).get(key)
    except Exception:                                  # noqa: BLE001
        return None


def _delegated_scope(scope):
    """The scope for the DELEGATED tool exchange: the run scope minus INTERNAL
    own-storage actions.

    Bare files:read/write govern the agent's OWN context and memory on Andyur's
    side (reached with the run token, never the sidecar), so they are never
    delegated to an external tool. They must not enter the tool exchange: an
    external AS has no mapping for them, and a strict scope map (correctly)
    refuses the WHOLE call on an unmapped action -- leaving them in withholds
    EVERY tool. Qualified variants (files:read@account=X name external, pinned
    data) ARE delegated and stay. `None` (unrestricted) passes through.

    Single source of truth for what is internal: registry.INTERNAL_ACTIONS.
    """
    if scope is None:
        return None
    from ..server.registry import INTERNAL_ACTIONS
    return [a for a in scope if a not in INTERNAL_ACTIONS]


def _pin_as_rar(pin) -> str | None:
    """The pin as an RFC 9396 authorization detail.

    Andyur's internal pin is `{"team": "checkout"}`; the detail an authorization
    server registers is `{"type": "andyur_pin", "identifier": "checkout"}`. These
    were two vocabularies for one fact with nothing translating between them, so
    anything Andyur produced was refused `invalid_authorization_details`. The
    translation lives on the way OUT, so there is still exactly one internal
    representation of a pin.
    """
    if not pin:
        return None
    # `datatypes` carries the pin's KEY. Andyur's pin is {"team": "checkout"} and
    # the dimension matters: a resource server asks "was this minted for the TEAM
    # I am being asked about", and a detail that says only "checkout" cannot
    # answer it. RFC 9396 sec 2 defines `datatypes` as a registered member, so
    # this is the standard's own field rather than one invented here.
    return json.dumps(
        [{"type": "andyur_pin", "identifier": str(v), "datatypes": [str(k)]}
         for k, v in sorted(dict(pin).items())],
        separators=(",", ":"))


def _fetch_subject_token(run_token: str | None,
                         andyur_actor_token: str | None = None,
                         *, include_subject: bool = False):
    """This run's subject token, over the run-scoped API.

    Fetched rather than read from the environment: in the non-pod shape the agent
    shares a uid with this process and can read /proc/<pid>/environ.

    Absent is an ordinary answer -- with no external authorization server there
    is nothing to present one to. A FAILURE is also absent rather than fatal,
    because the gateway's preflight is what decides whether a tool is offered and
    two components with an opinion on that is one too many.
    """
    if not config.AS_TOKEN_ENDPOINT or not run_token:
        return None
    run_id = _claim_of(run_token, "r")
    if not run_id:
        return None
    try:
        headers = identity.run_token_header()
        if andyur_actor_token:
            headers["Authorization"] = f"Bearer {andyur_actor_token}"
        r = httpx.get(f"{config.SERVER_URL}/runs/{run_id}/subject-token",
                      headers=headers, timeout=5.0)
        if r.status_code != 200:
            # "tool egress", not one broker's name: this helper serves the
            # gateway and sidecar paths alike, and a sidecar run's identity
            # failures must not grep as gateway failures.
            print(f"[runner] tool egress: no subject token ({r.status_code}); "
                  "the exchange will fail closed", flush=True)
            return None
        payload = r.json()
        if include_subject:
            return (payload.get("subject_token"), payload.get("expected_subject"),
                    payload.get("expected_actor"))
        return payload.get("subject_token")
    except Exception as exc:                           # noqa: BLE001
        print(f"[runner] tool egress: no subject token ({type(exc).__name__}); "
              "the exchange will fail closed", flush=True)
        return None


def _fetch_actor_token(audience: str) -> str | None:
    """This run's own JWT-SVID, presented to the AS as WHO IS ACTING.

    Fetched from the Workload API socket, which in the sandbox is the sidecar
    mount and attests this container's run labels -- so `act.sub` in the issued
    token is the RUN's SPIFFE ID, not the agent's name. Two concurrent runs of
    one agent are two principals at the tool (identity finding I2).

    The caller chooses the relying party. Andyur's preflight and an external AS
    are distinct audiences and must never be handed the same JWT-SVID merely
    because both exchanges happen during one launch.
    """
    try:
        token = identity.fetch_token(audience=audience)
        claims = jwt.decode(token, options={"verify_signature": False})
        remaining = int(claims["exp"]) - int(time.time())
        if _run_deadline is None:
            required = RUN_TTL_SECONDS + 60
        else:
            required = max(int(_run_deadline - time.time()), 0) + 60
        if remaining < required:
            raise ValueError(
                f"JWT-SVID lifetime {remaining}s is shorter than the remaining "
                f"run plus refresh margin ({required}s)")
        return token
    except Exception as exc:                           # noqa: BLE001
        print(f"[runner] tool egress: no actor SVID ({type(exc).__name__}: {exc}); "
              "the exchange will fail closed", flush=True)
        return None


def _start_tool_egress(agent: str, mcp_servers: dict, *,
                       partitioned: tuple[dict, dict] | None = None,
                       selected_model: str | None = None):
    """Stand up this run's egress boundary -- the per-run tool sidecar -- the
    way _start_model_proxy stands up the model one.

    Returns (mcp_servers_for_the_agent, sidecar_or_None). When no configured
    tool asks for platform authority AND the model leg has nothing to carry,
    the agent's toolset is returned unchanged and nothing is started, so an
    agent with only stdio or unauthenticated tools costs nothing.
    """
    registry_authoritative = partitioned is not None
    managed, passthrough = (partitioned if registry_authoritative
                            else gateway.split_tools(mcp_servers))
    sidecar_llm = LLM_MODE == "api" and selected_model is not None
    if not managed and not sidecar_llm:
        return (passthrough if registry_authoritative else mcp_servers), None
    return _start_tool_sidecar(agent, managed, passthrough,
                               selected_model=selected_model)


def _start_tool_sidecar(agent: str, managed: dict, passthrough: dict, *,
                        selected_model: str | None = None):
    """The sidecar counterpart of the agentgateway path above (ADR-003): one
    loopback listener that strips the agent's headers, mints the delegated token
    per audience, and presents the run's X509-SVID to the tool.

    Same contract and same guarantees as the gateway path: returns
    (mcp_servers_for_the_agent, stoppable_or_None), NEVER raises, and on any
    doubt returns only `passthrough` -- a managed tool handed back with its real
    URL is an unauthenticated call, the one outcome worse than the tool being
    missing. In API mode this same listener also owns /llm, injects the shared
    LiteLLM credential, and enforces the manifest-selected model.
    """
    def withhold(reason: str, names) -> tuple[dict, None]:
        try:
            print(f"[runner] tool sidecar: {reason}; withholding {sorted(names)} "
                  "rather than calling them unauthenticated", flush=True)
        except Exception:                             # noqa: BLE001
            # Same argument as the gateway path: SAYING we withheld is best
            # effort, WITHHOLDING is not.
            pass
        return passthrough, None

    # EVERYTHING below is inside this try, for the reason documented on the
    # gateway path: this runs outside the block that tears the other services
    # down, so an escape here strands the model proxy with the run's credential.
    srv = None
    # Where the agent reaches this sidecar's /llm and /tools. Loopback shapes
    # (agent shares the netns) keep 127.0.0.1; the isolated-pod shapes (k8s, and
    # the O1 Docker per-run network where the agent is single-homed) bind all
    # interfaces and advertise the routable name (`sidecar` alias / pod IP), so
    # the URL handed to the agent resolves from ITS netns. Missing this made the
    # api+LiteLLM pod path hand the agent an unreachable loopback /llm under O1.
    advertise = _advertise_host()
    bind_host = "0.0.0.0" if advertise else "127.0.0.1"
    try:
        # Which egress carries the tools is otherwise invisible exactly when it
        # matters: a run whose tools were all withheld prints no per-tool line.
        print(f"[runner] tool egress: sidecar ({agent})", flush=True)
        llm_enabled = LLM_MODE == "api" and selected_model is not None
        llm_url = config.LITELLM_URL if llm_enabled else ""
        llm_key = os.environ.pop("LITELLM_MASTER_KEY", "") if llm_url else ""
        if llm_enabled and (not llm_url or not llm_key):
            return withhold("API mode requires ANDYUR_LITELLM_URL and the "
                            "sidecar-held LITELLM_MASTER_KEY", managed)
        if not managed:
            ident = proxy_sidecar.RunIdentity("", lambda: "", lambda: {})
            srv = toolsidecar.ToolSidecar(
                router=toolsidecar.router_from_managed({}), identity=ident,
                scope=None, pin=None, gateway_url=llm_url,
                llm_master_key=llm_key, enforced_model=selected_model,
                trusted_traceparent=otel.current_traceparent(),
                host=bind_host, advertise_host=advertise or None)
            base = srv.start()
            print(f"[runner] model egress: {base}/llm -> {llm_url} "
                  f"(model {selected_model})", flush=True)
            return passthrough, srv
        run_token = identity.run_token_header().get(identity.RUN_TOKEN_HEADER)
        if not run_token:
            return withhold("this run has no run token to authenticate the "
                            "exchange with", managed)
        andyur_actor_token = _fetch_actor_token(identity.SERVER_AUDIENCE)

        # Reachability, before the agent is promised anything, for the reason
        # the gateway path probes: an unreachable upstream surfaces as a failed
        # MCP `initialize`, which is no session at all -- the agent loses the
        # tool with a transport error and nothing anywhere says why.
        reachable, refused = gateway.preflight(managed)
        for name, why in refused.items():
            print(f"[runner] tool sidecar: {name} WITHHELD, {why}", flush=True)
        if not reachable:
            return withhold("no declared tool server is reachable", managed)
        delegated_names = {name for name, cfg in reachable.items()
                           if cfg.get("credential_mode", "managed") == "managed"}
        if gateway.discovery_enabled():
            # Said out loud because the gateway path HAS this control: an
            # operator who turned on RFC 9728 discovery and switched egress
            # must not believe it is still confirming anything.
            print("[runner] tool sidecar: RFC 9728 endpoint discovery is not "
                  "applied on this egress; the registry/manifest is the "
                  "binding authority for its resource identifiers", flush=True)

        # WHO the exchange presents. The subject is fetched once (it is the
        # run's sealed grant, not rotating material); the actor and the mTLS
        # material stay behind callables because the sidecar re-presents them
        # across the run and a rotation must be a fresh fetch. Empty-string
        # fallbacks fail CLOSED downstream: asclient.exchange refuses an empty
        # leg, and the local mint reads neither.
        fetched_subject = (_fetch_subject_token(
            run_token, andyur_actor_token, include_subject=True)
            if delegated_names else ("", ""))
        if isinstance(fetched_subject, tuple):
            if len(fetched_subject) == 3:
                subject_token, expected_subject, expected_actor = fetched_subject
            else:
                subject_token, expected_subject = fetched_subject
                expected_actor = None
        else:
            # Compatibility for injected test doubles. The external-AS path
            # below refuses a missing trusted subject; local minting does not
            # inspect an external token response.
            subject_token, expected_subject, expected_actor = fetched_subject, None, None
        subject_token = subject_token or ""
        if config.AS_TOKEN_ENDPOINT and delegated_names:
            # Keyed on AS_TOKEN_ENDPOINT exactly as the gateway path is.
            # `AS_ISSUER or SERVER_AUDIENCE` would fail OPEN here: with an
            # external AS and no issuer configured, the fallback hands a
            # Andyur-audience SVID to the adopter's AS -- the cross-relying-
            # party reuse _fetch_actor_token's own contract forbids.
            actor_audience = config.AS_ISSUER
            if (not subject_token or not expected_subject or not expected_actor
                    or not _fetch_actor_token(actor_audience)):
                # The gateway refuses this combination before starting; tools
                # promised and then refused 502-by-502 are the same fact
                # discovered later, per call, with the AS blamed.
                return withhold("the external-AS exchange is missing its "
                                "subject or actor leg", reachable)
        else:
            actor_audience = identity.SERVER_AUDIENCE
        ident = proxy_sidecar.RunIdentity(
            subject_token=subject_token,
            expected_subject=expected_subject or "",
            expected_actor=expected_actor or "",
            actor_token=lambda: _fetch_actor_token(actor_audience) or "",
            mtls_material=lambda: identity.export_tls_pems("runner"))
        scope = _delegated_scope(_claim_of(run_token, "sc"))
        try:
            audience_ceiling = _claim_of(run_token, "au")
        except KeyError:
            # Compatibility for injected/test claim readers written before the
            # audience claim existed; a real grant reader already returns None.
            audience_ceiling = None
        pin = _pin_as_rar(_claim_of(run_token, "pn"))

        if audience_ceiling is not None and "*" not in audience_ceiling:
            reachable = {name: cfg for name, cfg in reachable.items()
                         if cfg["audience"] in audience_ceiling}
            if not reachable:
                return withhold("the registry audience ceiling refused every "
                                "declared tool", managed)

        # The most likely field failure on this egress, probed here so it gets
        # a NAMED refusal: build_app loads this material eagerly, and without
        # the probe a missing Workload API surfaces as `unexpected ...` from
        # inside construction after the budgeted loops above.
        try:
            ident.mtls_material()
        except Exception as exc:                      # noqa: BLE001
            return withhold(
                "this run has no X509-SVID material for the sidecar's mTLS "
                f"tool client ({type(exc).__name__}: {exc}); is the SPIRE "
                "Workload API reachable?", reachable)

        # WHERE the token is minted. With an external AS configured the sidecar
        # exchanges there directly (build_app's default, asclient.exchange, with
        # the subject and actor legs above); otherwise at Andyur's own
        # /oauth/token, authenticated by the run token, which already fixes the
        # actor, the user and the pin server-side.
        if config.AS_TOKEN_ENDPOINT or not delegated_names:
            exchange_fn = None
        else:
            server = gateway._server_host_port()
            if not server:
                return withhold("no external AS is configured and Andyur's own "
                                "mint is not addressable over http", reachable)
            exchange_fn = gateway.local_exchange(
                run_token, server, actor_token=andyur_actor_token)

            # POSITIVE CONTROL, per audience, through the same mint the sidecar
            # will use at call time: a listening endpoint is not a working
            # exchange, and the default ANDYUR_AGENT_AUTH=off refuses every one.
            # Each probe is REBUILT with the remaining budget
            # rather than reusing `exchange_fn`, whose fixed timeout belongs to
            # the run's later mints: budget-gating only the loop entry lets the
            # last admitted probe overshoot the budget by its whole timeout.
            # Local mint only: preflighting an external AS would spend a real
            # delegated credential there per audience, and its refusals already
            # surface per-call with the AS's own reason.
            verdicts: dict[str, str | None] = {}
            mint_deadline = time.monotonic() + gateway.MINT_BUDGET
            for name in sorted(delegated_names):
                audience = reachable[name]["audience"]
                if audience in verdicts:
                    continue
                left = mint_deadline - time.monotonic()
                if left <= 0:
                    verdicts[audience] = (
                        f"not checked: the {gateway.MINT_BUDGET}s budget for "
                        "verifying the mint was spent on earlier audiences")
                    continue
                probe = gateway.local_exchange(
                    run_token, server, timeout=left,
                    actor_token=andyur_actor_token)
                try:
                    probe(audience=audience, scope=scope)
                    verdicts[audience] = None
                except Exception as exc:              # noqa: BLE001
                    verdicts[audience] = str(exc)
            granted = {n: c for n, c in reachable.items()
                       if n not in delegated_names or not verdicts[c["audience"]]}
            for name in sorted(delegated_names - set(granted)):
                print(f"[runner] tool sidecar: {name} WITHHELD, the mint "
                      f"refused a token for {reachable[name]['audience']}: "
                      f"{verdicts[reachable[name]['audience']]}", flush=True)
            if not granted:
                return withhold("the mint refused every declared audience",
                                reachable)
            reachable = granted

        # Construction is INSIDE the try on purpose: build_app creates the mTLS
        # tool client eagerly, so a run with no X509-SVID (SPIRE down, identity
        # off) raises HERE, and must withhold rather than escape.
        srv = toolsidecar.ToolSidecar(
            router=toolsidecar.router_from_managed(reachable),
            identity=ident, scope=scope, pin=pin,
            gateway_url=llm_url, llm_master_key=llm_key,
            enforced_model=selected_model,
            trusted_traceparent=otel.current_traceparent(),
            exchange_fn=exchange_fn,
            host=bind_host, advertise_host=advertise or None)
        base = srv.start()
        agent_view = toolsidecar.agent_tool_config(base, reachable, passthrough)
        # Named individually, and INSIDE the try that owns `srv`: print() can
        # raise (ENOSPC, non-UTF-8 stdout), and by now a started sidecar holds
        # the run's material -- a log line must not strand it.
        for name, cfg in reachable.items():
            print(f"[runner] tool sidecar: {name} -> {cfg['url']} "
                  f"(aud {cfg['audience']}) via {base}/tools/{name}", flush=True)
        if llm_url:
            print(f"[runner] model egress: {base}/llm -> {llm_url} "
                  f"(model {selected_model})", flush=True)
    except Exception as exc:                          # noqa: BLE001
        if srv is not None:
            try:
                srv.stop()
            except Exception:                         # noqa: BLE001
                # stop() does not raise today; the guarantee must not depend on
                # that staying true.
                pass
        return withhold(f"unexpected {type(exc).__name__}: {exc}", managed)
    return agent_view, srv


RUN_TTL_SECONDS = int(os.environ.get("ANDYUR_RUN_TTL_SECONDS", "900"))

# When the bounded run clock starts (armed beside each asyncio.timeout below).
# Actor-SVID freshness is judged against what REMAINS of the run, not the full
# bound: the SPIRE agent serves cached JWT-SVIDs down to half their TTL, so a
# late tool call in a long run would otherwise be refused over a token that
# still comfortably outlives the run. Before the clock is armed there is no
# remainder to measure, so the full bound applies and short tokens fail closed.
_run_deadline: float | None = None


def _arm_run_deadline() -> None:
    global _run_deadline
    _run_deadline = time.time() + RUN_TTL_SECONDS
# in-flight halt poll: how often to check, and how long the check may stay
# unavailable before failing closed (so a brief server blip is tolerated)
HALT_POLL_SECONDS = float(os.environ.get("ANDYUR_HALT_POLL_SECONDS", "5"))
HALT_POLL_MESSAGES = int(os.environ.get("ANDYUR_HALT_POLL_MESSAGES", "5"))
HALT_FAIL_CLOSED_SECONDS = float(os.environ.get("ANDYUR_HALT_FAIL_CLOSED_SECONDS", "60"))
# Run-path logs are the andyur.log.v1 envelope on STDOUT (trace/span ids
# stamped), where `kubectl logs` and the gates read them.
observability.configure_logging("andyur-runner", stream=sys.stdout, root=True)
_tracer = otel.setup_tracing("andyur-runner")
TRACE_TOOL_PAYLOADS = os.environ.get(
    "ANDYUR_OTEL_TOOL_PAYLOADS", "off").lower() in ("1", "on", "true")


# Redact secret-shaped values so credentials never land in traces or the saved
# transcript: a run's tool input/output and message stream would otherwise leak
# the provider key, bearer tokens, JWTs, or its own run token (R2).
#
# HONEST SCOPE, because this comment used to claim more. The redactor module is
# shared with the server, but the server only re-redacts on ONE path: the
# conversation turn/event channel. Everything the runner PUTs to
# /agents/{name}/files/... -- transcripts, summaries, memory -- is stored exactly
# as sent. So redaction of the mind is runner-only, and a runner that forgot to
# call it would write the secret through. Making it a property of the storage
# boundary is the fix; saying it already is one was the bug.


def _span_str(x, n: int = 600) -> str:
    """A compact, single-line, secret-redacted string for a span attribute."""
    s = x if isinstance(x, str) else json.dumps(x, default=str)
    s = _redact(" ".join(s.split()))
    return s if len(s) <= n else s[:n] + " ..."


def _set_tool_payload(span, attribute: str, value) -> None:
    """Keep customer payloads out of default persistent trace storage."""
    if TRACE_TOOL_PAYLOADS:
        span.set_attribute(attribute, _span_str(value))
    else:
        span.set_attribute(f"{attribute}_captured", False)


def _message_record(message) -> dict:
    try:
        data = dataclasses.asdict(message)
    except (TypeError, ValueError):
        data = {"repr": repr(message)}
    return {"type": type(message).__name__, "data": data}


async def _put_file(api, agent: str, relpath: str, content: str, run_id: str):
    """Write a run artifact to the mind through the server (not to disk), so
    the runner needs no storage access and can be fully sandboxed. Returns the
    response so a caller can react to a non-2xx -- the client does not raise on
    4xx, so a 413 (body over the server's cap) is otherwise indistinguishable
    from success."""
    return await api.put(
        f"/agents/{agent}/files/{relpath}",
        json={"content": content, "actor": "runner", "run_id": run_id},
    )


def _transcript_refusal_warning(resp, body: str) -> str | None:
    """The WARNING message when a transcript PUT was refused, or None when it was
    persisted. The runner's HTTP client does not raise on 4xx, so a 413 (the
    transcript exceeded the server's ANDYUR_MAX_REQUEST_BYTES cap) is otherwise
    indistinguishable from success and the run's audit record drops silently.
    The in-process runner accumulates the transcript across many turns with no
    single-stream bound, so this is reachable even above a generous cap."""
    if resp is None or resp.is_success:
        return None
    return (f"the {len(body.encode())}-byte conversation transcript was refused "
            f"({resp.status_code}) and NOT persisted; the run's audit record is "
            f"lost -- raise ANDYUR_MAX_REQUEST_BYTES if large transcripts are "
            f"expected")


async def _fetch_context(api, agent: str) -> dict:
    """The agent's run context, FAILING CLOSED on a non-2xx.

    A registry-bound agent whose authoritative manifest cannot be resolved makes
    /context return 503 (the server refuses to fall back to the mutable legacy
    mind). That must stop the run HERE, at the boundary, rather than returning an
    error body that later fails as an incidental KeyError on a missing field.
    """
    resp = await api.get(f"/agents/{agent}/context")
    resp.raise_for_status()
    return resp.json()


async def _registry_tool_partition(api, run_id: str, ctx: dict):
    """Fetch and validate the reduced tool descriptor for a bound run.

    None means a legacy/unbound agent. A bound agent never falls back to its
    mutable workspace mcp.json: endpoint failure, binding mismatch, or wire
    contract drift aborts preparation.
    """
    expected = ctx.get("registry_agent_id")
    if not expected:
        return None
    response = await api.get(f"/runs/{run_id}/registry-tools")
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("registry_agent_id") != expected:
        raise registry_consumption.UnlaunchableResolution(
            "run-tools response does not match the context registry binding")
    descriptors = payload.get("tools")
    if not isinstance(descriptors, list):
        raise registry_consumption.UnlaunchableResolution(
            "run-tools response has no descriptor list")
    return registry_consumption.managed_from_descriptors(descriptors)


async def _tool_inputs(api, agent: str, run_id: str, ctx: dict):
    """Return (legacy MCP config, optional authoritative registry partition)."""
    partitioned = await _registry_tool_partition(api, run_id, ctx)
    if partitioned is not None:
        return {}, partitioned
    return await _load_mcp(api, agent), None


async def _tool_inputs_or_finish(api, agent: str, run_id: str, ctx: dict):
    """Prepare tools or terminally fail the assigned run before launch.

    Registry outages must not leave a pending run holding its agent slot until
    the reaper. The failure is named and finalization is bounded like the normal
    finish path; None tells each execution shape to stop before starting local
    services.
    """
    try:
        if LLM_MODE == "api":
            has_url = bool(config.LITELLM_URL)
            has_key = bool(os.environ.get("LITELLM_MASTER_KEY"))
            if has_url != has_key:
                raise registry_consumption.UnlaunchableResolution(
                    "API sidecar model egress requires ANDYUR_LITELLM_URL and "
                    "a sidecar-held LITELLM_MASTER_KEY together")
        return await _tool_inputs(api, agent, run_id, ctx)
    except Exception as exc:  # noqa: BLE001 - boundary normalizes all failures
        error = f"registry tool preparation failed: {_redact(str(exc))}"
        finalized, _ = await post_finish(api, run_id, summary=None, error=error)
        print(f"runner: {error}", flush=True)
        if not finalized:
            print("runner: could not confirm terminal run state after retries; "
                  "leaving it for the reaper", flush=True)
        return None


async def _load_mcp(api, agent: str) -> dict:
    """Load this agent's external tool servers from its mcp.json (in the mind).
    Returns {name: config} for the Claude Agent SDK, or {} if the agent has no
    custom tools. Best-effort: a missing or malformed file just means no extra
    tools, never a failed run."""
    try:
        r = await api.get(f"/agents/{agent}/files/mcp.json")
        if r.status_code != 200:
            return {}
        servers = json.loads(r.json()["content"]).get("mcpServers", {})
        return servers if isinstance(servers, dict) else {}
    except Exception as exc:
        print(f"[mcp] skipped custom tools: {type(exc).__name__}: {exc}", flush=True)
        return {}


async def _recall_for(api, agent: str, run: dict, ctx: dict) -> str:
    """Query the memory graph with this run's wakeup context (why it was woken,
    unread messages, open tasks) and format the relevant subgraph for prompt
    injection. Best-effort: empty string on any issue, so recall never blocks."""
    try:
        wakeup = " ".join(filter(None, [
            run.get("reason", ""),
            " ".join(m.get("body", "") for m in ctx.get("messages", [])),
            " ".join(t.get("title", "") for t in ctx.get("tasks", [])),
        ]))
        r = await api.get(
            f"/agents/{agent}/graph/recall", params={"q": wakeup, "limit": 5}
        )
        r.raise_for_status()
        seeds = r.json()
        if not seeds:
            return ""
        lines = []
        for s in seeds:
            lines.append(f"- **{s['name']}** ({s['type']})")
            for f in s.get("facts", []):
                arrow = "->" if f["dir"] == "out" else "<-"
                lines.append(f"    {arrow} {f['predicate']} {f['other']}")
        return "\n".join(lines)
    except Exception as exc:
        print(f"[recall] skipped: {type(exc).__name__}: {exc}", flush=True)
        return ""


async def _capture(api, agent, run_id, ctx, summary, proxy_url=None) -> None:
    """Capture this run into the memory graph: record the summary as an episode,
    extract entities + facts (seeded by the agent's purpose), embed entities
    locally, and write it all through the graph API. Best-effort: any failure is
    logged and skipped, never propagated, so capture cannot fail a run."""
    try:
        await api.post(
            f"/agents/{agent}/graph/episodes",
            json={"text": summary, "run_id": run_id},
        )
        profile = ctx.get("profile") or {}
        purpose = "\n".join(filter(None, [
            profile.get("description", ""), profile.get("scope", ""),
            (ctx.get("knowledge") or "")[:800],
        ])) or "general-purpose agent"
        # feed back the types this agent already coined so its ontology converges
        try:
            tr = await api.get(f"/agents/{agent}/graph/types")
            known_types = tr.json() if tr.status_code == 200 else []
        except Exception:
            known_types = []
        g = await extract_graph(purpose, summary, known_types, proxy_url)
        for e in g["entities"]:
            name = str(e.get("name", "")).strip()
            if not name:
                continue
            vec = await embed_text(f"{name}: {e.get('type', '')}")
            await api.post(
                f"/agents/{agent}/graph/entities",
                json={"name": name, "type": e.get("type", "entity"),
                      "run_id": run_id, "embedding": vec},
            )
        for f in g["facts"]:
            s, p, o = f.get("subject"), f.get("predicate"), f.get("object")
            if s and p and o:
                await api.post(
                    f"/agents/{agent}/graph/facts",
                    json={"subject": s, "predicate": p, "object": o,
                          "run_id": run_id},
                )
        print(f"[capture] {len(g['entities'])} entities, {len(g['facts'])} facts",
              flush=True)
    except Exception as exc:
        print(f"[capture] skipped: {type(exc).__name__}: {exc}", flush=True)


async def _halted(api, workflow_id: str | None):
    """In-flight kill-switch check. Returns True (halted), False (active/none),
    or None if the check could NOT be made -- the caller fails CLOSED after
    repeated None, so a kill-switch cannot be defeated by making the check fail."""
    if not workflow_id:
        return False
    try:
        r = await api.get(f"/workflows/{workflow_id}")
        if r.status_code != 200:
            return None  # denied/error -> unavailable, fail closed after the window
        return r.json().get("state") == "halted"
    except Exception:
        return None


async def _post_reply(api, run_id: str, kind: str, body: str = "") -> None:
    """Append one reply event, best-effort. A lost event must never crash the
    session: the operator's next poll simply misses it."""
    try:
        await api.post(f"/runs/{run_id}/reply", json={"kind": kind, "body": body})
    except Exception as exc:
        print(f"runner: reply({kind}) failed ({_redact(str(exc))})", flush=True)


def _record_llm_response(model: str, *, blocks: int = 0) -> None:
    """Record an observed provider/SDK response for every execution shape.

    This is deliberately gateway-neutral. It says a response crossed the model
    boundary; it does not pretend to measure wire latency when the SDK owns that
    HTTP call in another process.
    """
    with _tracer.start_as_current_span("llm.response") as span:
        span.set_attribute("gen_ai.operation.name", "chat")
        span.set_attribute("gen_ai.request.model", model)
        span.set_attribute("gen_ai.response.model", model)
        span.set_attribute("andyur.model", model)
        span.set_attribute("andyur.llm_mode", LLM_MODE)
        span.set_attribute("andyur.llm.response_blocks", blocks)


def _start_llm_request(model: str):
    """Start the duration-bearing model wait span under the current run span."""
    span = _tracer.start_span("llm.request")
    span.set_attribute("gen_ai.operation.name", "chat")
    span.set_attribute("gen_ai.request.model", model)
    span.set_attribute("andyur.model", model)
    span.set_attribute("andyur.llm_mode", LLM_MODE)
    return span


async def _stream_turn(api, client, run_id: str, transcript: list,
                       model: str = DEFAULT_MODEL) -> dict:
    """Drive ONE turn: the query was already sent; stream the agent's reply,
    posting each text block to the operator (redacted) and recording every SDK
    message to the transcript. Returns the ResultMessage meta for this turn."""
    meta: dict = {}
    pending_llm = _start_llm_request(model)
    try:
        async for message in client.receive_response():
            transcript.append(_redact(json.dumps(
                _message_record(message), default=str)))
            if isinstance(message, AssistantMessage):
                if pending_llm is not None:
                    pending_llm.end()
                    pending_llm = None
                _record_llm_response(model, blocks=len(message.content))
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text:
                        # redact BEFORE it leaves the process: a reply must never
                        # carry the provider key, run token, or a JWT to the operator
                        await _post_reply(api, run_id, "chunk", _redact(block.text))
            elif isinstance(message, UserMessage):
                # Tool results cause the SDK to issue the next model request.
                if pending_llm is None:
                    pending_llm = _start_llm_request(model)
            elif isinstance(message, ResultMessage):
                meta = {
                    "num_turns": message.num_turns,
                    "session_id": message.session_id,
                    "is_error": message.is_error,
                    "subtype": getattr(message, "subtype", None),
                }
    finally:
        if pending_llm is not None:
            pending_llm.end()
    return meta


async def _run_conversation(api, agent: str, run_id: str, run: dict, parent) -> int:
    """Persistent conversational session. Every headless security property holds
    (scoped run token, isolation, redaction, halt kill-switch); the session is
    additionally bounded on every axis (idle, wall-clock, per-turn, turn count,
    turn size) so it can never pin a slot or burn cost without limit."""
    wf_id = run.get("workflow_id")
    with _tracer.start_as_current_span(f"conversation {agent}", context=parent) as span:
        span.set_attribute("andyur.run_id", run_id)
        span.set_attribute("andyur.agent", agent)
        span.set_attribute("andyur.run_type", "conversation")
        span.set_attribute("andyur.workflow_id", wf_id or "")

        # phase 1: prepare (mind + per-agent tool servers). instructions are
        # server-overridden in ctx for a registry-bound agent; model comes from
        # ctx["registry_model"] (else default).
        ctx = await _fetch_context(api, agent)
        selected_model = registry_consumption.model_from_ctx(ctx) or DEFAULT_MODEL
        span.set_attribute("andyur.model", selected_model)
        tool_inputs = await _tool_inputs_or_finish(api, agent, run_id, ctx)
        if tool_inputs is None:
            span.set_attribute("andyur.result", "failed")
            return 1
        mcp_servers, registry_tools = tool_inputs
        preamble = build_conversation_preamble(ctx, run)

        # start the run; 409 => halted/cancelled between assignment and start
        started = await api.post(f"/runs/{run_id}/start")
        if started.status_code == 409:
            return 0
        started.raise_for_status()

        scratch = tempfile.mkdtemp(prefix=f"andyur-{run_id}-")
        origin_trace = otel.current_traceparent()
        # Same correction as execute(): a service START belongs inside the guard.
        # Outside it, a sidecar that will not come up escaped this coroutine after
        # the run was already marked started, leaving it `running` for the reaper.
        # Pre-bound because the teardown and the post-loop stop reference them.
        tool_gateway = None
        proxy = None
        proxy_url = None
        transcript: list[str] = []
        error: str | None = None
        turns_done = 0
        first = True

        session_start = time.monotonic()
        last_activity = time.monotonic()
        first_halt_error: float | None = None
        POLL = 1.0

        try:
            mcp_servers, tool_gateway = _start_tool_egress(
                agent, mcp_servers, partitioned=registry_tools,
                selected_model=selected_model)
            if (LLM_MODE == "api"
                    and config.LITELLM_URL):
                if tool_gateway is None:
                    raise RuntimeError("unified model sidecar failed to start")
                os.environ.pop("ANDYUR_BROKER_TOKEN", None)
                proxy_url, proxy = f"{tool_gateway.base_url}/llm", None
            else:
                proxy_url, proxy = _start_model_proxy()
            # open_conversation opens the scratch dir for the agent uid itself
            async with open_conversation(
                agent, scratch, origin_trace, run_id,
                extra_mcp_servers=mcp_servers, proxy_url=proxy_url,
                model=selected_model,
            ) as client:
                while True:
                    now = time.monotonic()
                    # --- session-level bounds (checked between turns) ---
                    if now - session_start > config.CONVERSATION_MAX_SECONDS:
                        await _post_reply(api, run_id, "session_end", "session time limit reached")
                        break
                    if now - last_activity > config.CONVERSATION_IDLE_SECONDS:
                        await _post_reply(api, run_id, "session_end", "closed: idle timeout")
                        break
                    if turns_done >= config.CONVERSATION_MAX_TURNS:
                        await _post_reply(api, run_id, "session_end", "turn limit reached")
                        break
                    # kill-switch: a halted workflow ends the session at once. The
                    # check FAILS CLOSED like the headless path -- if it stays
                    # unavailable for a sustained window, end the session, so the
                    # kill-switch cannot be defeated by making the check fail.
                    halt = await _halted(api, wf_id)
                    if halt is True:
                        await _post_reply(api, run_id, "session_end", "halted")
                        error = "conversation halted"
                        break
                    if halt is None:
                        if first_halt_error is None:
                            first_halt_error = now
                        elif now - first_halt_error >= HALT_FAIL_CLOSED_SECONDS:
                            await _post_reply(api, run_id, "session_end",
                                              "closed: halt check unavailable")
                            error = "halt check unavailable; failing closed"
                            break
                    else:
                        first_halt_error = None

                    # --- pull the next human turn (server beats liveness for us) ---
                    try:
                        r = await api.get(f"/runs/{run_id}/next-turn")
                        if r.status_code in (401, 404, 409):
                            error = "run token/record no longer valid"
                            break
                        r.raise_for_status()
                        turn = r.json().get("turn")
                    except Exception as exc:
                        # transient: back off and retry within the idle window
                        print(f"runner: next-turn poll failed ({_redact(str(exc))})", flush=True)
                        await asyncio.sleep(POLL)
                        continue
                    if turn is None:
                        await asyncio.sleep(POLL)
                        continue
                    if turn.get("kind") == "close":
                        await _post_reply(api, run_id, "session_end", "closed by operator")
                        break

                    # --- process one message turn ---
                    body = turn.get("body") or ""
                    transcript.append(_redact(json.dumps(
                        {"turn": turn.get("seq"), "human": body}, default=str)))
                    query = (preamble + "\n\n---\n\nHuman: " + body) if first else body
                    first = False
                    turns_done += 1
                    meta: dict = {}
                    try:
                        async with asyncio.timeout(config.CONVERSATION_TURN_TTL_SECONDS):
                            await client.query(query)
                            meta = await _stream_turn(
                                api, client, run_id, transcript, selected_model)
                        await _post_reply(api, run_id, "turn_end")
                    except (TimeoutError, asyncio.TimeoutError):
                        # a turn that will not complete leaves the SDK client in an
                        # indeterminate state; end the session rather than risk it
                        await _post_reply(api, run_id, "error", "turn exceeded time limit")
                        await _post_reply(api, run_id, "session_end", "closed: a turn timed out")
                        error = "conversation turn TTL exceeded"
                        break
                    # a turn that ended in an SDK error (e.g. the CLI exited) leaves
                    # the persistent client unusable, so end the session cleanly with
                    # a clear reason rather than crashing on the next query()
                    if meta.get("is_error"):
                        await _post_reply(api, run_id, "session_end",
                                          f"closed: agent turn ended ({meta.get('subtype')})")
                        error = f"conversation turn error: {meta.get('subtype')}"
                        break
                    last_activity = time.monotonic()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            await _post_reply(api, run_id, "error", "the session ended unexpectedly")
        finally:
            # Every stop runs, whatever any other one does. Each holds a
            # different credential, so one failure must not skip the rest --
            # ordering alone does not give that. to_thread because stop() joins
            # for up to 5s and this can chain several: done inline they add up to
            # a frozen runner loop during teardown.
            await _stop_all(
                ("the tool gateway", (lambda: asyncio.to_thread(tool_gateway.stop))
                 if tool_gateway is not None else None),
                ("the model proxy", proxy.stop if proxy is not None else None),
            )

        # phase 4/5: persist transcript (best-effort) and finalize the run
        summary = f"conversation: {turns_done} turn(s)"
        error = _redact(error) if error else error  # never persist a secret in error
        try:
            body = "\n".join(transcript) + "\n"
            resp = await _put_file(api, agent,
                                   f"runs/{run_id}/transcript.jsonl", body, run_id)
            warning = _transcript_refusal_warning(resp, body)
            if warning:
                print(f"runner: WARNING {warning}", flush=True)
        except Exception as exc:
            print(f"runner: WARNING writing conversation transcript failed "
                  f"({_redact(str(exc))})", flush=True)
        ok, why = await post_finish(api, run_id, summary=summary, error=error)
        if not ok:
            print(f"runner: conversation finish failed ({why})", flush=True)
        span.set_attribute("andyur.result", "failed" if error else "done")
    otel.flush()
    return 1 if error else 0


# Control-plane secrets the sidecar must never place in the agent process's
# environment. The agent (B) reaches the model proxy and the tool service on
# loopback; it needs none of these, and the CLI it spawns must not inherit them.
# Concurrently-OPEN tool spans. A tool_use with no matching tool_result is never
# popped and lives until the loop ends, and both the id and the pairing are
# chosen by the untrusted half -- so the byte budget on the wire does not bound
# this at all. Measured: an 86-byte event buys ~3.5 KB of open span, so the
# 64 MiB the channel permits converts to several GB of sidecar memory and an OOM
# of the half holding every credential. Bound what is RETAINED, not just what is
# SENT.
_MAX_OPEN_TOOL_SPANS = int(os.environ.get("ANDYUR_MAX_OPEN_TOOL_SPANS", "512"))


def _open_tool_span(tool_spans: dict, span_id, span) -> None:
    """Register an open tool span, evicting the oldest when the cap is reached.

    A diagnostic must never cost more memory than the run it describes. dict
    preserves insertion order, so the first item is the oldest."""
    while len(tool_spans) >= _MAX_OPEN_TOOL_SPANS:
        _oldest, _sp = next(iter(tool_spans.items()))
        _sp.set_attribute("andyur.tool_incomplete", True)
        _sp.set_attribute("andyur.tool_evicted", True)
        _sp.end()
        del tool_spans[_oldest]
    tool_spans[span_id] = span


def _as_number(value):
    """A number the untrusted side sent, or None.

    protocol.sanitize fixes the SHAPE of an event; these fix the types INSIDE the
    result object, which the sidecar goes on to float(), redact and store. bool is
    excluded deliberately: it is an int subclass, and a cost of True is not a
    cost."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _as_text(value):
    """A string the untrusted side sent, or None. Anything else is dropped
    rather than coerced with str(), so a forged object cannot smuggle a repr into
    the run record."""
    return value if isinstance(value, str) else None


def _launch_agent_process(channel_url: str, channel_token: str | None):
    """Spawn the credential-less agent process (B) that drives the SDK and
    forwards its stream to this sidecar. Its own session group, so the sidecar
    can kill the whole tree (B, the CLI, any shell the agent ran) at once.

    The channel token travels by ENVIRONMENT, never argv: /proc/<pid>/cmdline is
    world-readable, so a token on B's command line is readable by ANY uid on the
    host or in the container. In the environment it is at least owner-only.

    BE PRECISE ABOUT WHAT THAT BUYS, PER MODE -- this comment used to claim more
    than is true, and the difference is the whole point of the split:

      process mode  B runs at the sidecar's uid and the CLI is dropped to 1001 by
                    the setpriv wrapper, so /proc/<B>/environ really is out of the
                    agent's reach.
      pod mode      B and the CLI are BOTH uid 1001 in the same container, so the
                    agent CAN read /proc/<B>/environ. Verified: it does.
                    os.environ.pop() does not help -- /proc/<pid>/environ is the
                    exec-time snapshot and cannot be rewritten.

    So in pod mode nothing in B's environment is a secret from the agent, and the
    design does not depend on one being: B is handed NO credential at all (see
    orchestrator._agent_argv), and the channel token unlocks only the runtime-v1
    context/events channel -- whose context the workload is meant to read -- while forgery is blocked by
    the channel's one-stream guard, not by the token. The token's job is to keep
    a THIRD container that joins the namespace off the port.

    The rule this leaves behind, which matters more than the fix: in pod mode,
    never put anything in B's environment that the agent may not have."""
    from . import agentenv
    env = agentenv.allowed(os.environ, channel_token=channel_token)
    argv = [sys.executable, "-m", "andyur.agent", "--channel-url", channel_url]
    return subprocess.Popen(argv, env=env, start_new_session=True)


def _runtime_v1_context(*, agent_id: str, run_id: str, prompt: str,
                        run_input: str | None,
                        selected_model: str | None, model_base_url: str,
                        mcp_url: str, mcp_headers: dict,
                        extra_mcp_servers: dict, traceparent: str | None) -> dict:
    """Build the public, immutable context served to an untrusted workload.

    This is deliberately a projection rather than a renamed internal input
    dictionary: only protocol fields cross the runtime boundary, and the
    advertised byte limits are the exact values AgentChannel enforces.
    """
    return {
        "protocol_version": PROTOCOL_V1,
        "run_id": run_id,
        "agent_id": agent_id,
        "model": selected_model,
        "input": {
            "prompt": prompt,
            # The structured field the protocol reserved (section 3): present
            # only when the trigger handed this run an input, and then the
            # caller's value itself, not a rendering of it.
            **({"data": runinput.value_of(run_input)} if run_input else {}),
        },
        "services": {
            "model_base_url": model_base_url,
            "mcp_url": mcp_url,
            "mcp_headers": dict(mcp_headers),
            "extra_mcp_servers": dict(extra_mcp_servers),
        },
        "limits": {
            "deadline": None,
            "max_line_bytes": _MAX_LINE,
            "max_stream_bytes": _MAX_STREAM,
        },
        "trace": {"traceparent": traceparent},
    }


def _kill_agent_process(proc) -> None:
    """SIGKILL the agent process's whole group. Never the sidecar's own group:
    if B were somehow in it (it never is -- start_new_session), signalling the
    group would take the sidecar down with it, so refuse and kill B alone."""
    if proc is None or proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    if pgid == os.getpgid(0):
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def _watch_agent_process(proc, channel: AgentChannel) -> None:
    """Fail fast when B dies without completing its stream. Without this a B that
    crashes before (or during) forwarding would leave the sidecar blocked on the
    message queue until the run TTL -- turning an instant failure into a long
    hang. inject_done is idempotent, so a clean finish already seen wins."""
    while proc.poll() is None:
        await asyncio.sleep(0.2)
    code = proc.returncode if proc.returncode is not None else -1
    await channel.inject_done(
        code, f"agent process exited (code {code}) before completing the stream")


async def _watch_agent_container(channel: AgentChannel, timeout: float) -> None:
    """Pod mode's equivalent of the process watchdog.

    Here the agent is a separate CONTAINER launched by the daemon, so this
    process has no handle to poll -- there is no exit code to notice. What it can
    notice is that the agent never turned up. Bound the wait, so an agent image
    that cannot start fails the run in a named way instead of holding it, and its
    slot, until the run TTL."""
    try:
        await asyncio.wait_for(channel.connected.wait(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        await channel.inject_done(
            -1, f"the agent container never connected within {timeout:.0f}s")


async def _run_split(api, agent: str, run_id: str, run: dict, parent,
                     serve_only: bool = False) -> int:
    """Headless run as the container split: a sidecar (this process) holding the
    run token and serving the tools + model proxy, and a separate agent process
    forwarding its SDK stream here. Every property of the in-process headless
    path holds -- scoped token, redaction on receipt, halt kill-switch, TTL,
    isolation -- with the message SOURCE moved from an in-process SDK generator
    to the A<->B channel, and the run token no longer in the process that spawns
    the untrusted CLI at all."""
    with _tracer.start_as_current_span(f"runner {agent}", context=parent) as run_span:
        run_span.set_attribute("andyur.run_id", run_id)
        run_span.set_attribute("andyur.agent", agent)
        run_span.set_attribute("andyur.agent_spiffe_id", run.get("agent_spiffe_id") or "")
        run_span.set_attribute("andyur.workflow_id", run.get("workflow_id") or "")
        run_span.set_attribute("andyur.split", True)

        # phase 1: prepare (same as the in-process headless path)
        with _tracer.start_as_current_span("runner.prepare"):
            ctx = await _fetch_context(api, agent)
            selected_model = registry_consumption.model_from_ctx(ctx) or DEFAULT_MODEL
            # instructions are server-overridden in ctx, so the prompt built
            # below inherits them; the manifest model is threaded to the split
            # agent through the channel inputs (see below) for model parity.
            open_tasks = (await api.get("/tasks", params={"assignee": agent})).json()
            ctx["tasks"] = [t for t in open_tasks if t["state"] != "closed"]
            ctx["messages"] = (
                await api.get("/messages", params={"recipient": agent, "state": "unread"})
            ).json()
            tool_inputs = await _tool_inputs_or_finish(api, agent, run_id, ctx)
            if tool_inputs is None:
                run_span.set_attribute("andyur.result", "failed")
                return 1
            mcp_servers, registry_tools = tool_inputs

        # phase 2: prompt
        with _tracer.start_as_current_span("runner.prompt"):
            if ctx.get("graph_enabled"):
                ctx["graph_recall"] = await _recall_for(api, agent, run, ctx)
            prompt = build_prompt(ctx, run)
            await _put_file(api, agent, f"runs/{run_id}/prompt.md", prompt, run_id)
            started = await api.post(f"/runs/{run_id}/start")
            if started.status_code == 409:
                return 0
            started.raise_for_status()

        summary: str | None = None
        error: str | None = None
        meta: dict = {}
        transcript: list[str] = []
        tool_spans: dict = {}

        with _tracer.start_as_current_span("runner.execute") as exec_span:
            exec_span.set_attribute("andyur.llm_mode", LLM_MODE)
            exec_span.set_attribute(
                "andyur.model", selected_model)
            origin_trace = otel.current_traceparent()

            # SAY WHICH SHAPE THIS RUN ACTUALLY TOOK. Without it, "the runner ran
            # the split" and "the runner silently ran un-split" produce identical
            # logs -- which is exactly how a missing ANDYUR_AGENT_SPLIT in the
            # container went unnoticed: every harness passed either way, because
            # a run that is less split still works.
            print(f"[runner] split={config.AGENT_SPLIT_MODE} "
                  f"(agent runs {'in its own container' if config.AGENT_SPLIT_POD else 'as a separate process'})",
                  flush=True)
            # A holds these; B and the CLI merely use them over loopback.
            # The agent (B) is handed loopback URLs, never the upstream address
            # or the token. In pod mode A and B share a netns, so the same
            # 127.0.0.1 the model proxy relies on reaches this too.
            # EVERY service start is guarded, which this comment used to claim
            # while the three starts below it sat OUTSIDE the try. A failure
            # starting the tool sidecar or the model proxy -- a port collision, a
            # bad image, a sidecar that will not come up -- therefore escaped
            # after the run was marked started, leaking the others and stranding
            # the run 'running' for the reaper: the exact outcome the sentence
            # promised it prevented. Now the starts are inside, so a failure
            # tears the others down and finalizes the run as failed.
            tool_gateway = None
            proxy = None
            proxy_url = None
            tool_svc: ToolService | None = None
            front: ExecFront | None = None
            channel: AgentChannel | None = None
            proc = None
            watchdog: asyncio.Task | None = None
            wf_id = run.get("workflow_id")
            last_poll = 0.0
            msgs_since_poll = 0
            first_poll_error: float | None = None
            try:
                mcp_servers, tool_gateway = _start_tool_egress(
                    agent, mcp_servers, partitioned=registry_tools,
                    selected_model=selected_model)
                if (LLM_MODE == "api"
                        and config.LITELLM_URL):
                    if tool_gateway is None:
                        raise RuntimeError("unified model sidecar failed to start")
                    os.environ.pop("ANDYUR_BROKER_TOKEN", None)
                    proxy_url, proxy = f"{tool_gateway.base_url}/llm", None
                else:
                    proxy_url, proxy = _start_model_proxy()
                if serve_only:
                    # exec/v1 serve-only: the stock workload reaches the model
                    # proxy and the MCP tool service BY URL and reports NOTHING
                    # back. Do NOT construct a channel at all. A channel would
                    # hand a hostile exec/v1 image a result/done sink whose done
                    # drives _put_file (summary.json, transcript.jsonl) and
                    # _capture (the memory graph) under THIS run's token -- a
                    # write path ADR-011 says exec/v1 does not have. There is no
                    # agent to connect and no stream to consume; serve the front
                    # (readiness + /llm), the model proxy and the tool service
                    # until the workload exits (the daemon reads its container
                    # exit and tears the group down) or the run TTL fires. The
                    # DAEMON owns completion (worker-finish), so this side never
                    # posts /start-less: it DID post /start above, and it never
                    # posts /finish. Returning here runs the finally below
                    # (tears down the front, proxy + tool service) and skips the
                    # channel, the connect watchdog, and the finalize block.
                    front, tool_svc, mcp_url = _start_serve_only_services(
                        agent, run_id, origin_trace, proxy_url,
                        enforced_model=_exec_granted_model())
                    _arm_run_deadline()
                    try:
                        why = await _serve_only_park(RUN_TTL_SECONDS)
                    except asyncio.CancelledError:
                        why = "cancelled"
                    _serve_log(f"[runner] serve-only: leaving ({why})")
                    # The spans still open here (runner.execute, the root) end
                    # as the enclosing `with` blocks close on this return; the
                    # BOUNDED export of everything happens once, in main().
                    return 0
                mcp_token = secrets.token_urlsafe(32) if config.AGENT_SPLIT_TOKENS else None
                # POD MODE: the agent is a container the DAEMON launched, so the
                # daemon -- the only party that talks to both halves -- minted the
                # channel credential and handed each of us a copy. Minting our own
                # here would produce a secret the agent could never present.
                # PROCESS MODE: this process spawns the agent, so it mints it.
                if config.AGENT_SPLIT_POD:
                    channel_token = os.environ.get("ANDYUR_CHANNEL_TOKEN") or None
                    channel_port = config.CHANNEL_PORT
                else:
                    channel_token = (secrets.token_urlsafe(32)
                                     if config.AGENT_SPLIT_TOKENS else None)
                    channel_port = 0
                advertise = _advertise_host()
                tool_svc = ToolService(
                    agent, origin_trace, run_id, token=mcp_token,
                    **_tool_service_network())
                mcp_url = tool_svc.start()
                inputs = _runtime_v1_context(
                    agent_id=ctx.get("registry_agent_id") or agent,
                    run_id=run_id,
                    prompt=prompt,
                    run_input=run.get("input"),
                    selected_model=selected_model,
                    model_base_url=proxy_url,
                    mcp_url=mcp_url,
                    mcp_headers=({"Authorization": f"Bearer {mcp_token}"}
                                 if mcp_token else {}),
                    extra_mcp_servers=mcp_servers,
                    traceparent=origin_trace,
                )
                # The channel binds all interfaces whenever the agent is in a
                # separate netns/Pod (advertise set) and reaches it by the
                # advertised name; otherwise loopback. Under O1 the UNTRUSTED
                # agent reaches this only over the per-run internal network it is
                # single-homed on, so it cannot reach the sidecar's other
                # (SANDBOX_NETWORK) interface at all. Binding 0.0.0.0 also exposes
                # the port on that SANDBOX_NETWORK interface, i.e. to the framework
                # (server/worker) and sibling sidecars -- NOT the same as
                # Kubernetes NetworkPolicy, which would gate that interface too.
                # The channel and tool service are token-gated, so that exposure
                # is inert; the model proxy is not (see _start_model_proxy), so
                # its SANDBOX_NETWORK exposure is a trusted-plane residual bounded
                # by the per-run broker token and SVID TTL (compromised-sidecar,
                # not agent, threat). Recorded in docs/network-topology.md.
                channel_host = "0.0.0.0" if advertise else "127.0.0.1"
                channel = AgentChannel(
                    inputs, token=channel_token, host=channel_host, port=channel_port)
                channel_url = await channel.start()
                if config.AGENT_SPLIT_POD:
                    # Nothing to spawn: the agent container is already coming up
                    # beside us and will connect on its own. Watch for it never
                    # arriving instead of watching a process exit.
                    watchdog = asyncio.create_task(
                        _watch_agent_container(channel, config.AGENT_CONNECT_TIMEOUT))
                else:
                    proc = _launch_agent_process(channel_url, channel_token)
                    watchdog = asyncio.create_task(_watch_agent_process(proc, channel))
                pending_llm = _start_llm_request(selected_model)
                _arm_run_deadline()
                _arm_run_deadline()
                async with asyncio.timeout(RUN_TTL_SECONDS):
                    async for ev in channel.messages():
                        transcript.append(
                            _redact(json.dumps(ev.get("record", {}), default=str)))
                        if ev.get("record", {}).get("type") == "AssistantMessage":
                            if pending_llm is not None:
                                pending_llm.end()
                                pending_llm = None
                            _record_llm_response(
                                selected_model,
                                blocks=len(ev.get("texts", [])) +
                                len(ev.get("tools", [])))
                        msgs_since_poll += 1
                        # in-flight kill-switch, identical cadence to the
                        # in-process path: wall-clock OR a burst of messages,
                        # failing closed only after a sustained unavailable window.
                        now_m = time.monotonic()
                        if wf_id and (now_m - last_poll >= HALT_POLL_SECONDS
                                      or msgs_since_poll >= HALT_POLL_MESSAGES):
                            last_poll = now_m
                            msgs_since_poll = 0
                            wf_state = await _halted(api, wf_id)
                            if wf_state is True:
                                error = "workflow halted mid-run"
                                break
                            if wf_state is None:
                                if first_poll_error is None:
                                    first_poll_error = now_m
                                elif now_m - first_poll_error >= HALT_FAIL_CLOSED_SECONDS:
                                    error = "halt check unavailable; failing closed"
                                    break
                            else:
                                first_poll_error = None
                        for text in ev.get("texts", []):
                            print(text, flush=True)
                        for t in ev.get("tools", []):
                            pretty = str(t.get("name", "")).replace(
                                "mcp__", "").replace("__", "/")
                            sp = _tracer.start_span(f"tool:{pretty}")
                            sp.set_attribute("andyur.tool", t.get("name", ""))
                            _set_tool_payload(
                                sp, "andyur.tool_input", t.get("input", ""))
                            _open_tool_span(tool_spans, t.get("id"), sp)
                        for r in ev.get("results", []):
                            sp = tool_spans.pop(r.get("tool_use_id"), None)
                            if sp is not None:
                                res = r.get("content")
                                if isinstance(res, list):
                                    res = " ".join(x.get("text", "") for x in res
                                                   if isinstance(x, dict))
                                _set_tool_payload(sp, "andyur.tool_result", res)
                                if r.get("is_error"):
                                    sp.set_attribute("andyur.tool_error", True)
                                sp.end()
                        if (ev.get("record", {}).get("type") == "UserMessage"
                                and ev.get("results") and pending_llm is None):
                            pending_llm = _start_llm_request(selected_model)
                        if ev.get("result"):
                            result = ev["result"]
                            # COERCE, do not trust. Every value here was chosen by
                            # the untrusted half, and two of them are used outside
                            # the guard below -- a forged total_cost_usd of "free"
                            # raised out of the whole function past finalization,
                            # so one JSON field stranded the run 'running' and
                            # pinned its worker slot until the reaper ~17min later.
                            summary = _as_text(result.get("result"))
                            meta = {
                                "num_turns": _as_number(result.get("num_turns")),
                                "total_cost_usd": _as_number(result.get("total_cost_usd")),
                                "session_id": _as_text(result.get("session_id")),
                                "is_error": bool(result.get("is_error")),
                                "usage": result.get("usage"),
                            }
                            if result.get("is_error"):
                                error = describe_failure_fields(result)
            except TimeoutError:
                error = f"run exceeded TTL of {RUN_TTL_SECONDS}s"
            except Exception as exc:
                # Covers both a failed service startup and a consume-loop error.
                error = f"{type(exc).__name__}: {exc}"
            finally:
                if locals().get("pending_llm") is not None:
                    pending_llm.end()
                    pending_llm = None
                # WHAT TEARDOWN MEANS HERE DEPENDS ON THE SHAPE, and claiming
                # otherwise overstated it:
                #
                #   process mode  proc is B; SIGKILL its group and the agent, its
                #                 CLI and every shell it started die at once.
                #   pod mode      proc is None BY CONSTRUCTION -- B is a container
                #                 this process has no handle on and deliberately
                #                 no Docker socket for. Destroying it is the
                #                 daemon's job (kill on the condemn beat, cleanup
                #                 when this container exits, sweep after a restart).
                #                 What we CAN do here is sever the channel and the
                #                 tool service, which stops the agent ACTING as
                #                 the platform; stopping it EXECUTING is bounded
                #                 by the heartbeat interval.
                _kill_agent_process(proc)      # a no-op in pod mode, by design
                if watchdog is not None:
                    watchdog.cancel()
                # EVERY stop runs, whatever any other one does. `channel.stop()`
                # re-raises whatever its serve task raised, and with a plain
                # sequence that skipped every later stop and left a live
                # credential holder outliving the run. Nothing after this point
                # needs a tool: graph capture is a model call.
                await _stop_all(
                    ("the tool gateway",
                     (lambda: asyncio.to_thread(tool_gateway.stop))
                     if tool_gateway is not None else None),
                    ("the tool service", tool_svc.stop if tool_svc is not None else None),
                    ("the exec front", front.stop if front is not None else None),
                    ("the agent channel", channel.stop if channel is not None else None),
                )
                tool_gateway = None
                # A RUN WITH NOTHING LEFT TO DO STOPS SPENDING NOW. The proxy
                # normally outlives this block so graph capture (itself a model
                # call) can use it, and capture requires a summary -- so when
                # there is no summary, holding the credential open buys nothing
                # and leaves a reachable way to spend through the finalize
                # retries. That is exactly the halt and TTL case.
                #
                # The condition is `summary is None`, NOT `error is not None`:
                # those are not the same set. A ResultMessage can carry BOTH a
                # summary and is_error, so keying on the error killed the proxy
                # for every failed-with-a-message run and silently disabled its
                # graph capture -- which swallows its own errors, so nothing
                # would have said so.
                if summary is None and proxy is not None:
                    proxy.stop()
                    proxy = None

            for sp in tool_spans.values():
                sp.set_attribute("andyur.tool_incomplete", True)
                sp.end()
            # A clean stream that never carried a result, or a B that died: take
            # the channel's done-sentinel error as the cause. channel is None only
            # if startup failed before it was built, in which case error is set.
            if summary is None and error is None:
                done = (channel.done if channel is not None else None) or {}
                # _as_text, because the done sentinel is the agent's too: a
                # forged {"error": {...}} reached _redact below, which calls
                # re.sub on it and raises TypeError on a dict.
                error = _as_text(done.get("error")) or "run produced no result message"
            # A DIAGNOSTIC MUST NEVER COST A RUN ITS FINALIZATION. These are span
            # attributes; everything below them -- the transcript, summary.json,
            # and /runs/{id}/finish -- is the run's actual outcome. They sit
            # outside the guard above, so an exception here skipped all of it.
            try:
                if meta.get("num_turns") is not None:
                    exec_span.set_attribute("andyur.num_turns", meta["num_turns"])
                if meta.get("total_cost_usd") is not None:
                    exec_span.set_attribute("andyur.cost_usd", float(meta["total_cost_usd"]))
            except Exception as exc:
                print(f"runner: cost/turn span attributes skipped "
                      f"({type(exc).__name__})", flush=True)

        if serve_only:
            # exec/v1: the healthy serve-only path RETURNED inside the try, so
            # reaching here means a service failed to start (the missing-bearer
            # refusal above, a port collision). The sidecar must not take the
            # completion path even then: no summary/transcript write, no
            # capture, no /finish -- the daemon is the sole completer (H2/MED5)
            # and reads the WORKLOAD's container exit. Exit non-zero instead, so
            # the proxy Pod goes unready and the controller rolls the group back.
            _serve_log(f"runner: serve-only sidecar failed to start: "
                       f"{_redact(error or 'unknown error')}")
            if proxy is not None:
                proxy.stop()
            run_span.set_attribute("andyur.result", "failed")
            # bounded like the healthy exit: a failed start with the collector
            # down must not hold the Pod for the exporter's retries (R MED-6)
            otel.shutdown_bounded(SERVE_ONLY_FLUSH_SECONDS)
            return 1

        summary = _redact(summary) if summary else summary
        error = _redact(error) if error else error

        with _tracer.start_as_current_span("runner.process"):
            for path, content in (
                (f"runs/{run_id}/transcript.jsonl", "\n".join(transcript) + "\n"),
                (f"runs/{run_id}/summary.json",
                 json.dumps({"summary": summary, "error": error, **meta},
                            indent=2, default=str) + "\n"),
            ):
                try:
                    await _put_file(api, agent, path, content, run_id)
                except Exception as exc:
                    print(f"runner: writing {path} failed ({_redact(str(exc))})", flush=True)

        if ctx.get("graph_enabled") and summary:
            try:
                with _tracer.start_as_current_span("runner.capture"):
                    await _capture(api, agent, run_id, ctx, summary, proxy_url)
            except Exception as exc:
                print(f"runner: capture failed ({_redact(str(exc))})", flush=True)

        if proxy is not None:
            proxy.stop()

        with _tracer.start_as_current_span("runner.finalize"):
            ok, why = await post_finish(api, run_id, summary=summary, error=error)
            if not ok:
                print(f"runner: finish failed after retries ({why}); "
                      "leaving run for the reaper", flush=True)

        run_span.set_attribute("andyur.result", "failed" if error else "done")

    otel.flush()
    return 1 if error else 0


async def execute(agent: str, run_id: str, serve_only: bool = False) -> int:
    if serve_only:
        # The serve-only sidecar is the container's PID 1 and parks; its stop
        # must be honoured from the first instruction. The other shapes keep
        # their default dispositions: a handler here would swallow a SIGTERM
        # the host-process runner relies on to exit (R LOW, PR #22).
        _install_stop_handler(asyncio.get_running_loop())
    cert, verify = identity.client_tls("runner")
    async with httpx.AsyncClient(
        base_url=SERVER_URL, timeout=10, auth=identity.httpx_auth(),
        cert=cert, verify=verify, headers=identity.run_token_header(),
    ) as api:
        # fetch the run first so we can join its distributed trace
        resp = await api.get(f"/runs/{run_id}")
        if resp.status_code in (401, 404, 409):
            # the run was cancelled/halted before we got going (so its token is no
            # longer valid), or it is gone: nothing to run, exit cleanly
            return 0
        resp.raise_for_status()
        run = resp.json()
        parent = otel.context_from(run.get("trace_ctx"))

        # Conversational runs take a wholly separate lifecycle: a persistent
        # session driven by a human turn loop, not a one-shot prompt. Same
        # identity, container, token, and isolation -- only longer-lived. They
        # stay in-process regardless of the split flag (Phase 1 splits headless
        # runs only; the conversational turn loop is a later phase).
        if run.get("run_type") == "conversation":
            return await _run_conversation(api, agent, run_id, run, parent)

        # Container split (Phase 1): a headless run executes as a sidecar (this
        # process, holding the run token) plus a credential-less agent process.
        if config.AGENT_SPLIT:
            return await _run_split(api, agent, run_id, run, parent,
                                    serve_only=serve_only)

        with _tracer.start_as_current_span(f"runner {agent}", context=parent) as run_span:
            run_span.set_attribute("andyur.run_id", run_id)
            run_span.set_attribute("andyur.agent", agent)
            # the agent's platform identity (SPIFFE ID), so a trace is tied to
            # who ran, not just the human-readable name
            run_span.set_attribute("andyur.agent_spiffe_id",
                                   run.get("agent_spiffe_id") or "")
            # the workflow this run belongs to, so a whole multi-agent fan-out
            # is filterable by one id in traces, logs, and audit
            run_span.set_attribute("andyur.workflow_id", run.get("workflow_id") or "")

            # phase 1: prepare (the mind + open tasks + unread messages, all
            # fetched over HTTP so the runner needs no storage access)
            with _tracer.start_as_current_span("runner.prepare"):
                ctx = await _fetch_context(api, agent)
                selected_model = registry_consumption.model_from_ctx(ctx) or DEFAULT_MODEL
                # A registry-bound agent's instructions are already overridden in
                # ctx by the server, and its manifest model rides in
                # ctx["registry_model"]; the runner is a pure consumer.
                open_tasks = (
                    await api.get("/tasks", params={"assignee": agent})
                ).json()
                ctx["tasks"] = [t for t in open_tasks if t["state"] != "closed"]
                ctx["messages"] = (
                    await api.get(
                        "/messages", params={"recipient": agent, "state": "unread"}
                    )
                ).json()
                tool_inputs = await _tool_inputs_or_finish(api, agent, run_id, ctx)
                if tool_inputs is None:
                    run_span.set_attribute("andyur.result", "failed")
                    return 1
                mcp_servers, registry_tools = tool_inputs

            # phase 2: prompt (saved to the mind; scratch is a local ephemeral
            # working directory for the agent's cwd, never persisted)
            with _tracer.start_as_current_span("runner.prompt"):
                if ctx.get("graph_enabled"):
                    ctx["graph_recall"] = await _recall_for(api, agent, run, ctx)
                prompt = build_prompt(ctx, run)
                await _put_file(api, agent, f"runs/{run_id}/prompt.md", prompt, run_id)
                scratch = tempfile.mkdtemp(prefix=f"andyur-{run_id}-")
                started = await api.post(f"/runs/{run_id}/start")
                if started.status_code == 409:
                    # the workflow was halted (run cancelled) between assignment
                    # and start: the server already freed the agent, so exit
                    # cleanly instead of crashing on raise_for_status
                    return 0
                started.raise_for_status()

            # phase 3: execute (drive the LLM)
            summary: str | None = None
            error: str | None = None
            meta: dict = {}
            transcript: list[str] = []
            tool_spans: dict = {}  # tool_use_id -> open span, for per-tool tracing
            with _tracer.start_as_current_span("runner.execute") as exec_span:
                exec_span.set_attribute("andyur.llm_mode", LLM_MODE)
                exec_span.set_attribute(
                    "andyur.model", selected_model)
                # capture this run's trace context here, inside the span, so the
                # agent's task/message tools can hand it to woken agents and a
                # multi-agent flow becomes one end-to-end trace
                origin_trace = otel.current_traceparent()
                # STARTING A SERVICE BELONGS INSIDE THE GUARD.
                #
                # These lines sat ABOVE the try, after POST /runs/{id}/start had
                # already marked the run started. A failure starting the tool
                # sidecar or the model proxy -- a port collision, a bad image, a
                # sidecar that will not come up -- therefore escaped execute()
                # with no finish call, and the run sat `running` until the
                # reaper. The split path's twin carries a comment claiming
                # everything from there on is guarded; neither path was.
                #
                # The four names below are pre-bound because the teardown and
                # the capture/stop code AFTER the loop reference them, and an
                # exception before their assignment would turn a handled
                # failure into a NameError in the handler.
                tool_gateway = None
                proxy = None
                proxy_url = None
                pending_llm = None
                last_poll = 0.0
                msgs_since_poll = 0
                first_poll_error: float | None = None
                try:
                    mcp_servers, tool_gateway = _start_tool_egress(
                        agent, mcp_servers, partitioned=registry_tools,
                        selected_model=selected_model)
                    if (LLM_MODE == "api"
                            and config.LITELLM_URL):
                        if tool_gateway is None:
                            raise RuntimeError("unified model sidecar failed to start")
                        os.environ.pop("ANDYUR_BROKER_TOKEN", None)
                        proxy_url, proxy = f"{tool_gateway.base_url}/llm", None
                    else:
                        proxy_url, proxy = _start_model_proxy()
                    pending_llm = _start_llm_request(selected_model)
                    _arm_run_deadline()
                    async with asyncio.timeout(RUN_TTL_SECONDS):
                        async for message in run_agent(
                            agent, prompt, scratch, origin_trace, run_id,
                            extra_mcp_servers=mcp_servers, proxy_url=proxy_url,
                            model=selected_model,
                        ):
                            transcript.append(
                                _redact(json.dumps(_message_record(message), default=str))
                            )
                            msgs_since_poll += 1
                            # in-flight kill-switch: poll halt on a WALL-CLOCK
                            # cadence (not every message, which would be a per-run
                            # request flood), and FAIL CLOSED only after the check
                            # stays unavailable for a sustained window -- so a brief
                            # server blip does not kill a healthy run, but a run
                            # that makes the check fail cannot outlast the window.
                            # (Bounds a halted run between tool calls; interrupting
                            # work inside one tool call needs a killable sandbox --
                            # see R1/R2.)
                            wf_id = run.get("workflow_id")
                            now_m = time.monotonic()
                            # poll on a wall-clock cadence OR after a burst of
                            # messages, so a run can't outrun the check with many
                            # quick tool calls inside one cadence window
                            if wf_id and (now_m - last_poll >= HALT_POLL_SECONDS
                                          or msgs_since_poll >= HALT_POLL_MESSAGES):
                                last_poll = now_m
                                msgs_since_poll = 0
                                wf_state = await _halted(api, wf_id)
                                if wf_state is True:
                                    error = "workflow halted mid-run"
                                    break
                                if wf_state is None:
                                    if first_poll_error is None:
                                        first_poll_error = now_m
                                    elif now_m - first_poll_error >= HALT_FAIL_CLOSED_SECONDS:
                                        error = "halt check unavailable; failing closed"
                                        break
                                else:
                                    first_poll_error = None
                            # one span per tool call, opened on the tool_use and
                            # closed on its result, so every tool the agent uses
                            # (base, Andyur's, or a custom MCP one) shows up in
                            # the trace under runner.execute
                            if isinstance(message, AssistantMessage):
                                if pending_llm is not None:
                                    pending_llm.end()
                                    pending_llm = None
                                _record_llm_response(
                                    selected_model, blocks=len(message.content))
                                for block in message.content:
                                    if isinstance(block, TextBlock):
                                        print(block.text, flush=True)
                                    elif isinstance(block, ToolUseBlock):
                                        pretty = block.name.replace(
                                            "mcp__", "").replace("__", "/")
                                        sp = _tracer.start_span(f"tool:{pretty}")
                                        sp.set_attribute("andyur.tool", block.name)
                                        _set_tool_payload(
                                            sp, "andyur.tool_input", block.input)
                                        _open_tool_span(tool_spans, block.id, sp)
                            elif isinstance(message, UserMessage):
                                blocks = message.content
                                saw_tool_result = False
                                if isinstance(blocks, list):
                                    for block in blocks:
                                        if isinstance(block, ToolResultBlock):
                                            saw_tool_result = True
                                            sp = tool_spans.pop(
                                                block.tool_use_id, None)
                                            if sp is not None:
                                                res = block.content
                                                if isinstance(res, list):
                                                    res = " ".join(
                                                        x.get("text", "")
                                                        for x in res
                                                        if isinstance(x, dict))
                                                _set_tool_payload(
                                                    sp, "andyur.tool_result", res)
                                                if getattr(block, "is_error", False):
                                                    sp.set_attribute(
                                                        "andyur.tool_error", True)
                                                sp.end()
                                if saw_tool_result and pending_llm is None:
                                    pending_llm = _start_llm_request(selected_model)
                            elif isinstance(message, ResultMessage):
                                summary = message.result
                                meta = {
                                    "num_turns": message.num_turns,
                                    "total_cost_usd": message.total_cost_usd,
                                    "session_id": message.session_id,
                                    "is_error": message.is_error,
                                    "usage": message.usage,
                                }
                                if message.is_error:
                                    error = describe_failure(message)
                except TimeoutError:
                    error = f"run exceeded TTL of {RUN_TTL_SECONDS}s"
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                finally:
                    if pending_llm is not None:
                        pending_llm.end()
                        pending_llm = None
                    # THE ONLY GUARANTEED EXIT in this function. Everything from
                    # here to finalize -- span attributes, artifact writes, graph
                    # capture -- runs unguarded, so a stop() placed down there is
                    # skipped by any exception raised down there, and the run
                    # would end with a live proxy still holding a usable grant.
                    # The split path already stops its tool proxy in a finally;
                    # this one said it did the same and did not.
                    #
                    # Safe to stop this early because nothing after the agent
                    # loop calls a tool: graph capture is a model call, and the
                    # model proxy is stopped separately and later for that reason.
                    if tool_gateway is not None:
                        await asyncio.to_thread(tool_gateway.stop)
                        tool_gateway = None
                for sp in tool_spans.values():  # close any tool left open (e.g. TTL)
                    sp.set_attribute("andyur.tool_incomplete", True)
                    sp.end()
                # Guarded for the same reason as the split path's twin: these are
                # diagnostics, and everything after them is the run's outcome. The
                # SDK does not coerce the CLI's JSON either, so total_cost_usd is
                # only as well-typed as whatever the CLI emitted.
                try:
                    if meta.get("num_turns") is not None:
                        exec_span.set_attribute("andyur.num_turns", meta["num_turns"])
                    if meta.get("total_cost_usd") is not None:
                        exec_span.set_attribute(
                            "andyur.cost_usd", float(meta["total_cost_usd"])
                        )
                except Exception as exc:
                    print(f"runner: cost/turn span attributes skipped "
                          f"({type(exc).__name__})", flush=True)

            if summary is None and error is None:
                error = "run produced no result message"
            # never persist a secret in the summary/error the model or an
            # exception string may carry (these land in summary.json and the run
            # record, both readable later)
            summary = _redact(summary) if summary else summary
            error = _redact(error) if error else error

            # phase 4: process. Each artifact write is INDEPENDENTLY best-effort so
            # one bad write (oversized transcript, a lone 500) can never prevent the
            # run from being finalized below.
            with _tracer.start_as_current_span("runner.process"):
                for path, content in (
                    (f"runs/{run_id}/transcript.jsonl", "\n".join(transcript) + "\n"),
                    (f"runs/{run_id}/summary.json",
                     json.dumps({"summary": summary, "error": error, **meta},
                                indent=2, default=str) + "\n"),
                ):
                    try:
                        await _put_file(api, agent, path, content, run_id)
                    except Exception as exc:
                        print(f"runner: writing {path} failed ({_redact(str(exc))})", flush=True)

            # phase 4b: capture into the memory graph (best-effort; only when the
            # graph is enabled, so runs make no extra LLM call otherwise)
            if ctx.get("graph_enabled") and summary:
                try:
                    with _tracer.start_as_current_span("runner.capture"):
                        await _capture(api, agent, run_id, ctx, summary, proxy_url)
                except Exception as exc:
                    print(f"runner: capture failed ({_redact(str(exc))})", flush=True)

            # phase 5: finalize -- the important state transition, in its OWN try
            # with retries, so an artifact-write failure never strands the run
            # 'running'. If it still fails, the server's reaper finalizes it later.
            # The proxy holds the run's model credential, so it must not outlive
            # the run under ANY exit -- TTL, halt, exception. Stopped HERE and not
            # at the end of the execute phase, because graph capture above is
            # itself a model call and goes through the same proxy: stopping it
            # earlier silently disabled capture, which swallows its own errors.
            if proxy is not None:
                proxy.stop()
            # Normally already stopped in the finally above; this catches the one
            # case that finally cannot -- an exception before the try was entered.
            if tool_gateway is not None:
                await asyncio.to_thread(tool_gateway.stop)

            with _tracer.start_as_current_span("runner.finalize"):
                ok, why = await post_finish(api, run_id, summary=summary, error=error)
                if not ok:
                    print(f"runner: finish failed after retries ({why}); "
                          "leaving run for the reaper", flush=True)

            run_span.set_attribute("andyur.result", "failed" if error else "done")

    otel.flush()  # short-lived process: force-export before exit
    return 1 if error else 0


def main() -> None:
    # FIRST, before anything can spawn: take the run token out of the
    # environment, so no subprocess inherits it whether or not this process
    # chose that subprocess's environment. See identity.seal_run_token -- the
    # SDK's version check spawns the CLI with no env argument, and under the uid
    # split that CLI path is the wrapper that drops to the AGENT's uid.
    identity.seal_run_token()
    parser = argparse.ArgumentParser(prog="andyur-runner")
    parser.add_argument("--agent", required=True)
    parser.add_argument("--run-id", required=True)
    # SERVER-SUPPLIED, via the launch manifest's proxy command (never the image
    # or env): the run is a stock exec/v1 workload, so this sidecar serves the
    # model proxy + MCP and never hosts a channel watchdog or posts /finish.
    parser.add_argument("--serve-only", action="store_true")
    args = parser.parse_args()
    try:
        code = asyncio.run(execute(args.agent, args.run_id,
                                   serve_only=args.serve_only))
    finally:
        # Also covers prepare-time early returns. Their span context exits while
        # execute unwinds; flushing here exports that ended failure span before
        # this short-lived runner process terminates.
        if args.serve_only:
            # TELEMETRY MUST NOT SLOW THE TEARDOWN (observability-exit-criteria
            # 7, second half; R on the plan): the serve-only exit is what a Pod
            # delete pays for (MED-0), so the export is BOUNDED. With the
            # collector unreachable the spans are dropped, the exit is not.
            if not otel.shutdown_bounded(SERVE_ONLY_FLUSH_SECONDS):
                _serve_log(f"[runner] serve-only: telemetry export cut at the "
                           f"{SERVE_ONLY_FLUSH_SECONDS}s bound (collector unreachable?)")
        else:
            otel.flush()
    sys.exit(code)


if __name__ == "__main__":
    main()

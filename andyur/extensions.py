"""Extensions: code from outside this package that the platform may load, and
the complete list of places it may plug in.

An extension is an installed distribution that declares an entry point in the
`andyur.extensions` group. Installing one does nothing. It is loaded only when
the operator names it in `ANDYUR_EXTENSIONS` (comma-separated), so the set of
code a deployment runs is still one environment variable to read -- the property
the fixed provider registries were protecting when they refused discovery
outright. An implicit extension is one nobody reviewed, and there is none.

## The seams are the methods of `Registrar`, and there are no others

An extension's entry point is a callable taking a `Registrar`. What it is
OFFERED is exactly what `Registrar` offers; it is not handed the app, the
database or the config. Adding a seam is adding a method here, where a reviewer
sees it.

That is a statement about the interface, not a sandbox. An enabled extension is
Python in the server's process and can import anything the server can. Naming
one in ANDYUR_EXTENSIONS is trusting it as much as the platform itself, which
is why nothing is loaded that the operator did not name.

## The policy is bounded, because it is somebody else's code on every request

An authorization policy is called through `PolicyGate`: on a thread of its own,
with a deadline, and never more than a fixed number at once. A policy
that hangs costs the requests that were waiting on it and nothing else -- it
cannot hold the server's request threads, so liveness and the operator's halt
stay reachable. Late or saturated is answered as unavailable, never as allowed.

## Failure is loud, at startup

A named extension that is not installed, that fails to import, that raises while
registering, or that claims a name something else already holds, stops the
process. The alternative -- serving without it -- would silently drop whatever
the operator enabled it for, and for an authorization policy that means serving
with fewer refusals than were configured.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import dataclasses
import functools
import inspect
import logging
import os
import threading
import time
import types
from collections.abc import Callable, Mapping
from importlib import metadata
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("andyur.extensions")

ENTRY_POINT_GROUP = "andyur.extensions"
ENV_VAR = "ANDYUR_EXTENSIONS"
POLICY_TIMEOUT_ENV = "ANDYUR_EXTENSION_POLICY_TIMEOUT"
POLICY_CONCURRENCY_ENV = "ANDYUR_EXTENSION_POLICY_CONCURRENCY"
DEFAULT_POLICY_TIMEOUT = 2.0
DEFAULT_POLICY_CONCURRENCY = 8

# What a consultation can come to. Only ALLOW lets the request continue.
ALLOW = "allow"
REFUSE = "refuse"
ERROR = "error"
TIMEOUT = "timeout"
SATURATED = "saturated"


class ExtensionError(ValueError):
    """An extension could not be loaded as configured. A configuration mistake,
    like `UnknownProvider`: it must stop the process, not surface per request."""


@dataclasses.dataclass(frozen=True)
class UserRequest:
    """What an authorization policy is told about one user-authenticated call.

    `action` is the route as declared, `"<METHOD> <path template>"` (for example
    `"POST /agents/{name}/trigger"`), so a policy matches on the route and never
    parses a caller-supplied path. `params` are that route's path parameters.
    `claims` are the user token's claims, already validated by the platform."""
    subject: str
    is_admin: bool
    claims: Mapping[str, Any]
    action: str
    params: Mapping[str, str]

    @classmethod
    def of(cls, *, subject: str, is_admin: bool, claims: Mapping[str, Any],
           action: str, params: Mapping[str, str]) -> "UserRequest":
        """A request the policy cannot use to reach back into the platform.

        The claims are a deep copy behind a read-only view. The platform has
        already taken the subject and the admin role from its own copy, so a
        policy that edits what it is handed changes nothing today -- and must
        still change nothing on the day something caches validated claims."""
        return cls(subject=subject, is_admin=is_admin, action=action,
                   claims=types.MappingProxyType(copy.deepcopy(dict(claims))),
                   params=types.MappingProxyType(dict(params)))


@runtime_checkable
class AuthorizationPolicy(Protocol):
    """Further narrows what an authenticated user may do. Never widens it.

    Consulted once for every request that presents a user token, on every API
    route, after the platform has authenticated the calling workload and the
    user and before the route runs. Every platform check -- the workload's
    role, ownership, the admin role -- still applies whatever the policy says. Return None to allow, or a reason to refuse (a 403 carrying
    it). The platform's own refusals cannot be overridden from here: nothing
    returned by this method can turn a refusal into an allow.

    The policy sees the route and its parameters, not whether the named thing
    exists, and should keep it that way: a refusal that depends on existence
    would answer a question the platform's 404s deliberately do not."""

    def refuse(self, request: UserRequest) -> str | None: ...


@dataclasses.dataclass(frozen=True)
class Decision:
    """What one consultation came to. `reason` is the policy's own text on a
    REFUSE and is untrusted; `error` is what it raised on an ERROR."""
    outcome: str
    seconds: float
    reason: str | None = None
    error: BaseException | None = None


class PolicyGate:
    """Calls the policy without letting it hold the server.

    The policy runs on a thread of its own, so a slow one never occupies a
    request thread; the caller waits for it on the event loop with a deadline.
    A slot is taken before the call and given back when the policy actually
    RETURNS, not when the caller stopped waiting: a policy that hangs keeps
    its slot, and once every slot is held by a hung call the gate answers
    SATURATED at once instead of starting another thread behind it. The cost
    of a hung policy is therefore bounded at `concurrency` threads and
    `timeout` seconds, and the answer while it hangs is a refusal.

    The threads are daemons. A pool's workers are joined at interpreter exit,
    so one hung policy call made the server unable to stop without SIGKILL --
    the moment an operator most needs a restart to work.

    The cap is on calls, not on callers: one user sending requests faster than
    the policy answers can hold every slot, and other users are then told 503.
    A rate limit per caller belongs in front of the server, not in here."""

    def __init__(self, policy: AuthorizationPolicy, *, timeout: float,
                 concurrency: int):
        self._policy = policy
        self.timeout = timeout
        self.concurrency = concurrency
        self._slots = threading.BoundedSemaphore(concurrency)

    async def consult(self, request: UserRequest) -> Decision:
        started = time.monotonic()

        def elapsed() -> float:
            return time.monotonic() - started

        if not self._slots.acquire(blocking=False):
            return Decision(SATURATED, elapsed())
        loop = asyncio.get_running_loop()
        answer: asyncio.Future = loop.create_future()
        # The caller's context, so a decision service the policy calls is a
        # child of this consultation's span and not a trace of its own.
        context = contextvars.copy_context()

        def deliver(result) -> None:
            if not answer.done():
                answer.set_result(result)

        def call() -> None:
            try:
                result = context.run(self._ask, request)
            finally:
                self._slots.release()
            try:
                loop.call_soon_threadsafe(deliver, result)
            except RuntimeError:
                pass    # the loop is gone; nobody is waiting for the answer

        try:
            threading.Thread(target=call, daemon=True,
                             name="andyur-extension-policy").start()
        except BaseException:
            self._slots.release()
            raise
        try:
            verdict, raised = await asyncio.wait_for(answer, self.timeout)
        except asyncio.TimeoutError:
            return Decision(TIMEOUT, elapsed())
        if raised is not None:
            return Decision(ERROR, elapsed(), error=raised)
        if verdict is None:
            return Decision(ALLOW, elapsed())
        if isinstance(verdict, str):
            return Decision(REFUSE, elapsed(), reason=verdict)
        # Not None and not a reason. Refused, and reported as the policy's
        # fault: `False` or `0` from a policy written as a predicate would
        # otherwise read as a refusal it never meant, or worse, as an allow.
        return Decision(ERROR, elapsed(), error=TypeError(
            f"refuse() returned {type(verdict).__name__}; it must return None "
            "to allow or a string reason to refuse"))

    def _ask(self, request: UserRequest) -> tuple[Any, BaseException | None]:
        """Call the policy and hand back what it returned or what it raised.

        Returned, never re-raised: whatever a policy raises is the policy
        failing. Left to propagate, a CancelledError from the policy reads as
        the request being cancelled, and a StopIteration cannot be set on a
        future at all -- it surfaced as a timeout a full deadline later."""
        try:
            return self._policy.refuse(request), None
        except BaseException as exc:    # noqa: BLE001 - nothing it raises allows
            return None, exc


WorkflowProviderBuilder = Callable[[], Any]


@dataclasses.dataclass(frozen=True)
class LoadedExtension:
    name: str
    distribution: str
    version: str


@dataclasses.dataclass(frozen=True)
class Loaded:
    extensions: tuple[LoadedExtension, ...] = ()
    workflow_providers: Mapping[str, WorkflowProviderBuilder] = dataclasses.field(
        default_factory=dict)
    authorization_policy: AuthorizationPolicy | None = None
    # Which extension registered the policy, so the log and the span can say
    # whose refusal it was. The caller is told the reason and not the name.
    authorization_policy_from: str | None = None
    policy_timeout: float = DEFAULT_POLICY_TIMEOUT
    policy_concurrency: int = DEFAULT_POLICY_CONCURRENCY

    @functools.cached_property
    def authorization_gate(self) -> PolicyGate | None:
        """The one way the policy is called. Built once per load, so its slots
        and its threads are shared by every request."""
        if self.authorization_policy is None:
            return None
        return PolicyGate(self.authorization_policy, timeout=self.policy_timeout,
                          concurrency=self.policy_concurrency)


class Registrar:
    """The complete set of seams an extension may plug into."""

    def __init__(self, reserved_providers: frozenset[str]):
        self._reserved_providers = reserved_providers
        self._providers: dict[str, tuple[str, WorkflowProviderBuilder]] = {}
        self._policy: tuple[str, AuthorizationPolicy] | None = None
        self._current: str | None = None

    def workflow_provider(self, name: str, builder: WorkflowProviderBuilder) -> None:
        """Offer a workflow provider under `name`, selectable through
        ANDYUR_WORKFLOW_PROVIDER like a built-in one. A built-in name cannot be
        taken: a run bound to `temporal` must mean the same engine whatever is
        installed beside it."""
        key = name.strip().lower()
        if not key:
            raise ExtensionError(f"extension {self._current!r} offered a workflow "
                                 "provider with an empty name")
        if key in self._reserved_providers:
            raise ExtensionError(
                f"extension {self._current!r} offered workflow provider {key!r}, "
                "which is built in; an extension cannot replace a built-in provider")
        if key in self._providers:
            raise ExtensionError(
                f"workflow provider {key!r} is offered by both "
                f"{self._providers[key][0]!r} and {self._current!r}")
        if not callable(builder):
            raise ExtensionError(f"extension {self._current!r} offered workflow "
                                 f"provider {key!r} without a callable builder")
        self._providers[key] = (self._current or "?", builder)

    def authorization_policy(self, policy: AuthorizationPolicy) -> None:
        """Install the one policy that may further narrow user requests. One,
        because two policies raise the question of which refusal wins and whether
        either sees the other, and the honest answer is to not have it."""
        if not isinstance(policy, AuthorizationPolicy):
            raise ExtensionError(f"extension {self._current!r} offered an "
                                 "authorization policy without a refuse() method")
        if inspect.iscoroutinefunction(policy.refuse):
            # It would return a coroutine, which is neither None nor a reason:
            # every request refused, with nothing saying why until one arrives.
            raise ExtensionError(
                f"extension {self._current!r} offered an authorization policy "
                "whose refuse() is async; it is called from a worker thread and "
                "must be an ordinary function")
        if self._policy is not None:
            raise ExtensionError(
                f"an authorization policy is offered by both {self._policy[0]!r} "
                f"and {self._current!r}; at most one may be enabled")
        self._policy = (self._current or "?", policy)


def configured_names() -> tuple[str, ...]:
    raw = os.environ.get(ENV_VAR, "")
    names = [n.strip() for n in raw.split(",") if n.strip()]
    if len(set(names)) != len(names):
        raise ExtensionError(f"{ENV_VAR}={raw!r} names an extension twice")
    return tuple(names)


def load(names: tuple[str, ...], *, reserved_providers: frozenset[str] = frozenset(),
         entry_points: Callable[..., Any] | None = None) -> Loaded:
    """Load exactly the named extensions, or refuse. Nothing installed but
    unnamed is imported."""
    if not names:
        return Loaded()
    entry_points = entry_points or metadata.entry_points
    registrar = Registrar(reserved_providers)
    loaded: list[LoadedExtension] = []
    for name in names:
        matches = list(entry_points(group=ENTRY_POINT_GROUP, name=name))
        if not matches:
            raise ExtensionError(
                f"{ENV_VAR} names extension {name!r}, but no installed distribution "
                f"declares it in the {ENTRY_POINT_GROUP!r} entry-point group")
        if len(matches) > 1:
            owners = sorted(_dist_name(ep) for ep in matches)
            raise ExtensionError(
                f"extension {name!r} is declared by more than one installed "
                f"distribution ({', '.join(owners)}); which one runs would be "
                "an accident of install order")
        ep = matches[0]
        try:
            register = ep.load()
        except Exception as exc:
            raise ExtensionError(f"extension {name!r} failed to import: {exc}") from exc
        registrar._current = name
        try:
            register(registrar)
        except ExtensionError:
            raise
        except Exception as exc:
            raise ExtensionError(f"extension {name!r} failed while registering: "
                                 f"{exc}") from exc
        loaded.append(LoadedExtension(name, _dist_name(ep), _dist_version(ep)))
    policy = registrar._policy
    timeout, concurrency = policy_limits()
    return Loaded(
        extensions=tuple(loaded),
        workflow_providers={k: b for k, (_, b) in registrar._providers.items()},
        authorization_policy=policy[1] if policy else None,
        authorization_policy_from=policy[0] if policy else None,
        policy_timeout=timeout,
        policy_concurrency=concurrency,
    )


def policy_limits() -> tuple[float, int]:
    """The deadline and the concurrency cap, or a refusal to start.

    A value that does not parse stops the process. Falling back to the default
    would run a deployment under a bound its operator did not choose."""
    def read(env: str, default, kind):
        raw = os.environ.get(env, "").strip()
        if not raw:
            return default
        try:
            value = kind(raw)
        except ValueError:
            value = 0
        if not value > 0:
            raise ExtensionError(f"{env}={raw!r} must be a positive number")
        return value

    return (read(POLICY_TIMEOUT_ENV, DEFAULT_POLICY_TIMEOUT, float),
            read(POLICY_CONCURRENCY_ENV, DEFAULT_POLICY_CONCURRENCY, int))


def _dist_name(ep) -> str:
    dist = getattr(ep, "dist", None)
    return getattr(dist, "name", None) or "unknown"


def _dist_version(ep) -> str:
    dist = getattr(ep, "dist", None)
    return getattr(dist, "version", None) or "unknown"


@functools.cache
def loaded() -> Loaded:
    """The extensions this process runs, loaded once from ANDYUR_EXTENSIONS."""
    # Imported here, not at module top: the registry imports this module.
    from .orchestration.registry import BUILDERS

    result = load(configured_names(), reserved_providers=frozenset(BUILDERS))
    for ext in result.extensions:
        log.warning("extension enabled: %s (%s %s)", ext.name, ext.distribution,
                    ext.version)
    return result


def reset() -> None:
    """Forget what was loaded, so a test can change ANDYUR_EXTENSIONS."""
    loaded.cache_clear()

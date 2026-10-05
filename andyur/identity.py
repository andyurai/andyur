"""SPIFFE workload identity for Andyur.

Every Andyur process (server, daemon, runner, CLI) gets its identity from the
local SPIRE agent's Workload API rather than from a shared secret. This module
is the single integration point:

- server side: validate an incoming JWT-SVID and read the caller's SPIFFE ID
- client side: attach this process's JWT-SVID as a bearer token

IDENTITY IS NOT OPTIONAL, AND `ANDYUR_IDENTITY` NO LONGER EXISTS.

It was a flag until 7 August 2026, defaulting to off. That is why this deletion
gets a paragraph instead of a line: the flag was not a feature toggle, it was a
way to run half of Andyur and have it look green.

Delegation delegates to a run. Without an attested per-run identity there is no
"this run", so an RFC 8693 exchange carries a subject and no actor, which asserts
the user acted directly. That is impersonation, and an authorization server is
right to refuse it. An Andyur with identity off is therefore not a smaller Andyur,
it is a proxy that forwards a user's token, which is what every other gateway
already does.

The cost of having had the flag, concretely. The authority path was built and
tested with identity off, because the sandbox was not required there. The
identity path was built and tested with the sandbox on, where `ANDYUR_AS_*` never
reached the run container. Each half passed its own tests. The composition had
never once executed, in either direction, and the flag is what made both of those
look like complete configurations.

`replaceable-components.md`'s rule -- every feature off by default where it adds
a dependency -- is right for the PDP, the identity provider and the tracing
backend, which Andyur COMPOSES. It was wrongly applied to what Andyur IS.

SPIFFE_ENDPOINT_SOCKET (or the default local agent socket) locates the Workload
API. A process that cannot reach it fails, loudly; it does not fall back.
"""

import logging
import os
import threading
from pathlib import Path

from . import layout

MTLS_ON = os.environ.get("ANDYUR_MTLS", "off").lower() in ("1", "on", "true")


class _DropCancelledOnClose(logging.Filter):
    """py-spiffe logs an error when it tears down a Workload API gRPC stream on
    source close (StatusCode.CANCELLED). That is expected shutdown noise, not a
    failure. Drop only those records; let any real source error through."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "CANCELLED" not in record.getMessage()


for _name in ("spiffe.workloadapi.x509_source", "spiffe.workloadapi.jwt_source"):
    logging.getLogger(_name).addFilter(_DropCancelledOnClose())

# What the server calls itself, and the audience it requires on inbound tokens.
SERVER_AUDIENCE = os.environ.get("ANDYUR_AUDIENCE", "andyur-server")
TRUST_DOMAIN = os.environ.get("ANDYUR_TRUST_DOMAIN", "andyur.local")

def socket_path() -> str:
    """The Workload API socket: SPIFFE_ENDPOINT_SOCKET, or the layout's default.

    The default follows the layout and not ANDYUR_DATA_DIR: run.sh starts the
    SPIRE agent on the checkout's own data/ whatever the state directory is set
    to, and a deployment that puts the socket elsewhere names it explicitly.

    Resolved on each call rather than at import, so a process that names its
    socket never needs a default to be computable -- an installed copy's
    default needs a home directory, and a container uid may not have one."""
    explicit = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if explicit:
        return explicit
    return "unix:" + str(layout.default_data_dir() / "spire" / "agent" / "api.sock")


# ---------------------------------------------------------------------------
# Server side: a long-lived JwtSource for validation, plus a validate helper.
# ---------------------------------------------------------------------------

# Bounded wait for the Workload API, so a not-yet-propagated entry or an
# unreachable SPIRE agent surfaces as an error instead of hanging the process
# forever (py-spiffe otherwise retries with no deadline). Applied to both the
# blocking source init and each SVID fetch.
SVID_TIMEOUT = float(os.environ.get("ANDYUR_SVID_TIMEOUT", "30"))

# One lock guards lazy construction of BOTH module-global JwtSources.
#
# Two failure modes this closes (found by red-team, 2026-08-13):
#  - PERMANENT LATCH: py-spiffe's watcher sets the source _closed/_error on any
#    unretryable Workload API stream error (e.g. a SPIRE agent restart) and it
#    stays dead forever. A bare `is None` cache never rebuilds it, so one blip
#    would 401 all token validation until the process is restarted. We rebuild
#    a source that reports is_closed().
#  - INIT RACE: the auth dependencies run as sync functions in the anyio
#    threadpool, so a cold-start burst had N threads each construct their own
#    source (each a gRPC stream + watcher thread), N-1 of them orphaned and
#    never closed. The lock serializes construction to exactly one.
# Holding the lock across JwtSource.__init__ (which blocks up to SVID_TIMEOUT
# for the first bundle) is deliberate: one thread builds while the rest wait
# and then reuse it, rather than each building its own.
_JWT_SOURCE_LOCK = threading.Lock()
_jwt_source = None


def _rebuilt_if_dead(src, *, timeout: float | None = None):
    """Return src if it is live, else a fresh JwtSource (closing the dead one).
    If construction raises (SPIRE unreachable), the exception propagates and the
    caller's global is left unchanged, so a failed build fails the request and
    retries next time rather than caching a broken source."""
    from spiffe import JwtSource

    if src is not None and not src.is_closed():
        return src
    if src is not None:
        try:
            src.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup of a dead source
            pass
    return JwtSource(socket_path=socket_path(), timeout_in_seconds=(
        SVID_TIMEOUT if timeout is None else max(0.001, timeout)))


def _get_jwt_source():
    global _jwt_source
    with _JWT_SOURCE_LOCK:
        _jwt_source = _rebuilt_if_dead(_jwt_source)
    return _jwt_source


def validate_token(token: str) -> str:
    """Validate a JWT-SVID against the trust bundle and required audience.
    Returns the caller's SPIFFE ID string. Raises on any failure."""
    from spiffe import JwtSvid, TrustDomain

    bundle = _get_jwt_source().get_bundle_for_trust_domain(
        TrustDomain(TRUST_DOMAIN)
    )
    svid = JwtSvid.parse_and_validate(token, bundle, audience={SERVER_AUDIENCE})
    return str(svid.spiffe_id)


# ---------------------------------------------------------------------------
# Client side: fetch this process's JWT-SVID and attach it as a bearer token.
# ---------------------------------------------------------------------------

_client_jwt_source = None


def _requested_subject():
    subject = os.environ.get("ANDYUR_SPIFFE_ID", "").strip()
    if not subject:
        return None
    from spiffe import SpiffeId

    return SpiffeId(subject)


def fetch_token(audience: str = SERVER_AUDIENCE, *, timeout: float | None = None) -> str:
    """Fetch this workload's JWT-SVID for `audience`. Bounded by SVID_TIMEOUT so a
    runner whose SPIRE entry has not propagated (or whose agent is unreachable)
    fails its call instead of hanging the whole process indefinitely."""
    global _client_jwt_source
    acquired = (_JWT_SOURCE_LOCK.acquire() if timeout is None else
                _JWT_SOURCE_LOCK.acquire(timeout=max(0.001, timeout)))
    if not acquired:
        raise TimeoutError("timed out waiting for the SPIFFE JWT source")
    try:
        _client_jwt_source = _rebuilt_if_dead(
            _client_jwt_source, timeout=timeout)
    finally:
        _JWT_SOURCE_LOCK.release()
    return _client_jwt_source.fetch_svid(
        audience={audience}, subject=_requested_subject(),
        timeout=SVID_TIMEOUT if timeout is None else max(0.001, timeout)
    ).token


def auth_header(audience: str = SERVER_AUDIENCE, *, timeout: float | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {fetch_token(audience, timeout=timeout)}"}


# The run token (R1) is injected into a runner's environment by the daemon at
# launch (ANDYUR_RUN_TOKEN). It names which agent+run this process is, so the
# server can scope its API calls. Carried on every run-scoped request.
RUN_TOKEN_HEADER = "X-Andyur-Run-Token"


def bearer_token(header: str | None) -> str | None:
    """The token from an `Authorization: Bearer <token>` header, or None.

    The auth-scheme is matched CASE-INSENSITIVELY (RFC 9110 sec 11.1): `bearer`
    and `Bearer` name the same scheme, so a spec-conforming client that sends the
    lowercase form must be accepted, not 401'd. One helper so every bearer-parsing
    site agrees on this -- the broker learned it the hard way and fixed only itself."""
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


# Set once the runner has taken its token OUT of the environment (see seal_run_token).
_sealed_run_token: str | None = None


def seal_run_token() -> None:
    """Move the run token from the environment into this process's memory.

    WHY THE ENVIRONMENT IS NOT GOOD ENOUGH. `os.environ` is inherited by every
    subprocess unless something overrides it, and the runner cannot rely on
    overriding it, because not every spawn is under its control. The Claude
    Agent SDK runs a version check before the real launch:

        anyio.open_process([self._cli_path, "-v"], stdout=PIPE, stderr=PIPE)

    with NO env argument, so that child inherits os.environ verbatim -- and
    under the uid split `cli_path` is the setpriv wrapper that drops to the
    AGENT's uid. So a process was running as the agent, holding the
    control-plane run token, twice per run, while the runner's own audit
    correctly reported that the audited spawn held nothing. The audit was not
    wrong; it was watching the one spawn that was already safe.

    Scrubbing the override dict fixes the spawns you know about. Emptying the
    environment fixes the ones you do not, including the next library that adds
    a subprocess. That is the difference worth paying a module-level variable
    for.

    Not a memory-secrecy claim: the token is still in this process, and
    /proc/<pid>/environ keeps whatever the process was STARTED with regardless.
    The uid split is what stops the agent reading either. This closes
    INHERITANCE, which is the part that put the token under the agent's own uid.
    """
    global _sealed_run_token
    token = os.environ.pop("ANDYUR_RUN_TOKEN", "")
    if token:
        _sealed_run_token = token
    # The SDK's version-check spawn is guarded by this, read from os.environ (so
    # options.env cannot suppress it). Belt and braces with the pop above: one
    # stops the token travelling, the other stops the unenveloped spawn at all.
    os.environ["CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK"] = "1"


def run_token_header() -> dict[str, str]:
    token = _sealed_run_token or os.environ.get("ANDYUR_RUN_TOKEN")
    return {RUN_TOKEN_HEADER: token} if token else {}


def httpx_auth():
    """An httpx auth flow that attaches a fresh JWT-SVID to every request, so
    short-lived tokens are never stale."""
    import httpx

    class _BearerSvid(httpx.Auth):
        def auth_flow(self, request):
            request.headers["Authorization"] = f"Bearer {fetch_token()}"
            yield request

    return _BearerSvid()


# Convenience: short role name from a SPIFFE ID (last path segment).
def role_of(spiffe_id: str) -> str:
    return spiffe_id.rstrip("/").rsplit("/", 1)[-1]


def parse_agent_run(spiffe_id: str) -> tuple[str | None, str | None]:
    """Parse a per-run SVID `spiffe://<td>/agent/<name>/run/<run_id>` back to
    (agent, run_id). Returns (None, None) for any other shape (a role SVID, a
    bare agent SVID, etc.), so callers can tell a container-attested run SVID
    apart from a role identity. See spire_registrar.run_spiffe_id."""
    if not spiffe_id.startswith(AGENT_ID_PREFIX):
        return (None, None)
    rest = spiffe_id[len(AGENT_ID_PREFIX):].rstrip("/")
    parts = rest.split("/")
    if len(parts) == 3 and parts[1] == "run" and parts[0] and parts[2]:
        return (parts[0], parts[2])
    return (None, None)


# ---------------------------------------------------------------------------
# Launching a child process under a role's identity. When identity is on, the
# child must run as the per-role executable so the SPIRE attestor recognizes
# it; the role binaries need the venv site-packages on PYTHONPATH.
# ---------------------------------------------------------------------------

_PROJECT_ROOT = str(layout.PACKAGE_PARENT)


def role_python(role: str) -> str:
    """Path to the interpreter a child running as `role` should use."""
    binary = os.path.join(_PROJECT_ROOT, "infra", "roles", "bin", f"andyur-{role}")
    if os.path.exists(binary):
        return binary
    import sys

    return sys.executable


AGENT_ID_PREFIX = f"spiffe://{TRUST_DOMAIN}/agent/"


def agent_spiffe_id(agent_name: str) -> str:
    """The platform identity of an Andyur agent. SPIRE attests the *runtime*
    (this is an Andyur runner); Andyur issues and binds this per-agent identity
    to each run on top of that attested runtime."""
    return AGENT_ID_PREFIX + agent_name


def assert_live_x509_identity(expected_spiffe_id: str) -> None:
    """Boundedly prove this workload has its exact X509-SVID and trust bundle.

    Readiness must exercise the Workload API, not merely stat its socket. This
    keeps the private key in the SPIFFE library's in-memory context and closes
    the source immediately; unlike ``export_tls_pems`` it writes nothing.
    """
    from spiffe import TrustDomain, X509Source

    src = X509Source(socket_path=socket_path(), timeout_in_seconds=SVID_TIMEOUT)
    try:
        context = src.get_x509_context()
        actual = str(context.default_svid.spiffe_id)
        if actual != expected_spiffe_id:
            raise ValueError(
                f"workload identity mismatch: expected {expected_spiffe_id}, got {actual}")
        bundle = src.get_bundle_for_trust_domain(TrustDomain(TRUST_DOMAIN))
        if bundle is None:
            raise ValueError("workload trust bundle is unavailable")
    finally:
        src.close()


# ---------------------------------------------------------------------------
# mTLS: export this process's X509-SVID + trust bundle to PEM files so a TLS
# stack (uvicorn, httpx) can present the cert and verify peers. SVIDs rotate
# hourly; for a session the exported PEMs stay valid. Peers are verified to be
# in the Andyur trust domain.
# ---------------------------------------------------------------------------

# Modes for the exported material. The KEY is the secret; the cert chain and the
# trust bundle are public by construction (they are what we hand to every peer),
# so only the key and the directory holding it are locked down.
KEY_MODE = 0o600
TLS_DIR_MODE = 0o700


def _write_private(path: str, data: bytes) -> None:
    """Write secret bytes to `path` so the file is NEVER, not even for an
    instant, readable by anyone but its owner.

    THE WINDOW IS THE WHOLE POINT, and the obvious spelling does not close it.
    `open(path, "wb")` creates the file at 0666 & ~umask -- 0644 in every
    container this platform runs in -- and a `chmod` AFTER the write leaves the
    private key world-readable for the entire duration of the write. An agent
    sharing the filesystem does not need to win a race it can simply poll for;
    it only has to be looping on the path. os.open with an explicit mode creates
    the file 0600 in ONE syscall, so no world-readable version of it ever exists.

    The fchmod is not redundant with that mode. O_CREAT's mode argument is
    IGNORED when the file already exists, and this function re-runs on every
    SVID export -- so a key.pem left behind at 0644 by an older build, or by a
    build that ran before this fix, would keep 0644 forever and the new secret
    would be written straight into it. fchmod runs on the fd BEFORE a single
    byte is written, which is why it is here and not after the write.

    Failure to secure the file is a hard error, deliberately: a private key that
    could not be protected must not be written at all. os.open raising leaves no
    file behind; a chmod that cannot be applied means we do not know who can
    read what we are about to write, and guessing is how the 0644 shipped."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_MODE)
    try:
        handle = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)   # fdopen did not take ownership, so nothing else will
        raise
    with handle:
        os.fchmod(fd, KEY_MODE)
        handle.write(data)


def export_tls_pems(role: str) -> dict:
    """Write cert chain, private key, and CA bundle PEMs for this process.
    Returns {'cert', 'key', 'bundle'} file paths.

    WHY THIS TOUCHES DISK AT ALL. The X509-SVID's private key belongs in memory;
    uvicorn's --ssl-keyfile and httpx's load_cert_chain both take PATHS, so
    there is no in-memory handoff to give them. The key therefore lands in a
    file, and the only question left is who else can open it. Under the uid
    split the runner and the untrusted agent share a filesystem, so "0644 in a
    0755 directory" would mean the agent can lift the workload's private key and
    speak to the control plane AS the workload -- the one credential the run
    token, the broker split and the env scrub all exist to keep away from it.
    The directory is 0700 (the agent cannot even traverse it) and the key 0600
    (it cannot read it if it somehow gets in); either alone would do, and both
    is what a private key deserves."""
    from cryptography.hazmat.primitives import serialization

    from spiffe import X509Source, TrustDomain

    # bounded like the JWT source, so a workload whose SPIRE entry has not
    # propagated fails fast instead of blocking the process forever
    src = X509Source(socket_path=socket_path(), timeout_in_seconds=SVID_TIMEOUT)
    svid = src.get_x509_context().default_svid
    bundle = src.get_bundle_for_trust_domain(TrustDomain(TRUST_DOMAIN))

    out = os.path.join(_project_data(), "tls", role)
    # `mode=` on makedirs is masked by the umask AND ignored outright when the
    # directory already exists -- and it always already exists from the second
    # export onward. Neither guarantees anything, so chmod unconditionally, and
    # do it BEFORE any file is created inside: a directory that is 0755 while
    # the key is being written is the same open window in a different place.
    # Only the per-role directory is narrowed, never the shared `tls` parent,
    # because two roles exporting under one data dir as different uids would
    # then lock each other out.
    layout.create_data_dir(Path(_project_data()))
    os.makedirs(out, exist_ok=True)
    try:
        os.chmod(out, TLS_DIR_MODE)
    except PermissionError:
        # The directory already exists and belongs to another uid. Narrowing it
        # is not ours to do, and refusing here would turn a hardening step into
        # an outage for a deployment that shares a data dir across roles -- the
        # exact case the comment above says not to break. The key file's own
        # 0600 is the control that matters and is applied regardless; the
        # directory mode is defence in depth. Say so rather than failing, so a
        # narrowed-directory assumption is never made silently.
        print(f"[identity] could not narrow {out} to {oct(TLS_DIR_MODE)} "
              "(owned by another uid); the key file's own mode still applies",
              flush=True)
    cert_p = os.path.join(out, "cert.pem")
    key_p = os.path.join(out, "key.pem")
    bundle_p = os.path.join(out, "bundle.pem")

    with open(cert_p, "wb") as f:
        for cert in svid.cert_chain:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        key_p,
        svid.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    with open(bundle_p, "wb") as f:
        for authority in bundle.x509_authorities:
            f.write(authority.public_bytes(serialization.Encoding.PEM))
    src.close()
    return {"cert": cert_p, "key": key_p, "bundle": bundle_p}


def _project_data() -> str:
    return str(layout.data_dir())


def client_tls(role: str):
    """(cert, verify) for an httpx client presenting this role's SVID.

    SPIFFE certificates identify by URI SAN (spiffe://...), not by DNS name,
    so ordinary TLS hostname verification always fails. We build an SSL
    context that trusts the Andyur bundle, presents our SVID, and skips the
    hostname check; trust-domain membership is enforced by the bundle (only
    Andyur SVIDs chain to it). Returns (None, True) when mTLS is off."""
    if not MTLS_ON:
        return None, True
    import ssl

    pems = export_tls_pems(role)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=pems["bundle"])
    ctx.check_hostname = False  # SPIFFE verifies by URI SAN, not hostname
    ctx.load_cert_chain(certfile=pems["cert"], keyfile=pems["key"])
    return None, ctx


# Secrets the runner process must never carry. The runner reaches the mind over
# HTTP through the server (never touches object storage or the graph directly), and
# only the server mints/verifies run tokens, so none of these belong in its env.
# Keeping them out means the same-uid agent cannot lift them from the runner's
# /proc/<pid>/environ to forge tokens for other agents or reach storage directly.
_RUNNER_DENY = frozenset({
    "ANDYUR_RUN_TOKEN_SECRET",
    "ANDYUR_S3_ACCESS_KEY",
    "ANDYUR_S3_SECRET_KEY",
    "ANDYUR_NEO4J_PASSWORD",
})


def assert_agent_isolation() -> None:
    """Refuse to launch untrusted agents that share this uid while SPIFFE roles
    are attested by (executable path + uid).

    Roles are registered with `unix:path` + `unix:uid`
    selectors. A non-sandboxed run puts the agent -- arbitrary code with Bash --
    at the SAME uid as the runner, so it can simply exec a peer role's binary
    (e.g. infra/roles/bin/andyur-server) and be handed the CONTROL-PLANE SVID:
    it matches every selector. That is full impersonation, and no amount of env
    scrubbing fixes it, because the attacker legitimately satisfies the policy.

    Sandbox mode closes it (no host filesystem, so no role binaries and no
    Workload API socket in the container, and the agent runs as its own uid).
    Set ANDYUR_ALLOW_UNISOLATED_AGENT=on to accept the risk knowingly.

    Unconditional since identity stopped being a flag. It used to return early
    with identity off, which meant the ONE configuration where the agent could
    steal an SVID was also the configuration where this refused to look."""
    sandbox_on = os.environ.get("ANDYUR_SANDBOX", "off").lower() in ("1", "on", "true")
    ack = os.environ.get("ANDYUR_ALLOW_UNISOLATED_AGENT", "").lower() in (
        "1", "on", "true",
    )
    if sandbox_on or ack:
        return
    raise RuntimeError(
        "Andyur requires ANDYUR_SANDBOX=on: without it the agent shares the "
        "runner's uid and could exec a peer role's binary to obtain that role's "
        "SVID (including the control plane). Run with ANDYUR_SANDBOX=on, or set "
        "ANDYUR_ALLOW_UNISOLATED_AGENT=on to accept this risk."
    )


def runner_launch_env(run_token: str | None = None,
                      broker_token: str | None = None) -> dict:
    """The env a non-sandbox runner subprocess is launched with. One place so the
    two launch sites (daemon, cli local-run) cannot drift: strip the runner-deny
    secrets, drop the provider key when brokered (the runner routes model calls
    through the broker and never needs it -- keeps it out of the runner's
    /proc/environ, readable by the same-uid agent), and stamp the run token."""
    env = role_env("runner")
    if os.environ.get("ANDYUR_BROKER_URL", ""):
        env.pop("ANTHROPIC_API_KEY", None)
    if run_token:
        env["ANDYUR_RUN_TOKEN"] = run_token
    if broker_token:
        # A DIFFERENT credential from the run token, and the difference is the
        # point: the model client sends this on every call, so it must live in
        # the agent's reach, and it is minted for the broker alone. See
        # runtoken.PURPOSE_BROKER.
        env["ANDYUR_BROKER_TOKEN"] = broker_token
    return env


def role_env(role: str, base: dict | None = None) -> dict:
    """Environment for a child running as `role`, adding the venv
    site-packages so the standalone role interpreter finds dependencies.

    For the untrusted `runner` role, strip secrets it never needs (see
    _RUNNER_DENY) so an agent sharing its uid cannot read them from /proc."""
    env = dict(base if base is not None else os.environ)
    if role == "runner":
        for var in _RUNNER_DENY:
            env.pop(var, None)
    site = os.path.join(_PROJECT_ROOT, ".venv", "lib", "python3.12", "site-packages")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = site + (os.pathsep + existing if existing else "")
    return env

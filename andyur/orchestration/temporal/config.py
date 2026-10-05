"""How to reach a Temporal service, OSS or Cloud.

**The same provider serves both.** Cloud differs from a self-hosted service in
its address, its namespace and its credentials -- and in nothing else that
Andyur cares about. So there is no `if cloud:` anywhere in this package, and
adding one would be the beginning of two providers wearing one name.

Everything here is read from the environment because a connection is
deployment configuration, not a decision: an operator who moves from a local
service to a hosted one changes these values and nothing else.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

PREFIX = "ANDYUR_TEMPORAL_"


@dataclass(frozen=True)
class TemporalConfig:
    """Connection settings. No secrets are stored on this object beyond the API
    key, which is read at construction and never logged or put in a payload."""

    address: str = "localhost:7233"
    namespace: str = "default"
    task_queue: str = "andyur"

    # Cloud, or any TLS-fronted deployment. `tls` alone is enough for a service
    # presenting a public certificate; the client cert pair is for mTLS.
    tls: bool = False
    client_cert_path: str | None = None
    client_key_path: str | None = None
    # THE CA THAT VALIDATES THE SERVER, and its absence was a hole rather than
    # an omission. A SPIFFE-issued server certificate is signed by the trust
    # domain's own CA, which is in no system root store -- so without this the
    # client either refuses a correctly configured engine or, worse, is pointed
    # at a public root store and verifies against the wrong authority entirely.
    server_ca_path: str | None = None
    api_key: str | None = None

    # How long a call to the service may take before Andyur gives up on it.
    # Bounded because the control plane calls this on request paths: an
    # unbounded wait here is a trigger endpoint that hangs instead of failing.
    rpc_timeout_seconds: float = 10.0

    # WHO DISPATCHES AN ADMITTED RUN (Architecture B+, ADR-014 D11).
    #   native  the engine observes the run; the native assignment loop hands
    #           it to the worker daemon (Architecture A)
    #   engine  the engine dispatches it: an `execute_run(run_id)` Activity on
    #           the execution queue, run by the execution worker
    # Anything else is refused at construction rather than read as one of these.
    dispatch: str = "native"
    execution_queue: str = "andyur-runs"

    def __post_init__(self) -> None:
        if self.dispatch not in ("native", "engine"):
            raise ValueError(
                f"ANDYUR_TEMPORAL_DISPATCH must be 'native' or 'engine', not "
                f"{self.dispatch!r}")

    @classmethod
    def from_env(cls) -> "TemporalConfig":
        def s(name, default=None):
            v = os.environ.get(PREFIX + name)
            return v.strip() if v and v.strip() else default

        return cls(
            address=s("ADDRESS", "localhost:7233"),
            namespace=s("NAMESPACE", "default"),
            task_queue=s("TASK_QUEUE", "andyur"),
            tls=(s("TLS", "off") or "off").lower() in {"on", "true", "1", "yes"},
            client_cert_path=s("CLIENT_CERT"),
            client_key_path=s("CLIENT_KEY"),
            server_ca_path=s("SERVER_CA"),
            api_key=s("API_KEY"),
            rpc_timeout_seconds=float(s("RPC_TIMEOUT_SECONDS", "10") or 10),
            dispatch=(s("DISPATCH", "native") or "native").lower(),
            execution_queue=s("EXECUTION_QUEUE", "andyur-runs"),
        )

    def describe(self) -> str:
        """For logs and health output. Deliberately omits the API key: this
        string is the one most likely to be pasted into an issue."""
        where = f"{self.address}/{self.namespace}"
        return f"{where} (tls={'on' if self.tls else 'off'}, queue={self.task_queue})"

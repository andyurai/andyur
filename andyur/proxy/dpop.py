"""Per-run RFC 9449 holder lifecycle for the trusted tool sidecar."""

from __future__ import annotations

import threading

from requests_oauth2client import DPoPKey

from ..resource_dpop import access_token_hash


class ClosedDPoPHolder(RuntimeError):
    pass


class RunDPoPHolder:
    """One non-serialized ES256 holder key, released with one run sidecar.

    `requests-oauth2client` owns proof construction and Curity nonce state. The
    wrapper prevents key serialization from becoming an Andyur API and makes
    reference release observable and idempotent. Python cannot guarantee a
    physical memory wipe, so this class makes no zeroization claim.
    """

    def __init__(self):
        self._key: DPoPKey | None = DPoPKey.generate(alg="ES256")
        self._lock = threading.Lock()

    @property
    def jkt(self) -> str:
        with self._lock:
            if self._key is None:
                raise ClosedDPoPHolder("the run DPoP holder is closed")
            return self._key.dpop_jkt

    def token_endpoint_key(self) -> DPoPKey:
        """Trusted AS adapter access; never expose this to the agent/API."""
        with self._lock:
            if self._key is None:
                raise ClosedDPoPHolder("the run DPoP holder is closed")
            return self._key

    def resource_proof(self, method: str, url: str, access_token: str) -> str:
        with self._lock:
            if self._key is None:
                raise ClosedDPoPHolder("the run DPoP holder is closed")
            return str(self._key.proof(
                method, url, ath=access_token_hash(access_token)))

    def close(self) -> None:
        with self._lock:
            self._key = None

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._key is None

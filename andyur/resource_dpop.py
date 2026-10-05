"""RFC 9449 enforcement at an Andyur-managed resource boundary.

PyJWT and cryptography carry JOSE. This module owns only the comparisons that
require the live request plus bounded, fail-closed replay state. The access
token claims supplied here must already have been signature/issuer/audience/
lifetime verified by the resource's OAuth verifier.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass

import jwt


class DPoPRefused(ValueError):
    pass


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def access_token_hash(token: str) -> str:
    try:
        raw = token.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise DPoPRefused("access token is not bounded ASCII") from exc
    return _b64u(hashlib.sha256(raw).digest())


def _thumbprint(jwk: dict) -> str:
    if set(jwk) != {"kty", "crv", "x", "y"} \
            or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" \
            or not all(isinstance(jwk.get(name), str) and jwk[name]
                       for name in ("x", "y")):
        raise DPoPRefused("proof JWK is not one public P-256 key")
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"), sort_keys=True).encode()
    return _b64u(hashlib.sha256(canonical).digest())


@dataclass(frozen=True)
class DPoPDecision:
    actor: str
    jti: str
    holder_jkt: str
    proof_iat: int


class DPoPVerifier:
    """Thread-safe, non-evicting replay enforcement partitioned by run actor."""

    def __init__(self, *, freshness_seconds: int = 5, clock_skew_seconds: int = 1,
                 per_run_entries: int = 512, aggregate_entries: int = 4096,
                 max_proof_bytes: int = 8192):
        if not (freshness_seconds > clock_skew_seconds >= 0
                and per_run_entries > 0 and aggregate_entries >= per_run_entries
                and max_proof_bytes > 0):
            raise ValueError("invalid DPoP verifier limits")
        self.freshness_seconds = freshness_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.per_run_entries = per_run_entries
        self.aggregate_entries = aggregate_entries
        self.max_proof_bytes = max_proof_bytes
        self._seen: dict[str, dict[tuple[str, str], int]] = {}
        self._lock = threading.Lock()

    def _consume(self, actor: str, holder: str, jti: str, expires: int,
                 now: int) -> None:
        with self._lock:
            empty = []
            for partition_actor, partition in self._seen.items():
                stale = [key for key, deadline in partition.items() if deadline <= now]
                for key in stale:
                    del partition[key]
                if not partition:
                    empty.append(partition_actor)
            for partition_actor in empty:
                self._seen.pop(partition_actor, None)
            partition = self._seen.get(actor)
            replay_key = (holder, jti)
            if partition is not None and replay_key in partition:
                raise DPoPRefused("proof jti was replayed")
            total = sum(len(value) for value in self._seen.values())
            if total >= self.aggregate_entries:
                raise DPoPRefused("aggregate replay capacity is closed")
            if partition is not None and len(partition) >= self.per_run_entries:
                raise DPoPRefused("run replay capacity is closed")
            self._seen.setdefault(actor, {})[replay_key] = expires

    def validate(self, *, access_token: str, access_claims: dict,
                 proof: str, method: str, external_url: str,
                 expected_actor: str, now: int | None = None) -> DPoPDecision:
        if not isinstance(proof, str) or not proof \
                or len(proof.encode("utf-8")) > self.max_proof_bytes:
            raise DPoPRefused("DPoP proof is absent or oversized")
        if not isinstance(method, str) or method != method.upper() or not method:
            raise DPoPRefused("request method is not canonical uppercase")
        if not isinstance(external_url, str) or not external_url.startswith("https://"):
            raise DPoPRefused("resource URL is not sealed HTTPS")
        if not isinstance(expected_actor, str) or not expected_actor:
            raise DPoPRefused("resource has no sealed expected actor")
        act = access_claims.get("act")
        if not isinstance(act, dict) or set(act) != {"sub"} \
                or act.get("sub") != expected_actor:
            raise DPoPRefused("token actor does not match sealed run actor")
        cnf = access_claims.get("cnf")
        if not isinstance(cnf, dict) or set(cnf) != {"jkt"} \
                or not isinstance(cnf.get("jkt"), str) or not cnf["jkt"]:
            raise DPoPRefused("token cnf is not one closed jkt binding")
        try:
            header = jwt.get_unverified_header(proof)
        except Exception as exc:  # noqa: BLE001
            raise DPoPRefused("proof JOSE header is unreadable") from exc
        if set(header) != {"alg", "jwk", "typ"} \
                or header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            raise DPoPRefused("proof JOSE header is outside the closed profile")
        jwk = header.get("jwk")
        holder = _thumbprint(jwk) if isinstance(jwk, dict) else ""
        if not hmac.compare_digest(holder, cnf["jkt"]):
            raise DPoPRefused("proof holder does not match token cnf")
        try:
            claims = jwt.decode(
                proof, jwt.PyJWK.from_dict(jwk).key, algorithms=["ES256"],
                options={"verify_aud": False,
                         "require": ["jti", "iat", "htm", "htu", "ath"]})
        except Exception as exc:  # noqa: BLE001
            raise DPoPRefused("proof signature or required claims are invalid") from exc
        if not isinstance(claims.get("jti"), str) or not claims["jti"] \
                or len(claims["jti"].encode()) > 128:
            raise DPoPRefused("proof jti is outside the closed profile")
        issued = claims.get("iat")
        current = int(time.time()) if now is None else now
        if not isinstance(issued, int) or isinstance(issued, bool) \
                or not (-self.clock_skew_seconds <= current - issued
                        < self.freshness_seconds):
            raise DPoPRefused("proof is outside the freshness window")
        if claims.get("htm") != method \
                or not hmac.compare_digest(str(claims.get("htu", "")), external_url):
            raise DPoPRefused("proof method or external URL does not match")
        if not hmac.compare_digest(str(claims.get("ath", "")),
                                   access_token_hash(access_token)):
            raise DPoPRefused("proof ath does not bind the access token")
        self._consume(expected_actor, holder, claims["jti"],
                      issued + self.freshness_seconds, current)
        return DPoPDecision(expected_actor, claims["jti"], holder, issued)

    def counts(self) -> tuple[int, int]:
        with self._lock:
            return len(self._seen), sum(len(value) for value in self._seen.values())

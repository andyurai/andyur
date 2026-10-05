from __future__ import annotations

import json
import stat
import time
import urllib.parse
from pathlib import Path
from collections.abc import Callable

import httpx

from .. import otel


MAX_RESPONSE = 64 << 10
PROVIDERS = frozenset({"entra", "okta", "auth0", "pingfederate", "pingam"})
KINDS = frozenset({"andyur-client", "test-user"})
SERVICE_REF = __import__("re").compile(r"^[a-z][a-z0-9-]{2,63}$")
# RFC 9110 field-name token. Anchored so a name carrying CR/LF, a colon or
# whitespace cannot reach the outbound request builder.
HEADER_NAME = __import__("re").compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")


class OpenBaoError(RuntimeError):
    def __init__(self, message: str, *, reason: str = "invalid") -> None:
        super().__init__(message)
        self.reason = reason


def _failure_reason(exc: Exception) -> str:
    return exc.reason if isinstance(exc, OpenBaoError) else "unknown"


def _private_file(path: str, *, what: str, limit: int) -> bytes:
    source = Path(path)
    try:
        info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise OpenBaoError(f"{what} must be a regular non-symlink file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise OpenBaoError(f"{what} must not be accessible by group/other")
        with source.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise OpenBaoError(f"cannot read {what}") from exc
    if not data or len(data) > limit:
        raise OpenBaoError(f"{what} is empty or exceeds {limit} bytes")
    return data


class OpenBaoClient:
    """A bounded, lease-scoped client for the trusted credential service.

    Authentication is a purpose-specific projected JWT/SVID read from a private
    file. The resulting OpenBao token exists only in memory and is revoked on
    close. Callers select from closed provider/kind vocabularies, so untrusted
    input cannot become an arbitrary vault path.
    """

    def __init__(self, address: str, ca_file: str, role: str, *,
                 transport: httpx.BaseTransport | None = None):
        parsed = urllib.parse.urlsplit(address)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise OpenBaoError("OpenBao address must be a credential-free HTTPS origin")
        if not role or len(role) > 128 or not role.replace("-", "").isalnum():
            raise OpenBaoError("OpenBao role is invalid")
        ca = _private_file(ca_file, what="OpenBao CA", limit=64 << 10)
        # httpx needs a path for its SSL context; reading above establishes the
        # bounded, private, non-symlink contract before it consumes the file.
        del ca
        self._base = address.rstrip("/")
        self._role = role
        self._token: str | None = None
        self._client = httpx.Client(verify=ca_file, timeout=httpx.Timeout(5, connect=2),
                                    transport=transport,
                                    headers={"Accept-Encoding": "identity"})

    def _json(self, method: str, path: str, *, payload=None, authenticated=False,
              validate: Callable[[dict], object] | None = None):
        operation = "fetch" if method == "GET" else \
            "cleanup" if path.endswith("/revoke-self") else \
            "exchange" if path.endswith("/login") else "call"
        with otel.observe_dependency(
                "andyur-credential-service", "vault", operation,
                _failure_reason):
            response = self._request_json(
                method, path, payload=payload, authenticated=authenticated)
            return validate(response) if validate is not None else response

    def _request_json(self, method: str, path: str, *, payload=None,
                      authenticated=False) -> dict:
        deadline = time.monotonic() + 5
        headers = {}
        if authenticated:
            if self._token is None:
                raise OpenBaoError("OpenBao client is not authenticated")
            headers["X-Vault-Token"] = self._token
        try:
            with self._client.stream(method, self._base + path, json=payload,
                                     headers=headers) as response:
                body = bytearray()
                if response.is_stream_consumed:  # MockTransport/in-memory clients
                    body += response.content
                else:
                    for chunk in response.iter_raw():
                        body += chunk
                        if len(body) > MAX_RESPONSE:
                            raise OpenBaoError("OpenBao response exceeds 64 KiB")
                        if time.monotonic() > deadline:
                            raise OpenBaoError(
                                "OpenBao response exceeded total 5-second budget",
                                reason="timeout")
                if len(body) > MAX_RESPONSE:
                    raise OpenBaoError("OpenBao response exceeds 64 KiB")
                if response.status_code < 200 or response.status_code >= 300:
                    raise OpenBaoError(
                        f"OpenBao refused request with HTTP {response.status_code}",
                        reason="refused")
        except httpx.HTTPError as exc:
            reason = "timeout" if isinstance(exc, httpx.TimeoutException) \
                else "unavailable"
            raise OpenBaoError(
                f"OpenBao transport failed: {type(exc).__name__}",
                reason=reason) from exc
        # A 2xx with no body is success with nothing to say, not a protocol error:
        # POST /v1/auth/token/revoke-self answers 204 No Content, and a real
        # OpenBao (unlike a mock that returns a JSON body) sends an empty body for
        # it. Parsing "" as JSON would raise here and break close()/`__exit__`,
        # so an empty 2xx body is an empty object.
        if not body:
            return {}
        try:
            parsed = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OpenBaoError("OpenBao returned malformed JSON") from exc
        if not isinstance(parsed, dict):
            raise OpenBaoError("OpenBao returned a non-object response")
        return parsed

    def login(self, jwt_file: str) -> None:
        if self._token is not None:
            raise OpenBaoError("OpenBao client is already authenticated")
        try:
            jwt = _private_file(jwt_file, what="OpenBao workload JWT", limit=16 << 10).decode()
        except UnicodeDecodeError as exc:
            raise OpenBaoError("OpenBao workload JWT must be UTF-8") from exc
        def validate(response: dict) -> str:
            auth = response.get("auth")
            token = auth.get("client_token") if isinstance(auth, dict) else None
            lease = auth.get("lease_duration") if isinstance(auth, dict) else None
            if not isinstance(token, str) or not token or not isinstance(lease, int) \
                    or lease <= 0 or lease > 900:
                raise OpenBaoError("OpenBao returned an invalid or overlong login lease")
            return token
        token = self._json("POST", "/v1/auth/jwt/login",
                           payload={"role": self._role, "jwt": jwt}, validate=validate)
        self._token = token

    def read(self, environment: str, provider: str, kind: str) -> dict[str, str]:
        if environment not in {"development", "production"}:
            raise OpenBaoError("unknown credential environment")
        if provider not in PROVIDERS or kind not in KINDS:
            raise OpenBaoError("unknown credential provider or kind")
        if environment == "production" and kind == "test-user":
            raise OpenBaoError("production test-user credentials are forbidden")
        def validate(response: dict) -> dict[str, str]:
            outer = response.get("data")
            secret = outer.get("data") if isinstance(outer, dict) else None
            if (not isinstance(secret, dict) or not secret
                    or not all(isinstance(k, str) and isinstance(v, str) and v
                               for k, v in secret.items())):
                raise OpenBaoError("OpenBao secret has an invalid shape")
            return dict(secret)
        return self._json(
            "GET", f"/v1/secret/data/{environment}/authorization-servers/{provider}/{kind}",
            authenticated=True, validate=validate)

    def write(self, environment: str, provider: str, kind: str,
              secret: dict[str, str]) -> None:
        if environment != "development":
            raise OpenBaoError("this client cannot write production credentials")
        if provider not in PROVIDERS or kind != "andyur-client":
            raise OpenBaoError("unknown or non-writable credential path")
        if (not isinstance(secret, dict) or set(secret) != {"client_id", "client_secret"}
                or not all(isinstance(value, str) and value for value in secret.values())
                or sum(len(value.encode()) for value in secret.values()) > 16 << 10):
            raise OpenBaoError("credential secret must contain bounded client_id/client_secret")
        self._json(
            "POST", f"/v1/secret/data/{environment}/authorization-servers/{provider}/{kind}",
            # CAS=0 is create-only. A repeated provisioning run must not silently
            # replace the credential used by a certified runtime.
            payload={"data": secret, "options": {"cas": 0}}, authenticated=True)

    def read_service_headers(self, credential_ref: str) -> dict[str, str]:
        """Every header this brokered credential sets, as {name: value}.

        The shape is a MAP because a single name/value pair could not express a
        vendor that authenticates with two headers, and Datadog -- DD-API-KEY
        plus DD-APPLICATION-KEY -- is the most important observability vendor
        for an SRE agent.

        WHICH names are acceptable is not decided here. This validates only that
        the secret is well formed: real names, real values, no CR/LF, bounded.
        The authorization question, "may THIS binding set THIS header", is
        answered at the sidecar against the binding's own declared set, because
        that is authority data and the vault holds transport material. A single
        hardcoded allowlist in this file was the previous answer and it could
        not describe any vendor outside two names.
        """
        if not isinstance(credential_ref, str) or not SERVICE_REF.fullmatch(credential_ref):
            raise OpenBaoError("invalid brokered service credential reference")

        def validate(response: dict) -> dict[str, str]:
            outer = response.get("data")
            secret = outer.get("data") if isinstance(outer, dict) else None
            if not isinstance(secret, dict) or set(secret) != {"headers"}:
                raise OpenBaoError("brokered service credential has an invalid shape")
            headers = secret["headers"]
            if not isinstance(headers, dict) or not headers or len(headers) > 8:
                raise OpenBaoError(
                    "brokered service credential must carry 1..8 headers")
            out: dict[str, str] = {}
            for name, value in headers.items():
                if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
                    raise OpenBaoError(
                        "brokered service credential has an invalid header name")
                if name.lower() in {k.lower() for k in out}:
                    raise OpenBaoError(
                        "brokered service credential repeats a header name")
                if (not isinstance(value, str) or not value
                        or "\r" in value or "\n" in value
                        or len(value.encode()) > 16 << 10):
                    raise OpenBaoError(
                        "brokered service credential value is invalid")
                out[name] = value
            return out

        return self._json(
            "GET", f"/v1/secret/data/production/saas/{credential_ref}",
            authenticated=True, validate=validate)

    def close(self) -> None:
        try:
            if self._token is not None:
                self._json("POST", "/v1/auth/token/revoke-self",
                           payload={}, authenticated=True)
        finally:
            self._token = None
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

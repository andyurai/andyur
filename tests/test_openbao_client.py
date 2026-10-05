import json
from contextlib import contextmanager

import httpx
import pytest

from andyur.credential_service.openbao import OpenBaoClient, OpenBaoError
from andyur.credential_service import openbao


def _private(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value)
    path.chmod(0o600)
    return str(path)


def _client(tmp_path, handler):
    ca = _private(tmp_path, "ca.pem", "test-ca")
    return OpenBaoClient("https://openbao.test", ca, "credential-service",
                         transport=httpx.MockTransport(handler))


def test_workload_login_reads_private_file_and_revokes_lease(tmp_path):
    seen = []
    def handler(request):
        seen.append((request.url.path, request.headers.get("x-vault-token")))
        if request.url.path.endswith("login"):
            assert json.loads(request.content) == {"role": "credential-service", "jwt": "svid"}
            return httpx.Response(200, json={"auth": {"client_token": "lease", "lease_duration": 300}})
        return httpx.Response(204, json={})
    jwt = _private(tmp_path, "svid.jwt", "svid")
    client = _client(tmp_path, handler)
    client.login(jwt)
    client.close()
    assert seen == [("/v1/auth/jwt/login", None),
                    ("/v1/auth/token/revoke-self", "lease")]
    assert "lease" not in repr(client.__dict__)


def test_close_succeeds_on_a_real_empty_204_not_a_json_body(tmp_path):
    """A REAL OpenBao answers revoke-self with 204 No Content -- an EMPTY body.
    The other mocks send `httpx.Response(204, json={})`, whose parseable `{}`
    hid a live bug: _json() choked on the empty body and close() (and so the
    `with` context manager) raised against a real vault. This pins the empty
    2xx-body path both directly and through __exit__."""
    def handler(request):
        if request.url.path.endswith("login"):
            return httpx.Response(200, json={"auth": {"client_token": "t", "lease_duration": 30}})
        return httpx.Response(204)  # genuinely empty, as OpenBao really answers
    jwt = _private(tmp_path, "svid.jwt", "svid")
    client = _client(tmp_path, handler)
    client.login(jwt)
    client.close()          # must not raise on the empty 204
    assert client._token is None

    # ...and the same through the context manager, whose __exit__ calls close().
    with _client(tmp_path, handler) as c:
        c.login(_private(tmp_path, "svid2.jwt", "svid"))
    assert c._token is None


def test_read_uses_closed_path_and_returns_only_string_secret(tmp_path):
    writes = []
    def handler(request):
        if request.url.path.endswith("login"):
            return httpx.Response(200, json={"auth": {"client_token": "t", "lease_duration": 30}})
        if request.method == "POST":
            writes.append(json.loads(request.content))
            return httpx.Response(204, json={})
        return httpx.Response(200, json={"data": {"data": {"client_id": "id", "secret": "s"}}})
    client = _client(tmp_path, handler)
    client.login(_private(tmp_path, "jwt", "svid"))
    assert client.read("development", "entra", "andyur-client") == {
        "client_id": "id", "secret": "s"}
    with pytest.raises(OpenBaoError, match="unknown"):
        client.read("development", "../../root", "andyur-client")
    with pytest.raises(OpenBaoError, match="forbidden"):
        client.read("production", "entra", "test-user")
    client.write("development", "entra", "andyur-client",
                 {"client_id": "id", "client_secret": "secret"})
    assert writes == [{"data": {"client_id": "id", "client_secret": "secret"},
                       "options": {"cas": 0}}]
    with pytest.raises(OpenBaoError, match="cannot write production"):
        client.write("production", "entra", "andyur-client",
                     {"client_id": "id", "client_secret": "secret"})
    client.close()


def test_rejects_insecure_origin_public_jwt_and_overlong_lease(tmp_path):
    ca = _private(tmp_path, "ca", "ca")
    with pytest.raises(OpenBaoError, match="HTTPS"):
        OpenBaoClient("http://openbao", ca, "role")
    jwt = tmp_path / "jwt"
    jwt.write_text("svid")
    jwt.chmod(0o644)
    client = _client(tmp_path, lambda _: httpx.Response(200, json={}))
    with pytest.raises(OpenBaoError, match="group/other"):
        client.login(str(jwt))
    client.close()
    client = _client(tmp_path, lambda _: httpx.Response(
        200, json={"auth": {"client_token": "t", "lease_duration": 901}}))
    with pytest.raises(OpenBaoError, match="overlong"):
        client.login(_private(tmp_path, "jwt2", "svid"))
    client.close()


def test_rejects_oversized_or_malformed_secret_and_never_logs_body(tmp_path):
    responses = iter([
        httpx.Response(200, json={"auth": {"client_token": "t", "lease_duration": 30}}),
        httpx.Response(200, content=b"x" * ((64 << 10) + 1)),
        httpx.Response(204, json={}),
    ])
    client = _client(tmp_path, lambda _: next(responses))
    client.login(_private(tmp_path, "jwt", "svid"))
    with pytest.raises(OpenBaoError, match="64 KiB") as error:
        client.read("development", "okta", "andyur-client")
    assert "xxx" not in str(error.value)
    client.close()


def test_service_header_path_and_shape_are_closed(tmp_path):
    seen = []
    def handler(request):
        seen.append(request.url.path)
        if request.url.path.endswith("login"):
            return httpx.Response(200, json={"auth": {
                "client_token": "t", "lease_duration": 30}})
        if request.url.path.endswith("revoke-self"):
            return httpx.Response(204, json={})
        return httpx.Response(200, json={"data": {"data": {
            "headers": {"Authorization": "Bearer service"}}}})
    client = _client(tmp_path, handler)
    client.login(_private(tmp_path, "jwt", "svid"))
    assert client.read_service_headers("github-service") == {
        "Authorization": "Bearer service"}
    with pytest.raises(OpenBaoError, match="invalid.*reference"):
        client.read_service_headers("../../root")
    client.close()
    assert "/v1/secret/data/production/saas/github-service" in seen


@pytest.mark.parametrize(("response", "expected"), [
    (httpx.Response(403), "refused"),
    (httpx.ConnectError("down"), "unavailable"),
    (httpx.ReadTimeout("slow"), "timeout"),
])
def test_openbao_dependency_signal_classifies_failure_without_secret_fields(
        tmp_path, monkeypatch, response, expected):
    observed = []

    @contextmanager
    def observe(service, dependency, operation, classify):
        try:
            yield
        except Exception as exc:
            observed.append((service, dependency, operation, classify(exc)))
            raise

    monkeypatch.setattr(openbao.otel, "observe_dependency", observe)

    def handler(request):
        if isinstance(response, Exception):
            raise response
        return response

    client = _client(tmp_path, handler)
    with pytest.raises(OpenBaoError):
        client.login(_private(tmp_path, "telemetry.jwt", "TOP-SECRET-SVID"))
    client.close()
    assert observed == [(
        "andyur-credential-service", "vault", "exchange", expected)]
    assert "TOP-SECRET-SVID" not in repr(observed)


def test_openbao_invalid_200_is_failure_not_transport_success(tmp_path, monkeypatch):
    observed = []

    @contextmanager
    def observe(service, dependency, operation, classify):
        try:
            yield
        except Exception as exc:
            observed.append(("failure", classify(exc)))
            raise
        else:
            observed.append(("success", None))

    monkeypatch.setattr(openbao.otel, "observe_dependency", observe)
    client = _client(tmp_path, lambda request: httpx.Response(
        200, json={"auth": {"client_token": "token", "lease_duration": 901}}))
    with pytest.raises(OpenBaoError, match="invalid or overlong"):
        client.login(_private(tmp_path, "invalid.jwt", "jwt"))
    client.close()
    assert observed == [("failure", "invalid")]

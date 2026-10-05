from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from andyur.asprovision import cli
from andyur.asprovision.model import ProvisionSpecError, load_spec
from andyur.asprovision.terraform import VERSIONS, render


def _document(provider: str) -> dict:
    configs = {
        "entra": {"tenant_id": "00000000-0000-0000-0000-000000000001",
                  "redirect_uri": "https://localhost/callback",
                  "middle_identifier": "api://andyur-middle",
                  "downstream_identifier": "api://andyur-files"},
        "okta": {"org_name": "dev-123456", "base_url": "okta.com",
                 "authorization_server_id": "default",
                 "redirect_uri": "https://localhost/callback"},
        "auth0": {"domain": "andyur-dev.us.auth0.com",
                  "source_audience": "https://andyur.example/source",
                  "target_audience": "https://andyur.example/files",
                  "redirect_uri": "https://localhost/callback"},
        "pingfederate": {"issuer": "https://ping.example",
                          "token_endpoint": "https://ping.example/as/token.oauth2",
                          "jwks_url": "https://ping.example/pf/JWKS"},
        "pingam": {"issuer": "https://am.example/oauth2/realms/root",
                   "token_endpoint": "https://am.example/oauth2/realms/root/access_token",
                   "jwks_url": "https://am.example/oauth2/realms/root/connect/jwk_uri"},
    }
    return {"schema": "andyur-as-provision/v1", "provider": provider,
            "name_prefix": "andyur-cert", "actions": {"files:read": "files.read"},
            "config": configs[provider]}


def _load(tmp_path: Path, provider: str):
    path = tmp_path / f"{provider}.json"
    path.write_text(json.dumps(_document(provider)))
    return load_spec(str(path))


@pytest.mark.parametrize("provider", ["entra", "okta", "auth0", "pingfederate", "pingam"])
def test_closed_specs_render_deterministically_with_private_files(tmp_path, provider):
    first, second = tmp_path / "first", tmp_path / "second"
    one = render(_load(tmp_path, provider), str(first))
    two = render(_load(tmp_path, provider), str(second))
    assert one == two
    for name, digest in one["files"].items():
        data = (first / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        assert stat.S_IMODE((first / name).stat().st_mode) == 0o600
    assert stat.S_IMODE((first / "render-manifest.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(extra=True),
    lambda d: d["actions"].update({"BAD": "x"}),
    lambda d: d["config"].update(secret="must-not-be-here"),
])
def test_spec_rejects_unknown_or_invalid_authority(tmp_path, mutation):
    document = _document("auth0")
    mutation(document)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ProvisionSpecError):
        load_spec(str(path))


def test_cloud_templates_pin_providers_and_never_embed_credentials(tmp_path):
    expected = {
        "entra": ["access_as_user", "required_resource_access", "api://andyur-middle"],
        "okta": ["urn:ietf:params:oauth:grant-type:token-exchange", "client_secret_basic"],
        "auth0": ["on_behalf_of_token_exchange", 'subject_type = "user"'],
    }
    for provider, markers in expected.items():
        output = tmp_path / provider
        render(_load(tmp_path, provider), str(output))
        main = (output / "main.tf").read_text()
        variables = (output / "terraform.tfvars.json").read_text()
        assert f'version = "= {VERSIONS[provider]}"' in main
        assert "client_secret" not in variables.lower()
        assert all(marker in main or marker in variables for marker in markers)


def test_render_refuses_to_overwrite_any_existing_file(tmp_path):
    output = tmp_path / "owned"
    output.mkdir()
    (output / "state.tfstate").write_text("valuable")
    with pytest.raises(ValueError, match="refusing"):
        render(_load(tmp_path, "auth0"), str(output))
    assert (output / "state.tfstate").read_text() == "valuable"


def test_plan_verifies_render_and_apply_requires_exact_plan_digest(tmp_path, monkeypatch, capsys):
    output = tmp_path / "render"
    render(_load(tmp_path, "auth0"), str(output))
    calls = []

    def fake_terraform(directory, args):
        calls.append(args)
        if args[0] == "plan":
            (directory / "andyur.tfplan").write_bytes(b"reviewed-plan")

    monkeypatch.setattr(cli, "_terraform", fake_terraform)
    cli.main(["plan", "--dir", str(output)])
    digest = json.loads(capsys.readouterr().out)["plan_sha256"]
    with pytest.raises(SystemExit, match="digest"):
        cli.main(["apply", "--dir", str(output), "--plan-sha256", "0" * 64])
    cli.main(["apply", "--dir", str(output), "--plan-sha256", digest])
    assert calls[-1] == ["apply", "andyur.tfplan"]


def test_plan_rejects_post_render_tampering_before_terraform(tmp_path, monkeypatch):
    output = tmp_path / "render"
    render(_load(tmp_path, "okta"), str(output))
    (output / "main.tf").write_text("resource widened")
    monkeypatch.setattr(cli, "_terraform", lambda *_: pytest.fail("must not execute"))
    with pytest.raises(SystemExit, match="changed after review"):
        cli.main(["plan", "--dir", str(output)])


def test_opentofu_requires_private_enforced_state_and_plan_encryption(tmp_path, monkeypatch):
    encryption = tmp_path / "encryption.hcl"
    encryption.write_text('state { enforced = true }\nplan { enforced = true }\n')
    encryption.chmod(0o600)
    monkeypatch.setenv("ANDYUR_TOFU_ENCRYPTION_FILE", str(encryption))
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    cli._terraform(tmp_path, ["validate"])
    assert calls[0][0][0] == "tofu"
    assert calls[0][1]["env"]["TF_ENCRYPTION"] == encryption.read_text()
    encryption.chmod(0o644)
    with pytest.raises(SystemExit, match="group/other"):
        cli._terraform(tmp_path, ["validate"])


def test_status_never_prints_sensitive_outputs(tmp_path, monkeypatch):
    output = tmp_path / "render"
    render(_load(tmp_path, "entra"), str(output))
    calls = []
    monkeypatch.setattr(cli, "_terraform", lambda directory, args: calls.append(args))
    cli.main(["status", "--dir", str(output)])
    assert calls == [["state", "list"]]


def test_store_hands_outputs_to_openbao_without_printing_secret(tmp_path, monkeypatch, capsys):
    output = tmp_path / "render"
    render(_load(tmp_path, "okta"), str(output))
    for name in ("ANDYUR_OPENBAO_ADDR", "ANDYUR_OPENBAO_CA_FILE",
                 "ANDYUR_OPENBAO_ROLE", "ANDYUR_OPENBAO_JWT_FILE"):
        monkeypatch.setenv(name, "configured")
    monkeypatch.setattr(cli, "_terraform_output", lambda _: {
        "andyur_client_id": {"value": "client-id"},
        "andyur_client_secret": {"value": "never-print-me"}})
    events = []

    class Vault:
        def __init__(self, *args): events.append(("init", args))
        def __enter__(self): return self
        def __exit__(self, *_): events.append(("close",))
        def login(self, path): events.append(("login", path))
        def write(self, environment, provider, kind, secret):
            events.append(("write", (environment, provider, kind, dict(secret))))

    monkeypatch.setattr(cli, "OpenBaoClient", Vault)
    cli.main(["store", "--dir", str(output)])
    printed = capsys.readouterr().out
    assert "never-print-me" not in printed
    assert '"stored": true' in printed
    assert ("write", ("development", "okta", "andyur-client",
                      {"client_id": "client-id", "client_secret": "never-print-me"})) in events


def test_store_refuses_missing_vault_identity_before_reading_outputs(tmp_path, monkeypatch):
    output = tmp_path / "render"
    render(_load(tmp_path, "auth0"), str(output))
    for name in ("ANDYUR_OPENBAO_ADDR", "ANDYUR_OPENBAO_CA_FILE",
                 "ANDYUR_OPENBAO_ROLE", "ANDYUR_OPENBAO_JWT_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "_terraform_output", lambda _: pytest.fail("must not read secrets"))
    with pytest.raises(SystemExit, match="missing OpenBao"):
        cli.main(["store", "--dir", str(output)])


def test_ping_bundle_is_explicitly_non_terraform(tmp_path):
    output = tmp_path / "ping"
    render(_load(tmp_path, "pingam"), str(output))
    bundle = json.loads((output / "pingam-import.json").read_text())
    assert bundle["provider"] == "pingam"
    assert "token exchanger plugin" in bundle["requirements"]
    with pytest.raises(SystemExit, match="import bundles"):
        cli.main(["status", "--dir", str(output)])

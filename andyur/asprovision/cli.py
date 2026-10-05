from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

from .model import load_spec
from .terraform import render
from ..credential_service import OpenBaoClient, OpenBaoError


def _verify_render(directory: Path) -> str:
    try:
        manifest = json.loads((directory / "render-manifest.json").read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SystemExit("directory is not a valid Andyur provisioning render") from exc
    if (not isinstance(manifest, dict)
            or set(manifest) != {"schema", "provider", "files"}
            or manifest["schema"] != "andyur-as-provision-render/v1"
            or manifest["provider"] not in {"entra", "okta", "auth0",
                                            "pingfederate", "pingam"}
            or not isinstance(manifest["files"], dict)):
        raise SystemExit("provisioning render manifest has an invalid schema")
    for name, expected in manifest["files"].items():
        if (not isinstance(name, str) or Path(name).name != name
                or not isinstance(expected, str) or len(expected) != 64):
            raise SystemExit("provisioning render manifest has an invalid file entry")
        try:
            actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise SystemExit(f"rendered file is missing: {name}") from exc
        if actual != expected:
            raise SystemExit(f"rendered file changed after review: {name}")
    return manifest["provider"]


def _encryption_environment() -> dict[str, str]:
    source = os.environ.get("ANDYUR_TOFU_ENCRYPTION_FILE", "")
    if not source:
        raise SystemExit("set ANDYUR_TOFU_ENCRYPTION_FILE; unencrypted state is forbidden")
    path = Path(source)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise SystemExit("OpenTofu encryption configuration must be a regular non-symlink file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SystemExit("OpenTofu encryption configuration must not be accessible by group/other")
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit("cannot read OpenTofu encryption configuration") from exc
    if len(raw) > 64 << 10:
        raise SystemExit("OpenTofu encryption configuration exceeds 64 KiB")
    try:
        config = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("OpenTofu encryption configuration must be UTF-8") from exc
    if ("state" not in config or "plan" not in config
            or config.count("enforced = true") < 2):
        raise SystemExit("OpenTofu encryption must enforce both state and plan encryption")
    environment = os.environ.copy()
    environment["TF_ENCRYPTION"] = config
    return environment


def _terraform(directory: Path, args: list[str]) -> None:
    try:
        subprocess.run(["tofu", f"-chdir={directory}", *args], check=True,
                       env=_encryption_environment())
    except FileNotFoundError as exc:
        raise SystemExit("OpenTofu is required for encrypted cloud-provider provisioning") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def _terraform_output(directory: Path) -> dict:
    try:
        result = subprocess.run(
            ["tofu", f"-chdir={directory}", "output", "-json"], check=True,
            capture_output=True, env=_encryption_environment())
    except FileNotFoundError as exc:
        raise SystemExit("OpenTofu is required for encrypted cloud-provider provisioning") from exc
    except subprocess.CalledProcessError as exc:
        # Do not include captured provider output: provider diagnostics have
        # historically echoed values thought to be sensitive.
        raise SystemExit(exc.returncode) from exc
    if len(result.stdout) > 256 << 10:
        raise SystemExit("OpenTofu output exceeds 256 KiB")
    try:
        output = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("OpenTofu returned malformed output JSON") from exc
    if not isinstance(output, dict):
        raise SystemExit("OpenTofu returned a non-object output")
    return output


def _output_value(output: dict, name: str) -> str:
    item = output.get(name)
    value = item.get("value") if isinstance(item, dict) else None
    if not isinstance(value, str) or not value:
        raise SystemExit(f"OpenTofu output {name} is missing or invalid")
    return value


def _store_in_openbao(directory: Path, provider: str) -> None:
    required = {name: os.environ.get(name, "") for name in (
        "ANDYUR_OPENBAO_ADDR", "ANDYUR_OPENBAO_CA_FILE",
        "ANDYUR_OPENBAO_ROLE", "ANDYUR_OPENBAO_JWT_FILE")}
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit("missing OpenBao settings: " + ", ".join(missing))
    output = _terraform_output(directory)
    secret = {"client_id": _output_value(output, "andyur_client_id"),
              "client_secret": _output_value(output, "andyur_client_secret")}
    try:
        with OpenBaoClient(required["ANDYUR_OPENBAO_ADDR"],
                           required["ANDYUR_OPENBAO_CA_FILE"],
                           required["ANDYUR_OPENBAO_ROLE"]) as vault:
            vault.login(required["ANDYUR_OPENBAO_JWT_FILE"])
            vault.write("development", provider, "andyur-client", secret)
    except OpenBaoError as exc:
        raise SystemExit(f"OpenBao credential handoff failed: {exc}") from exc
    finally:
        secret.clear()
        output.clear()
    print(json.dumps({"stored": True, "provider": provider,
                      "path": "development/authorization-servers/"
                              f"{provider}/andyur-client"}, sort_keys=True))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="andyur-as-provision")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("render")
    generate.add_argument("--spec", required=True)
    generate.add_argument("--out", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--dir", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--dir", required=True)
    apply.add_argument("--plan-sha256", required=True)
    status = commands.add_parser("status")
    status.add_argument("--dir", required=True)
    store = commands.add_parser("store")
    store.add_argument("--dir", required=True)
    args = parser.parse_args(argv)

    if args.command == "render":
        print(json.dumps(render(load_spec(args.spec), args.out), sort_keys=True))
        return
    directory = Path(args.dir).resolve()
    provider = _verify_render(directory)
    if provider in {"pingfederate", "pingam"}:
        raise SystemExit("Ping renders are reviewed import bundles, not Terraform directories")
    if args.command == "plan":
        _terraform(directory, ["init"])
        _terraform(directory, ["validate"])
        _terraform(directory, ["plan", "-out=andyur.tfplan"])
        digest = hashlib.sha256((directory / "andyur.tfplan").read_bytes()).hexdigest()
        print(json.dumps({"plan_sha256": digest, "plan": str(directory / "andyur.tfplan")}))
    elif args.command == "apply":
        plan_file = directory / "andyur.tfplan"
        if not plan_file.is_file():
            raise SystemExit("run plan first")
        actual = hashlib.sha256(plan_file.read_bytes()).hexdigest()
        if actual != args.plan_sha256:
            raise SystemExit("plan digest does not match --plan-sha256; refusing apply")
        _terraform(directory, ["apply", "andyur.tfplan"])
    elif args.command == "status":
        # Outputs include OAuth client secrets. Status deliberately reports only
        # owned resource addresses and never serializes output values to stdout.
        _terraform(directory, ["state", "list"])
    else:
        _store_in_openbao(directory, provider)

"""Operator CLI. Thin HTTP client for the control plane server."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx

from . import authlogin, config, identity, layout
from .config import PROJECT_ROOT, SERVER_URL


def _user_token() -> str | None:
    """The END USER's OIDC token, when the deployment has user-auth on.

    Two credentials travel on an authenticated call and they answer different
    questions: the SVID says WHICH COMPONENT is calling, and this says WHICH
    HUMAN it is calling for. Ownership and admin are read from the second, so
    with `ANDYUR_USER_AUTH=on` the server answers 401 to every owner-gated
    endpoint without it -- and until now the CLI never sent one, which meant a
    deployment with an IdP could not be driven by the tool this repository
    tells operators to use. Found by turning user-auth on in the Kubernetes
    reference deployment, where the first `andyur api GET /agents` came back
    "user-auth is on: a user OIDC token is required".

    Deliberately NOT `authlogin.load_token()`: that is a login at the external
    AUTHORIZATION SERVER for tool authority, a different issuer answering a
    different question, and quietly presenting one where the other is expected
    is how two credentials become one confused one.
    """
    token = os.environ.get("ANDYUR_USER_TOKEN", "").strip()
    return token or None


def _client() -> httpx.Client:
    cert, verify = identity.client_tls("operator")
    headers = {}
    token = _user_token()
    if token:
        headers["X-Andyur-User-Token"] = token
    return httpx.Client(
        base_url=SERVER_URL, timeout=10, auth=identity.httpx_auth(),
        cert=cert, verify=verify, headers=headers,
    )


REPOSITORY_URL = "https://github.com/andyurai/andyur"


def _how_to_get_a_deployment() -> tuple[str, ...]:
    """What to tell someone whose command found nothing to talk to.

    The advice has to name things the reader HAS. From a source checkout that
    is run.sh. Installed from a package there is no run.sh: this command
    operates a deployment and does not contain one, so it says how to reach
    one that exists and where the thing that starts one lives.
    """
    if layout.SOURCE_CHECKOUT:
        return ("start the stack:   ./run.sh docker-up   (supported)",
                "or, on this host:  ./run.sh up")
    return ("this command was installed as a package: it operates an Andyur "
            "deployment and does not start one.",
            "reach a running one:  set SPIFFE_ENDPOINT_SOCKET and ANDYUR_SERVER_URL",
            f"start one:           clone {REPOSITORY_URL} and follow its quickstart")


def _die_if_down(exc: httpx.ConnectError) -> None:
    _die(f"cannot reach the andyur server at {SERVER_URL}",
         *_how_to_get_a_deployment(), exc=exc)


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2))


def cmd_auth_login(args) -> None:
    """Sign in at whichever authorization server is configured.

    Andyur never handles the password. This opens the AS's own login page; the
    AS returns a code to a loopback listener, and the code is useless without a
    verifier that never left this process.
    """
    issuer = args.issuer or config.AS_ISSUER
    if not issuer:
        print("no authorization server configured.", file=sys.stderr)
        print("  set ANDYUR_AS_ISSUER, or pass --issuer", file=sys.stderr)
        print("  standalone: ./run.sh reference-as   then --issuer "
              "http://localhost:8099", file=sys.stderr)
        raise SystemExit(1)
    try:
        tokens = authlogin.login(issuer, scope=args.scope,
                                 audience=args.audience or config.SERVER_URL,
                                 resources=tuple(args.resource or ()),
                                 open_browser=not args.no_browser)
    except Exception as exc:                                   # noqa: BLE001
        print(f"login failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    path = authlogin.save_token(tokens)
    # The token itself is NEVER printed. It is a bearer credential, and a
    # terminal scrollback and a CI log are both places it should not be.
    print(f"signed in at {tokens.get('issuer', issuer)}")
    print(f"credentials stored in {path} (mode 0600)")


def cmd_auth_logout(args) -> None:
    if authlogin.logout():
        print("signed out; stored credentials removed")
    else:
        print("not signed in")


def cmd_auth_status(args) -> None:
    tok = authlogin.load_token()
    if not tok:
        print("not signed in")
        raise SystemExit(1)
    # Claims are shown WITHOUT verifying the signature, and the output says so:
    # this reports what the CLI is holding, and is not a validation of it.
    import base64 as _b64
    try:
        part = tok.split(".")[1]
        claims = json.loads(_b64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:                                          # noqa: BLE001
        print(f"signed in; stored token is not a readable JWT "
              f"({authlogin.credentials_path()})")
        return
    print(f"signed in as {claims.get('sub')!r} at {claims.get('iss')!r}")
    print(f"  expires   {claims.get('exp')}  (unverified: this reads the stored "
          "token, it does not validate it)")
    print(f"  stored in {authlogin.credentials_path()}")


def cmd_health(args) -> None:
    with _client() as c:
        _print_json(c.get("/health").json())


def cmd_api(args) -> None:
    """One authenticated request against the control plane, for shell harnesses.

    Every harness used to carry its own curl, and curl cannot fetch an SVID --
    which is how the entire demo tooling ran unauthenticated for months. This
    verb is the single place a script gets an operator-credentialed call, made
    through the same client every other CLI command uses, so a harness cannot
    quietly drift back to bare HTTP.

    On success the raw response body goes to stdout so callers parse exactly
    what the server said. On a >=400 status the body and the status line go to
    stderr with a non-zero exit instead: `if` around a call reads as "did the
    server say yes", and a script that null-redirects stdout still sees which
    control refused and why.
    """
    body = None
    if args.data is not None:
        raw = sys.stdin.read() if args.data == "-" else args.data
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"--data is not valid JSON: {exc}", file=sys.stderr)
            raise SystemExit(2)
    headers = {}
    for h in args.header or []:
        name, sep, value = h.partition(":")
        if not sep or not name.strip():
            print(f"--header must look like 'Name: value', got {h!r}",
                  file=sys.stderr)
            raise SystemExit(2)
        # The SVID bearer is attached by the client's auth flow AFTER these, so
        # a caller cannot replace the operator credential with --header.
        headers[name.strip()] = value.strip()
    # An absolute URL wins over the client's base_url, which is the point of
    # --server: config reads .env with override=True, so a script's exported
    # ANDYUR_SERVER_URL can be silently replaced by a stray .env entry -- and a
    # harness that thinks it is talking to its scratch server while DELETEing
    # against the real one is the worst version of that. An explicit target is
    # immune to the environment.
    url = args.server.rstrip("/") + args.path if args.server else args.path
    with _client() as c:
        r = c.request(args.method.upper(), url, json=body, headers=headers)
    ok = r.status_code < 400 or r.status_code in (args.allow or [])
    if not ok:
        if r.text:
            print(r.text, file=sys.stderr)
        print(f"HTTP {r.status_code} {args.method.upper()} {args.path}",
              file=sys.stderr)
        raise SystemExit(1)
    sys.stdout.write(r.text)


def cmd_create(args) -> None:
    body = {
        "name": args.name,
        "description": args.description,
        "personality": args.personality,
        "scope": args.scope,
    }
    # Launch from a registry manifest: the server resolves the definition and
    # materializes the agent's ceiling from it. Only send the key when set, so a
    # plain create still posts the same body as before.
    if getattr(args, "registry_agent_id", None):
        body["registry_agent_id"] = args.registry_agent_id
    with _client() as c:
        resp = c.post("/agents", json=body)
        if resp.status_code != 201:
            print(f"error {resp.status_code}: {resp.json().get('detail')}",
                  file=sys.stderr)
            raise SystemExit(1)
        if body.get("registry_agent_id"):
            print(f"created agent '{args.name}' from registry "
                  f"{args.registry_agent_id}")
        else:
            print(f"created agent '{args.name}'")
        # Optionally seed the agent's mind from files (its job and what it knows).
        for path, relfile, label in (
            (args.instructions_file, "instructions.md", "instructions"),
            (args.knowledge_file, "knowledge.md", "knowledge"),
            (args.mcp_file, "mcp.json", "tools (mcp)"),
        ):
            if not path:
                continue
            try:
                content = Path(path).read_text()
            except OSError as exc:
                print(f"  could not read {label} file '{path}': {exc}",
                      file=sys.stderr)
                continue
            r = c.put(f"/agents/{args.name}/files/{relfile}",
                      json={"content": content, "actor": "operator"})
            if r.status_code == 200:
                print(f"  set {label} from {path}")
            else:
                print(f"  failed to set {label}: {r.status_code}", file=sys.stderr)


def cmd_registry_list(args) -> None:
    """The agent-definition catalog (the registry), not the launched agents.

    These are manifests you can launch FROM; `andyur agents list` shows agents that
    have actually been created on this server."""
    with _client() as c:
        r = c.get("/v1/registry/agents")
    if r.status_code != 200:
        print(f"error {r.status_code}: {r.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)
    agents = r.json().get("agents", [])
    if not agents:
        print("the registry has no agents "
              "(set ANDYUR_AGENT_REGISTRY_DIR, or configure governed mode)")
        return
    # Grouped by bundle, because that is how they were installed and how an
    # operator thinks about removing them. Ungrouped manifests come first under
    # a heading that says what they are rather than pretending to be a bundle.
    grouped: dict[str, list[dict]] = {}
    for a in agents:
        grouped.setdefault(a.get("bundle") or "", []).append(a)

    fmt = "  {:<26} {:<22} {}"
    for bundle in sorted(grouped):
        print(f"\n{bundle or '(ungrouped)'}")
        for a in sorted(grouped[bundle], key=lambda x: x["name"]):
            card = a.get("card") or {}
            print(fmt.format(a["agent_id"], a["name"], card.get("summary", "")))
            # Prerequisites are the difference between an agent that works on
            # arrival and one that sits idle waiting for a backend nobody
            # mentioned. Worth a line of its own.
            for need in card.get("requires") or ():
                print(f"{'':<28}   needs: {need}")
    print("\nlaunch one with: "
          "andyur agents create <name> --registry-agent-id <AGENT ID>")


def cmd_bundle_list(args) -> None:
    """What is installed, and how big each one is."""
    with _client() as c:
        r = c.get("/v1/registry/bundles")
    if r.status_code != 200:
        print(f"error {r.status_code}: {r.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)
    bundles = r.json().get("bundles", [])
    if not bundles:
        print("no bundles installed")
        return
    for item in bundles:
        label = item["bundle"] or "(ungrouped)"
        count = item["agents"]
        print(f"{label:<24} {count} agent{'' if count == 1 else 's'}")
    print("\ninstall one with: andyur bundle install <directory>")


def cmd_bundle_install(args) -> None:
    """Read a directory of agent files and install them as one bundle.

    The whole bundle is sent in one request. Reading them here means a broken
    file is caught before the server is asked to do anything, and the name comes
    from the directory so the obvious invocation is the correct one.
    """
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"{directory}: not a directory", file=sys.stderr)
        raise SystemExit(1)
    files = sorted(directory.glob("*.json"))
    if not files:
        print(f"{directory}: no *.json agent files found", file=sys.stderr)
        raise SystemExit(1)
    agents = []
    for path in files:
        try:
            agents.append(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            print(f"{path}: not valid JSON: {exc}", file=sys.stderr)
            raise SystemExit(1)
    name = args.name or directory.resolve().name
    with _client() as c:
        r = c.put(f"/v1/registry/bundles/{name}",
                  json={"agents": agents, "replace": args.replace})
    if r.status_code != 200:
        print(f"install refused ({r.status_code}): {r.json().get('detail')}",
              file=sys.stderr)
        raise SystemExit(1)
    body = r.json()
    verb = "replaced" if body.get("replaced") else "installed"
    print(f"{verb} bundle {body['bundle']!r} with {len(body['agents'])} agent(s):")
    for agent in body["agents"]:
        print(f"  {agent}")
    print("\nsee them with: andyur registry list")


def cmd_bundle_uninstall(args) -> None:
    with _client() as c:
        r = c.delete(f"/v1/registry/bundles/{args.name}")
    if r.status_code != 200:
        print(f"uninstall refused ({r.status_code}): {r.json().get('detail')}",
              file=sys.stderr)
        raise SystemExit(1)
    body = r.json()
    print(f"removed bundle {body['bundle']!r} ({len(body['removed'])} agent(s))")
    # Saying this unprompted, because the opposite is a reasonable thing to
    # believe and finding out otherwise means finding a running agent you
    # thought you had removed.
    print("agents already created from it keep running; "
          "stop one with: andyur agents pause <name>")


def cmd_registry_resolve(args) -> None:
    """One registry agent's full, validated definition: instructions, model,
    tools, and ceiling -- exactly what a launch from it would bind."""
    with _client() as c:
        r = c.get(f"/v1/registry/agents/{args.agent_id}/resolve")
    if r.status_code != 200:
        print(f"error {r.status_code}: {r.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)
    _print_json(r.json())


def cmd_agents_validate(args) -> None:
    """Validate governed manifests without contacting the control plane."""
    from .agentspec import InvalidManifest, load_manifest
    try:
        manifests = [load_manifest(path, governed=True) for path in args.manifests]
    except InvalidManifest as exc:
        print(f"invalid manifest: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    for manifest in manifests:
        print(f"valid {manifest.metadata.id} ({manifest.metadata.version})")


def cmd_agents_init(args) -> None:
    """Write a governed v1 manifest skeleton without overwriting work."""
    destination = Path(args.output)
    if destination.exists():
        print(f"init refused: {destination} already exists", file=sys.stderr)
        raise SystemExit(1)
    document = {
        "apiVersion": "andyur.ai/v1",
        "kind": "Agent",
        "metadata": {"id": args.agent_id, "name": args.name, "version": "0.1.0"},
        "runtime": {
            "type": "container",
            "image": {"ref": args.image_ref, "digest": args.image_digest},
            "command": ["/app/agent", "serve"],
            "interface": {"protocol": "andyur-agent-runtime/v1"},
        },
        "instructions": "Replace with this agent's reviewed instructions.",
    }
    from .agentspec import InvalidManifest, parse_manifest
    try:
        parse_manifest(document, source="generated manifest", governed=True)
    except InvalidManifest as exc:
        print(f"init refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n")
    print(f"initialized valid governed manifest at {destination}")


def cmd_agents_package(args) -> None:
    """Compile one immutable authority/runtime snapshot from reviewed policy."""
    from .agentspec import InvalidManifest, ManifestDenied
    from .agentspec.models import InconsistentPolicy
    from .registry.models import InvalidAgentManifest
    from .agentspec.publisher import (CONFORMANCE_GATE_DIR, package_agents,
                                      publish_snapshot)
    if bool(args.publish_ref) != bool(args.cosign_key):
        print("package refused: --publish-ref and --cosign-key are required together",
              file=sys.stderr)
        raise SystemExit(1)
    try:
        output = package_agents(
            args.manifests, args.policy_resolution, args.output,
            approved_models=tuple(args.approved_model),
            policy_revision=args.policy_revision,
            max_lifetime_seconds=args.max_lifetime_seconds,
        )
    except (InvalidManifest, ManifestDenied, InconsistentPolicy,
            InvalidAgentManifest) as exc:
        # InvalidAgentManifest is the REGISTRY validator's refusal, raised
        # by the publisher's own readback. It is not a subclass of the
        # agentspec errors, so it used to escape here and reach the
        # operator as a Python traceback naming an overlay file they never
        # wrote -- from a function that already wraps OSError specifically
        # to avoid exactly that.
        print(f"package refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"packaged governed snapshot at {output}")
    if args.publish_ref:
        try:
            pinned = publish_snapshot(
                output, args.publish_ref, args.cosign_key,
                allow_http_registry=args.allow_http_registry,
                disable_transparency_log=args.disable_transparency_log,
                conformance_evidence=tuple(args.conformance_evidence),
                conformance_key=args.conformance_key,
                gate_dir=args.conformance_gate_dir or CONFORMANCE_GATE_DIR,
            )
        except InvalidManifest as exc:
            # The snapshot itself is complete and immutable; only publication
            # failed. Say where it is, because the retry cannot reuse --output.
            print(f"publication refused: {exc}\n"
                  f"the packaged snapshot at {output} is complete and unpublished; "
                  f"publish it after fixing the evidence, or remove it to repackage",
                  file=sys.stderr)
            raise SystemExit(1) from exc
        print(f"published and signed immutable snapshot {pinned}")


def cmd_agents_conformance(args) -> None:
    """Run the manifest's exact workload (pinned image + command) through the
    live v1 gate, and accept only evidence the publisher would accept."""
    from .agentspec import InvalidManifest, load_manifest
    from .agentspec.publisher import (CONFORMANCE_GATE_DIR,
                                      CONFORMANCE_GATE_SCRIPT,
                                      EXEC_CONFORMANCE_GATE_SCRIPT,
                                      load_conformance_evidence)
    try:
        manifest = load_manifest(args.manifest, governed=True)
    except InvalidManifest as exc:
        print(f"conformance refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    runtime = manifest.runtime
    if runtime.type != "container" or runtime.image is None or not runtime.image.digest:
        print("conformance refused: manifest must select a governed container image",
              file=sys.stderr)
        raise SystemExit(1)
    # The interface the manifest declares selects the gate: a runtime-v1 agent
    # speaks the protocol (G1-G6); an exec/v1 workload is a stock process the
    # platform speaks ABOUT (ADR-011 D8), proven by the sibling gate under the
    # same evidence contract.
    exec_v1 = manifest.runtime.interface_protocol == "exec/v1"
    gate = CONFORMANCE_GATE_DIR / (EXEC_CONFORMANCE_GATE_SCRIPT if exec_v1
                                   else CONFORMANCE_GATE_SCRIPT)
    if not gate.is_file():
        print(f"conformance gate is not installed at {gate}", file=sys.stderr)
        raise SystemExit(1)
    evidence = Path(args.evidence).resolve()
    if evidence.exists():
        print(f"conformance refused: evidence already exists at {evidence}",
              file=sys.stderr)
        raise SystemExit(1)
    selected_image = f"{runtime.image.ref}@{runtime.image.digest}"
    selected_command = tuple(runtime.command)
    process_env = os.environ.copy()
    process_env["ANDYUR_CONFORMANCE_IMAGE"] = selected_image
    process_env["ANDYUR_CONFORMANCE_COMMAND"] = json.dumps(list(selected_command))
    process_env["ANDYUR_CONFORMANCE_EVIDENCE"] = str(evidence)
    if exec_v1:
        # The exec/v1 gate resolves the manifest's process and configuration
        # blocks through the real parser: what it launches is what the
        # publisher will seal, not a re-typed copy.
        process_env["ANDYUR_CONFORMANCE_MANIFEST"] = str(Path(args.manifest).resolve())
        if getattr(args, "input", None):
            process_env["ANDYUR_CONFORMANCE_INPUT"] = str(Path(args.input).resolve())
    result = subprocess.run(
        [sys.executable, str(gate)], cwd=PROJECT_ROOT, env=process_env,
    )
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    try:
        proven = load_conformance_evidence(evidence, gate_dir=CONFORMANCE_GATE_DIR)
    except InvalidManifest as exc:
        print(f"conformance refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if (proven.image, proven.command) != (selected_image, selected_command):
        print("conformance refused: evidence is not bound to the selected image "
              "and command", file=sys.stderr)
        raise SystemExit(1)
    print(f"conformance evidence: {evidence}")
    if args.sign_evidence:
        from .agentspec.publisher import sign_evidence
        try:
            signature = sign_evidence(
                evidence, args.sign_evidence,
                disable_transparency_log=args.disable_transparency_log)
        except InvalidManifest as exc:
            print(f"conformance evidence signing failed: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        print(f"conformance signature: {signature}")


def cmd_list(args) -> None:
    with _client() as c:
        agents = c.get("/agents").json()
    if not agents:
        print("no agents yet, create one with: andyur agents create <name>")
        return
    fmt = "{:<20} {:<10} {:<20} {}"
    print(fmt.format("NAME", "STATE", "CREATED", "DESCRIPTION"))
    for a in agents:
        print(fmt.format(a["name"], a["state"], a["created_at"], a["description"]))


def _daemon_alive(c: httpx.Client) -> bool:
    """Is a worker going to pick this run up, or must we run it locally?

    `/workers` is ADMIN-ONLY, and the principals allowed to trigger a run are
    OWNERS, who are usually not admins. So the ordinary case for this call is a
    403 whose body is a detail string -- and indexing that string as if it were
    a list of worker rows raised `TypeError: string indices must be integers`,
    which made `agents trigger` unusable by exactly the people entitled to use
    it.

    Unreadable is not the same as absent. When we cannot see the workers we
    assume one is there: the server has already ACCEPTED the run, so the
    worker path is the normal outcome, and guessing "no daemon" instead would
    send an unprivileged caller down the local-runner path -- which needs
    credentials they are even less likely to hold. A run that waits is a
    visible state; a run executed in the wrong place is not.
    """
    try:
        resp = c.get("/workers")
    except httpx.HTTPError:
        return True
    if resp.status_code != 200:
        if resp.status_code != 403:
            print(f"could not read /workers ({resp.status_code}); assuming a "
                  "worker daemon is running", file=sys.stderr)
        return True
    try:
        rows = resp.json()
    except ValueError:
        return True
    if not isinstance(rows, list):
        return True
    return any(isinstance(w, dict) and w.get("alive") for w in rows)


def _post(path: str, ok_msg: str) -> None:
    """POST an operator control and report plainly. Shared by the three kill
    switches so they cannot drift into three different error styles."""
    with _client() as c:
        resp = c.post(path)
    if resp.status_code not in (200, 201):
        detail = ""
        try:
            detail = resp.json().get("detail", "")
        except Exception:
            detail = resp.text[:120]
        print(f"error {resp.status_code}: {detail}", file=sys.stderr)
        raise SystemExit(1)
    print(ok_msg)


def cmd_pause(args) -> None:
    """Stop an agent being woken, and drop the run it is queued for.

    A run already RUNNING is not interrupted -- that is what halt is for. Pause
    is the agent-level switch: it stops the next one."""
    _post(f"/agents/{args.agent}/pause",
          f"{args.agent} paused: it will not be woken, and any queued run was dropped")


def cmd_delete(args) -> None:
    """Delete an agent and everything in its namespace.

    Prompts unless --yes, because this is the one operator command with nothing
    behind it: there is no undo, no trash, and the agent's memory graph and mind
    files go with it."""
    if not args.yes:
        print(f"delete '{args.agent}' and ALL of its runs, tasks, messages, "
              f"schedules, mind files and memory? This cannot be undone.")
        if input("type the agent name to confirm: ").strip() != args.agent:
            print("aborted"); raise SystemExit(1)
    with _client() as c:
        resp = c.delete(f"/agents/{args.agent}",
                        params={"force": "true"} if args.force else None)
    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("detail", "")
        except Exception:
            detail = resp.text[:120]
        print(f"error {resp.status_code}: {detail}", file=sys.stderr)
        raise SystemExit(1)
    removed = resp.json()["removed"]
    gone = ", ".join(f"{v} {k}" for k, v in removed.items() if v)
    print(f"deleted {args.agent}" + (f" ({gone})" if gone else ""))


def cmd_resume(args) -> None:
    _post(f"/agents/{args.agent}/resume", f"{args.agent} resumed")


def cmd_halt(args) -> None:
    """Stop a whole workflow: every run in it, including ones already executing.

    The runs are condemned server-side and their containers destroyed by the
    worker, so this does not depend on the agent cooperating. Queued work in the
    workflow is torn down too, and unhalt does not resurrect it."""
    _post(f"/workflows/{args.workflow}/halt",
          f"workflow {args.workflow} halted: running runs are being destroyed")


def cmd_unhalt(args) -> None:
    """Re-open a workflow for NEW work. What halt tore down stays torn down."""
    _post(f"/workflows/{args.workflow}/unhalt",
          f"workflow {args.workflow} re-opened for new work")


def _run_input_from_args(args):
    """The --input / --input-file value as the JSON value the server seals.

    JSON if it parses, otherwise the text itself as a JSON string: an operator
    typing `--input 'fix the flaky test'` means that sentence, and one typing
    `--input '{"incident": "INC-4471"}'` means that object. The server and
    the launcher never guess again; the sealed value is what it is."""
    if getattr(args, "input_file", None):
        with open(args.input_file, encoding="utf-8") as fh:
            raw = fh.read()
    elif getattr(args, "input", None) is not None:
        raw = args.input
    else:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def cmd_trigger(args) -> None:
    body = {"reason": args.reason}
    value = _run_input_from_args(args)
    if value is not None:
        body["input"] = value
    with _client() as c:
        resp = c.post(f"/agents/{args.agent}/trigger", json=body)
        if resp.status_code != 201:
            print(
                f"error {resp.status_code}: {resp.json().get('detail')}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        run_id = resp.json()["run_id"]
        daemon = _daemon_alive(c)
        run_token = None
        if not daemon:
            # no worker to mint it: fetch a run token so the local runner can make
            # run-scoped calls when agent-auth is on (a no-op when it is off)
            tok = c.post(f"/runs/{run_id}/token")
            if tok.status_code == 200:
                run_token = tok.json().get("run_token")

    if daemon:
        print(f"run {run_id} queued for '{args.agent}', a worker will pick it up")
        if args.no_wait:
            return
        _wait_for_run(run_id)
    else:
        print(f"run {run_id} claimed; no worker daemon alive, running locally...")
        identity.assert_agent_isolation()  # local runs are never sandboxed
        env = identity.runner_launch_env(run_token)  # deny-strip + brokered key drop
        subprocess.run(
            [
                identity.role_python("runner"),
                "-m",
                "andyur.runner",
                "--agent",
                args.agent,
                "--run-id",
                run_id,
            ],
            cwd=PROJECT_ROOT,
            env=env,
        )
        _report_run(run_id)


def _wait_for_run(run_id: str) -> None:
    import time

    last_state = None
    while True:
        with _client() as c:
            run = c.get(f"/runs/{run_id}").json()
        if run["state"] != last_state:
            print(f"run {run_id}: {run['state']}")
            last_state = run["state"]
        if run["state"] in ("done", "failed", "cancelled"):
            break
        time.sleep(2)
    _report_run(run_id, run)


def _report_run(run_id: str, run: dict | None = None) -> None:
    if run is None:
        with _client() as c:
            run = c.get(f"/runs/{run_id}").json()
    print(f"\nrun {run_id} finished with state: {run['state']}")
    if run.get("summary"):
        print(f"summary: {run['summary']}")
    if run.get("error"):
        print(f"error: {run['error']}", file=sys.stderr)
        raise SystemExit(1)


def cmd_console(args) -> None:
    """Launch the local console (a localhost web UI). It holds this operator
    identity and proxies the control plane, so the browser needs no credential.
    With ANDYUR_USER_AUTH=on it first signs the user in at the IdP (same PKCE
    flow as `andyur auth login`); the server then decides user vs admin mode
    from the token's role."""
    from . import console
    console.launch(open_browser=not args.no_browser, port=args.port)


def cmd_workers(args) -> None:
    with _client() as c:
        workers = c.get("/workers").json()
    if not workers:
        print("no workers have ever heartbeat, start one with: ./run.sh daemon")
        return
    fmt = "{:<40} {:<6} {:<7} {}"
    print(fmt.format("WORKER", "SLOTS", "ALIVE", "LAST HEARTBEAT"))
    for w in workers:
        print(fmt.format(w["id"], w["slots"], str(w["alive"]), w["last_heartbeat"]))


def cmd_runs(args) -> None:
    with _client() as c:
        if c.get(f"/agents/{args.agent}").status_code == 404:
            print(f"no agent named '{args.agent}'", file=sys.stderr)
            raise SystemExit(1)
        # the run history, not the LIMIT-5 recent_runs the detail view carries;
        # walk the opaque cursor so nothing is silently truncated
        runs, before = [], None
        while True:
            resp = c.get("/runs", params={"agent": args.agent,
                                          **({"before": before} if before else {})})
            # CHECK THE STATUS BEFORE INDEXING THE BODY. This walked straight
            # into `page["runs"]`, so any non-2xx -- an expired user token is
            # the ordinary one -- surfaced as `KeyError: 'runs'` and a
            # traceback, hiding a 401 that says exactly what is wrong. Same
            # shape as the `/workers` 403 that broke `agents trigger`: a
            # refusal body is a dict too, and indexing it succeeds at being
            # confusing.
            if resp.status_code != 200:
                detail = ""
                try:
                    body = resp.json()
                    detail = body.get("detail", "") if isinstance(body, dict) else ""
                except ValueError:
                    detail = resp.text[:200]
                print(f"could not read runs ({resp.status_code}): {detail}",
                      file=sys.stderr)
                raise SystemExit(1)
            page = resp.json()
            runs += page.get("runs", [])
            before = page.get("next")
            if not before:
                break
    if not runs:
        print("no runs yet")
        return
    fmt = "{:<14} {:<8} {:<8} {:<21} {}"
    print(fmt.format("RUN", "TYPE", "STATE", "CREATED", "REASON"))
    for r in runs:
        print(fmt.format(r["id"], r["run_type"], r["state"], r["created_at"], r["reason"]))


def cmd_actions(args) -> None:
    """The consequential actions one run requested, and what Andyur decided.

    The operator's read of the same rows the console renders. Both come from the
    HTTP API and neither opens the database, which is the MVP exit criterion
    rather than a convenience.
    """
    with _client() as c:
        resp = c.get(f"/runs/{args.run_id}/actions")
    if resp.status_code == 404:
        print(f"no run '{args.run_id}'", file=sys.stderr)
        raise SystemExit(1)
    rows = resp.json()
    if not rows:
        print("no consequential action was requested by this run")
        return
    fmt = "{:<14} {:<20} {:<26} {:<18} {:<14} {}"
    print(fmt.format("ACTION", "TOOL", "TARGET", "DECISION", "RESULT", "DETAIL"))
    for r in rows:
        decision = r["decision"] or "-"
        if r["decision_reason"]:
            decision = f"{decision} ({r['decision_reason']})"
        print(fmt.format(r["id"], r["tool"], r["target"], decision,
                         r["result"] or "-", r["result_detail"] or ""))


def cmd_approve(args) -> None:
    """Consent, as a human, to an action a run is already entitled to perform.

    NOT a way to grant authority: an action reaches `approval_required` only
    because the run's sealed grant already named the authority, so approving is
    consenting to its use. The approver's name is recorded WITH how it was
    established -- from the IdP under user-auth, else asserted by this
    operator-gated API and rendered as the weaker claim it is.
    """
    with _client() as c:
        resp = c.post(f"/runs/{args.run_id}/actions/{args.action_id}/approve",
                      json={"approver": args.approver})
    if resp.status_code >= 400:
        print(resp.text, file=sys.stderr)
        print(f"HTTP {resp.status_code}", file=sys.stderr)
        raise SystemExit(1)
    _print_json(resp.json())


def cmd_show(args) -> None:
    with _client() as c:
        resp = c.get(f"/agents/{args.name}")
    if resp.status_code == 404:
        print(f"no agent named '{args.name}'", file=sys.stderr)
        raise SystemExit(1)
    _print_json(resp.json())


def cmd_schedule(args) -> None:
    with _client() as c:
        resp = c.post(
            f"/agents/{args.agent}/schedules",
            json={"cron": args.cron, "reason": args.reason},
        )
    if resp.status_code == 201:
        s = resp.json()
        print(f"scheduled '{args.agent}' on '{args.cron}' (schedule {s['id']})")
    else:
        print(f"error {resp.status_code}: {resp.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)


def cmd_schedules(args) -> None:
    with _client() as c:
        params = {"agent": args.agent} if args.agent else {}
        rows = c.get("/schedules", params=params).json()
    if not rows:
        print("no schedules")
        return
    fmt = "{:<14} {:<16} {:<16} {:<21} {}"
    print(fmt.format("ID", "AGENT", "CRON", "NEXT RUN", "REASON"))
    for s in rows:
        print(fmt.format(s["id"], s["agent"], s["cron"], s["next_run_at"], s["reason"]))


def cmd_unschedule(args) -> None:
    with _client() as c:
        resp = c.delete(f"/schedules/{args.schedule_id}")
    if resp.status_code == 404:
        print(f"no schedule '{args.schedule_id}'", file=sys.stderr)
        raise SystemExit(1)
    print(f"deleted schedule {args.schedule_id}")


def cmd_task(args) -> None:
    with _client() as c:
        resp = c.post(
            "/tasks",
            json={
                "assignee": args.assignee,
                "title": args.title,
                "detail": args.detail,
                "creator": "operator",
            },
        )
    if resp.status_code == 201:
        print(f"created task {resp.json()['id']} for '{args.assignee}'")
    else:
        print(f"error {resp.status_code}: {resp.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)


def cmd_tasks(args) -> None:
    params = {}
    if args.agent:
        params["assignee"] = args.agent
    if args.state:
        params["state"] = args.state
    with _client() as c:
        rows = c.get("/tasks", params=params).json()
    if not rows:
        print("no tasks")
        return
    fmt = "{:<14} {:<14} {:<12} {:<12} {}"
    print(fmt.format("ID", "ASSIGNEE", "STATE", "CREATOR", "TITLE"))
    for t in rows:
        print(fmt.format(t["id"], t["assignee"], t["state"], t["creator"], t["title"]))


def cmd_send(args) -> None:
    with _client() as c:
        resp = c.post(
            "/messages",
            json={"recipient": args.recipient, "body": args.body, "sender": "operator"},
        )
    if resp.status_code == 201:
        print(f"message sent to '{args.recipient}'")
    else:
        print(f"error {resp.status_code}: {resp.json().get('detail')}", file=sys.stderr)
        raise SystemExit(1)


def cmd_converse(args) -> None:
    """A live conversation with an agent: one persistent session (one identity,
    one container) that stays open across turns, instead of the message-emulated
    'chat'. The agent may ask clarifying questions and wait for your answer."""
    import time

    with _client() as c:
        resp = c.post(
            f"/agents/{args.agent}/trigger",
            json={"reason": "conversation", "run_type": "conversation"},
        )
        if resp.status_code != 201:
            detail = resp.json().get("detail") if resp.headers.get(
                "content-type", "").startswith("application/json") else resp.text
            print(f"error {resp.status_code}: {detail}", file=sys.stderr)
            raise SystemExit(1)
        run_id = resp.json()["run_id"]
        daemon = _daemon_alive(c)
        run_token = None
        if not daemon:
            tok = c.post(f"/runs/{run_id}/token")
            if tok.status_code == 200:
                run_token = tok.json().get("run_token")

    local_proc = None
    if not daemon:
        print(f"no worker daemon; running the session locally (run {run_id})...")
        identity.assert_agent_isolation()
        env = identity.runner_launch_env(run_token)
        local_proc = subprocess.Popen(
            [identity.role_python("runner"), "-m", "andyur.runner",
             "--agent", args.agent, "--run-id", run_id],
            cwd=PROJECT_ROOT, env=env,
        )

    print(f"conversation with '{args.agent}' (run {run_id}).")
    print("type a message and press enter; Ctrl-D to end the conversation.\n")
    cursor = 0

    # the operator's per-turn patience is derived from the server's turn TTL (plus
    # a margin), not a magic constant, so raising the turn TTL does not make the
    # CLI give up while the agent is still working
    turn_deadline_s = config.CONVERSATION_TURN_TTL_SECONDS + 30

    def drain(deadline: float) -> str | None:
        """Print reply events until this turn ends or the session ends. Returns
        'session_end' if the session closed (by event OR by terminal run state),
        else None when the turn completed."""
        nonlocal cursor
        while time.monotonic() < deadline:
            with _client() as c:
                resp = c.get(f"/runs/{run_id}/events", params={"after": cursor})
            if resp.status_code != 200:
                return "session_end"
            payload = resp.json()
            for ev in payload.get("events", []):
                cursor = ev["seq"]
                if ev["kind"] == "chunk":
                    print(ev["body"], end="", flush=True)
                elif ev["kind"] == "error":
                    print(f"\n[{ev['body']}]", flush=True)
                elif ev["kind"] == "turn_end":
                    print(flush=True)
                    return None
                elif ev["kind"] == "session_end":
                    print(f"\n[session ended: {ev['body']}]", flush=True)
                    return "session_end"
            # gate the "session is over" decision on the authoritative run STATE,
            # not only on a session_end event (a run-token holder could forge that
            # event; it cannot forge the run reaching a terminal state)
            if payload.get("state") in ("done", "failed", "cancelled"):
                print("\n[session ended]", flush=True)
                return "session_end"
            time.sleep(0.5)
        print("\n[no reply within the turn window]", flush=True)
        return None

    try:
        while True:
            try:
                line = input("you> ").strip()
            except EOFError:
                print()
                break
            if not line:
                continue
            with _client() as c:
                r = c.post(f"/runs/{run_id}/turn", json={"body": line})
            if r.status_code == 413:
                print("[message too large; shorten it]", file=sys.stderr)
                continue
            if r.status_code == 429:
                print("[the agent is behind; waiting for it to catch up]", file=sys.stderr)
                if drain(time.monotonic() + turn_deadline_s) == "session_end":
                    break
                continue
            if r.status_code != 201:
                detail = r.json().get("detail") if r.headers.get(
                    "content-type", "").startswith("application/json") else r.text
                print(f"[cannot send: {detail}]", file=sys.stderr)
                break
            if drain(time.monotonic() + turn_deadline_s) == "session_end":
                break
    finally:
        # always tell the session to close, so it does not linger to idle-timeout
        try:
            with _client() as c:
                c.post(f"/runs/{run_id}/close")
        except Exception:
            pass
        if local_proc is not None:
            try:
                local_proc.wait(timeout=15)
            except Exception:
                local_proc.terminate()
                try:
                    local_proc.wait(timeout=5)  # final reap after SIGTERM
                except Exception:
                    pass


def cmd_chat(args) -> None:
    import time

    print(f"chat with '{args.agent}'. Type a message and press enter; Ctrl-D to quit.")
    print("(the agent wakes on your message and replies back to you)\n")
    while True:
        try:
            line = input("you> ").strip()
        except EOFError:
            print()
            return
        if not line:
            continue
        with _client() as c:
            c.post(
                "/messages",
                json={"recipient": args.agent, "body": line, "sender": "operator"},
            )
        # poll for the agent's replies (messages addressed to the operator)
        deadline = time.monotonic() + 90
        got = False
        while time.monotonic() < deadline:
            with _client() as c:
                replies = c.get(
                    "/messages", params={"recipient": "operator", "state": "unread"}
                ).json()
            for m in replies:
                print(f"{m['sender']}> {m['body']}")
                with _client() as c:
                    c.post(f"/messages/{m['id']}/handle")
                got = True
            if got:
                break
            time.sleep(2)
        if not got:
            print("(no reply within 90s; the agent may be busy or no daemon is running)")


def cmd_mind(args) -> None:
    with _client() as c:
        resp = c.get(f"/agents/{args.agent}/files/{args.path}")
    if resp.status_code == 404:
        print(f"no file '{args.path}' for agent '{args.agent}'", file=sys.stderr)
        raise SystemExit(1)
    print(resp.json()["content"], end="")


def cmd_mind_history(args) -> None:
    params = {"path": args.path} if args.path else {}
    with _client() as c:
        rows = c.get(f"/agents/{args.agent}/versions", params=params).json()
    if not rows:
        print("no versions recorded")
        return
    fmt = "{:<14} {:<26} {:<10} {:<12} {:<6} {}"
    print(fmt.format("VERSION", "PATH", "ACTOR", "RUN", "SIZE", "WHEN"))
    for v in rows:
        print(fmt.format(
            v["id"], v["path"], v["actor"], v["run_id"] or "-",
            v["size"], v["created_at"],
        ))


def cmd_mind_restore(args) -> None:
    with _client() as c:
        resp = c.post(
            f"/agents/{args.agent}/restore",
            json={"version_id": args.version_id, "actor": "operator"},
        )
    if resp.status_code == 404:
        print(
            f"no version '{args.version_id}' for '{args.agent}'", file=sys.stderr
        )
        raise SystemExit(1)
    r = resp.json()
    print(f"restored '{r['restored']}' from version {r['from_version']} "
          f"(recorded as a new version)")


def _fmt_ago(iso: str) -> str:
    from datetime import datetime, timezone
    try:
        t = datetime.fromisoformat(iso)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        secs = (datetime.now(timezone.utc) - t).total_seconds()
        for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
            if secs >= n:
                return f"{int(secs // n)}{unit} ago"
        return f"{int(secs)}s ago"
    except Exception:
        return iso or "-"


def _unread(c: httpx.Client, who: str) -> int:
    try:
        return len(c.get("/messages",
                         params={"recipient": who, "state": "unread"}).json())
    except Exception:
        return 0


def _render_status(c: httpx.Client) -> str:
    agents = c.get("/agents").json()
    workers = c.get("/workers").json()
    schedules = c.get("/schedules").json()
    tasks = c.get("/tasks").json()
    details = {a["name"]: c.get(f"/agents/{a['name']}").json() for a in agents}

    graph_on, gcounts = False, {}
    for a in agents:
        r = c.get(f"/agents/{a['name']}/graph/counts")
        if r.status_code == 200:
            graph_on = True
            gcounts[a["name"]] = r.json()
    unread = _unread(c, "operator") + sum(_unread(c, a["name"]) for a in agents)

    running = sum(1 for a in agents if a["state"] == "running")
    alive = sum(1 for w in workers if w["alive"])
    open_tasks = sum(1 for t in tasks if t["state"] != "closed")

    out = [f"ANDYUR  {SERVER_URL}"]
    out.append(
        f"agents {len(agents)} ({running} running)   "
        f"workers {alive}/{len(workers)} alive   schedules {len(schedules)}   "
        f"tasks {open_tasks} open/{len(tasks)}   unread {unread}   "
        f"graph {'on' if graph_on else 'off'}"
    )
    out.append("")
    fmt = "  {:<16} {:<9} {:<5} {:<22} {}"
    out.append(fmt.format("AGENT", "STATE", "RUNS", "LAST RUN",
                          "GRAPH e/f" if graph_on else ""))
    for a in agents:
        recent = details[a["name"]].get("recent_runs", [])
        last = recent[0] if recent else None
        laststr = f"{last['state']} {_fmt_ago(last['created_at'])}" if last else "-"
        gc = gcounts.get(a["name"])
        gcs = f"{gc['entities']}/{gc['facts']}" if gc else ""
        # A paused agent is idle in the lifecycle sense and unavailable in the
        # operational one, and only the second is what an operator is reading
        # for. Showing "idle" alone read as "ready for work" when the agent had
        # been deliberately taken out of service. The two stay separate in the
        # data -- pause is policy, idle/queued/running is lifecycle, and they
        # are genuinely orthogonal (pausing does not stop a run already
        # executing) -- so this combines them only for display.
        state = f"{a['state']}*" if a.get("paused") else a["state"]
        out.append(fmt.format(a["name"], state, str(len(recent)), laststr, gcs))

    runs = []
    for a in agents:
        for r in details[a["name"]].get("recent_runs", []):
            runs.append((r["created_at"], a["name"], r))
    runs.sort(reverse=True)
    if any(a.get("paused") for a in agents):
        out.append("  * paused: will not be woken (andyur resume <agent>)")
    out.append("")
    out.append("  RECENT RUNS")
    rf = "  {:<14} {:<16} {:<8} {}"
    out.append(rf.format("RUN", "AGENT", "STATE", "REASON"))
    for _ts, agent, r in runs[:8]:
        out.append(rf.format(r["id"], agent, r["state"], (r["reason"] or "")[:44]))

    if open_tasks:
        out.append("")
        out.append("  OPEN TASKS")
        for t in tasks:
            if t["state"] != "closed":
                out.append(f"    [{t['id']}] {t['assignee']} <- {t['creator']}: "
                           f"({t['state']}) {t['title']}")
    return "\n".join(out)


def cmd_status(args) -> None:
    with _client() as c:
        print(_render_status(c))


def cmd_watch(args) -> None:
    import time
    try:
        while True:
            with _client() as c:
                snapshot = _render_status(c)
            print("\033[2J\033[H", end="")  # clear screen, home cursor
            print(snapshot)
            print(f"\n(refreshing every {args.interval}s; Ctrl-C to stop)")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()


def cmd_transcript(args) -> None:
    with _client() as c:
        r = c.get(f"/agents/{args.agent}/files/runs/{args.run_id}/transcript.jsonl")
    if r.status_code == 404:
        print(f"no transcript for run '{args.run_id}' of '{args.agent}'",
              file=sys.stderr)
        raise SystemExit(1)

    def short(x, n=400):
        s = x if isinstance(x, str) else json.dumps(x, default=str)
        s = " ".join(s.split())
        return s if len(s) <= n else s[:n] + " ..."

    for line in r.json()["content"].splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        typ, data = rec.get("type"), rec.get("data", {})
        if typ == "AssistantMessage":
            for b in data.get("content") or []:
                if not isinstance(b, dict):
                    continue
                if b.get("text", "").strip():
                    print(f"AGENT: {short(b['text'])}")
                elif "name" in b and "input" in b:
                    print(f"  -> TOOL CALL  {b['name']}({short(b.get('input', {}), 200)})")
        elif typ == "UserMessage":
            for b in data.get("content") or []:
                if isinstance(b, dict) and "tool_use_id" in b:
                    res = b.get("content")
                    if isinstance(res, list):
                        res = " ".join(x.get("text", "") for x in res
                                       if isinstance(x, dict))
                    flag = " [error]" if b.get("is_error") else ""
                    print(f"  <- TOOL RESULT{flag}: {short(res, 300)}")
        elif typ == "ResultMessage" and data.get("result"):
            print(f"RESULT: {short(data['result'])}")


def cmd_tools(args) -> None:
    with _client() as c:
        r = c.get(f"/agents/{args.agent}/files/mcp.json")
    if r.status_code == 404:
        print(f"'{args.agent}' has no custom tools (uses the built-in toolbox only)")
        return
    if r.status_code != 200:
        print(f"error {r.status_code}", file=sys.stderr)
        raise SystemExit(1)
    try:
        servers = json.loads(r.json()["content"]).get("mcpServers", {})
    except Exception:
        print("the agent's mcp.json is not valid JSON", file=sys.stderr)
        raise SystemExit(1)
    if not servers:
        print(f"'{args.agent}' has no tool servers configured")
        return
    print(f"custom tool servers for '{args.agent}':")
    for name, cfg in servers.items():
        if "command" in cfg:
            how = (cfg["command"] + " " + " ".join(cfg.get("args", []))).strip()
        else:
            how = cfg.get("url", cfg.get("type", "?"))
        print(f"  {name}: {how}")


def cmd_graph_consolidate(args) -> None:
    with _client() as c:
        resp = c.post(f"/agents/{args.agent}/graph/consolidate")
    if resp.status_code == 503:
        print("memory graph is disabled (start it and run the server with "
              "ANDYUR_GRAPH=neo4j)", file=sys.stderr)
        raise SystemExit(1)
    if resp.status_code == 404:
        print(f"no agent named '{args.agent}'", file=sys.stderr)
        raise SystemExit(1)
    r = resp.json()
    print(f"consolidated '{args.agent}': {r['entities_before']} -> "
          f"{r['entities_after']} entities (merged {r['merged']}, "
          f"pruned {r['pruned']})")


def build_parser() -> argparse.ArgumentParser:
    """The CLI's argument parser, separate from running it.

    Split out so the operator surface can be TESTED -- the alternative was a
    test that greps this file for a subcommand name, which passes just as
    happily when the command is defined and never wired up."""
    parser = argparse.ArgumentParser(
        prog="andyur", description="operate a fleet of long-lived AI agents"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Everything that targets an agent (create/inspect/run/schedule/message/
    # mind) lives under `andyur agents <verb>`; platform + infra commands
    # (auth, registry, status, watch, workers, halt, api, health) stay top-level.
    agents = sub.add_parser("agents",
                            help="create, run, inspect and manage agents")
    agentsub = agents.add_subparsers(dest="agents_command", required=True)

    auth = sub.add_parser("auth", help="sign in to the authorization server")
    authsub = auth.add_subparsers(dest="auth_command", required=True)
    p = authsub.add_parser("login", help="sign in (opens the AS's login page)")
    p.add_argument("--issuer", default="",
                   help="the authorization server (default: ANDYUR_AS_ISSUER)")
    p.add_argument("--scope", default="openid")
    p.add_argument("--audience", default="",
                   help="who the token is FOR (default: this Andyur server). The "
                        "resource CONSTRAINT is not set here -- it enters at the "
                        "exchange, when one tool is being called")
    p.add_argument("--resource", action="append",
                   help="what the work is ABOUT -- the pin, as an RFC 8707 "
                        "resource (repeatable). Standalone only: with an app in "
                        "front, the pin is chosen in that app's session")
    p.add_argument("--no-browser", action="store_true",
                   help="print the URL instead of opening a browser")
    p.set_defaults(func=cmd_auth_login)
    authsub.add_parser("logout", help="remove stored credentials").set_defaults(
        func=cmd_auth_logout)
    authsub.add_parser("status", help="show who is signed in").set_defaults(
        func=cmd_auth_status)

    sub.add_parser("health", help="check the server").set_defaults(func=cmd_health)

    p = sub.add_parser(
        "api", help="one authenticated request against the control plane (for scripts)")
    p.add_argument("method", help="HTTP method, e.g. GET or POST")
    p.add_argument("path", help="server path, e.g. /agents")
    p.add_argument("--data", help="JSON request body, or '-' to read it from stdin")
    p.add_argument("--header", action="append", metavar="'Name: value'",
                   help="extra request header (repeatable); the operator SVID "
                        "bearer is always attached and cannot be overridden")
    p.add_argument("--server", help="explicit base URL; immune to .env overriding "
                                    "ANDYUR_SERVER_URL in this subprocess")
    p.add_argument("--allow", action="append", type=int, metavar="STATUS",
                   help="treat this HTTP status as success (repeatable), e.g. "
                        "--allow 404 for a DELETE where absent is fine")
    p.set_defaults(func=cmd_api)

    p = agentsub.add_parser("create", help="create a new agent")
    p.add_argument("name")
    p.add_argument("--description", default="")
    p.add_argument("--personality", default="")
    p.add_argument("--scope", default="")
    p.add_argument("--registry-agent-id", default=None, metavar="agt_ID",
                   help="launch from a registry manifest: bind the agent to this "
                        "registry agent id (see `andyur registry list`). Its ceiling comes "
                        "from the manifest, so "
                        "--scope is ignored when this is set")
    p.add_argument("--instructions-file",
                   help="file whose contents become the agent's instructions "
                        "(its standing job description)")
    p.add_argument("--knowledge-file",
                   help="file whose contents become the agent's knowledge")
    p.add_argument("--mcp-file",
                   help="an mcp.json giving the agent custom tool servers "
                        "({\"mcpServers\": {name: {command, args, env}}})")
    p.set_defaults(func=cmd_create)

    p = agentsub.add_parser("init", help="write a new AgentManifest v1 skeleton")
    p.add_argument("--id", dest="agent_id", required=True, metavar="agt_ID")
    p.add_argument("--name", required=True)
    p.add_argument("--image-ref", required=True, metavar="OCI_REPOSITORY")
    p.add_argument("--image-digest", required=True, metavar="sha256:DIGEST")
    p.add_argument("--output", default="agent.json", metavar="FILE")
    p.set_defaults(func=cmd_agents_init)

    p = agentsub.add_parser(
        "validate", help="validate governed AgentManifest JSON files")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    p.set_defaults(func=cmd_agents_validate)

    p = agentsub.add_parser(
        "conformance", help="run a manifest's pinned image through runtime-v1")
    p.add_argument("manifest", metavar="MANIFEST")
    p.add_argument("--input", metavar="JSON_FILE", default=None,
                   help="the run input the exec/v1 gate delivers by the manifest's "
                        "declared mode (default: a small generic task object)")
    p.add_argument("--evidence", required=True, metavar="NEW_JSON",
                   help="new gate-generated evidence file; overwrite is refused")
    p.add_argument("--sign-evidence", metavar="COSIGN_KEY",
                   help="also sign the artifact with this cosign key (writes a "
                   "Sigstore bundle beside it; needs cosign v3+), so "
                   "publication can require it -- see `agents package "
                   "--conformance-key`. Without --disable-transparency-log "
                   "this publishes the artifact's hash to the public "
                   "transparency log")
    p.add_argument("--disable-transparency-log", action="store_true",
                   help="with --sign-evidence, skip public tlog upload")
    p.set_defaults(func=cmd_agents_conformance)

    p = agentsub.add_parser(
        "package", help="atomically compile a governed registry snapshot")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    p.add_argument("--policy-resolution", required=True, metavar="FILE",
                   help="reviewed agent-resolution/v1 authority catalog/ceiling")
    p.add_argument("--approved-model", action="append", default=[], metavar="MODEL",
                   help="approved model (repeatable; omitted means no model is approved)")
    p.add_argument("--policy-revision", required=True, metavar="REVISION")
    p.add_argument("--max-lifetime-seconds", type=int, default=None, metavar="SECONDS",
                   help="lifetime ceiling; omitted means no manifest may declare "
                        "a lifecycle and the platform default applies")
    p.add_argument("--output", required=True, metavar="NEW_DIRECTORY",
                   help="new immutable snapshot directory; existing paths are refused")
    p.add_argument("--publish-ref", metavar="OCI_REF_TAG",
                   help="push with ORAS and cosign the returned immutable digest")
    p.add_argument("--cosign-key", metavar="PRIVATE_KEY",
                   help="cosign private key (required with --publish-ref)")
    p.add_argument("--conformance-evidence", action="append", default=[],
                   metavar="JSON", help="green gate evidence for the exact "
                   "image AND command of a container agent (repeat for every "
                   "distinct image/command pair, not merely every image)")
    p.add_argument("--conformance-key", metavar="PUBLIC_KEY",
                   help="require each evidence artifact to carry a cosign "
                   "signature by this key (default: content binding only, "
                   "which proves WHICH gate an artifact describes but not WHO "
                   "produced it)")
    p.add_argument("--conformance-gate-dir", metavar="DIRECTORY",
                   help="conformance gate sources that produced the evidence "
                   "(default: this checkout's infra/byoa-spike; required when "
                   "publishing from an installed package, which ships no gate)")
    p.add_argument("--allow-http-registry", action="store_true",
                   help="allow a local/test registry without TLS")
    p.add_argument("--disable-transparency-log", action="store_true",
                   help="disable public tlog upload for private/local registries")
    p.set_defaults(func=cmd_agents_package)

    # The agent-definition registry (the manifest catalog you launch FROM),
    # distinct from `list` (agents created on this server).
    reg = sub.add_parser("registry",
                         help="browse the agent-definition registry (catalog)")
    regsub = reg.add_subparsers(dest="registry_command", required=True)
    regsub.add_parser("list", help="list the agents the registry offers"
                      ).set_defaults(func=cmd_registry_list)
    rp = regsub.add_parser("resolve",
                           help="show one registry agent's full definition")
    rp.add_argument("agent_id")
    rp.set_defaults(func=cmd_registry_resolve)

    bun = sub.add_parser("bundle", help="install and remove bundles of agents")
    bunsub = bun.add_subparsers(dest="bundle_command", required=True)
    bunsub.add_parser("list", help="list installed bundles"
                      ).set_defaults(func=cmd_bundle_list)
    bp = bunsub.add_parser("install", help="install a directory of agents as a bundle")
    bp.add_argument("directory", metavar="DIRECTORY",
                    help="a directory of andyur.agent-resolution/v1 *.json files")
    bp.add_argument("--name", default=None,
                    help="the installed bundle name (default: the directory's)")
    bp.add_argument("--replace", action="store_true",
                    help="overwrite a bundle of this name that is already installed")
    bp.set_defaults(func=cmd_bundle_install)
    up = bunsub.add_parser("uninstall", help="remove an installed bundle")
    up.add_argument("name")
    up.set_defaults(func=cmd_bundle_uninstall)

    agentsub.add_parser("list", help="list agents").set_defaults(func=cmd_list)

    sub.add_parser("status", help="one-shot overview of the whole platform"
                   ).set_defaults(func=cmd_status)

    p = sub.add_parser("watch", help="live-refreshing platform overview")
    p.add_argument("--interval", type=float, default=2.0)
    p.set_defaults(func=cmd_watch)

    p = agentsub.add_parser("show", help="show one agent in detail")
    p.add_argument("name")
    p.set_defaults(func=cmd_show)

    p = agentsub.add_parser("pause", help="stop an agent being woken (agent kill switch)")
    p.add_argument("agent")
    p.set_defaults(func=cmd_pause)

    p = agentsub.add_parser("delete", help="delete an agent and everything it owns")
    p.add_argument("agent")
    p.add_argument("--yes", action="store_true", help="skip the confirmation")
    p.add_argument("--force", action="store_true",
                   help="delete even if a run is live (for a run wedged by a dead worker)")
    p.set_defaults(func=cmd_delete)

    p = agentsub.add_parser("resume", help="let a paused agent be woken again")
    p.add_argument("agent")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("halt", help="stop a whole workflow, including running runs")
    p.add_argument("workflow")
    p.set_defaults(func=cmd_halt)

    p = sub.add_parser("unhalt", help="re-open a halted workflow for new work")
    p.add_argument("workflow")
    p.set_defaults(func=cmd_unhalt)

    p = agentsub.add_parser("trigger", help="wake an agent up for a run now")
    p.add_argument("agent")
    p.add_argument("--reason", default="manual trigger by operator")
    p.add_argument("--input", metavar="VALUE",
                   help="the run's input: JSON if it parses, otherwise sent as text")
    p.add_argument("--input-file", metavar="PATH",
                   help="read the run's input from a file (same rule as --input)")
    p.add_argument("--no-wait", action="store_true", help="do not poll for the result")
    p.set_defaults(func=cmd_trigger)

    p = sub.add_parser("console",
                       help="open the local console web UI (admin or user "
                            "mode under user-auth)")
    p.add_argument("--port", type=int, default=None,
                   help="bind port (default: an OS-assigned free loopback port)")
    p.add_argument("--no-browser", action="store_true",
                   help="print the URL instead of opening a browser")
    p.set_defaults(func=cmd_console)

    p = sub.add_parser("workers", help="list worker daemons")
    p.set_defaults(func=cmd_workers)

    p = agentsub.add_parser("runs", help="list an agent's recent runs")
    p.add_argument("agent")
    p.set_defaults(func=cmd_runs)

    p = agentsub.add_parser("schedule", help="schedule an agent on a cron cadence")
    p.add_argument("agent")
    p.add_argument("cron", help="cron expression, e.g. '*/5 * * * *'")
    p.add_argument("--reason", default="scheduled run")
    p.set_defaults(func=cmd_schedule)

    p = agentsub.add_parser("schedules", help="list schedules")
    p.add_argument("agent", nargs="?", default=None)
    p.set_defaults(func=cmd_schedules)

    p = agentsub.add_parser("unschedule", help="delete a schedule")
    p.add_argument("schedule_id")
    p.set_defaults(func=cmd_unschedule)

    p = agentsub.add_parser("task", help="create a task for an agent")
    p.add_argument("assignee")
    p.add_argument("title")
    p.add_argument("--detail", default="")
    p.set_defaults(func=cmd_task)

    p = agentsub.add_parser("tasks", help="list tasks")
    p.add_argument("agent", nargs="?", default=None)
    p.add_argument("--state", default=None, help="open | in_progress | closed")
    p.set_defaults(func=cmd_tasks)

    p = agentsub.add_parser("send", help="send a message to an agent")
    p.add_argument("recipient")
    p.add_argument("body")
    p.set_defaults(func=cmd_send)

    p = agentsub.add_parser("chat", help="message-emulated chat with an agent (REPL)")
    p.add_argument("agent")
    p.set_defaults(func=cmd_chat)

    p = agentsub.add_parser("converse",
                       help="live conversation with an agent (persistent session)")
    p.add_argument("agent")
    p.set_defaults(func=cmd_converse)

    p = agentsub.add_parser("mind", help="print a file from an agent's mind")
    p.add_argument("agent")
    p.add_argument("path", help="e.g. knowledge.md, instructions.md, memory/long_term.md")
    p.set_defaults(func=cmd_mind)

    p = agentsub.add_parser("mind-history",
                       help="show the version history of an agent's mind "
                            "(self + learnings; working memory is not versioned)")
    p.add_argument("agent")
    p.add_argument("path", nargs="?", default=None,
                   help="limit to one file, e.g. knowledge.md")
    p.set_defaults(func=cmd_mind_history)

    p = agentsub.add_parser("mind-restore", help="roll a mind file back to a prior version")
    p.add_argument("agent")
    p.add_argument("version_id")
    p.set_defaults(func=cmd_mind_restore)

    p = agentsub.add_parser("graph-consolidate",
                       help="mechanically merge + prune an agent's memory graph")
    p.add_argument("agent")
    p.set_defaults(func=cmd_graph_consolidate)

    p = agentsub.add_parser("tools", help="show an agent's custom (MCP) tool servers")
    p.add_argument("agent")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("actions",
                       help="what consequential actions a run requested, and "
                            "what Andyur decided about each")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_actions)

    p = sub.add_parser("approve",
                       help="approve one consequential action a run requested")
    p.add_argument("run_id")
    p.add_argument("action_id")
    p.add_argument("--approver", default=None,
                   help="who is approving (required when there is no IdP; "
                        "refused when user-auth is on, where the IdP names them)")
    p.set_defaults(func=cmd_approve)

    p = agentsub.add_parser("transcript",
                       help="show a run's full exchange (agent text, tool calls, results)")
    p.add_argument("agent")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_transcript)

    return parser


def _die(problem: str, *fixes: str, exc: BaseException) -> None:
    """One actionable line, then what to do about it, then stop.

    A traceback is the right output for a bug and the wrong output for a
    deployment that is not running: it asks the reader to debug Andyur's
    internals to learn that they have not started it. Set ANDYUR_DEBUG=1 to get
    the traceback back.
    """
    print(problem, file=sys.stderr)
    for fix in fixes:
        print(f"  {fix}", file=sys.stderr)
    if os.environ.get("ANDYUR_DEBUG", "").lower() in ("1", "on", "true"):
        raise exc
    raise SystemExit(1) from exc


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    # THE PACKAGED ENTRY POINT HAS TO EXPLAIN ITSELF.
    #
    # `pip install andyur` puts this command on a stranger's PATH, and the
    # defaults it then runs under are the PRODUCTION ones: ANDYUR_PROFILE is
    # `prod` unless set, and workload identity is not optional, so the first
    # thing a new user saw was a 25-line traceback ending in
    # "SPIFFE socket file ... does not exist". That is accurate and useless.
    #
    # Each branch below is a failure a correctly-behaving installation produces
    # on a machine with nothing running. Anything not listed here is a real
    # fault and still raises, because converting unknown exceptions into tidy
    # messages is how a bug becomes a support thread.
    try:
        args.func(args)
    except httpx.ConnectError as exc:
        _die_if_down(exc)
    except config.InsecureProfile as exc:
        _die(f"this deployment is not configured for ANDYUR_PROFILE={config.PROFILE}:",
             *str(exc).splitlines(),
             "ANDYUR_PROFILE=dev runs without these on a trusted machine",
             exc=exc)
    except Exception as exc:                     # noqa: BLE001 - narrowed below
        name = type(exc).__name__
        text = str(exc)
        if name in ("ArgumentError", "JwtSourceError") or "SPIFFE" in text:
            _die("no SPIFFE workload API is reachable, so this command cannot "
                 "prove who it is.",
                 "Andyur requires workload identity; it is not a toggle.",
                 *_how_to_get_a_deployment(),
                 f"socket looked for: {identity.socket_path()}",
                 exc=exc)
        raise


if __name__ == "__main__":
    main()

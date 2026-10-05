"""The two gates that stand between "it builds" and "somebody else can run it".

Neither can be executed here -- one needs a cluster, the other a signed bundle
and a cluster -- so what is checked is the SHAPE of the claim each one makes.
That is worth checking because both gates were green while being silent about
the thing they are named for:

  verify-partner-deploy.sh   verified two of five signed files and applied one of
                             three manifests by hand, never running the installer
                             the bundle ships. The IdP, the observability stack
                             and deploy.sh itself were shipped and untested.
  the consequential action   was proved against a real cluster with a hand-minted
                             grant, in-process. Nothing showed an AGENT asking.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PARTNER = ROOT / "infra" / "rc" / "verify-partner-deploy.sh"
REQUESTED = ROOT / "infra" / "kubernetes" / "verify-agent-requested-action.sh"
DEPLOY = ROOT / "infra" / "rc" / "deploy.sh"
RC = ROOT / "infra" / "rc" / "verify-rc-gate.sh"


# --- the partner gate deploys the way a partner does -------------------------

def test_the_partner_gate_runs_the_installer_rather_than_kubectl_apply():
    text = PARTNER.read_text()
    for invocation in ('deploy.sh" --ask', 'deploy.sh" --preflight'):
        assert invocation in text, f"the gate never runs {invocation}"
    assert re.search(r'bash "\$WORK/deploy\.sh" >', text), "the gate never deploys"
    # And no longer applies a manifest itself: doing that is what let two of the
    # three shipped manifests go untested for as long as they existed.
    assert "kubectl apply -f \"$WORK/control-plane.yaml\"" not in text


def test_the_signed_set_is_derived_from_the_bundle_not_listed_in_the_gate():
    """A gate that names the files it verifies cannot notice a file added to the
    bundle. Every signature present must verify, AND every file a partner is
    asked to trust must have one -- neither direction alone is enough."""
    text = PARTNER.read_text()
    assert 'for sig in "$WORK"/*.cosign-bundle.json' in text
    for must in ("control-plane.yaml", "idp.yaml", "observability.yaml",
                 "run-isolation.yaml", "deploy.sh", "release-manifest.json"):
        assert must in text, f"{must} is not required to arrive signed"


def test_the_gate_checks_the_api_server_and_not_the_installers_own_report():
    """`deploy.sh` reports what it applied; a script's account of what it did is
    the thing under test, so the objects are read back from the cluster."""
    text = PARTNER.read_text()
    for object_name in ("statefulset/andyur-server", "deployment/andyur-keycloak",
                        "deployment/otel-collector",
                        "deployment/andyur-netpol-reconciler"):
        assert object_name in text, f"{object_name} is never checked for"


def test_running_images_are_compared_by_digest_not_by_whole_reference():
    """The installer re-homes images to the registry the deployer named, keeping
    the digest -- which is the identity. Comparing whole references would fail
    every partner who pushed the same images to their own registry, the exact
    case this gate exists to prove."""
    text = PARTNER.read_text()
    assert 'digest="${image##*@}"' in text


# --- the agent-initiated action ---------------------------------------------

def test_the_gate_states_why_it_could_not_have_made_the_request_itself():
    """The claim is not "this script was careful". It is that the endpoint
    refuses an operator, so a row can only have come from the run."""
    text = REQUESTED.read_text()
    assert "why_the_gate_could_not_have_asked" in text
    assert "refuses an operator" in text or "REFUSES AN OPERATOR" in text
    # The gate only ever READS the action listing.
    assert 'api GET "/runs/$run_id/actions"' in text
    assert 'api POST "/runs/' not in text.replace(
        'api POST "/agents/$AGENT/trigger"', "")


def test_that_refusal_is_real_in_the_server():
    """The property the gate leans on, asserted against the server itself
    rather than against the gate's comment about it."""
    app = (ROOT / "andyur" / "server" / "app.py").read_text()
    handler = app[app.index('@app.post("/runs/{run_id}/actions"'):]
    handler = handler[:handler.index("@app.", 10)]
    assert "if ctx.is_operator:" in handler and "raise HTTPException(\n            403" in handler


def test_the_workload_substitution_is_recorded_rather_than_glossed():
    """The review named OpenSRE; unmodified OpenSRE cannot be handed an
    arbitrary tool. Using Goose instead is legitimate and is not the same claim,
    so the artifact says which workload ran and why. The workload is a
    parameter (Hermes Agent runs the same gate), so what is pinned is that the
    substitution names the workload that ACTUALLY ran, and that an unset
    parameter still means Goose rather than silently meaning nothing."""
    text = REQUESTED.read_text()
    assert '"workload_substitution"' in text
    assert '"review_named": "OpenSRE"' in text and '"used": workload' in text
    assert 'WORKLOAD="${ANDYUR_ACTION_WORKLOAD:-Goose}"' in text
    assert 'DEMO="${ANDYUR_ACTION_DEMO:-demos/goose}"' in text
    # the bound sources follow the demo that ran, never a hard-coded one
    assert 'f"{demo}/agent.json", f"{demo}/{input_file}"' in text
    assert '"demos/goose/agent.json"' not in text


def test_the_gate_asserts_the_cluster_moved_and_not_only_the_row():
    text = REQUESTED.read_text()
    assert '"cluster_moved"' in text
    assert 'before == "two" and after == "one"' in text


def test_the_gate_never_changes_the_shared_control_planes_credential():
    """Credential opt-in belongs to the operator; gate cleanup cannot revoke it."""
    text = REQUESTED.read_text()
    assert "trap cleanup EXIT" in text
    assert "automountServiceAccountToken}')\" == true" in text
    assert "patch statefulset" not in text


# --- and it is a line of the RC gate ----------------------------------------

def test_the_rc_gate_runs_it():
    text = RC.read_text()
    assert "verify-agent-requested-action.sh" in text
    assert "line requested cluster" in text


# --- the shared gate library -------------------------------------------------

def test_the_gate_library_is_self_contained_under_set_u(tmp_path):
    """EXTRACTING SHARED CODE MOVES ITS DEPENDENCIES TOO, and the one that was
    left behind (`IDP_REALM`, defined in the workload gate) made the second gate
    to source this file die with `unbound variable` -- from inside the very
    function whose job is to explain why there is no user token.

    So it is sourced here the way a NEW gate would source it: `set -u`, with
    only the two things its header says a caller must provide, and every helper
    called."""
    import os
    import subprocess

    binder = tmp_path / "bin"
    binder.mkdir()
    (binder / "kubectl").write_text("#!/usr/bin/env bash\necho ''\n")
    (binder / "kubectl").chmod(0o755)

    script = tmp_path / "newgate.sh"
    script.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
SYSTEM_NS=andyur-system
fail() {{ echo "FAILED: $*" >&2; exit 1; }}
. {ROOT / 'infra' / 'kubernetes' / 'lib' / 'gate.sh'}
fetch_user_token
printf '{{"a": 1}}' | json_field a
operator api GET /agents >/dev/null || true
echo LIBRARY-OK
""")
    script.chmod(0o755)
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                            env={**os.environ, "PATH": f"{binder}:{os.environ['PATH']}"},
                            timeout=60)
    assert "unbound variable" not in result.stderr, result.stderr
    assert "LIBRARY-OK" in result.stdout, result.stdout + result.stderr
    assert "1" in result.stdout


def test_both_gates_bind_the_library_in_their_evidence():
    """The library carries behaviour the artifacts are claims about -- how the
    token is refreshed, how a non-JSON answer is reported. Evidence that does
    not bind it goes stale on an edit nobody would notice."""
    workload = (ROOT / "infra" / "kubernetes" / "verify-exec-workload.sh").read_text()
    assert '"infra/kubernetes/lib/gate.sh"' in workload
    assert '"infra/kubernetes/lib/gate.sh"' in REQUESTED.read_text()


REQUESTED_ACTION_ARTIFACTS = {
    # workload name, artifact glob, demo whose manifest and input the gate bound
    "Goose": ("result-agent-requested-action-2*.json", "demos/goose"),
    "Hermes Agent": ("result-agent-requested-action-hermes-*.json", "demos/hermes"),
}


@pytest.mark.parametrize("workload", sorted(REQUESTED_ACTION_ARTIFACTS))
def test_each_stock_workload_asked_for_the_rollback_itself(workload):
    """THE AGENT ASKED, per workload. Each artifact is a claim about the
    workload that actually ran, so the claim is checked against itself: every
    check held, the substitution names this workload, its bound sources are
    this demo's, the tool call is seen at the MCP boundary, and every action
    row lands on the target the run was pinned to.

    One artifact per workload. A second, superseded file beside the first
    would let an old green stand in for a new red."""
    glob, demo = REQUESTED_ACTION_ARTIFACTS[workload]
    [path] = sorted((ROOT / "infra" / "kubernetes").glob(glob))
    result = json.loads(path.read_text())
    assert result["gate"] == "agent-requested-action" and result["ok"] is True
    assert all(result["checks"].values()), result["checks"]
    assert result["workload"]["name"] == workload
    assert result["workload"]["modified"] is False and result["workload"]["adapter_added"] is False
    assert result["workload_substitution"]["used"] == workload
    assert f"{demo}/agent.json" in result["source_sha256"]
    assert f"{demo}/rollback-input.json" in result["source_sha256"]
    assert result["tool_calls_observed"] == ["mcp.tool request_rollback"]
    rows = [r for r in result["action_rows"] if r["tool"] == "rollback_deployment"]
    assert rows and all(r["target"] == result["target"] for r in rows)
    assert rows[0]["decision"] == "allowed" and rows[0]["result"] == "succeeded"
    assert result["pod_template_revision"] == {"before": "two", "after": "one"}
    assert "action.decide" in result["trace"]["span_names"]


# --- the image can do what the platform decides ------------------------------

def test_the_server_image_can_perform_the_action_it_authorises():
    """THE GAP BETWEEN "THE DECISION IS RIGHT" AND "THE PRODUCT WORKS".

    The consequential action is the one thing the control plane DOES to a
    cluster: the agent asks, the server decides, and then the SERVER performs
    the rollback with its own ServiceAccount. Every test of that path -- the
    unit suite and the `action` lane both -- drives
    `andyur.server.kubernetes_deployments` in-process, where the import is
    satisfied by the developer's environment. The shipped server image did not
    install the Kubernetes client at all.

    Nothing noticed until an agent actually asked through the real path, and the
    row read `decision: allowed, result: failed, ModuleNotFoundError: No module
    named 'kubernetes'`: the platform authorising an action it could not carry
    out. Asserted here against the Dockerfile, so it cannot silently go away
    again the next time that install list is pruned."""
    import re

    adapter = (ROOT / "andyur" / "server" / "kubernetes_deployments.py").read_text()
    assert re.search(r"^\s*(from|import) kubernetes", adapter, re.M), (
        "this test is anchored on the server importing the kubernetes client; "
        "if that changed, the test must change with it")
    dockerfile = (ROOT / "Dockerfile.server").read_text()
    assert "kubernetes>=" in dockerfile, (
        "the server image cannot perform the rollback it authorises")


def test_the_control_plane_can_reach_the_api_server_it_must_patch():
    """The rollback is the one thing the control plane DOES to a cluster, and
    everything for it was in place -- the Role, the RoleBinding, the mounted
    ServiceAccount token -- except a route. The `server` NetworkPolicy had no
    egress to the Kubernetes API, so an action the platform had ALLOWED failed
    with `Connection refused` to the API's ClusterIP, while the audit row said
    it was authorised.

    The `action` lane could not have found it: it drives the adapter in-process
    from the host, where no NetworkPolicy applies. It took an agent asking
    through the real path in the real deployment."""
    import yaml

    manifest = ROOT / "infra" / "kubernetes" / "control-plane.yaml"
    docs = [d for d in yaml.safe_load_all(manifest.read_text()) if d]
    server = next(d for d in docs
                  if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "server")
    api = [rule for rule in server["spec"]["egress"]
           if any("ipBlock" in peer for peer in rule.get("to", []))
           and any(p["port"] == 6443 for p in rule.get("ports", []))]
    assert api, ("the control plane has no egress to the Kubernetes API, so it "
                 "cannot perform the rollback it authorises")


def test_every_ip_block_carries_a_render_marker():
    """An egress rule nobody marked keeps the BUILD machine's address in every
    partner's cluster. deploy.sh refuses an unmarked one at render time; this
    catches it in the suite, where a person is looking, rather than in someone
    else's deployment."""
    manifest = (ROOT / "infra" / "kubernetes" / "control-plane.yaml").read_text()
    lines = manifest.splitlines()
    for i, line in enumerate(lines):
        if "ipBlock" not in line:
            continue
        # the marker sits on a comment line above the rule, possibly with other
        # comment lines between
        preceding = "\n".join(lines[max(0, i - 8):i])
        assert "andyur:render=" in preceding, (
            f"line {i + 1} has an ipBlock with no andyur:render marker above it: "
            f"{line.strip()}")


def test_the_partner_gate_parses_manifests_instead_of_grepping_them():
    """A COMMENT in control-plane.yaml contains the words
    "image: `brokerstate_server". verify_bundle.py stopped grepping for exactly
    that reason and carries a paragraph about it -- and this gate then wrote its
    own `re.findall(r"image: (\\S+)")` and refused a good bundle on the same
    comment, costing an RC pass.

    One parser, imported, not two."""
    text = PARTNER.read_text()
    assert "from verify_bundle import images_in" in text
    # The comment above the fix NAMES the old regex, which is the point of it.
    # What must be gone is the CODE, so only non-comment lines are checked.
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert 'findall(r"image:' not in code


def test_that_parser_does_not_see_the_comment():
    """The property itself, not just the shape of the call."""
    import sys

    sys.path.insert(0, str(ROOT / "infra" / "rc"))
    from verify_bundle import images_in

    manifest = (ROOT / "infra" / "kubernetes" / "control-plane.yaml").read_text()
    assert "image: `brokerstate_server" in manifest, (
        "the comment this test is about is gone; the test can go with it")
    assert not any("brokerstate" in image for _, image in images_in(manifest))


# --- the teardown must not damage what it promises to leave alone ------------

RESET = ROOT / "infra" / "rc" / "reset-cluster.sh"


def test_the_teardown_never_selects_cluster_objects_by_substring():
    """It did, with `kubectl get clusterroles -o name | grep -E 'andyur'`, and
    SPIRE is installed here as the Helm release `andyur-spire`. So a script
    whose header promises "SPIRE: a prerequisite, not part of the deployment"
    deleted SPIRE's own ClusterRoles.

    The controller-manager lost `list pods` at cluster scope, created no
    registration entries, and two hours later the symptom was
    `JwtSourceError: Timeout waiting for the first update` in a worker that
    could not get an SVID -- a message about the workload API, in a component
    that was not the one broken.

    A destructive operation must not match by prefix."""
    text = RESET.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "grep -E 'andyur'" not in code
    assert "manifest_names" in code, "names must come from the manifests, not a pattern"


def test_the_teardown_deletes_exactly_what_the_manifests_define():
    """Every cluster-scoped object the platform's manifests define is a name
    this script will delete, and nothing else is."""
    import subprocess
    import yaml

    text = RESET.read_text()
    for kind in ("ClusterRoleBinding", "ClusterRole", "ClusterSPIFFEID"):
        assert kind in text, f"{kind} is never cleaned up"
    # And the files it reads those names from are the ones that create them.
    for manifest in ("control-plane.yaml", "rbac-consequential-action.yaml",
                     "run-isolation.yaml"):
        assert manifest in text, f"{manifest} defines cluster objects nobody removes"

    defined = set()
    for manifest in ("control-plane.yaml", "rbac-consequential-action.yaml",
                     "run-isolation.yaml"):
        path = ROOT / "infra" / "kubernetes" / manifest
        for doc in yaml.safe_load_all(path.read_text()):
            if doc and doc.get("kind") in ("ClusterRole", "ClusterRoleBinding",
                                           "ClusterSPIFFEID"):
                defined.add(doc["metadata"]["name"])
    assert defined, "no cluster-scoped objects found; the manifests changed shape"
    # None of them may be a SPIRE release object.
    assert not any(n.startswith("andyur-spire") for n in defined), (
        "the platform defines an object under SPIRE's release prefix; deleting "
        "by name is still right, but this test's premise needs revisiting")


def test_the_teardown_proves_spire_survived_it():
    """Not "we were careful" -- checked, with the repair command in the message,
    so the next person does not spend two hours on a workload-API error."""
    text = RESET.read_text()
    assert "auth can-i list pods" in text
    assert "helm get manifest" in text
    assert "Timeout waiting for the first update" in text


# --- the tool registry a stock workload is served ---------------------------

def test_the_tool_call_gate_expects_every_tool_the_platform_serves():
    """It expected seven for as long as the platform served seven, and then the
    consequential action added `request_rollback` to
    `driver.build_platform_server` -- which `toolservice.build_app` serves
    verbatim, so a workload saw eight and the gate would have failed from that
    moment.

    It did not, because its artifact bound toolservice.py and not driver.py:
    the recorded evidence went on describing a source that no longer produced
    it. Currency proves evidence matches today's SOURCE; it cannot prove that
    re-running would still pass. The binding is what closes that gap."""
    import re

    gate = (ROOT / "infra" / "kubernetes" / "verify-exec-tool-call.py").read_text()
    listed = set(re.findall(r'"([a-z_]+)"',
                            gate[gate.index("PLATFORM_TOOLS = sorted(["):
                                 gate.index("])", gate.index("PLATFORM_TOOLS"))]))
    driver = (ROOT / "andyur" / "runner" / "driver.py").read_text()
    served = set(re.findall(r'^\s*@tool\(\s*\n?\s*"([a-z_]+)"', driver, re.M))
    assert served, "no tools found in the driver; this test's premise changed"
    assert served <= listed, (
        f"the platform serves tools this gate does not expect: {sorted(served - listed)}")


def test_the_tool_call_gate_binds_the_module_the_registry_lives_in():
    gate = (ROOT / "infra" / "kubernetes" / "verify-exec-tool-call.py").read_text()
    assert '"andyur/runner/driver.py"' in gate, (
        "a tool added to the registry would not stale this gate's evidence")

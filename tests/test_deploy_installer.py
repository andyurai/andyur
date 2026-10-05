"""The installer a partner runs, and the three ways it must refuse.

`deploy.sh` is the most trust-bearing file in the bundle: a manifest is
applied, this is executed. It is tested by running it against a FAKE kubectl on
PATH, so the refusals and the preflight are asserted without a cluster -- and
so a refusal that only happens on my machine cannot be mistaken for a rule.
"""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "infra" / "rc" / "deploy.sh"

VALUES = """\
schema: andyur.deploy-values/v1
registry: {images: "reg.test", cidr: "10.0.0.1/32"}
model: {cidr: "10.0.0.2/32"}
agent_catalog: "reg.test/andyur-registry@sha256:dd"
idp: {mode: "bundled", issuer: "", audience: "", jwks: "", admin_role: ""}
spire: {namespace: "spire-system", release: "andyur-spire", trust_domain: "andyur.local"}
namespaces: {system: "andyur-system", runs: "andyur-runs"}
"""

# THREE ipBlocks, THREE DIFFERENT FACTS, each carrying the marker the renderer
# reads. They were rendered by one substitution over every ipBlock in the file,
# on the comment "every ipBlock in the file is the registry rule" -- so a
# deployer's worker got an API-server egress rule pointing at their REGISTRY,
# and failed with a message about the NetworkPolicy verification stamp.
MANIFEST = """\
apiVersion: v1
kind: ConfigMap
metadata: {name: cp}
data:
  a: "registry.example/andyur-server@sha256:aaaa"
  b: "registry.example/andyur-worker@sha256:bbbb"
  c: "registry.example/andyur-runner@sha256:cccc"
  d: '{name: ANDYUR_REGISTRY_REF, value: "registry.example/andyur-registry@sha256:dddd"}'
  # andyur:render=registry
  e: "- to: [{ipBlock: {cidr: 192.168.5.2/32}}]"
  # andyur:render=kubernetes-api
  g: "- to: [{ipBlock: {cidr: 192.168.64.2/32}}]"
  # andyur:render=model-host
  h: "- to: [{ipBlock: {cidr: 192.168.5.2/32}}]"
  f: "spiffe://andyur.local/control-plane"
"""

# The kubernetes.default Endpoints answer every fake kubectl must give: the
# renderer DISCOVERS the API server's addresses rather than asking for them,
# because it is a fact about the cluster and a wrong answer is invisible.
ENDPOINTS = """
        case "$*" in
          *"endpoints kubernetes"*) echo -n "10.99.0.1/32 "; exit 0 ;;
        esac
"""


@pytest.fixture
def bundle(tmp_path):
    """A bundle directory with the installer and a stand-in manifest set."""
    d = tmp_path / "bundle"
    d.mkdir()
    shutil.copy(INSTALLER, d / "deploy.sh")
    (d / "deploy.sh").chmod(0o755)
    (d / "control-plane.yaml").write_text(MANIFEST)
    (d / "idp.yaml").write_text("apiVersion: v1\nkind: List\nitems: []\n")
    (d / "observability.yaml").write_text("apiVersion: v1\nkind: List\nitems: []\n")
    (d / "run-isolation.yaml").write_text("apiVersion: v1\nkind: List\nitems: []\n")
    # The workflow engine is a required bundle member now: control-plane.yaml
    # mounts a ConfigMap it defines, and deploy.sh refuses a bundle without it.
    (d / "temporal.yaml").write_text("apiVersion: v1\nkind: List\nitems: []\n")
    (d / "andyur.values.yaml").write_text(VALUES)
    # A python3 WITH PyYAML on PATH, which is the installer's one interpreter
    # prerequisite and is not a given.
    #
    # deploy.sh reads the values file with the SYSTEM python3 -- a partner runs
    # it out of the bundle, with no virtualenv -- and PyYAML is a dev-only
    # dependency (ADR-008 C2 keeps runtime manifest loading on JSON). A clean
    # Linux runner's python3 therefore has no PyYAML, every lookup returned
    # empty, and all 15 tests in this module failed on CI while passing on the
    # author's Mac, whose system python3 happened to carry it. The installer now
    # SAYS so rather than misdirecting; this makes the suite hermetic, by
    # putting the interpreter that is running these tests on PATH -- it has
    # PyYAML by definition, since pytest itself came from the same environment.
    binder = d / "bin"
    binder.mkdir(exist_ok=True)
    shim = binder / "python3"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    return d


def _fake_kubectl(bundle, script: str, endpoints: bool = True) -> None:
    """A kubectl on PATH that answers however the test needs it to."""
    binder = bundle / "bin"
    binder.mkdir(exist_ok=True)
    fake = binder / "kubectl"
    # Every fake answers the endpoints query first: without it the renderer
    # refuses, and a test that meant to exercise a LATER refusal would pass for
    # the wrong reason.
    fake.write_text("#!/usr/bin/env bash\n"
                    + (textwrap.dedent(ENDPOINTS) if endpoints else "")
                    + textwrap.dedent(script))
    fake.chmod(0o755)


def _run(bundle, *args, **kw):
    env = {**os.environ, "PATH": f"{bundle / 'bin'}:{os.environ['PATH']}",
           # the probe waits on a cluster these tests do not have
           "ANDYUR_PULL_PROBE_SECONDS": "1"}
    env.update(kw.pop("env", {}))
    return subprocess.run([str(bundle / "deploy.sh"), *args], cwd=bundle, env=env,
                          capture_output=True, text=True, timeout=120)


# --- what it refuses --------------------------------------------------------

def test_no_values_file_is_refused_before_anything_happens(bundle):
    (bundle / "andyur.values.yaml").unlink()
    result = _run(bundle, "--preflight")
    assert result.returncode != 0
    assert "--ask" in result.stderr


def test_an_unanswered_question_is_refused_rather_than_defaulted(bundle):
    """Every one of these is something a wrong guess turns into a pod that
    fails for a reason pointing somewhere else. There is no safe default, so
    an empty answer is a caller believing they configured something."""
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('images: "reg.test"', 'images: ""'))
    result = _run(bundle, "--preflight")
    assert result.returncode != 0 and "registry" in result.stderr.lower()


def test_external_idp_without_an_issuer_is_refused(bundle):
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('mode: "bundled"', 'mode: "external"'))
    result = _run(bundle, "--preflight")
    assert result.returncode != 0
    assert "external" in result.stderr and "issuer" in result.stderr


# --- what it renders --------------------------------------------------------

def test_the_render_moves_the_registry_and_keeps_the_digest(bundle):
    """A digest IS the identity, so re-homing an image must never re-tag it."""
    _fake_kubectl(bundle, "exit 1\n")          # preflight will fail; render ran first
    _run(bundle, "--preflight")
    rendered = (bundle / "rendered" / "control-plane.yaml").read_text()
    assert "reg.test/andyur-server@sha256:aaaa" in rendered
    assert "registry.example" not in rendered
    assert "10.0.0.1/32" in rendered and "192.168.5.2/32" not in rendered
    assert "reg.test/andyur-registry@sha256:dd" in rendered


def test_each_ip_block_is_rendered_from_its_own_answer(bundle):
    """THE BUG THIS EXISTS FOR: one substitution over every ipBlock in the file.

    Three rules, three different facts -- the registry (answered), the model
    host (answered) and the Kubernetes API (discovered). Rendering all three to
    the registry's address gave a partner a worker that could not reach the API
    server, reported as a NetworkPolicy-stamp failure naming nothing they chose.
    """
    _fake_kubectl(bundle, "exit 1\n")
    _run(bundle, "--preflight")
    rendered = (bundle / "rendered" / "control-plane.yaml").read_text()
    assert 'e: "- to: [{ipBlock: {cidr: 10.0.0.1/32}}]"' in rendered, "registry"
    assert 'g: "- to: [{ipBlock: {cidr: 10.99.0.1/32}}]"' in rendered, "the discovered API server"
    assert 'h: "- to: [{ipBlock: {cidr: 10.0.0.2/32}}]"' in rendered, "the model host"


def test_an_unmarked_ip_block_is_refused_rather_than_shipped_unrendered(bundle):
    """An egress rule nobody marked keeps the BUILD machine's address. Asserted
    positively -- every rendered cidr must be one of the three this deployment
    chose -- so a rule ADDED later cannot slip through by being unknown."""
    (bundle / "control-plane.yaml").write_text(
        MANIFEST + '  z: "- to: [{ipBlock: {cidr: 203.0.113.9/32}}]"\n')
    _fake_kubectl(bundle, "exit 1\n")
    result = _run(bundle, "--preflight")
    output = result.stdout + result.stderr
    assert "203.0.113.9/32" in output and "BUILT on" in output
    assert result.returncode != 0


def test_a_manifest_whose_markers_are_gone_is_refused(bundle):
    """The other direction: the renderer and the manifest drifting apart must
    fail loudly, because a silently unrendered egress rule points at us."""
    (bundle / "control-plane.yaml").write_text(
        MANIFEST.replace("# andyur:render=model-host", "# a comment"))
    _fake_kubectl(bundle, "exit 1\n")
    result = _run(bundle, "--preflight")
    output = result.stdout + result.stderr
    assert "model-host" in output and "drifted apart" in output
    assert result.returncode != 0


def test_rendering_refuses_when_the_api_server_cannot_be_discovered(bundle):
    """It is not asked for, so it cannot be answered wrong -- but it CAN be
    unavailable, and rendering a guess into a NetworkPolicy is the failure this
    whole file exists to prevent."""
    _fake_kubectl(bundle, """
        case "$*" in
          *"endpoints kubernetes"*) exit 1 ;;
          *) exit 0 ;;
        esac
    """, endpoints=False)
    result = _run(bundle, "--preflight")
    assert result.returncode != 0
    assert "endpoints" in (result.stdout + result.stderr)
    assert not (bundle / "rendered" / "control-plane.yaml").exists(), (
        "a manifest was rendered without the address it needed")


def test_a_registry_with_a_path_in_it_is_rehomed_whole(bundle):
    """`ghcr.io/acme` is a registry too. Substituting only the segment before
    the image NAME left `ghcr.io/` in place and grew a second registry in front
    of it. Ours are single-segment today, which is exactly why that would have
    gone unnoticed."""
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('images: "reg.test"', 'images: "ghcr.io/acme"'))
    (bundle / "control-plane.yaml").write_text(
        MANIFEST.replace("registry.example/andyur-server", "old.host/team/andyur-server"))
    _fake_kubectl(bundle, "exit 1\n")
    _run(bundle, "--preflight")
    rendered = (bundle / "rendered" / "control-plane.yaml").read_text()
    assert "ghcr.io/acme/andyur-server@sha256:aaaa" in rendered
    assert "old.host" not in rendered and "ghcr.io/ghcr.io" not in rendered


def test_a_manifest_with_no_andyur_images_is_refused(bundle):
    """The check that every image names the answered registry is vacuous if
    there are no images. A control plane without them is not one."""
    (bundle / "control-plane.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cp}\ndata:\n"
        "  # andyur:render=registry\n"
        '  a: "- to: [{ipBlock: {cidr: 1.1.1.1/32}}]"\n'
        "  # andyur:render=kubernetes-api\n"
        '  b: "- to: [{ipBlock: {cidr: 1.1.1.2/32}}]"\n'
        "  # andyur:render=model-host\n"
        '  c: "- to: [{ipBlock: {cidr: 1.1.1.3/32}}]"\n'
        '  d: \'{name: ANDYUR_REGISTRY_REF, value: "x"}\'\n')
    # A fake kubectl, like every other test here. Without one this reached for
    # whatever cluster the developer happened to have, so it passed on a machine
    # with a healthy one and failed on the render's API-address discovery on a
    # machine without -- a test whose result depended on the room it ran in.
    _fake_kubectl(bundle, "exit 1\n")
    result = _run(bundle, "--preflight")
    assert result.returncode != 0
    assert "names no Andyur images" in result.stdout + result.stderr


# --- the preflight ----------------------------------------------------------

def test_a_spire_release_under_another_name_is_caught_before_applying(bundle):
    """THE QUIETEST FAILURE IN THE SYSTEM. The ClusterSPIFFEIDs declare
    className <namespace>-<release>; install SPIRE under another name and the
    controller ignores every one of them with no error at all -- no SVIDs, and
    pods that never become ready. Answerable before anything is applied."""
    _fake_kubectl(bundle, """
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) exit 0 ;;   # prints nothing: no match
          *storageclass*) echo "standard"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle, "--preflight")
    output = result.stdout + result.stderr
    assert "no SPIRE release named 'andyur-spire'" in output
    assert "ignores every identity" in output
    assert result.returncode != 0, "an unmet precondition must stop the deploy"


def test_a_missing_secret_stops_the_deploy_and_says_where_to_look(bundle):
    _fake_kubectl(bundle, """
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret andyur-secrets"*) exit 1 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle, "--preflight")
    output = result.stdout + result.stderr
    assert "Secret andyur-secrets is missing" in output
    assert "PREREQUISITES.md" in output
    assert result.returncode != 0


def test_nothing_is_applied_when_a_precondition_is_unmet(bundle):
    """The whole point: these are answerable BEFORE anything exists, and every
    one of them is otherwise found as a CrashLoopBackOff naming the wrong
    thing."""
    applied = bundle / "applied.log"
    # `-f -` is the preflight's own pull probe, which applies a Pod from stdin
    # and is not a manifest. The first version of this fake logged both, and
    # reported that the installer had applied something when it had not --
    # a false positive on the single most important property here.
    _fake_kubectl(bundle, f"""
        case "$*" in
          version*) exit 0 ;;
          *"apply -n"*"-f -"*) exit 0 ;;
          *apply*) echo "$*" >> {applied} ; exit 0 ;;
          *"crd clusterspiffeids"*) exit 1 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle)
    assert result.returncode != 0
    assert not applied.exists(), "a manifest was applied despite an unmet precondition"


def test_a_namespace_this_release_cannot_render_is_refused(bundle):
    """`andyur-system` and `andyur-runs` are written into the manifests -- the
    worker's env, the ClusterSPIFFEID selectors, the NetworkPolicy peers, the
    Roles. The render moves images, addresses and the catalog, not names. So an
    answer that is not the default produced a control plane whose every selector
    pointed at a namespace nothing was in, and nothing said so."""
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('runs: "andyur-runs"', 'runs: "platform-runs"'))
    result = _run(bundle, "--preflight")
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "NAMESPACES" in output and "platform-runs" in output


def test_the_spiffe_class_name_is_rendered_from_the_answers(bundle):
    """QUESTION 7's OWN FAILURE, which this installer described and then let
    happen: "The ClusterSPIFFEIDs use a className of <namespace>-<release>; get
    this wrong and the controller ignores every identity silently -- no SVIDs,
    no error."

    It asked for the namespace and the release, the preflight checked SPIRE was
    really installed under them, and nothing rendered them. The manifests
    hard-code `spire-system-andyur-spire`, so a deployer who answered anything
    else got a green preflight and identities no controller watches."""
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('release: "andyur-spire"', 'release: "corp-spire"')
              .replace('namespace: "spire-system"', 'namespace: "identity"'))
    (bundle / "run-isolation.yaml").write_text(
        "apiVersion: spire.spiffe.io/v1alpha1\nkind: ClusterSPIFFEID\n"
        "metadata: {name: andyur-run-proxy}\nspec:\n"
        "  className: spire-system-andyur-spire\n")
    _fake_kubectl(bundle, "exit 1\n")
    _run(bundle, "--preflight")
    for name in ("control-plane.yaml", "run-isolation.yaml"):
        rendered = (bundle / "rendered" / name).read_text()
        if "className" in rendered:
            assert "identity-corp-spire" in rendered, f"{name} kept the build's class"
            assert "spire-system-andyur-spire" not in rendered


def test_an_identity_with_no_class_name_is_refused_rather_than_shipped(bundle):
    """A ClusterSPIFFEID with NO className is not "unclassed" -- to a controller
    running `watchClassless: false` it is invisible. No entry, no error, and a
    run proxy two components away reporting `Timeout waiting for the first
    update` from the workload API.

    That is exactly what shipped: run-isolation.yaml declared an identity and
    never carried a className, in any commit."""
    (bundle / "run-isolation.yaml").write_text(
        "apiVersion: spire.spiffe.io/v1alpha1\nkind: ClusterSPIFFEID\n"
        "metadata: {name: andyur-run-proxy}\nspec:\n"
        "  spiffeIDTemplate: spiffe://andyur.local/x\n")
    _fake_kubectl(bundle, "exit 1\n")
    result = _run(bundle, "--preflight")
    output = result.stdout + result.stderr
    assert "declares an identity nothing will ever create" in output
    assert result.returncode != 0


def test_the_model_address_is_read_from_the_cluster_not_shipped(bundle):
    """control-plane.yaml carries ANDYUR_OLLAMA_URL as a numeric ClusterIP with
    the comment "Render the numeric ClusterIP of the andyur-ollama Service
    here" -- and nothing rendered it, so the BUILD MACHINE's address shipped.

    It survived every deploy onto a cluster that already had that Service,
    because Kubernetes keeps a ClusterIP for the life of the Service. Delete the
    namespace -- a first-time deployer, or a teardown between RC passes -- and
    the new Service gets a new address while the worker keeps handing the old
    one to every run. Every model call then fails `upstream_unreachable` against
    an IP that belongs to nothing."""
    applied = bundle / "applied.log"
    _fake_kubectl(bundle, f"""
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *"service andyur-ollama"*) echo -n "10.99.44.5"; exit 0 ;;
          *"set env"*) echo "$*" >> {applied} ; exit 0 ;;
          *rollout*) exit 0 ;;
          *"jsonpath={{.status.phase}}"*) echo -n "Running"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle)
    assert applied.exists(), (
        "the model address was never set on the worker\n"
        + (result.stdout + result.stderr)[-800:])
    assert "10.99.44.5" in applied.read_text()
    assert "ANDYUR_OLLAMA_URL=http://10.99.44.5:11434" in applied.read_text()


def test_a_model_service_with_no_address_stops_the_deploy(bundle):
    """A guess here is the build machine's address all over again."""
    _fake_kubectl(bundle, """
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *"service andyur-ollama"*) exit 1 ;;
          *"jsonpath={.status.phase}"*) echo -n "Running"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle)
    output = result.stdout + result.stderr
    assert "upstream_unreachable" in output
    assert result.returncode != 0


ENGINE = """\
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata: {name: andyur-temporal}
spec:
  className: spire-system-andyur-spire
  spiffeIDTemplate: spiffe://andyur.local/workflow-engine
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: andyur-temporal-db}
spec:
  volumeClaimTemplates:
    - metadata: {name: data}
      spec: {resources: {requests: {storage: 50Gi}}}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: andyur-temporal-authz}
data:
  envoy.yaml: |
    principals: ["spiffe://andyur.local/control-plane"]
"""


def test_the_trust_domain_reaches_the_engine_manifest(bundle):
    """The trust domain was rendered into control-plane.yaml alone. Under any
    other one, the engine's authorizer listed IDs the cluster never issues and
    fetched its certificate under a name SPIRE does not serve: the durable
    provider stayed offline, with no error anywhere."""
    (bundle / "andyur.values.yaml").write_text(
        VALUES.replace('trust_domain: "andyur.local"', 'trust_domain: "corp.example"'))
    (bundle / "temporal.yaml").write_text(ENGINE)
    _fake_kubectl(bundle, "exit 1\n")
    _run(bundle, "--preflight")

    rendered = (bundle / "rendered" / "temporal.yaml").read_text()
    assert "andyur.local" not in rendered, "the engine kept the build's trust domain"
    assert "spiffe://corp.example/control-plane" in rendered
    assert "spiffe://corp.example/workflow-engine" in rendered


def test_a_changed_database_volume_template_does_not_stop_the_deploy(bundle):
    """A StatefulSet's volume template is immutable, so re-applying the engine
    with a larger one failed -- and the installer died there, before the
    control plane. The StatefulSet is now re-created around its running Pod
    and claim, and the deployer is told the claim still needs resizing."""
    (bundle / "temporal.yaml").write_text(ENGINE)
    calls = bundle / "calls.log"
    _fake_kubectl(bundle, f"""
        echo "$*" >> {calls}
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *"service andyur-ollama"*) echo -n "10.99.44.5"; exit 0 ;;
          *"get statefulset andyur-temporal-db"*) echo -n "10Gi"; exit 0 ;;
          *"jsonpath={{.status.phase}}"*) echo -n "Running"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    result = _run(bundle)
    log = calls.read_text().splitlines()

    orphan = [i for i, c in enumerate(log)
              if "delete statefulset andyur-temporal-db" in c and "--cascade=orphan" in c]
    engine = [i for i, c in enumerate(log) if "apply -f" in c and "temporal.yaml" in c]
    assert orphan and engine and orphan[0] < engine[0], (
        "the StatefulSet was not re-created around its Pod before the apply\n"
        + (result.stdout + result.stderr)[-800:])
    assert "10Gi -> 50Gi" in result.stdout + result.stderr


def test_positive_control_an_unchanged_volume_template_is_left_alone(bundle):
    """Deleting a StatefulSet on every deploy, even orphaned, is churn with no
    cause; it happens only when the template actually differs."""
    (bundle / "temporal.yaml").write_text(ENGINE)
    calls = bundle / "calls.log"
    _fake_kubectl(bundle, f"""
        echo "$*" >> {calls}
        case "$*" in
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *"service andyur-ollama"*) echo -n "10.99.44.5"; exit 0 ;;
          *"get statefulset andyur-temporal-db"*) echo -n "50Gi"; exit 0 ;;
          *"jsonpath={{.status.phase}}"*) echo -n "Running"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)
    _run(bundle)
    assert not any("delete statefulset andyur-temporal-db" in c
                   for c in calls.read_text().splitlines())


def _engine_fake(bundle, calls, before, after):
    """A kubectl whose authorizer ConfigMap reports `before` until the engine
    manifest is applied and `after` from then on."""
    state = bundle / "applied-engine"
    _fake_kubectl(bundle, f"""
        echo "$*" >> {calls}
        case "$*" in
          *"apply -f"*temporal.yaml*) touch {state}; exit 0 ;;
          *"configmap andyur-temporal-authz"*)
             if [ -e {state} ]; then echo -n "{after}"; else echo -n "{before}"; fi; exit 0 ;;
          version*) exit 0 ;;
          *"crd clusterspiffeids"*) exit 0 ;;
          *"statefulset -n spire-system"*) echo "andyur-spire-server 1/1"; exit 0 ;;
          *"get secret"*) exit 0 ;;
          *storageclass*) echo "standard"; exit 0 ;;
          *"service andyur-ollama"*) echo -n "10.99.44.5"; exit 0 ;;
          *"get statefulset andyur-temporal-db"*) echo -n "50Gi"; exit 0 ;;
          *"jsonpath={{.status.phase}}"*) echo -n "Running"; exit 0 ;;
          *) exit 0 ;;
        esac
    """)


def test_a_changed_authorizer_config_restarts_the_engine(bundle):
    """Envoy reads its config at start: a changed allowlist applied without a
    restart leaves the old one deciding who may call the engine."""
    (bundle / "temporal.yaml").write_text(ENGINE)
    calls = bundle / "calls.log"
    _engine_fake(bundle, calls, "100", "101")
    _run(bundle)
    assert any("rollout restart deployment/andyur-temporal" in c
               for c in calls.read_text().splitlines()), "the engine was not restarted"


def test_positive_control_an_unchanged_authorizer_config_does_not_restart_it(bundle):
    (bundle / "temporal.yaml").write_text(ENGINE)
    calls = bundle / "calls.log"
    _engine_fake(bundle, calls, "100", "100")
    _run(bundle)
    assert not any("rollout restart deployment/andyur-temporal" in c
                   for c in calls.read_text().splitlines()), (
        "the engine was restarted on a deploy that changed nothing it reads")

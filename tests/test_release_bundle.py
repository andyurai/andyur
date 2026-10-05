"""What a partner receives, and the three functions that decide it.

`emit_deployment`, `write_bundle` and `push_image` had no tests at all: they
were exercised only by running a release by hand, which is how `--push-to`
shipped in a state where it could not complete on any tree, the rendered
manifest was signed at a path it is never written to, and nothing assembled a
bundle. Those were found by doing a real release against a real registry; these
are here so the next one is found by the suite.
"""

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "infra" / "rc"))
import build_release as br                                    # noqa: E402

PUSHED = {
    "andyur-server": "reg.test/andyur-server@sha256:" + "a" * 64,
    "andyur-worker": "reg.test/andyur-worker@sha256:" + "b" * 64,
    "andyur-runner": "reg.test/andyur-runner@sha256:" + "c" * 64,
}
REGISTRY_REF = "reg.test/andyur-registry@sha256:" + "d" * 64


def _render(tmp_path, **kwargs):
    return br.emit_deployment(ROOT, tmp_path, PUSHED, **kwargs)


# --- the manifest a partner applies ---------------------------------------

def test_every_placeholder_is_replaced_by_something_pullable(tmp_path):
    text = _render(tmp_path, registry_ref=REGISTRY_REF).read_text()
    assert "registry.example" not in text
    for digest in list(PUSHED.values()) + [REGISTRY_REF]:
        assert digest in text


def test_the_governed_registry_is_an_input_and_its_absence_is_refused(tmp_path):
    """THE DEFECT THAT MADE --push-to UNUSABLE ON ANY TREE. control-plane.yaml
    pins FOUR references and a release builds three: andyur-registry is the
    governed agent catalog, an artifact published by `andyur agents package`
    whose content is the adopter's agents, not our platform. Building it here
    would be this file inventing an agent catalog; omitting it left a
    placeholder the (correct) refusal then rejected, after pushing three
    images."""
    with pytest.raises(br.ReleaseRefused) as refusal:
        _render(tmp_path)
    message = str(refusal.value)
    assert "andyur-registry" in message
    # The refusal must be actionable: a dead end is what the release-python
    # refusal used to be, and this one names the command that produces the ref.
    assert "andyur agents package" in message and "--registry-ref" in message


def test_a_partially_substituted_manifest_is_never_written(tmp_path):
    """A half-rendered manifest deploys the real control plane beside an image
    nobody can pull, and the failure appears at runtime in someone else's
    cluster."""
    with pytest.raises(br.ReleaseRefused):
        br.emit_deployment(ROOT, tmp_path, {"andyur-server": PUSHED["andyur-server"]},
                           registry_ref=REGISTRY_REF)
    assert not (tmp_path / "control-plane.yaml").exists()


# --- how the snapshot is verified is a property of the REGISTRY ------------

def test_the_registry_flags_default_to_the_strict_values(tmp_path):
    text = _render(tmp_path, registry_ref=REGISTRY_REF).read_text()
    assert '{name: ANDYUR_REGISTRY_ALLOW_HTTP, value: "off"}' in text
    assert '{name: ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG, value: "off"}' in text


def test_the_registry_flags_flip_only_when_asked(tmp_path):
    """These are rendered rather than shipped as a guess because they describe
    the REGISTRY, not the platform. The strict values are right for a
    production registry and unsatisfiable for a local one -- a snapshot signed
    with a local key was never in a public transparency log, so cosign reaches
    for the Sigstore mirror, the server's NetworkPolicy refuses the egress, and
    the agent registry is 503. That happened."""
    text = _render(tmp_path, registry_ref=REGISTRY_REF,
                   registry_allow_http=True, registry_ignore_tlog=True).read_text()
    assert '{name: ANDYUR_REGISTRY_ALLOW_HTTP, value: "on"}' in text
    assert '{name: ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG, value: "on"}' in text
    assert '{name: ANDYUR_REGISTRY_ALLOW_HTTP, value: "off"}' not in text


def test_the_flags_are_rendered_against_the_manifest_that_ships(tmp_path):
    """The substitution is textual, so it fails SILENTLY if control-plane.yaml
    ever writes those two settings differently -- the flags would stay strict,
    the deployment would 503 on its registry, and nothing would say why. This
    asserts the shipped manifest still contains exactly what the renderer looks
    for."""
    shipped = (ROOT / "infra/kubernetes/control-plane.yaml").read_text()
    for flag in ("ANDYUR_REGISTRY_ALLOW_HTTP", "ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG"):
        assert shipped.count('{name: %s, value: "off"}' % flag) == 1, flag


# --- the bundle ------------------------------------------------------------

def _manifest(images=True):
    artifacts = [{"name": "andyur-0.1.0-py3-none-any.whl", "kind": "python-artifact"}]
    if images:
        artifacts += [{"name": f"{name}:abc", "kind": "container-image",
                       "extra": {"pullable_as": digest}}
                      for name, digest in PUSHED.items()]
    return {"frozen_commit": "0" * 40, "artifacts": artifacts}


def _release_dir(tmp_path):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "dist").mkdir(parents=True)
    for name in ("control-plane.yaml", "release-manifest.json", "cosign.pub"):
        (out / name).write_text("x\n")
    for name in ("control-plane.yaml", "release-manifest.json"):
        (out / f"{name}.cosign-bundle.json").write_text("{}\n")
    # The installer, which a real release output carries and signs: a partner
    # RUNS it, which makes it the most trust-bearing file in the bundle.
    (out / br.INSTALLER).write_text("#!/usr/bin/env bash\ntrue\n")
    (out / f"{br.INSTALLER}.cosign-bundle.json").write_text("{}\n")
    # The companion manifests a real release output carries: the control plane
    # references both, so a bundle without them cannot come up.
    for companion in br.COMPANION_MANIFESTS:
        (out / companion).write_text("apiVersion: v1\nkind: List\nitems: []\n")
        (out / f"{companion}.cosign-bundle.json").write_text("{}\n")
    # The things a partner must NEVER receive, sitting right beside them.
    (out / "dist" / "andyur-0.1.0.tar.gz").write_text("the tree\n")
    (out / "dist" / "andyur-0.1.0-py3-none-any.whl").write_text("the wheel\n")
    return out


def test_the_bundle_holds_what_a_deployer_needs_and_nothing_else(tmp_path):
    out = _release_dir(tmp_path)
    bundle = br.write_bundle(out, _manifest(), ephemeral_key=True)
    assert {p.name for p in bundle.iterdir()} == {
        "control-plane.yaml", "control-plane.yaml.cosign-bundle.json",
        "idp.yaml", "idp.yaml.cosign-bundle.json",
        "observability.yaml", "observability.yaml.cosign-bundle.json",
        "run-isolation.yaml", "run-isolation.yaml.cosign-bundle.json",
        # The workflow engine. The control plane mounts a ConfigMap only this
        # defines and binds the Temporal provider, so a bundle without it
        # cannot start the API. Signed like every other manifest.
        "temporal.yaml", "temporal.yaml.cosign-bundle.json",
        "deploy.sh", "deploy.sh.cosign-bundle.json",
        "release-manifest.json", "release-manifest.json.cosign-bundle.json",
        "cosign.pub", "VERIFY.md", "PREREQUISITES.md"}


def test_the_sdist_and_the_wheel_cannot_reach_the_bundle(tmp_path):
    """Not by pruning: `write_bundle` copies an EXPLICIT LIST into a fresh
    directory, so source cannot arrive by being forgotten. The release output
    contains both, one directory up, throughout."""
    out = _release_dir(tmp_path)
    bundle = br.write_bundle(out, _manifest(), ephemeral_key=True)
    names = [p.name for p in bundle.rglob("*")]
    assert not [n for n in names if n.endswith((".tar.gz", ".whl", ".py"))]
    assert (out / "dist" / "andyur-0.1.0.tar.gz").exists(), "the release still has it"


def test_verify_md_names_the_digests_a_deployer_must_pull(tmp_path):
    out = _release_dir(tmp_path)
    text = (br.write_bundle(out, _manifest(), ephemeral_key=True)
            / "VERIFY.md").read_text()
    for digest in PUSHED.values():
        assert digest in text
    assert "cosign verify-blob" in text and "kubectl apply" in text


def test_verify_md_says_what_the_signature_is_worth(tmp_path):
    """An ephemeral key means the signatures prove the directory is internally
    consistent and nothing more. A deployer who is not told that will read a
    verified signature as provenance.

    Two SEPARATE output directories on purpose: the bundle is written into the
    release output, so reusing one would leave the first run's `cosign.pub`
    lying beside the second run's VERIFY.md and the assertion below would pass
    on a stale file. (The first version of this test did exactly that, and
    ended in `or True`, which is an assertion that cannot fail.)"""
    ephemeral = (br.write_bundle(_release_dir(tmp_path / "eph"), _manifest(),
                                 ephemeral_key=True) / "VERIFY.md").read_text()
    assert "NOT provenance" in ephemeral

    real_out = _release_dir(tmp_path / "real")
    real_bundle = br.write_bundle(real_out, _manifest(), ephemeral_key=False)
    assert "OUT OF BAND" in (real_bundle / "VERIFY.md").read_text()
    # A key the operator supplied is NOT shipped beside what it verifies: its
    # public half is obtained separately or the signature proves nothing about
    # provenance, which is the entire difference between the two modes.
    assert "cosign.pub" not in {p.name for p in real_bundle.iterdir()}


def test_an_image_that_was_never_pushed_is_named_as_such(tmp_path):
    """A bundle whose manifest records an image with no pullable reference is
    one a partner cannot deploy; VERIFY.md must not render a blank."""
    out = _release_dir(tmp_path)
    manifest = _manifest()
    manifest["artifacts"][1]["extra"] = {}
    text = (br.write_bundle(out, manifest, ephemeral_key=True) / "VERIFY.md").read_text()
    assert "NOT PUSHED" in text


# --- the push ---------------------------------------------------------------

def test_a_push_that_yields_no_repository_digest_is_refused(monkeypatch):
    """FAIL CLOSED. `docker push` exiting 0 is not evidence that anyone else can
    pull the image: the digest is read back from the daemon afterwards and must
    name the registry we pushed to. Recording a reference nobody can pull is
    worse than recording none."""
    calls = []

    def fake_run(*argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ("docker", "image"):
            return json.dumps(["other.registry/andyur-server@sha256:" + "e" * 64])
        return ""

    monkeypatch.setattr(br, "run", fake_run)
    with pytest.raises(br.ReleaseRefused) as refusal:
        br.push_image("andyur-server:abc", "reg.test")
    assert "no repository digest" in str(refusal.value)
    assert ("docker", "push", "reg.test/andyur-server:abc") in calls


def test_a_push_returns_the_digest_that_names_this_registry(monkeypatch):
    wanted = "reg.test/andyur-server@sha256:" + "f" * 64
    monkeypatch.setattr(br, "run", lambda *a, **k: json.dumps(
        ["stale.registry/andyur-server@sha256:" + "0" * 64, wanted])
        if a[:2] == ("docker", "image") else "")
    assert br.push_image("andyur-server:abc", "reg.test") == wanted


def test_verify_md_explains_the_stamp_and_who_now_renews_it(tmp_path):
    """The daemon refuses to start unless the run namespace carries a
    NetworkPolicy verification stamp from the last 600 seconds. That used to be
    a known limitation of the bundle -- the verifier was a script in the source
    tree, so the control plane served and the worker crash-looped, and the RC
    gate reported `statefulset/andyur-worker never reached the applied
    generation` about a stamp rather than about the bundle.

    The bundle now deploys a reconciler that re-proves containment and stamps.
    VERIFY.md must say WHICH of those two worlds this bundle is, because a
    partner reading the old sentence would leave a working worker for dead."""
    out = _release_dir(tmp_path)
    text = (br.write_bundle(out, _manifest(), ephemeral_key=True)
            / "VERIFY.md").read_text()
    assert "andyur-netpol-reconciler" in text
    assert "600 seconds" in text
    # The positive control is the reason to believe the denials, so it is named.
    assert "positive control" in text
    # And what it does NOT prove, so the two proofs are not read as one.
    assert "allow-all" in text
    # The stale promise is gone: a partner told the verifier is missing will not
    # look for the component that is right there.
    assert "NOT IN THIS BUNDLE" not in text


def test_verify_md_describes_the_profile_the_manifest_actually_ships(tmp_path):
    """It said `ANDYUR_PROFILE=dev` and explained at length why prod could not
    ship. The manifest has shipped prod, with a bundled Keycloak, since the IdP
    went in -- so the one document a partner reads to know what they deployed
    described a different deployment."""
    out = _release_dir(tmp_path)
    bundle = br.write_bundle(out, _manifest(), ephemeral_key=True)
    text = (bundle / "VERIFY.md").read_text()
    # The SHIPPING manifest, not the fixture's stand-in: this test exists
    # because the document and the manifest disagreed, so it has to read the
    # real one.
    shipped = (Path(br.__file__).resolve().parents[2]
               / "infra" / "kubernetes" / "control-plane.yaml").read_text()
    assert "ANDYUR_PROFILE, value: prod" in shipped, "the manifest itself changed"
    assert "ANDYUR_PROFILE=prod" in text and "ANDYUR_PROFILE=dev" not in text


# --- the bundle carries everything the control plane references ------------

def test_the_bundle_carries_the_manifests_the_control_plane_references(tmp_path):
    """`control-plane.yaml` validates user tokens against the IdP's in-cluster
    Service and exports telemetry to the collector's. Shipping it alone handed a
    partner a manifest whose server exits at boot looking for an identity
    provider that was not in the box -- and nothing in the bundle said so."""
    out = _release_dir(tmp_path)
    bundle = br.write_bundle(out, _manifest(), ephemeral_key=True)
    names = {p.name for p in bundle.iterdir()}
    # run-isolation.yaml creates the namespace runs launch into. Without it a
    # partner had a control plane and nowhere to put a run, and the symptom was
    # the worker's NetworkPolicy-stamp refusal, which names something else.
    assert {"idp.yaml", "observability.yaml", "run-isolation.yaml"} <= names
    for name in br.COMPANION_MANIFESTS:
        assert f"{name}.cosign-bundle.json" in names, (
            f"{name} ships without its signature: a deployer is asked to trust "
            "it exactly as much as the control plane")


def test_the_bundle_says_what_must_exist_before_it_can_work(tmp_path):
    """Four things the manifest needs and does not create. The quietest is the
    SPIRE release NAME: the ClusterSPIFFEIDs carry a className of
    `<namespace>-<release>`, so installing SPIRE under another name makes the
    controller ignore them silently -- no SVIDs, no error, pods that never
    become ready."""
    out = _release_dir(tmp_path)
    text = (br.write_bundle(out, _manifest(), ephemeral_key=True)
            / "PREREQUISITES.md").read_text()
    assert "spire-system-andyur-spire" in text
    assert "andyur-secrets" in text and "andyur-idp-secrets" in text
    assert "spire-crds" in text and "0.30.0" in text
    assert "ANDYUR_REGISTRY_REF" in text
    assert "kubectl apply -f idp.yaml" in text


def test_a_release_missing_a_companion_manifest_is_refused(tmp_path):
    """Refused at BUILD time, where it is a missing file, rather than at deploy
    time where it is a pod that never starts."""
    root = tmp_path / "fake-root"
    (root / "infra" / "kubernetes").mkdir(parents=True)
    with pytest.raises(br.ReleaseRefused) as refusal:
        br.copy_companions(root, tmp_path)
    assert "cannot come up" in str(refusal.value)


def test_every_image_in_every_shipped_manifest_is_pinned_by_digest():
    """A tag is a name someone else can repoint. The identity provider shipped
    tag-pinned for a day because the only check looked at Andyur's own images."""
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "infra" / "rc"))
    import verify_bundle as vb

    for name in ("control-plane.yaml", *br.COMPANION_MANIFESTS):
        text = (ROOT / "infra" / "kubernetes" / name).read_text()
        for image in re.findall(r"image: (\S+)", text):
            if image.startswith("`"):        # a shell fragment in a comment
                continue
            if "registry.example" in image:  # rendered at release time
                continue
            assert "@sha256:" in image, f"{name} runs {image}, which is a tag"
    assert {"idp.yaml", "observability.yaml", "run-isolation.yaml"} <= set(vb.SIGNED)


# --- the image check reads YAML, not prose ---------------------------------

def _vb():
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "infra" / "rc"))
    import verify_bundle
    return verify_bundle


def test_a_comment_that_mentions_an_image_is_not_an_image():
    """The first version grepped `image: (\\S+)` over raw text and refused a
    good bundle because a COMMENT contained the words "image:
    `brokerstate_server". A check that reads YAML as prose finds things that
    are not there -- and this one refused the real bundle on its first run."""
    manifest = """
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    # the probe used to import the whole serving module -- see `image: notreal`
    - name: app
      image: example.test/app@sha256:aa
"""
    assert _vb().images_in(manifest) == [("container app", "example.test/app@sha256:aa")]


def test_an_image_named_only_in_an_env_var_is_still_an_image():
    """Kubernetes has two places an image lives. The run proxy and agent are
    launched later by the daemon from ANDYUR_KUBERNETES_*_IMAGE, so a tag there
    is exactly as unpinned as one in a Pod spec -- and nothing in the
    manifest's container list would show it."""
    manifest = """
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: worker
      image: example.test/worker@sha256:bb
      env:
        - name: ANDYUR_KUBERNETES_PROXY_IMAGE
          value: example.test/proxy:latest
"""
    found = dict((where, image) for where, image in _vb().images_in(manifest))
    assert found["ANDYUR_KUBERNETES_PROXY_IMAGE"] == "example.test/proxy:latest"


def test_a_tag_anywhere_in_a_shipped_manifest_refuses_the_bundle(tmp_path):
    vb = _vb()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for required in vb.REQUIRED:
        (bundle / required).write_text("placeholder\n")
    for signed in vb.SIGNED:
        (bundle / f"{signed}.cosign-bundle.json").write_text("{}\n")
    (bundle / "idp.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"
        "spec: {containers: [{name: kc, image: quay.io/keycloak/keycloak:26.2}]}\n")
    problems = vb.check(bundle)
    assert any("UNPINNED IMAGE" in p and "idp.yaml" in p for p in problems), problems


def test_the_installer_ships_signed_and_executable(tmp_path):
    """A manifest is applied; the installer is EXECUTED. That makes it the most
    trust-bearing file here, so it travels with a signature like everything
    else and arrives runnable."""
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "infra" / "rc"))
    import verify_bundle as vb

    out = _release_dir(tmp_path)
    bundle = br.write_bundle(out, _manifest(), ephemeral_key=True)
    installer = bundle / br.INSTALLER
    assert installer.is_file() and (bundle / f"{br.INSTALLER}.cosign-bundle.json").is_file()
    assert installer.stat().st_mode & 0o111, "the installer arrived without execute permission"
    assert br.INSTALLER in vb.REQUIRED and br.INSTALLER in vb.SIGNED


def test_the_shipped_installer_is_the_one_in_the_tree():
    """Two copies of a program is one copy and one drifting comment. The bundle
    takes the tree's file rather than a rendered variant of it."""
    import hashlib
    tree = (ROOT / "infra" / "rc" / br.INSTALLER).read_bytes()
    assert hashlib.sha256(tree).hexdigest()  # readable, and it is what gets copied
    assert b"--preflight" in tree and b"--ask" in tree


# --- what gets signed, and what cannot be ------------------------------------

def test_the_agent_catalog_is_recorded_but_never_signed_as_a_file():
    """It is an OCI REFERENCE, not a file in this directory. It carries its own
    cosign signature in the registry and ships its own verification key beside
    the bundle; what binds it HERE is the digest in the release manifest, and
    the release manifest is signed.

    Falling through to the `dist/` branch made the signer look for a file named
    `registry/andyur-registry@sha256:...`, and the whole release died at signing
    with no message at all."""
    source = (Path(br.__file__)).read_text()
    dispatch = source[source.index('if artifact.kind == "agent-catalog"'):]
    dispatch = dispatch[:dispatch.index("artifact.signature = sign(")]
    assert "continue" in dispatch, "the catalog reference is being sent to the signer"
    assert '"public-key"' in dispatch, (
        "the catalog's verification key ships at the top of the output, not in dist/")


def test_an_artifact_the_signer_cannot_find_is_named():
    """The `else` branch is an ASSUMPTION about where a kind lives. A new kind
    that does not live there produced a failure naming neither the artifact nor
    the kind -- which is how the previous defect cost a whole RC pass."""
    source = (Path(br.__file__)).read_text()
    assert "nothing to sign for" in source
    assert "which does not exist" in source


# --- the telemetry path can start on a cluster nobody prepared ---------------

def test_the_bundle_carries_the_config_its_telemetry_deployments_mount(tmp_path):
    """THE BUNDLE SHIPPED DEPLOYMENTS THAT COULD NOT START.

    observability.yaml carries the Collector's and Jaeger's Deployments,
    Services and NetworkPolicies -- and neither ConfigMap. Those were created
    by `apply-observability.sh`, which lives in the source tree a deployer does
    not have. On any cluster where a developer had ever run it the ConfigMaps
    already existed, so the bundle looked complete for as long as it was only
    deployed onto one.

    The failure is not subtle and it names the wrong thing: the Collector sits
    in ContainerCreating on `configmap "otel-collector-config" not found`, the
    control plane's telemetry export has nowhere to go, `/ready` times out, and
    the CONTROL PLANE never becomes Ready -- reported as a telemetry problem.

    Found by tearing the cluster down between two RC passes, which is the
    entire argument for doing that."""
    import yaml

    # THE REAL copy_companions, against the REAL manifest -- not the fixture's
    # stand-in. What is under test is that the release adds the ConfigMaps to
    # the file it ships, and a stub observability.yaml would prove nothing
    # about the Deployments that mount them.
    out = tmp_path / "companions"
    out.mkdir()
    br.copy_companions(br.PLATFORM_ROOT, out)
    docs = [d for d in yaml.safe_load_all((out / "observability.yaml").read_text()) if d]
    maps = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}
    assert set(maps) == {"otel-collector-config", "andyur-jaeger-config"}

    # Every ConfigMap a Deployment in this file mounts must be one of them.
    mounted = set()
    for doc in docs:
        if doc["kind"] != "Deployment":
            continue
        for volume in doc["spec"]["template"]["spec"].get("volumes", []):
            if "configMap" in volume:
                mounted.add(volume["configMap"]["name"])
    assert mounted <= set(maps), f"unmountable ConfigMap(s): {mounted - set(maps)}"

    # And the config inside is the real one, still parseable.
    collector = yaml.safe_load(maps["otel-collector-config"]["data"]["config.yaml"])
    assert {"receivers", "exporters", "service"} <= set(collector)


def test_a_changed_telemetry_config_rolls_the_pods_that_read_it(tmp_path):
    """A ConfigMap is read at start, so applying a new one changed nothing
    running: an upgrade that fixed the Collector's relabelling kept dropping
    every Temporal metric until the Collector happened to restart. Each
    Deployment's pod template carries its config's hash, so a changed config
    is a changed template, which `kubectl apply` rolls."""
    import hashlib

    import yaml

    out = tmp_path / "companions"
    out.mkdir()
    br.copy_companions(br.PLATFORM_ROOT, out)
    docs = [d for d in yaml.safe_load_all((out / "observability.yaml").read_text()) if d]
    deployments = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Deployment"}

    for app, relative in br.CONFIG_OWNERS.items():
        expected = hashlib.sha256((br.PLATFORM_ROOT / relative).read_bytes()).hexdigest()
        stamped = (deployments[app]["spec"]["template"]["metadata"]
                   .get("annotations", {}).get("andyur.ai/config-sha256"))
        assert stamped == expected, (
            f"{app}'s pod template does not carry the hash of {relative}; a "
            "changed config would not restart it")


def test_the_rendered_config_is_the_one_source_verbatim():
    """One source per config file. Rendering it through a YAML dumper would
    drop every comment in it, and those files are what a deployer reads when
    the telemetry path misbehaves."""
    for name, relative in br.OBSERVABILITY_CONFIGS:
        source = (br.PLATFORM_ROOT / relative).read_text()
        rendered = br._configmap_documents(br.PLATFORM_ROOT)
        block = rendered[rendered.index(f"name: {name}"):]
        for line in source.splitlines():
            if line.strip().startswith("#") and len(line) > 20:
                assert line.strip() in block, f"{relative}: a comment was lost"
                break


def test_the_recorded_digest_is_the_repository_that_was_pushed(monkeypatch):
    """RepoDigests belongs to an IMAGE ID, not to a name.

    Two repositories built from the same Dockerfile are the same image, so
    `andyur-worker` and a gate's `andyur-exec-input` carry each other's
    digests. The filter was `startswith(registry + "/")` and took the first
    hit, so a real release recorded

        andyur-worker  ->  localhost:5000/andyur-exec-input@sha256:3ca0c1f6...
        andyur-runner  ->  localhost:5000/andyur-exec-tool-call@sha256:7e667b04...

    in release-manifest.json: the release lying about what it built, in the one
    document a deployer pulls from. On the build machine both repositories
    exist so nothing fails; a partner gets a reference to a repository this
    release never published."""
    wanted = "reg.test/andyur-worker@sha256:" + "a" * 64
    other = "reg.test/andyur-exec-input@sha256:" + "b" * 64
    monkeypatch.setattr(br, "run", lambda *a, **k: json.dumps(
        # the sibling repository's digest listed FIRST, as the daemon did
        [other, wanted]) if a[:3] == ("docker", "image", "inspect") else "")
    assert br.push_image("andyur-worker:abc", "reg.test") == wanted


def test_a_push_with_no_digest_for_its_own_repository_is_refused(monkeypatch):
    """Only a sibling's digest present means this push produced nothing
    quotable -- which must not become a recorded reference."""
    monkeypatch.setattr(br, "run", lambda *a, **k: json.dumps(
        ["reg.test/andyur-exec-input@sha256:" + "b" * 64])
        if a[:3] == ("docker", "image", "inspect") else "")
    with pytest.raises(br.ReleaseRefused) as refusal:
        br.push_image("andyur-worker:abc", "reg.test")
    assert "andyur-worker" in str(refusal.value)


def test_two_digests_for_one_repository_are_never_guessed_between(monkeypatch):
    monkeypatch.setattr(br, "run", lambda *a, **k: json.dumps(
        ["reg.test/andyur-worker@sha256:" + "a" * 64,
         "reg.test/andyur-worker@sha256:" + "c" * 64])
        if a[:3] == ("docker", "image", "inspect") else "")
    with pytest.raises(br.ReleaseRefused) as refusal:
        br.push_image("andyur-worker:abc", "reg.test")
    assert "refusing to guess" in str(refusal.value)


def test_every_configmap_the_control_plane_mounts_ships_in_the_bundle():
    """A BUNDLE DEPLOY COULD NOT START THE CONTROL PLANE, and every gate passed.

    The server Pod mounts `andyur-temporal-spiffe-helper`, which only
    temporal.yaml defines, and temporal.yaml was not a companion manifest. A
    missing, non-optional ConfigMap volume holds a Pod in ContainerCreating, so
    a partner running deploy.sh from the bundle got no API at all. The gates
    never saw it because the engine had been applied by hand on the machine
    that ran them.

    Asserted as the general property rather than "temporal.yaml is listed",
    because the next manifest to grow a dependency will not be this one.
    """
    import yaml

    kube = ROOT / "infra" / "kubernetes"
    shipped = ("control-plane.yaml", *br.COMPANION_MANIFESTS)

    defined = set()
    for name in shipped:
        for doc in yaml.safe_load_all((kube / name).read_text()):
            if doc and doc.get("kind") == "ConfigMap":
                defined.add(doc["metadata"]["name"])

    needed = set()
    for doc in yaml.safe_load_all((kube / "control-plane.yaml").read_text()):
        if not doc or doc.get("kind") not in ("StatefulSet", "Deployment"):
            continue
        for vol in doc["spec"]["template"]["spec"].get("volumes", []):
            cm = vol.get("configMap")
            if cm and not cm.get("optional"):
                needed.add(cm["name"])

    missing = sorted(needed - defined)
    assert not missing, (
        f"control-plane.yaml mounts {missing}, which no shipped manifest "
        "defines -- a bundle deploy leaves the Pod in ContainerCreating")


def test_the_engine_is_applied_before_the_control_plane_that_binds_it():
    """Order is the other half: shipped but applied second still leaves the
    server Pod waiting on a volume that does not exist yet."""
    text = (ROOT / "infra" / "rc" / "deploy.sh").read_text()
    apply_block = text[text.index("apply() {"):]
    engine = apply_block.index('"$RENDERED/temporal.yaml"')
    control = apply_block.index('"$RENDERED/control-plane.yaml"')
    assert engine < control, (
        "temporal.yaml is applied after control-plane.yaml, whose server Pod "
        "mounts a ConfigMap temporal.yaml defines")

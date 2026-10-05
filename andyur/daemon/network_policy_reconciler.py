"""Keep the run namespace's containment stamp fresh, by re-proving containment.

THE PROBLEM THIS EXISTS FOR. The worker refuses to start, and refuses to
launch, unless the run namespace carries a NetworkPolicy verification stamp
under 600 seconds old (`kubernetes_api.assert_isolation_ready`). That check is
right: an agent sandbox whose containment was verified once, months ago, on a
cluster whose CNI has since been reconfigured, is not a verified sandbox. But
nothing in a shipped deployment ever renewed the stamp -- only a developer
running `infra/kubernetes/verify-network-policy.sh` from a source checkout did.
So a partner who deployed the bundle got a control plane that came up cleanly
and could never run anything, with a crash-looping worker whose message named
a stamp they had no way to produce. That was the last thing standing between
"the bundle deploys" and "the bundle works".

WHAT IT WILL NOT DO, and this is the entire design. It does not stamp on a
timer. A component that writes "containment verified" because five minutes have
passed has converted a safety property into a decoration, and the worker's
refusal -- which is a good refusal -- into a formality. Every cycle it RUNS A
LIVE PROBE inside the run namespace, under the same isolation a run gets, and
stamps only if every expectation held. When one does not hold it REMOVES the
stamp, so the worker stops launching within one heartbeat rather than after
someone notices.

WHAT THE PROBE ASSERTS, from inside an isolated Pod, against real addresses:

  same-run allow      the agent reaches its own run's proxy         (POSITIVE
                      CONTROL: without it, every deny below could be
                      a broken probe, a missing image, or a Pod that
                      never got a network -- and a probe that cannot
                      distinguish "denied" from "did not run" is the
                      false green this repository keeps finding)
  cross-run deny      the other run's proxy is unreachable
  api deny            the Kubernetes API is unreachable
  internet deny       a public address is unreachable
  metadata deny       169.254.169.254 is unreachable
  collector deny      the OTLP collector is unreachable (ingest is
                      unauthenticated, so an isolated agent must not reach it)
  dns deny            cluster DNS does not resolve for the agent,
                      while it DOES resolve for this reconciler -- the
                      second half being the positive control for the first

WHAT IT DELIBERATELY DOES NOT ASSERT. The release gate
(`verify-network-policy.sh`) also applies an allow-all NetworkPolicy to prove
the probe can go RED, then removes it and proves enforcement returns. That
mutation intentionally breaks containment in a live cluster. It belongs in a
one-off release gate run by a person, not in a loop that runs every five
minutes in somebody's cluster. The gate keeps it; this records that it does
not, in the stamp's own annotations, rather than letting a reader assume the
two proofs are the same proof.

The stamp it writes is exactly what `assert_isolation_ready` reads: the label,
the epoch second, and the namespace UID -- the UID being what stops a stamp
from surviving a namespace that was deleted and recreated underneath it.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import time

log = logging.getLogger("andyur.netpol-reconciler")

# The stamp `kubernetes_api.assert_isolation_ready` reads. Named here from that
# module's constants rather than retyped, because a stamp written under a key
# the reader does not read is the most silent failure this component could have.
LABEL_VERIFIED = "andyur.network-policy/verified"
ANNOTATION_AT = "andyur.network-policy/verified-at"
ANNOTATION_UID = "andyur.network-policy/namespace-uid"
ANNOTATION_BY = "andyur.network-policy/verified-by"
ANNOTATION_CHECKS = "andyur.network-policy/checks"
ANNOTATION_NOT_COVERED = "andyur.network-policy/not-covered"

MAX_STAMP_AGE = 600          # what the worker enforces
# How long the probe waits for its OWN NetworkPolicy to be programmed before it
# reports. Not a fudge factor: a Pod's network exists before the CNI has written
# its rules, and this is the width of that window.
SETTLE_SECONDS = 45
# What the probe Pod prints its result behind. One string, used by the program
# that writes it and the code that reads it, so the two cannot disagree.
MARKER = "ANDYUR_PROBE "
DEFAULT_INTERVAL = 240       # comfortably inside it, twice over
PROBE_TIMEOUT = 180          # one cycle's own budget

NOT_COVERED = ("the allow-all mutation proof (that the probe can go red) is the "
               "release gate's, not this loop's: it breaks containment on "
               "purpose and must not run unattended")

# The battery, run INSIDE the isolated Pod, so what is measured is what an
# agent would experience.
#
# IT DOES NOT MEASURE AT FIRST SIGHT, and that is not a detail. A Pod's network
# exists before the CNI has finished programming the NetworkPolicy rules for it,
# so a probe that runs its checks the instant the container starts measures the
# window BEFORE its own policy is in force -- and reports that an isolated agent
# reached the Kubernetes API, the public internet and cluster DNS. That is
# exactly what happened on the first live cycle: every expectation "failed", the
# stamp was withdrawn, and containment was fine. The release gate has known this
# for longer (`eventually_tcp`, verify-network-policy.sh) and this file had to
# learn it separately.
#
# So it retries until every expectation holds or the deadline passes, and it
# reports BOTH: the settled observation, which is judged, and the FIRST one,
# which is not judged and is kept because "the pod could reach the internet for
# the first four seconds of its life" is a real fact about this cluster and
# hiding it behind a retry loop would be the papering-over this repository keeps
# undoing.
_AGENT_PROGRAM = r"""
import json, os, socket, sys, time

def tcp(host, port):
    if not host:
        return "no-address"
    try:
        socket.create_connection((host, int(port)), 3).close()
        return "allow"
    except OSError:
        return "deny"

def dns():
    socket.setdefaulttimeout(3)
    try:
        socket.getaddrinfo("kubernetes.default.svc", 443)
        return "resolved"
    except OSError:
        return "denied"

def battery():
    return {
        "same_run_allow": tcp(os.environ.get("OWN_PROXY_IP"), 8765),
        "cross_run_deny": tcp(os.environ.get("OTHER_PROXY_IP"), 8765),
        "api_deny": tcp(os.environ.get("API_IP"), 443),
        "internet_deny": tcp("1.1.1.1", 443),
        "metadata_deny": tcp("169.254.169.254", 80),
        "collector_deny": tcp(os.environ.get("COLLECTOR_IP"), 4318),
        "dns_deny": dns(),
    }

expected = json.loads(os.environ["EXPECTED"])
deadline = time.monotonic() + float(os.environ.get("SETTLE_SECONDS", "45"))
attempts, first, observed = 0, None, None
while True:
    attempts += 1
    observed = battery()
    if first is None:
        first = dict(observed)
    if observed == expected or time.monotonic() >= deadline:
        break
    time.sleep(2)
# chr(10), not an escape: this program is carried in a RAW string, so a "\n"
# written here reaches the Pod as backslash-n and the result line ends with two
# stray characters instead of a newline.
sys.stdout.write(MARKER_PLACEHOLDER + json.dumps(
    {"observed": observed, "first_observation": first, "attempts": attempts},
    sort_keys=True) + chr(10))
sys.stdout.flush()
"""

EXPECTED = {
    "same_run_allow": "allow",
    "cross_run_deny": "deny",
    "api_deny": "deny",
    "internet_deny": "deny",
    "metadata_deny": "deny",
    "collector_deny": "deny",
    "dns_deny": "denied",
}

_SECURITY = {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
             "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
             "capabilities": {"drop": ["ALL"]},
             "seccompProfile": {"type": "RuntimeDefault"}}


_AGENT_PROGRAM = _AGENT_PROGRAM.replace("MARKER_PLACEHOLDER", repr(MARKER))


def _pod(name, namespace, image, labels, program, env=None, port=None):
    container = {"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-c", program],
                 "securityContext": dict(_SECURITY),
                 "env": [{"name": k, "value": v} for k, v in sorted((env or {}).items())],
                 "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}
    if port:
        container["ports"] = [{"name": "probe", "containerPort": port}]
        container["readinessProbe"] = {"tcpSocket": {"port": "probe"},
                                       "periodSeconds": 1, "timeoutSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace, "labels": dict(labels)},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                     "terminationGracePeriodSeconds": 1,
                     "securityContext": {"runAsNonRoot": True,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container],
                     "volumes": [{"name": "tmp", "emptyDir": {}}]}}


def _policy(name, namespace, run, prefix):
    """The isolation an actual run gets: talk to your own proxy, nothing else."""
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace,
                         "labels": {"andyur.probe/id": prefix}},
            "spec": {"podSelector": {"matchLabels": {"andyur.probe/run": run}},
                     "policyTypes": ["Ingress", "Egress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": {
                         "andyur.probe/run": run, "andyur.probe/role": "agent"}}}],
                         "ports": [{"protocol": "TCP", "port": 8765}]}],
                     "egress": [{"to": [{"podSelector": {"matchLabels": {
                         "andyur.probe/run": run, "andyur.probe/role": "proxy"}}}],
                         "ports": [{"protocol": "TCP", "port": 8765}]}]}}


class Reconciler:
    """One cycle: probe, then stamp or unstamp. Everything it creates, it deletes.

    The Kubernetes client is injected so this is testable without a cluster and
    so the component holds exactly the API surface its Role grants.
    """

    def __init__(self, core, networking, runs_namespace: str, system_namespace: str,
                 image: str, clock=time.time):
        self.core = core
        self.networking = networking
        self.runs_namespace = runs_namespace
        self.system_namespace = system_namespace
        self.image = image
        self.clock = clock

    # -- the probe ---------------------------------------------------------
    def _delete_probe(self, prefix: str) -> None:
        """Best effort, and ALWAYS attempted. A probe Pod left behind is a Pod
        in the run namespace that no run owns, which is exactly what the
        workload gates check for and report as a reaper defect."""
        selector = f"andyur.probe/id={prefix}"
        for namespace in (self.runs_namespace,):
            try:
                self.core.delete_collection_namespaced_pod(
                    namespace, label_selector=selector, grace_period_seconds=0)
            except Exception as exc:                      # noqa: BLE001
                log.warning("could not delete probe pods (%s): %s", prefix, exc)
            try:
                self.networking.delete_collection_namespaced_network_policy(
                    namespace, label_selector=selector)
            except Exception as exc:                      # noqa: BLE001
                log.warning("could not delete probe policies (%s): %s", prefix, exc)

    def _wait(self, namespace: str, name: str, want, deadline: float):
        while self.clock() < deadline:
            pod = self.core.read_namespaced_pod(name, namespace)
            if want(pod):
                return pod
            time.sleep(1)
        raise TimeoutError(f"pod {namespace}/{name} did not reach the expected state")

    @staticmethod
    def _ready(pod) -> bool:
        return any(c.type == "Ready" and c.status == "True"
                   for c in (pod.status.conditions or []))

    @staticmethod
    def _finished(pod) -> bool:
        return pod.status.phase in ("Succeeded", "Failed")

    def _service_ip(self, namespace: str, name: str) -> str:
        try:
            return self.core.read_namespaced_service(name, namespace).spec.cluster_ip or ""
        except Exception:                                 # noqa: BLE001
            return ""

    def probe(self) -> dict:
        """Run the battery once. Returns the observations, never raises for a
        failed EXPECTATION -- only for a probe that could not be run at all,
        which is a different thing and is reported as such."""
        prefix = "netpol-probe-" + secrets.token_hex(4)
        deadline = self.clock() + PROBE_TIMEOUT
        server = ("import http.server;http.server.ThreadingHTTPServer("
                  "('0.0.0.0',8765),http.server.SimpleHTTPRequestHandler)"
                  ".serve_forever()")
        try:
            for run in ("a", "b"):
                self.networking.create_namespaced_network_policy(
                    self.runs_namespace, _policy(f"{prefix}-{run}", self.runs_namespace, run, prefix))
                self.core.create_namespaced_pod(self.runs_namespace, _pod(
                    f"{prefix}-{run}-proxy", self.runs_namespace, self.image,
                    {"andyur.probe/id": prefix, "andyur.probe/run": run,
                     "andyur.probe/role": "proxy"}, server, port=8765))
            ips = {}
            for run in ("a", "b"):
                pod = self._wait(self.runs_namespace, f"{prefix}-{run}-proxy",
                                 self._ready, deadline)
                ips[run] = pod.status.pod_ip

            # THE AGENT CARRIES THE ADDRESSES IN. It has no DNS -- that is one of
            # the things under test -- so every target must be an address
            # resolved out here, by something that still has a network.
            env = {"OWN_PROXY_IP": ips["a"] or "", "OTHER_PROXY_IP": ips["b"] or "",
                   "API_IP": self._service_ip("default", "kubernetes"),
                   "COLLECTOR_IP": self._service_ip(self.system_namespace, "otel-collector")}
            # The expectations are sent IN so the Pod knows when it has settled.
            # Judging still happens out here: the Pod reports what it saw, and
            # is not the thing that decides whether that is acceptable.
            settle = {"EXPECTED": json.dumps(EXPECTED, sort_keys=True),
                      "SETTLE_SECONDS": str(SETTLE_SECONDS)}
            missing = [k for k, v in env.items() if not v]
            if missing:
                return {"error": "could not resolve probe targets: " + ", ".join(sorted(missing))}
            self.core.create_namespaced_pod(self.runs_namespace, _pod(
                f"{prefix}-a-agent", self.runs_namespace, self.image,
                {"andyur.probe/id": prefix, "andyur.probe/run": "a",
                 "andyur.probe/role": "agent"}, _AGENT_PROGRAM, env={**env, **settle}))
            pod = self._wait(self.runs_namespace, f"{prefix}-a-agent", self._finished, deadline)
            # THE LOG IS NOT READ AT FIRST SIGHT EITHER. A Pod reaching a
            # terminal phase does not mean its last line has been collected, and
            # "the probe Pod produced no result line" is indistinguishable from
            # a probe that genuinely printed nothing.
            # NEITHER LINE BOUNDARIES NOR WHAT FOLLOWS. `splitlines()` plus
            # `json.loads` needed the result to be a whole line with nothing
            # after it, and any deviation -- a stray character at the end, a
            # log the API returned as one blob -- came back as "the probe Pod
            # produced no result line", which is a claim about the PROBE and
            # was false. The marker is found wherever it is, and exactly one
            # JSON value is decoded from it; anything after it is not our
            # business.
            logs = ""
            decoder = json.JSONDecoder()
            for _ in range(15):
                logs = self.core.read_namespaced_pod_log(f"{prefix}-a-agent",
                                                         self.runs_namespace)
                at = logs.find(MARKER)
                if at >= 0:
                    try:
                        return decoder.raw_decode(logs, at + len(MARKER))[0]
                    except ValueError as exc:
                        return {"error": f"the probe Pod's result line is not "
                                         f"JSON ({exc}): {logs[at:at + 200]!r}"}
                time.sleep(1)
            return {"error": f"the probe Pod ({pod.status.phase}) printed no "
                             f"{MARKER.strip()!r} marker; its output began "
                             f"{logs[:200]!r} and ended {logs[-200:]!r}"}
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            self._delete_probe(prefix)

    # -- the stamp ---------------------------------------------------------
    def stamp(self, observed: dict) -> None:
        namespace = self.core.read_namespace(self.runs_namespace)
        at = int(self.clock())
        self.core.patch_namespace(self.runs_namespace, {"metadata": {
            "labels": {LABEL_VERIFIED: "true"},
            "annotations": {
                ANNOTATION_AT: str(at),
                ANNOTATION_UID: namespace.metadata.uid,
                ANNOTATION_BY: "andyur-netpol-reconciler",
                # WHAT WAS ACTUALLY CHECKED, on the stamp itself. A stamp that
                # says only "verified" cannot be told apart from a stamp
                # somebody wrote by hand, and the two mean different things.
                ANNOTATION_CHECKS: json.dumps(observed, sort_keys=True),
                ANNOTATION_NOT_COVERED: NOT_COVERED,
            }}})
        log.info("containment re-proved; stamped %s at %d", self.runs_namespace, at)

    def unstamp(self, why: str) -> None:
        """Remove the stamp so the worker stops launching. An empty-string
        label value is not absence -- `assert_isolation_ready` compares against
        'true', so anything else refuses -- but the key is set to null so the
        namespace does not carry a stale claim at all."""
        self.core.patch_namespace(self.runs_namespace, {"metadata": {
            "labels": {LABEL_VERIFIED: None},
            "annotations": {ANNOTATION_AT: None, ANNOTATION_UID: None,
                            ANNOTATION_CHECKS: json.dumps({"withdrawn": why})}}})
        log.error("containment NOT proved (%s); withdrew the stamp on %s -- "
                  "the worker will refuse to launch until it is re-proved",
                  why, self.runs_namespace)

    def cycle(self) -> bool:
        """One probe and its consequence. True when the namespace is stamped."""
        result = self.probe()
        if result.get("error"):
            self.unstamp(result["error"])
            return False
        observed = result["observed"]
        # NOT JUDGED, KEPT. What the Pod saw before its own policy was in force
        # is a real property of this cluster's CNI, and the settle loop would
        # otherwise erase it.
        observed = dict(observed)
        observed["_first_observation"] = result.get("first_observation")
        observed["_settled_after_attempts"] = result.get("attempts")
        # THE POSITIVE CONTROL IS CHECKED FIRST AND BY NAME. If the agent could
        # not reach its own proxy, every other line reading "deny" is
        # uninformative, and stamping on it would be recording a probe's own
        # failure as a security property.
        if observed.get("same_run_allow") != "allow":
            self.unstamp("the positive control failed: the probe could not reach "
                         "its own run's proxy, so its denials mean nothing")
            return False
        # Only the closed set of expectations is judged; the two underscore keys
        # beside them are the record of the startup window, not claims.
        wrong = {k: observed.get(k) for k, want in EXPECTED.items()
                 if observed.get(k) != want}
        if wrong:
            self.unstamp("containment expectations not met: "
                         + json.dumps(wrong, sort_keys=True))
            return False
        self.stamp(observed)
        return True


def _dns_works_here() -> bool:
    """The positive control for `dns_deny`, from OUTSIDE the run namespace.
    'The agent could not resolve' is only evidence of isolation if resolution
    works for something that is not isolated."""
    socket.setdefaulttimeout(3)
    try:
        socket.getaddrinfo("kubernetes.default.svc", 443)
        return True
    except OSError:
        return False


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    from kubernetes import client, config

    config.load_incluster_config()
    core = client.CoreV1Api()
    networking = client.NetworkingV1Api()
    runs_ns = os.environ.get("ANDYUR_KUBERNETES_NAMESPACE", "andyur-runs")
    system_ns = os.environ.get("ANDYUR_KUBERNETES_SYSTEM_NAMESPACE", "andyur-system")
    image = os.environ.get("ANDYUR_PROBE_IMAGE", "")
    interval = int(os.environ.get("ANDYUR_NETPOL_INTERVAL", DEFAULT_INTERVAL))
    if not image:
        log.error("ANDYUR_PROBE_IMAGE is unset: the probe must run a digest-pinned "
                  "image this cluster already has, and there is no safe default")
        return 2
    if interval >= MAX_STAMP_AGE:
        log.error("ANDYUR_NETPOL_INTERVAL=%ds is not shorter than the %ds the "
                  "worker enforces, so the stamp would expire between cycles",
                  interval, MAX_STAMP_AGE)
        return 2
    if not _dns_works_here():
        log.warning("cluster DNS does not resolve for this Pod either, so the "
                    "agent's DNS denial is not evidence of isolation this cycle")

    reconciler = Reconciler(core, networking, runs_ns, system_ns, image)
    while True:
        started = time.time()
        try:
            reconciler.cycle()
        except Exception:                                 # noqa: BLE001
            log.exception("the reconcile cycle raised; the stamp will expire on "
                          "its own if this continues")
        time.sleep(max(5.0, interval - (time.time() - started)))


if __name__ == "__main__":
    raise SystemExit(main())

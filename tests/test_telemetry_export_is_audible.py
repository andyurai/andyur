"""A signal is never exported to a backend that cannot receive it, and an
export that fails is never silent.

production-gaps 35. The dev stack pointed every component straight at Jaeger --
a TRACE backend, which serves /v1/traces and 404s /v1/metrics -- so every
metric the platform emitted locally was discarded. It said nothing, because
`try_record_metric` is designed never to change the operation it observes and
the export happens asynchronously afterwards.

(The collector ALSO exports metrics to that same trace backend, which fails the
same way in the cluster. That is row 37 and is deliberately not fixed here; see
the test below for why.)

`telemetry.export.failed` had been a DECLARED event with a field schema since
observability.py was written, and nothing had ever emitted it. That is the part
that let this last: a working exporter and one shouting into a wall look
identical from inside the process.
"""
import logging
import time

import pytest
import yaml

from andyur import observability, otel
from andyur.config import PROJECT_ROOT

COLLECTOR = PROJECT_ROOT / "infra" / "observability" / "otel-collector.yaml"
JAEGER = PROJECT_ROOT / "infra" / "observability" / "jaeger.yaml"
COMPOSE = PROJECT_ROOT / "infra" / "docker-compose.yml"


class _Result:
    def __init__(self, name):
        self.name = name


class _Backend:
    """An exporter that answers however the test tells it to."""

    def __init__(self, name="FAILURE"):
        self.result, self.calls = name, 0

    def export(self, *a, **k):
        self.calls += 1
        return _Result(self.result)


@pytest.fixture(autouse=True)
def _forget_complaints():
    otel._last_complaint.clear()
    yield
    otel._last_complaint.clear()


def _events(caplog):
    return [r for r in caplog.records
            if getattr(r, "event_name", "") == "telemetry.export.failed"]


def test_a_failing_export_says_so_by_name(caplog):
    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        assert otel._Audible(_Backend("FAILURE"), "metrics").export([]).name == "FAILURE"
    [event] = _events(caplog)
    # the DECLARED event, with the schema observability.py validates
    assert event.event_fields == {"signal": "metrics", "reason": "unavailable"}
    assert "reason" in observability._EVENT_FIELDS["telemetry.export.failed"]


def test_a_SUCCESSFUL_export_says_nothing(caplog):
    # The positive control. Without it, an implementation that complained on
    # every export would pass the test above.
    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        assert otel._Audible(_Backend("SUCCESS"), "metrics").export([]).name == "SUCCESS"
    assert _events(caplog) == []


def test_an_exporter_that_raises_still_says_so_and_still_raises(caplog):
    class _Raises:
        def export(self, *a, **k):
            raise ConnectionRefusedError("nothing is listening")

    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        with pytest.raises(ConnectionRefusedError):
            otel._Audible(_Raises(), "traces").export([])
    [event] = _events(caplog)
    assert event.event_fields["signal"] == "traces"


def test_the_complaint_is_throttled_per_signal(caplog, monkeypatch):
    """An exporter that cannot reach its backend fails EVERY batch.

    Unthrottled, saying so is a log flood -- which is its own way of being
    unreadable. One line a minute per signal.
    """
    exporter = otel._Audible(_Backend("FAILURE"), "metrics")
    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        for _ in range(50):
            exporter.export([])
    assert len(_events(caplog)) == 1, "the complaint is not throttled"

    # ...and it complains again once the window passes, or a backend that comes
    # back and fails again later would be silent forever
    caplog.clear()
    monkeypatch.setattr(otel, "_last_complaint",
                        {"metrics": time.monotonic() - otel._EXPORT_COMPLAINT_SECONDS - 1})
    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        exporter.export([])
    assert len(_events(caplog)) == 1

    # a DIFFERENT signal is throttled independently: traces failing must not
    # mask metrics failing
    caplog.clear()
    otel._last_complaint.clear()
    with caplog.at_level(logging.WARNING, logger="andyur.otel"):
        otel._Audible(_Backend("FAILURE"), "metrics").export([])
        otel._Audible(_Backend("FAILURE"), "traces").export([])
    assert {e.event_fields["signal"] for e in _events(caplog)} == {"metrics", "traces"}


def test_reporting_a_failure_never_becomes_the_failure(caplog, monkeypatch):
    # Telemetry must not change the operation it observes, and that includes
    # the code that reports telemetry being broken.
    def boom(*a, **k):
        raise RuntimeError("the logger is also broken")

    monkeypatch.setattr(observability, "event", boom)
    assert otel._Audible(_Backend("FAILURE"), "metrics").export([]).name == "FAILURE"


# --- the configuration half: nothing points a signal at the wrong backend ----

def test_metrics_have_somewhere_to_land_that_can_actually_receive_them():
    """Readable is the property; the Prometheus leg is what provides it.

    The collector ALSO exports metrics to `otlp_http/backend`, which is Jaeger,
    which declares a traces-only pipeline -- so that leg 404s every batch,
    forever, in the cluster as well as on a laptop. That is production-gaps 37
    and it is deliberately NOT fixed here: three shipped live-gate evidence
    artifacts bind this file by sha256, so the one-line change and the re-run
    of those gates belong in the same cluster session. What this asserts is the
    half that keeps metrics readable meanwhile.
    """
    collector = yaml.safe_load(COLLECTOR.read_text())
    jaeger = yaml.safe_load(JAEGER.read_text())

    # the backend really is traces-only, which is what makes row 37 a bug
    assert set(jaeger["service"]["pipelines"]) == {"traces"}

    metrics_exporters = collector["service"]["pipelines"]["metrics"]["exporters"]
    assert "prometheus" in metrics_exporters, "metrics have nowhere to land"
    assert "otlp_http/backend" in collector["service"]["pipelines"]["traces"]["exporters"]


def test_the_dev_stack_runs_the_same_collector_the_cluster_runs():
    """A laptop that is not the deployed architecture cannot verify it.

    The compose file pointed every component straight at Jaeger while
    jaeger.yaml's own header described itself as sitting BEHIND the collector.
    """
    compose = yaml.safe_load(COMPOSE.read_text())
    services = compose["services"]
    assert "otel-collector" in services, "the dev stack does not run a collector"
    collector, jaeger = services["otel-collector"], services["jaeger"]

    # it is not optional: same (absent) profile as jaeger, so `./run.sh jaeger`
    # brings it up
    assert collector.get("profiles") == jaeger.get("profiles") is None

    # the collector owns OTLP ingest; jaeger publishes only its UI/query API
    published = [p.split(":")[-1] for p in collector["ports"]]
    assert {"4317", "4318", "9464"} <= set(published)
    assert not any(p.endswith((":4317", ":4318")) for p in jaeger["ports"]), \
        "jaeger is still taking OTLP directly, so the collector is bypassed"

    # the SAME image the cluster pins, by digest
    k8s = (PROJECT_ROOT / "infra" / "kubernetes" / "observability.yaml").read_text()
    digest = collector["image"].split("@", 1)[1]
    assert digest in k8s, "the dev collector is a different build from the cluster's"


def test_scraped_engine_metrics_do_not_collide_with_the_exporters_own_label():
    """EVERY TEMPORAL METRIC WAS DROPPED, and it was reported as working.

    Temporal labels its series `service_name`; the Prometheus exporter's
    `resource_to_telemetry_conversion` adds a second `service_name` from the
    resource, and the exporter refuses the duplicate. The export held the
    scrape's bookkeeping and not one engine metric -- confirmed live, zero
    persistence or task-queue series out of ~7,000 scraped. It passed review as
    "scraped end to end", because the samples WERE scraped.

    Asserted as the property the exporter needs rather than as "a relabel
    exists": if the exporter adds `service_name`, then no scrape job whose
    target labels its own `service_name` may let that label through.
    """
    cfg = yaml.safe_load(COLLECTOR.read_text())
    adds_service_name = (cfg["exporters"]["prometheus"]
                         .get("resource_to_telemetry_conversion", {})
                         .get("enabled", False))
    if not adds_service_name:
        pytest.skip("the exporter does not add service_name; no collision possible")

    jobs = cfg["receivers"]["prometheus"]["config"]["scrape_configs"]
    temporal = next(j for j in jobs if j["job_name"] == "andyur-temporal")
    relabels = temporal.get("metric_relabel_configs", [])

    # APPLIED, IN ORDER, to a series as Temporal emits it. Checking that a
    # rename and a drop both exist passed with the drop FIRST, which loses the
    # label before it is copied: the order is the behaviour.
    import re

    labels = {"__name__": "service_requests", "service_name": "frontend",
              "operation": "StartWorkflowExecution"}
    for rule in relabels:
        action = rule.get("action", "replace")
        regex = re.compile("^(?:" + rule.get("regex", "(.*)") + ")$")
        if action == "replace":
            value = rule.get("separator", ";").join(
                labels.get(l, "") for l in rule.get("source_labels", []))
            m = regex.match(value)
            if m:
                out = m.expand(rule.get("replacement", "$1").replace("$", "\\"))
                if out:
                    labels[rule["target_label"]] = out
                else:
                    labels.pop(rule["target_label"], None)
        elif action == "labeldrop":
            labels = {k: v for k, v in labels.items() if not regex.match(k)}
        else:
            pytest.fail(f"a relabel action this test cannot evaluate: {action}")

    assert "service_name" not in labels, (
        "Temporal's own `service_name` reaches an exporter that adds another, "
        "and every such series is dropped")
    assert "frontend" in labels.values(), (
        f"the service is no longer on the series ({labels}), so an operator can "
        "no longer tell frontend from history")

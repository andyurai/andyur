#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The SAME digests infra/kubernetes/observability.yaml deploys (tests pin both).
COLLECTOR_IMAGE="docker.io/otel/opentelemetry-collector-contrib@sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc"
JAEGER_IMAGE="cr.jaegertracing.io/jaegertracing/jaeger@sha256:46a886260e04002d8f45e213fc39063fa11a50446048fdaa64786fc0840cb9f8"
PROMETHEUS_IMAGE="prom/prometheus@sha256:332c2f43e7e389d74d3893b55bb02fbbd684208e681eeb604641d5d769c0fe2a"

docker run --rm \
  -e ANDYUR_TELEMETRY_BACKEND_OTLP_ENDPOINT=http://127.0.0.1:4318 \
  -v "$ROOT/infra/observability/otel-collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  "$COLLECTOR_IMAGE" validate --config=/etc/otelcol-contrib/config.yaml

docker run --rm \
  -v "$ROOT/infra/observability/jaeger.yaml:/etc/jaeger/config.yaml:ro" \
  "$JAEGER_IMAGE" validate --config=/etc/jaeger/config.yaml

docker run --rm \
  -v "$ROOT/infra/observability/prometheus-alerts.yaml:/rules.yaml:ro" \
  --entrypoint=promtool "$PROMETHEUS_IMAGE" check rules /rules.yaml

#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
container="${ANDYUR_CURITY_CONTAINER:-confident_jackson}"
plugin="$here/plugin"
artifacts="$plugin/target/plugin"

docker run --rm -v "$plugin:/workspace" -w /workspace \
  maven:3.9.11-eclipse-temurin-21 mvn -q clean package
docker exec "$container" mkdir -p \
  /opt/idsvr/lib/plugins/andyur-spiffe-actor-token-exchange
docker exec "$container" find \
  /opt/idsvr/lib/plugins/andyur-spiffe-actor-token-exchange \
  -maxdepth 1 -type f -name '*.jar' -delete
for artifact in "$artifacts"/*.jar; do
  docker cp "$artifact" \
    "$container:/opt/idsvr/lib/plugins/andyur-spiffe-actor-token-exchange/"
done
docker restart "$container" >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS \
    http://127.0.0.1:8443/oauth/v2/oauth-anonymous/.well-known/openid-configuration \
    >/dev/null 2>&1; then
    cd "$root"
    export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
    exec "${PYTHON:-python3}" infra/curity/verify-single-exchange.py
  fi
  sleep 1
done

echo "Curity did not become ready after plugin installation" >&2
exit 1

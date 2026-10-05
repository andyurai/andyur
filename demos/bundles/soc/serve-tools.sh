#!/usr/bin/env bash
# Put the SOC bundle's tool servers behind SPIFFE TLS, for the Docker deployment.
#
# WHY ANY OF THIS IS NEEDED. Under ANDYUR_PROFILE=prod the runner refuses a
# plaintext http reach_url, because the sidecar attaches the run's delegated
# token to that hop. And it will not accept just any https either: it verifies
# the tool server against the SPIFFE TRUST BUNDLE with check_hostname off, so
# the server must present an X509-SVID from the same SPIRE. `osv-mcp` is a Go
# binary with no TLS and no SPIFFE, so `tls_front.py` holds the SVID for it.
#
#   ./serve-tools.sh up     register the SPIFFE ID and start the front
#   ./serve-tools.sh down    stop it and remove the registration
#
# The upstream (osv-mcp) runs wherever you like as long as the front can reach
# it; by default that is the host, on 8810.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

SPIRE_CONTAINER="${ANDYUR_SPIRE_SERVER_CONTAINER:-andyur-spire-server}"
SOCKET_VOLUME="${ANDYUR_SPIRE_SOCKET_VOLUME:-andyur-spire-sockets}"
NETWORK="${ANDYUR_TOOL_NETWORK:-andyur-control}"
# andyur-server, not andyur-worker: the worker image ships starlette and httpx
# but no uvicorn (it runs no HTTP server of its own), and this front does.
IMAGE="${ANDYUR_TOOL_IMAGE:-andyur-server}"
NAME="andyur-soc-tls-front"
# TWO SPELLINGS OF THE SAME LABEL, and they are not interchangeable: docker
# takes key=value, a SPIRE docker selector takes key:value. Writing the SPIRE
# form into `docker run --label` sets a KEY with no value, the selector then
# matches nothing, and the workload waits for an SVID that never comes --
# "Timeout waiting for the first update", which names neither the label nor
# the cause.
LABEL_KEY="andyur.role"
LABEL_VALUE="soc-tool"
SPIFFE_ID="spiffe://andyur.local/soc-tool"
PORT="${ANDYUR_SOC_TLS_PORT:-8443}"
UPSTREAM="${ANDYUR_SOC_UPSTREAM:-http://host.docker.internal:8810/mcp}"
RUN_NETWORK="${ANDYUR_SANDBOX_NETWORK:-andyur-runs}"
MODEL_NAME="andyur-soc-model-front"
TOOL_ALIAS="${ANDYUR_SOC_TOOL_ALIAS:-soc-osv}"
SOCAT_IMAGE="${ANDYUR_SOCAT_IMAGE:-alpine/socat}"

spire() { docker exec "$SPIRE_CONTAINER" /opt/spire/bin/spire-server "$@"; }

case "${1:-up}" in
up)
  docker inspect "$SPIRE_CONTAINER" >/dev/null 2>&1 || {
    echo "no $SPIRE_CONTAINER: bring the deployment up first (./run.sh docker-up)" >&2
    exit 1
  }

  # Delete first so a changed selector or parent is repaired rather than
  # duplicated -- the same reason docker-stack.sh's `entry` does it.
  existing="$(spire entry show -spiffeID "$SPIFFE_ID" -output json 2>/dev/null \
    | python3 -c 'import json,sys; [print(e["id"]) for e in json.load(sys.stdin).get("entries",[])]' 2>/dev/null || true)"
  for id in $existing; do spire entry delete -entryID "$id" >/dev/null; done

  spire entry create \
    -parentID "spiffe://andyur.local/agent/node" \
    -spiffeID "$SPIFFE_ID" \
    -selector "docker:label:${LABEL_KEY}:${LABEL_VALUE}" \
    -x509SVIDTTL 3600 >/dev/null
  echo "registered $SPIFFE_ID"

  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # ON THE RUN NETWORK, under a name the sidecar can resolve. The sidecar makes
  # the tool calls and it lives on the INTERNAL run network -- so a tool server
  # reachable only via host.docker.internal is withheld: "no declared tool
  # server is reachable". Same lesson as the model: everything a confined run
  # touches has to be ON its network, addressed by name.
  docker run -d --name "$NAME" \
    --label "${LABEL_KEY}=${LABEL_VALUE}" \
    --network "$RUN_NETWORK" --network-alias "$TOOL_ALIAS" \
    -v "$SOCKET_VOLUME:/run/spire/sockets:ro" \
    -v "$HERE/tls_front.py:/app/tls_front.py:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_DATA_DIR=/tmp/andyur \
    -e PYTHONUNBUFFERED=1 \
    -p "127.0.0.1:$PORT:$PORT" \
    --entrypoint python \
    "$IMAGE" /app/tls_front.py --upstream "$UPSTREAM" --port "$PORT" \
    --role soc-tool >/dev/null
  docker network connect "$NETWORK" "$NAME" >/dev/null 2>&1 || true
  echo "started $NAME as https://$TOOL_ALIAS:$PORT (on the run network) -> $UPSTREAM"

  # A MODEL THE RUN CAN ACTUALLY REACH.
  #
  # Runs live on `andyur-runs`, created --internal: no route to the host, which
  # is the containment doing its job. So Ollama on your laptop is unreachable
  # from a run however it is addressed, and `_container_url` correctly refuses
  # to rewrite host URLs under the prod profile rather than manufacture an
  # address that cannot resolve.
  #
  # The compose default already names the answer: `http://ollama:11434`, a
  # service ON that network. This publishes one, as a plain TCP forwarder to
  # the Ollama you already run -- so the models you have pulled are the models
  # the run uses, instead of a second multi-gigabyte copy in a container.
  #
  # It sits on BOTH networks on purpose: it needs the host to forward to, and
  # the run network to be reachable from. The RUN gains no egress -- it can
  # reach this name and nothing beyond it.
  docker rm -f "$MODEL_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$MODEL_NAME" \
    --network "$RUN_NETWORK" --network-alias ollama \
    "$SOCAT_IMAGE" TCP-LISTEN:11434,fork,reuseaddr "TCP:host.docker.internal:11434" >/dev/null
  docker network connect "$NETWORK" "$MODEL_NAME" >/dev/null 2>&1 || true
  echo "started $MODEL_NAME: runs resolve ollama:11434 -> your host's Ollama"
  echo
  echo "the bundle's reach_url should be:"
  echo "  https://$TOOL_ALIAS:$PORT/mcp"
  ;;
down)
  docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || true
  docker rm -f "$MODEL_NAME" >/dev/null 2>&1 && echo "stopped $MODEL_NAME" || true
  existing="$(spire entry show -spiffeID "$SPIFFE_ID" -output json 2>/dev/null \
    | python3 -c 'import json,sys; [print(e["id"]) for e in json.load(sys.stdin).get("entries",[])]' 2>/dev/null || true)"
  for id in $existing; do spire entry delete -entryID "$id" >/dev/null; done
  [ -n "$existing" ] && echo "removed $SPIFFE_ID" || true
  ;;
*)
  echo "usage: $0 {up|down}" >&2
  exit 1
  ;;
esac

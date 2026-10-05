#!/bin/sh
# Entrypoint for the containerized Andyur control-plane server.
#
# With ANDYUR_MTLS=on it runs as a SPIFFE workload behind mutual TLS: it exports
# its X509-SVID (fetched from the SPIRE agent it is attested to) and starts uvicorn
# requiring + verifying client certificates against the trust bundle. Runners then
# reach it only over mutually-authenticated TLS. Off, it serves plain HTTP (the
# Slice 4 shape). Mirrors the `./run.sh server` mTLS logic for the container.
set -e

SSL_FLAGS=""
case "${ANDYUR_MTLS:-off}" in
  1|on|true|ON|True)
    # export this process's SPIFFE X509-SVID + trust bundle to PEMs (bounded by
    # ANDYUR_SVID_TIMEOUT, so an un-propagated entry fails fast, not a hang)
    python -c "from andyur import identity; identity.export_tls_pems('server')"
    TLS="${ANDYUR_DATA_DIR:-/app/data}/tls/server"
    # --ssl-cert-reqs 2 = ssl.CERT_REQUIRED: require AND verify a client cert
    # chaining to the bundle, so only trust-domain members can connect
    SSL_FLAGS="--ssl-certfile $TLS/cert.pem --ssl-keyfile $TLS/key.pem \
      --ssl-ca-certs $TLS/bundle.pem --ssl-cert-reqs 2"
    echo "[server] mTLS on: requiring client X509-SVIDs"
    ;;
esac

exec uvicorn andyur.server.app:app \
  --host "${ANDYUR_HOST:-0.0.0.0}" --port "${ANDYUR_PORT:-8642}" $SSL_FLAGS

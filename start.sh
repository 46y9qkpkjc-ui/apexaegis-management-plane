#!/usr/bin/env bash
set -euo pipefail

# If PGSSLROOTCERT_CONTENT is provided (Railway secret), write it to disk
if [[ -n "${PGSSLROOTCERT_CONTENT:-}" ]]; then
  mkdir -p /etc/ssl/certs
  printf '%s\n' "$PGSSLROOTCERT_CONTENT" > /etc/ssl/certs/root.crt
  export PGSSLROOTCERT=/etc/ssl/certs/root.crt
fi

# If a host-mounted or injected cert is present, prefer it
if [[ -z "${PGSSLROOTCERT:-}" && -f "/etc/ssl/certs/root.crt" ]]; then
  export PGSSLROOTCERT=/etc/ssl/certs/root.crt
fi

# Ensure LISTEN_ADDR uses PORT if provided (Railway sets PORT)
export LISTEN_ADDR="${LISTEN_ADDR:-:${PORT:-8080}}"

echo "Starting management-plane..."
echo "  LISTEN_ADDR: $LISTEN_ADDR"
echo "  DEPLOY_MODE: ${DEPLOY_MODE:-cloud}"

# Migrations run automatically inside the binary via dbConn.Migrate() on startup
exec /usr/local/bin/management-plane

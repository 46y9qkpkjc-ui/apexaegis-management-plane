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

echo "Starting management-plane: will run migrations then start server"

# Run migrations (idempotent)
if [[ -x "/usr/local/bin/migrate-db.sh" ]]; then
  /usr/local/bin/migrate-db.sh || {
    echo "Migration failed" >&2
    exit 1
  }
fi

exec /usr/local/bin/management-plane

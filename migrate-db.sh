#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PGSSLROOTCERT="${PGSSLROOTCERT:-$HOME/.postgresql/root.crt}"
if [[ ! -f "$PGSSLROOTCERT" ]]; then
  echo "ERROR: PGSSLROOTCERT not found: $PGSSLROOTCERT"
  exit 1
fi

export PGSSLROOTCERT

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL is required. Set it before running this script."
  echo "Example: export DATABASE_URL='postgresql://user:pass@host:26257/apexaegis?sslmode=verify-full'"
  exit 1
fi

exec go run ./cmd/dbmigrate

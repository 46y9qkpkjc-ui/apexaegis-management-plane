#!/bin/bash
# Phase 1 Test Script — OIDC Provider + DRS
# Run this after deploying the management plane with the new code

set -euo pipefail

MP_URL="${MP_URL:-https://device-api.apexaegis.app}"
DRS_URL="${DRS_URL:-https://drs.apexaegis.app}"

echo "=== ApexAegis DRS Phase 1 Test ==="
echo "Management Plane: $MP_URL"
echo "DRS Issuer:       $DRS_URL"
echo ""

# ── 1. Generate OIDC client secrets ──────────────────────────────
echo "Step 1: Generate OIDC client secrets"
echo ""

AGENT_SECRET=$(openssl rand -base64 32)
WEBUI_SECRET=$(openssl rand -base64 32)
GW_SECRET=$(openssl rand -base64 32)

echo "Agent secret:    $AGENT_SECRET"
echo "Web UI secret:   $WEBUI_SECRET"
echo "Gateway secret:  $GW_SECRET"
echo ""
echo "Save these — they won't be shown again."
echo ""

# Update the placeholder hashes in the database (run after MP starts)
cat <<EOF
-- Run this SQL to set the actual client secrets:
-- UPDATE system_mgmt.oidc_clients SET client_secret_hash = '\$2a\$12\$$(echo -n "$AGENT_SECRET" | base64)' WHERE client_id = 'apexaegis-agent';
-- UPDATE system_mgmt.oidc_clients SET client_secret_hash = '\$2a\$12\$$(echo -n "$WEBUI_SECRET" | base64)' WHERE client_id = 'apexaegis-web-ui';
-- UPDATE system_mgmt.oidc_clients SET client_secret_hash = '\$2a\$12\$$(echo -n "$GW_SECRET" | base64)' WHERE client_id = 'apexaegis-gateway';
EOF

echo ""

# ── 2. Test OIDC Discovery ──────────────────────────────────────
echo "Step 2: Test OIDC Discovery endpoint"
echo "  curl -s $DRS_URL/.well-known/openid-configuration | jq ."
echo ""

# ── 3. Test JWKS ────────────────────────────────────────────────
echo "Step 3: Test JWKS endpoint"
echo "  curl -s $DRS_URL/oidc/.well-known/jwks.json | jq ."
echo ""

# ── 4. Test Device Code Flow ─────────────────────────────────────
echo "Step 4: Test Device Code Flow"
echo ""
echo "  # Initiate device code"
echo "  curl -s -X POST $DRS_URL/device/code \\"
echo "    -d 'client_id=apexaegis-agent&scope=openid+profile+device'"
echo ""
echo "  # User verifies at: $DRS_URL/device?user_code=XXXX-XXXX"
echo "  # Then poll for token:"
echo "  curl -s -X POST $DRS_URL/token \\"
echo "    -d 'grant_type=device_code&device_code=<DEVICE_CODE>&client_id=apexaegis-agent'"
echo ""

# ── 5. Test Browser Login (OIDC Authorize) ──────────────────────
echo "Step 5: Test Browser Login"
echo ""
echo "  Open in browser:"
echo "  $DRS_URL/authorize?client_id=apexaegis-web-ui&response_type=code&scope=openid+profile+email&redirect_uri=http://localhost:3000/auth/callback&state=test123"
echo ""

# ── 6. Test DRS Registration ────────────────────────────────────
echo "Step 6: Test DRS Device Registration"
echo ""
echo "  # Generate a test CSR"
echo "  openssl req -new -newkey rsa:2048 -nodes \\"
echo "    -keyout test-device.key -out test-device.csr \\"
echo "    -subj '/CN=test-device/O=org1/C=SG'"
echo ""
echo "  # Register device"
echo "  curl -s -X POST $DRS_URL/drs/v1/register \\"
echo "    -H 'X-Org-ID: org1' \\"
echo "    -d '{\"device_name\":\"DESKTOP-TEST\",\"os_type\":\"windows\",\"csr_pem\":\"'\\$(cat test-device.csr)'\"}'"
echo ""

echo "=== Test commands generated ==="
echo ""
echo "Next steps:"
echo "  1. Run migration 048 (auto on MP restart)"
echo "  2. Set DRS_ISSUER_URL=$DRS_URL in MP env"
echo "  3. Add Cloudflare CNAME: drs -> $MP_ALB_DNS"
echo "  4. Update OIDC client secrets in DB"
echo "  5. Test each endpoint above"

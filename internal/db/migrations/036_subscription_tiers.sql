-- ============================================================================
-- Migration 036: subscription tiers -> entitlements (features, gateway licensing,
-- tenancy-deployment licensing). Drives the MSP store + the billing page. Prices
-- are placeholders; adjust freely. Feature entitlements derive from features.min_plan.
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_mgmt.subscription_tiers (
    tier              VARCHAR(32) PRIMARY KEY,        -- standard | professional | enterprise
    display_name      VARCHAR(64) NOT NULL,
    rank              BIGINT NOT NULL DEFAULT 0,      -- ordering / feature-gating (higher = more)
    max_gateways      BIGINT NOT NULL DEFAULT 1,      -- gateway licensing (0 = unlimited)
    tenancy_type      VARCHAR(16) NOT NULL DEFAULT 'shared', -- shared | dedicated | both
    max_client_users  BIGINT NOT NULL DEFAULT 0,      -- 0 = unlimited
    monthly_price_usd BIGINT NOT NULL DEFAULT 0,      -- cents
    description       TEXT NOT NULL DEFAULT ''
);

INSERT INTO system_mgmt.subscription_tiers
  (tier, display_name, rank, max_gateways, tenancy_type, max_client_users, monthly_price_usd, description) VALUES
  ('standard',     'Standard',     1,  2, 'shared',    500,   50000,  'Pooled (shared) tenancy, core SSE features, up to 2 gateways.'),
  ('professional', 'Professional', 2,  5, 'shared',    2000, 150000,  'Pooled tenancy, advanced features, up to 5 gateways.'),
  ('enterprise',   'Enterprise',   3, 20, 'dedicated', 0,    500000,  'Dedicated tenancy option, all features, up to 20 gateways, unlimited users.')
ON CONFLICT (tier) DO UPDATE SET
  display_name = excluded.display_name, rank = excluded.rank, max_gateways = excluded.max_gateways,
  tenancy_type = excluded.tenancy_type, max_client_users = excluded.max_client_users,
  monthly_price_usd = excluded.monthly_price_usd, description = excluded.description;

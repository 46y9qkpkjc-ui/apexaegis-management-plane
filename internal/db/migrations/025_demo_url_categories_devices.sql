-- Bucket 3 (data foundation): give URL categories real domains, add a Financial
-- Services category, and seed compliant/non-compliant demo devices with posture.
-- Idempotent — safe to re-run.

-- ── URL category → domain mapping (the 002 categories were labels only) ──────
CREATE TABLE IF NOT EXISTS system_mgmt.url_category_domains (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID NOT NULL REFERENCES system_mgmt.url_categories(id) ON DELETE CASCADE,
    domain      VARCHAR(255) NOT NULL,
    source      VARCHAR(40) NOT NULL DEFAULT 'seed',   -- seed | ut1 | abuse.ch | manual
    created_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (category_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_url_category_domains_domain ON system_mgmt.url_category_domains (domain);
CREATE INDEX IF NOT EXISTS idx_url_category_domains_cat ON system_mgmt.url_category_domains (category_id);

-- Financial Services category (not in the 002 system seed) — needed for the demo.
INSERT INTO system_mgmt.url_categories (org_id, name, category_type, description, is_system, enabled)
VALUES (NULL, 'Financial Services', 'productivity', 'Banking and financial institutions', true, true)
ON CONFLICT DO NOTHING;

-- Curated representative domains, mapped to system categories by name. Full open-source
-- ingestion (UT1 Toulouse / abuse.ch) lands these at scale later via source='ut1'/'abuse.ch'.
INSERT INTO system_mgmt.url_category_domains (category_id, domain, source)
SELECT c.id, d.domain, 'seed'
FROM (VALUES
  ('Financial Services','dbs.com.sg'),
  ('Financial Services','posb.com.sg'),
  ('Financial Services','ocbc.com'),
  ('Financial Services','uob.com.sg'),
  ('Financial Services','citibank.com.sg'),
  ('Financial Services','hsbc.com.sg'),
  ('Financial Services','standardchartered.com.sg'),
  ('Financial Services','maybank2u.com.sg'),
  ('Financial Services','prudential.com.sg'),
  ('Financial Services','aia.com.sg'),
  ('Financial Services','gemoney.com'),
  ('Financial Services','moneysmart.sg'),
  ('Social Media','facebook.com'),
  ('Social Media','instagram.com'),
  ('Social Media','twitter.com'),
  ('Social Media','x.com'),
  ('Social Media','tiktok.com'),
  ('Social Media','linkedin.com'),
  ('Social Media','reddit.com'),
  ('Social Media','snapchat.com'),
  ('Social Media','threads.net'),
  ('Streaming Media','youtube.com'),
  ('Streaming Media','netflix.com'),
  ('Streaming Media','spotify.com'),
  ('Streaming Media','twitch.tv'),
  ('Streaming Media','disneyplus.com'),
  ('Streaming Media','primevideo.com'),
  ('Shopping','amazon.com'),
  ('Shopping','ebay.com'),
  ('Shopping','aliexpress.com'),
  ('Shopping','lazada.sg'),
  ('Shopping','shopee.sg'),
  ('News','cnn.com'),
  ('News','bbc.com'),
  ('News','straitstimes.com'),
  ('News','channelnewsasia.com'),
  ('News','reuters.com'),
  ('Webmail','gmail.com'),
  ('Webmail','outlook.com'),
  ('Webmail','proton.me'),
  ('Webmail','mail.yahoo.com'),
  ('Gambling','bet365.com'),
  ('Gambling','888.com'),
  ('Gambling','pokerstars.com'),
  ('Gambling','williamhill.com'),
  ('File Sharing','dropbox.com'),
  ('File Sharing','wetransfer.com'),
  ('File Sharing','mega.nz')
) AS d(cat, domain)
JOIN system_mgmt.url_categories c ON c.name = d.cat AND c.org_id IS NULL
ON CONFLICT (category_id, domain) DO NOTHING;

-- ── Demo devices (compliant + non-compliant) for the Devices page + posture ──
INSERT INTO system_mgmt.devices
  (org_id, device_id, device_name, device_type, os_type, os_version, client_version,
   compliance_status, last_ip, status, registered_via, last_seen)
VALUES
  ('a0000000-0000-0000-0000-000000000001','demo-dev-mark','MARK-MBP16','laptop','macos','15.2','3.4.1','compliant','203.0.113.11','active','mtls', now()),
  ('a0000000-0000-0000-0000-000000000001','demo-dev-anderson','ANDERSON-TP14','laptop','windows','11 23H2','3.4.1','non_compliant','203.0.113.12','active','mtls', now()),
  ('a0000000-0000-0000-0000-000000000001','demo-dev-sarah','SARAH-XPS15','laptop','windows','11 23H2','3.4.1','compliant','203.0.113.13','active','mtls', now()),
  ('a0000000-0000-0000-0000-000000000001','demo-dev-kiosk','LOBBY-KIOSK','desktop','linux','ubuntu 22.04','3.3.0','non_compliant','203.0.113.14','active','mtls', now())
ON CONFLICT (device_id) DO NOTHING;

-- Latest posture report per demo device (drives the device-detail scorecard).
INSERT INTO system_mgmt.device_posture_reports
  (org_id, device_id, compliant, score, disk_encrypted, firewall_enabled, antivirus_running, antivirus_name, os_version)
SELECT d.org_id, d.id, p.compliant, p.score, p.disk_encrypted, p.firewall_enabled, p.antivirus_running, p.antivirus_name, d.os_version
FROM (VALUES
  ('demo-dev-mark',     true,  96, true,  true,  true,  'CrowdStrike Falcon'),
  ('demo-dev-anderson', false, 41, false, true,  false, 'Windows Defender (disabled)'),
  ('demo-dev-sarah',    true,  92, true,  true,  true,  'Microsoft Defender'),
  ('demo-dev-kiosk',    false, 28, false, false, false, 'none')
) AS p(device_id, compliant, score, disk_encrypted, firewall_enabled, antivirus_running, antivirus_name)
JOIN system_mgmt.devices d ON d.device_id = p.device_id
  AND d.org_id = 'a0000000-0000-0000-0000-000000000001';

-- Force-disable Cloud RADIUS feature flag.
-- The feature was toggled ON via Web UI but we don't have a radsecproxy
-- connected yet. DDoS bots are hitting port 2083 and consuming MP resources.
-- Re-enable via the Web UI Feature Licensing page once radsecproxy is deployed.

UPDATE system_mgmt.features SET enabled = false, updated_by = 'migration-046', updated_at = now()
WHERE id = 'cloud-radius';

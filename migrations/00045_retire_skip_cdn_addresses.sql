-- +goose Up
-- skip_cdn_addresses (on/off) was replaced by cdn_ports. Past runs stored it,
-- and Rerun replays a run's settings, so those runs failed with "unknown
-- parameter". The validator now translates the old key; this rewrites the
-- stored settings so they read like everything written since.
--
-- "true" was the default of its week, not a choice: dropped, so today's
-- default (the CDN edge on 80 and 443) applies. "false" meant scan CDN
-- addresses too: cdn_ports=all, unless cdn_ports was already set.
UPDATE scan_run SET params = CASE
    WHEN params->>'skip_cdn_addresses' = 'false' AND NOT params ? 'cdn_ports'
      THEN (params - 'skip_cdn_addresses') || '{"cdn_ports": "all"}'::jsonb
    ELSE params - 'skip_cdn_addresses' END
  WHERE params ? 'skip_cdn_addresses';
UPDATE scan_profile SET params = CASE
    WHEN params->>'skip_cdn_addresses' = 'false' AND NOT params ? 'cdn_ports'
      THEN (params - 'skip_cdn_addresses') || '{"cdn_ports": "all"}'::jsonb
    ELSE params - 'skip_cdn_addresses' END
  WHERE params ? 'skip_cdn_addresses';
UPDATE scan_schedule SET params = CASE
    WHEN params->>'skip_cdn_addresses' = 'false' AND NOT params ? 'cdn_ports'
      THEN (params - 'skip_cdn_addresses') || '{"cdn_ports": "all"}'::jsonb
    ELSE params - 'skip_cdn_addresses' END
  WHERE params ? 'skip_cdn_addresses';

-- +goose Down
-- Nothing to restore: the old key is understood on the way in either way.
SELECT 1;

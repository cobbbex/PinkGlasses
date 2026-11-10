-- +goose Up
-- Runs record what they did. A passive run never ran an active tool, and a
-- deep run swept every port whatever its port set said; both now store that
-- (scanparams.ProfileFixed), and older runs are brought in line so a rerun or
-- a look at their settings says the same.
UPDATE scan_run SET params = params || '{"naabu_enabled": "false", "nmap_enabled": "false",
  "httpx_enabled": "false", "katana_enabled": "false", "gobuster_enabled": "false",
  "nuclei_enabled": "false"}'::jsonb
WHERE profile = 'passive';

UPDATE scan_run SET params = params || '{"ports": "full"}'::jsonb
WHERE profile = 'deep';

-- +goose Down
-- Nothing to restore: the old values were defaults nobody acted on.
SELECT 1;

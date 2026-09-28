-- +goose Up
-- How long a company keeps the detail of finished runs: tasks, per-run
-- observations, screenshots, raw output, change events. Nothing pruned them
-- before, so storage grew with clients times scans times time — the first
-- thing to fail on a busy install.
--
-- 0 means keep everything, which is what every company did until now, so an
-- upgrade changes nothing until someone sets a number. The current inventory
-- — names, hosts, services, findings — is never pruned; only the history of
-- the runs that observed it.
ALTER TABLE scope ADD COLUMN IF NOT EXISTS retention_days int NOT NULL DEFAULT 0
    CHECK (retention_days >= 0);

-- +goose Down
ALTER TABLE scope DROP COLUMN IF EXISTS retention_days;

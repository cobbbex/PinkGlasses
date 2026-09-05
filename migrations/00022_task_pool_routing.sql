-- +goose Up
-- Routing moves from the run to the task.
--
-- A run's passive stages (passive_enum, dns_brute, dns_resolve, ip_enrich) never
-- send a packet at the target, so they run on the standing local workers whatever
-- exit the run chose. Its active stages run on the run's exit pool: an ephemeral
-- fleet behind a VPN gateway, or a pool of enrolled remote workers. One run, two
-- pools, so the pool has to be a property of the task.
--
-- This also closes a hole in the old lease filter: `r.pool_id IS NULL` was true
-- for every worker, so a fleet worker inside a VPN gateway's namespace could
-- lease an unrelated run's task and scan it through the tunnel.
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS pool_id uuid REFERENCES worker_pool(id) ON DELETE SET NULL;

-- Pending tasks planned before this migration: keep them runnable by giving them
-- the pool the old filter would have matched — the run's pool, else the
-- standing local pool. Finished tasks keep NULL; nothing leases those.
UPDATE scan_task t SET pool_id = COALESCE(
    (SELECT r.pool_id FROM scan_run r WHERE r.id = t.run_id),
    (SELECT id FROM worker_pool WHERE name = 'local' LIMIT 1),
    (SELECT id FROM worker_pool WHERE is_default LIMIT 1))
WHERE t.status = 'pending' AND t.pool_id IS NULL;

-- The lease query filters on this alongside status.
CREATE INDEX IF NOT EXISTS idx_task_pending_pool ON scan_task (pool_id, priority, id) WHERE status = 'pending';

-- +goose Down
DROP INDEX IF EXISTS idx_task_pending_pool;
ALTER TABLE scan_task DROP COLUMN IF EXISTS pool_id;

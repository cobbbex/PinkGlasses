-- +goose Up
-- Teardown deletes a run's pool, and the cascade took the fleet row with it —
-- including `error`, which is the only place a fleet's failure reason is
-- recorded. A run whose VPN gateway never came up would show as failed with no
-- explanation anywhere, which is the exact shape of silent breakage this
-- codebase keeps paying for.
--
-- The pool is transient; the record of what happened is not. Detach them.
ALTER TABLE run_fleet ALTER COLUMN pool_id DROP NOT NULL;
ALTER TABLE run_fleet DROP CONSTRAINT IF EXISTS run_fleet_pool_id_fkey;
ALTER TABLE run_fleet ADD CONSTRAINT run_fleet_pool_id_fkey
    FOREIGN KEY (pool_id) REFERENCES worker_pool(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE run_fleet DROP CONSTRAINT IF EXISTS run_fleet_pool_id_fkey;
DELETE FROM run_fleet WHERE pool_id IS NULL;
ALTER TABLE run_fleet ALTER COLUMN pool_id SET NOT NULL;
ALTER TABLE run_fleet ADD CONSTRAINT run_fleet_pool_id_fkey
    FOREIGN KEY (pool_id) REFERENCES worker_pool(id) ON DELETE CASCADE;

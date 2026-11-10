-- +goose Up
-- +goose StatementBegin

-- Remote workers belong to the account that brought them up. Nobody else sees
-- them (an administrator does, to stop one) and only that account's scans run
-- on them: a pool has an owner, and a run may only send work to a pool its
-- own account owns. The standing local workers, the default pool and a run's
-- own fleet stay shared (owner NULL).
ALTER TABLE worker_pool ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES app_user(id) ON DELETE CASCADE;
-- Copied from the pool when the worker enrols, and kept, so a worker whose
-- account is removed goes with it — its credential too.
ALTER TABLE worker ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES app_user(id) ON DELETE CASCADE;

-- Pool names are each account's own: everyone has a pool called "remote".
ALTER TABLE worker_pool DROP CONSTRAINT IF EXISTS worker_pool_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS worker_pool_shared_name ON worker_pool (name) WHERE owner_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS worker_pool_owner_name ON worker_pool (owner_id, name) WHERE owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_worker_owner ON worker (owner_id);

-- Existing remote workers go to the account of the SSH exit that installed
-- them, failing that the first administrator.
UPDATE worker w SET owner_id = COALESCE(
    (SELECT e.owner_id FROM ssh_exit e
      WHERE e.worker_name = w.name AND e.pool_id IS NOT DISTINCT FROM w.pool_id
      ORDER BY e.created_at LIMIT 1),
    (SELECT e.owner_id FROM ssh_exit e WHERE e.worker_name = w.name ORDER BY e.created_at LIMIT 1),
    (SELECT u.id FROM app_user u WHERE u.role = 'admin' ORDER BY u.created_at LIMIT 1))
WHERE w.kind <> 'local';

-- A pool that held remote workers goes to their account when they all share
-- one, otherwise to the first administrator. The local pool, the default
-- pool and runs' own pools stay shared.
UPDATE worker_pool p SET owner_id = COALESCE(
    (SELECT min(x.o::text)::uuid FROM (
        SELECT w.owner_id AS o FROM worker w WHERE w.pool_id = p.id AND w.kind <> 'local' AND w.owner_id IS NOT NULL
        UNION SELECT e.owner_id FROM ssh_exit e WHERE e.pool_id = p.id) x
     HAVING count(DISTINCT x.o) = 1),
    (SELECT u.id FROM app_user u WHERE u.role = 'admin' ORDER BY u.created_at LIMIT 1))
WHERE NOT p.run_scoped AND NOT p.is_default AND p.name <> 'local';

-- A remote worker or SSH exit left in a pool that is not its account's moves
-- to that account's own "remote" pool.
INSERT INTO worker_pool (name, description, owner_id)
SELECT DISTINCT 'remote', 'Your remote workers', x.o FROM (
    SELECT w.owner_id AS o FROM worker w LEFT JOIN worker_pool p ON p.id = w.pool_id
     WHERE w.kind <> 'local' AND w.owner_id IS NOT NULL AND p.owner_id IS DISTINCT FROM w.owner_id
    UNION
    SELECT e.owner_id FROM ssh_exit e LEFT JOIN worker_pool p ON p.id = e.pool_id
     WHERE p.owner_id IS DISTINCT FROM e.owner_id) x
ON CONFLICT DO NOTHING;

UPDATE worker w SET pool_id = q.id
FROM worker_pool q
WHERE w.kind <> 'local' AND w.owner_id IS NOT NULL AND q.owner_id = w.owner_id AND q.name = 'remote'
  AND NOT EXISTS (SELECT 1 FROM worker_pool p WHERE p.id = w.pool_id AND p.owner_id = w.owner_id);

UPDATE ssh_exit e SET pool_id = q.id
FROM worker_pool q
WHERE q.owner_id = e.owner_id AND q.name = 'remote'
  AND NOT EXISTS (SELECT 1 FROM worker_pool p WHERE p.id = e.pool_id AND p.owner_id = e.owner_id);

-- Tokens not yet redeemed for a pool that is now someone's would enrol a
-- worker into it unannounced; they are revoked. The bootstrap token for the
-- local pool and runs' own tokens are untouched.
UPDATE enrollment_token t SET revoked_at = now()
WHERE t.revoked_at IS NULL AND t.uses < t.max_uses AND t.expires_at > now() AND NOT t.preapproved
  AND EXISTS (SELECT 1 FROM worker_pool p WHERE p.id = t.pool_id AND p.owner_id IS NOT NULL);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Names were unique install-wide; later accounts' pools of the same name are
-- numbered so the old constraint can come back.
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY name ORDER BY owner_id IS NOT NULL, created_at, id) AS rn
    FROM worker_pool)
UPDATE worker_pool p SET name = p.name || ' (' || ranked.rn || ')'
FROM ranked WHERE ranked.id = p.id AND ranked.rn > 1;
DROP INDEX IF EXISTS worker_pool_owner_name;
DROP INDEX IF EXISTS worker_pool_shared_name;
DROP INDEX IF EXISTS idx_worker_owner;
ALTER TABLE worker_pool ADD CONSTRAINT worker_pool_name_key UNIQUE (name);
ALTER TABLE worker DROP COLUMN IF EXISTS owner_id;
ALTER TABLE worker_pool DROP COLUMN IF EXISTS owner_id;
-- +goose StatementEnd

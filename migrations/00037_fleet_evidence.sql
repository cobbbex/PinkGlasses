-- +goose Up
-- What a failed fleet's containers looked like just before they were removed:
-- per container, its role, state, exit code, whether it was killed for memory,
-- and its last log lines. Teardown destroys the containers and their logs; this
-- is what the run view shows instead.
ALTER TABLE run_fleet ADD COLUMN IF NOT EXISTS evidence jsonb;

-- +goose Down
ALTER TABLE run_fleet DROP COLUMN IF EXISTS evidence;

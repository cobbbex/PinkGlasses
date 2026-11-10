-- +goose Up
-- A passive run never brute-forced: the planner dropped the stage whatever
-- the run's settings said. Runs stored every setting with its default, so
-- each passive run says dns_bruteforce=true, and rerunning one now that the
-- setting is honoured would brute-force a run that never did. Record what
-- happened. A passive run is brute-forced from now on only when switched on.
UPDATE scan_run SET params = params || '{"dns_bruteforce": "false"}'::jsonb
WHERE profile = 'passive';

-- +goose Down
-- Nothing to restore: the old value was a default nobody chose, and it was
-- never acted on.
SELECT 1;

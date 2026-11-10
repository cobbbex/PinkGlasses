-- +goose Up
-- Stopping or failing a run left its unfinished targets "running", so the
-- run page said work was going on in a run that had ended. Runs now set them
-- on the way out (store.SetRunStatus); this does the same for older runs.
UPDATE run_target t SET status = 'cancelled'
FROM scan_run r
WHERE r.id = t.run_id AND r.status = 'cancelled' AND t.status IN ('pending', 'running');

UPDATE run_target t SET status = 'failed'
FROM scan_run r
WHERE r.id = t.run_id AND r.status = 'failed' AND t.status IN ('pending', 'running');

-- +goose Down
SELECT 1;

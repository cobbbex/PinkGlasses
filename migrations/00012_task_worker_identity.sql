-- +goose Up
-- +goose StatementBegin

-- Which worker ran a task was only ever readable through scan_task.worker_id,
-- and that pointer is deliberately transient: the FK is ON DELETE SET NULL, and
-- both retry and lease reaping clear it so an unfinished task is not still
-- claimed by anyone. The consequence was that a finished run's Activity view
-- showed "unassigned" for every task as soon as its worker was replaced —
-- which happens on every worker rebuild.
--
-- Stamping the identity onto the task at lease time keeps the history readable:
-- the worker row can disappear, the record of what it did stays.
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS worker_name text;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS worker_kind text;

-- Backfill what is still recoverable — tasks whose worker row is still present.
-- Tasks whose worker is already gone cannot be recovered; they keep showing as
-- unassigned, and everything from here on is attributed.
UPDATE scan_task t
   SET worker_name = w.name, worker_kind = w.kind
  FROM worker w
 WHERE w.id = t.worker_id AND t.worker_name IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_task DROP COLUMN IF EXISTS worker_name;
ALTER TABLE scan_task DROP COLUMN IF EXISTS worker_kind;
-- +goose StatementEnd

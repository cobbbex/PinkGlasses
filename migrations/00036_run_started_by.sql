-- +goose Up
-- +goose StatementBegin

-- Who started a run: the account, and how — signed in to the app, through an
-- API token (a script or an MCP client), or by a schedule (its creator). The
-- name is kept as text so a run still says who started it after the account
-- is renamed or removed; the id links to the account while it exists.
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS started_by text;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS started_by_user_id uuid REFERENCES app_user(id) ON DELETE SET NULL;
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS started_via text;

-- Earlier runs: the audit log recorded who created or reran each one.
UPDATE scan_run r SET started_by = a.actor, started_by_user_id = a.user_id, started_via = 'session'
FROM (SELECT DISTINCT ON (subject) subject, actor, user_id FROM audit_log
      WHERE action IN ('run.create','run.rerun') ORDER BY subject, created_at) a
WHERE a.subject = r.id::text AND r.started_by IS NULL;

-- Scheduled runs: the schedule's creator, where the schedule still points at them.
UPDATE scan_run r SET started_by = s.created_by, started_via = 'schedule'
FROM scan_schedule s
WHERE s.last_run_id = r.id AND r.started_by IS NULL AND r.trigger = 'scheduled';
UPDATE scan_run SET started_via = 'schedule' WHERE started_via IS NULL AND trigger = 'scheduled';

-- +goose StatementEnd

-- +goose Down
ALTER TABLE scan_run DROP COLUMN IF EXISTS started_via;
ALTER TABLE scan_run DROP COLUMN IF EXISTS started_by_user_id;
ALTER TABLE scan_run DROP COLUMN IF EXISTS started_by;

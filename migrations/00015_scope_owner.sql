-- +goose Up
-- +goose StatementBegin

-- Who created a company, so the list can be narrowed to your own.
--
-- This is a free-text actor, not a user id: there is no users table yet, and
-- until Phase 17 lands the identity is whatever X-Forwarded-User claims, or
-- "local". The column is the seam — when real authentication arrives the owner
-- becomes verified rather than asserted, and this filter starts meaning
-- something without the UI changing.
ALTER TABLE scope ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT 'local';

-- The audit log already recorded who created each scope, so the existing rows
-- get their real owner rather than everything defaulting to 'local'.
UPDATE scope s SET created_by = a.actor
  FROM (
    SELECT DISTINCT ON (subject) subject, actor
    FROM audit_log WHERE action = 'scope.create'
    ORDER BY subject, created_at
  ) a
 WHERE a.subject = s.id::text AND a.actor <> '';

CREATE INDEX IF NOT EXISTS idx_scope_created_by ON scope (created_by);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scope_created_by;
ALTER TABLE scope DROP COLUMN IF EXISTS created_by;
-- +goose StatementEnd

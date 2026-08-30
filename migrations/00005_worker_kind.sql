-- +goose Up
-- +goose StatementBegin

-- Two vantage-point pools. Local workers sit inside your network and can reach
-- internal ranges; remote workers show the perimeter as an attacker sees it.
INSERT INTO worker_pool (name, description) VALUES
  ('local',  'Workers inside your network — can reach internal ranges'),
  ('remote', 'External VPS workers — true outside-in perimeter view')
ON CONFLICT (name) DO NOTHING;

-- The token decides what kind of worker it mints; the worker does not get to
-- claim its own kind (server-authoritative).
ALTER TABLE enrollment_token ADD COLUMN kind text NOT NULL DEFAULT 'vps';

-- Scope must explicitly opt in before any internal range is scanned, and then
-- only from the local pool (see scanproto CapInternal).
ALTER TABLE scope ADD COLUMN allow_private boolean NOT NULL DEFAULT false;

-- Reaping scaled-out local workers that were recreated (docker compose --scale
-- gives each replica a fresh container, hence a fresh enrollment).
CREATE INDEX idx_worker_kind_seen ON worker (kind, status, last_seen_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_worker_kind_seen;
ALTER TABLE scope DROP COLUMN IF EXISTS allow_private;
ALTER TABLE enrollment_token DROP COLUMN IF EXISTS kind;
DELETE FROM worker_pool WHERE name IN ('local','remote');
-- +goose StatementEnd

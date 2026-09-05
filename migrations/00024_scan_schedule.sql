-- +goose Up
-- Recurring scans. Nothing started a run without a person clicking; every
-- feature that shows change over time only accumulates if scans recur.
CREATE TABLE IF NOT EXISTS scan_schedule (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id       uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    profile        text NOT NULL DEFAULT 'standard',
    -- Where the run's active stages leave from; a passive profile needs neither.
    exit           text NOT NULL DEFAULT '' CHECK (exit IN ('', 'local', 'remote')),
    vpn_config_id  uuid REFERENCES vpn_config(id) ON DELETE SET NULL,
    pool_id        uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    worker_count   integer NOT NULL DEFAULT 2,
    every_hours    integer NOT NULL CHECK (every_hours >= 1),
    enabled        boolean NOT NULL DEFAULT true,
    -- next_run_at advances from itself, not from now, so a slow run does not
    -- drift the cadence.
    next_run_at    timestamptz NOT NULL DEFAULT now(),
    last_run_id    uuid REFERENCES scan_run(id) ON DELETE SET NULL,
    last_run_at    timestamptz,
    -- Why the last attempt did not start a run, in words, where the UI shows it.
    last_error     text,
    created_by     uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_schedule_due ON scan_schedule (next_run_at) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_schedule_scope ON scan_schedule (scope_id);

-- A company's default exit, so the launch dialog pre-selects it and a schedule
-- created without one has something to use.
ALTER TABLE scope ADD COLUMN IF NOT EXISTS default_exit text NOT NULL DEFAULT '' CHECK (default_exit IN ('', 'local', 'remote'));
ALTER TABLE scope ADD COLUMN IF NOT EXISTS default_vpn_config_id uuid REFERENCES vpn_config(id) ON DELETE SET NULL;
ALTER TABLE scope ADD COLUMN IF NOT EXISTS default_pool_id uuid REFERENCES worker_pool(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE scope DROP COLUMN IF EXISTS default_pool_id;
ALTER TABLE scope DROP COLUMN IF EXISTS default_vpn_config_id;
ALTER TABLE scope DROP COLUMN IF EXISTS default_exit;
DROP TABLE IF EXISTS scan_schedule;

-- +goose Up
-- +goose StatementBegin

-- A run that brings up its own workers records the fleet here, so the lifecycle
-- survives a control-plane restart: the scheduler can find fleets that were
-- never created, and containers that were never cleaned up.
--
-- The enrollment token is bound to the run's pool, which is what makes the
-- routing work: workers created with it enrol into that pool, and the lease
-- query already refuses to hand a pooled worker another run's tasks.
CREATE TABLE IF NOT EXISTS run_fleet (
    run_id       uuid PRIMARY KEY REFERENCES scan_run(id) ON DELETE CASCADE,
    pool_id      uuid NOT NULL REFERENCES worker_pool(id) ON DELETE CASCADE,
    workers      integer NOT NULL DEFAULT 1,
    enroll_token text NOT NULL,
    vpn_config_id uuid REFERENCES vpn_config(id) ON DELETE SET NULL,
    status       text NOT NULL DEFAULT 'requested',  -- requested|up|failed|torn_down
    error        text,
    egress_ip    text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    ready_at     timestamptz,
    torn_down_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_run_fleet_status ON run_fleet (status);

-- Pools created for a single run are marked, so teardown can remove them
-- without touching the pools an operator made.
ALTER TABLE worker_pool ADD COLUMN IF NOT EXISTS run_scoped boolean NOT NULL DEFAULT false;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE worker_pool DROP COLUMN IF EXISTS run_scoped;
DROP TABLE IF EXISTS run_fleet;
-- +goose StatementEnd

-- +goose Up
-- A follow-up run scans what an earlier run found, with the active stages
-- only. parent_run_id says which run; run_seed holds the names and addresses
-- it was started on, each under the run target it was found below, so the
-- run can be planned, shown and rerun from its own record.
ALTER TABLE scan_run ADD COLUMN parent_run_id uuid REFERENCES scan_run(id) ON DELETE SET NULL;

-- +goose StatementBegin
CREATE TABLE run_seed (
    run_id        uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    run_target_id uuid NOT NULL REFERENCES run_target(id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('domain', 'ip', 'cidr')),
    value         text NOT NULL,
    PRIMARY KEY (run_id, run_target_id, kind, value)
);
-- +goose StatementEnd
CREATE INDEX run_seed_run ON run_seed (run_id, kind);

-- +goose Down
DROP TABLE IF EXISTS run_seed;
ALTER TABLE scan_run DROP COLUMN IF EXISTS parent_run_id;

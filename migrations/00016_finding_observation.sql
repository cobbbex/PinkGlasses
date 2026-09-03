-- +goose Up
-- +goose StatementBegin

-- One row per finding per run that observed it: the exact trail behind the
-- finding row's first_seen/last_seen summary. With it, "was this present in
-- every scan or did it vanish and come back" is a query rather than a guess,
-- and a finding's presence can be computed against the runs that could have
-- seen it instead of being a status somebody has to remember to set.
CREATE TABLE IF NOT EXISTS finding_observation (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  uuid NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    run_id      uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    observed_at timestamptz NOT NULL DEFAULT now(),
    severity    text NOT NULL,
    evidence    jsonb,
    UNIQUE (finding_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_observation_run ON finding_observation (run_id);

-- The differ already recorded the run each existing finding first appeared in,
-- so history starts with a real point for every finding rather than nothing.
INSERT INTO finding_observation (finding_id, run_id, observed_at, severity, evidence)
SELECT f.id, ce.run_id, ce.created_at, f.severity, f.evidence
  FROM change_event ce JOIN finding f ON f.id = ce.asset_id
 WHERE ce.kind = 'new_finding' AND ce.asset_kind = 'finding'
ON CONFLICT (finding_id, run_id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS finding_observation;
-- +goose StatementEnd

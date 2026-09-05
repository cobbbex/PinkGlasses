-- +goose Up
-- Per-run record of a name resolving to an address.
--
-- domain_ip carries first_seen/last_seen for each name→address pair, which says
-- when the pair was first and most recently true but not what happened in
-- between: a name that moved to a new address and back leaves the same two
-- timestamps as one that never moved. Findings got a per-run history in 00016
-- for the same reason; this is the same shape for resolutions, so the host page
-- can show one dot per run that resolved the name — filled where it pointed
-- here, hollow where it pointed elsewhere.
CREATE TABLE IF NOT EXISTS domain_ip_observation (
    domain_id   uuid NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    ip_id       uuid NOT NULL REFERENCES ip_address(id) ON DELETE CASCADE,
    run_id      uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, ip_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_dio_ip ON domain_ip_observation (ip_id, run_id);

-- +goose Down
DROP TABLE IF EXISTS domain_ip_observation;

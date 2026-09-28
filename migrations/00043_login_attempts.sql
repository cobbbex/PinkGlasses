-- +goose Up
-- Sign-in attempts counted in the database rather than in each api process,
-- so several copies behind a load balancer share one limit: N copies used to
-- mean N times the allowed guesses.
CREATE TABLE IF NOT EXISTS login_attempt (
    id  bigserial PRIMARY KEY,
    key text NOT NULL,          -- "ip:<addr>" or "user:<name>"
    at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_login_attempt_key ON login_attempt (key, at DESC);

-- +goose Down
DROP TABLE IF EXISTS login_attempt;

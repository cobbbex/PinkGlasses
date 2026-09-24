-- +goose Up
-- Liveness of the services that have no endpoint the api can call: the
-- scheduler writes here every tick, the gateway every 15 s. The health page
-- reads the age of each row.
CREATE TABLE IF NOT EXISTS component_heartbeat (
    name      text PRIMARY KEY,
    last_seen timestamptz NOT NULL DEFAULT now(),
    detail    jsonb NOT NULL DEFAULT '{}'
);

-- +goose Down
DROP TABLE IF EXISTS component_heartbeat;

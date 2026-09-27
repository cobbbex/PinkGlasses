-- +goose Up
-- How often a channel hears from us. "per_run" (what every channel did until
-- now) sends a digest as each run finishes; "daily" collects a day's changes
-- across every run of the company into one message, sent after digest_hour
-- UTC. A busy install scanning hourly sent 24 messages a day; most people
-- want one.
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS cadence text NOT NULL DEFAULT 'per_run'
    CHECK (cadence IN ('per_run','daily'));
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS digest_hour int NOT NULL DEFAULT 7
    CHECK (digest_hour BETWEEN 0 AND 23);
-- The end of the last period sent, so a digest covers exactly what the one
-- before it did not, whatever the scheduler was doing in between.
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS digest_through timestamptz;

-- +goose Down
ALTER TABLE notification_channel DROP COLUMN IF EXISTS digest_through;
ALTER TABLE notification_channel DROP COLUMN IF EXISTS digest_hour;
ALTER TABLE notification_channel DROP COLUMN IF EXISTS cadence;

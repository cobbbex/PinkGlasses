-- +goose Up
-- A schedule is now made in the same dialog as a run, so it carries the same
-- choices a run does — parameters, preset, wordlists — and can be a one-off:
-- every_hours = 0 means "once, at next_run_at", after which it disables itself.
ALTER TABLE scan_schedule DROP CONSTRAINT IF EXISTS scan_schedule_every_hours_check;
ALTER TABLE scan_schedule ADD CONSTRAINT scan_schedule_every_hours_check CHECK (every_hours >= 0);
ALTER TABLE scan_schedule ADD COLUMN IF NOT EXISTS profile_id uuid REFERENCES scan_profile(id) ON DELETE SET NULL;
ALTER TABLE scan_schedule ADD COLUMN IF NOT EXISTS params jsonb NOT NULL DEFAULT '{}';
ALTER TABLE scan_schedule ADD COLUMN IF NOT EXISTS wordlist_ids uuid[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE scan_schedule DROP COLUMN IF EXISTS wordlist_ids;
ALTER TABLE scan_schedule DROP COLUMN IF EXISTS params;
ALTER TABLE scan_schedule DROP COLUMN IF EXISTS profile_id;
DELETE FROM scan_schedule WHERE every_hours = 0;
ALTER TABLE scan_schedule DROP CONSTRAINT IF EXISTS scan_schedule_every_hours_check;
ALTER TABLE scan_schedule ADD CONSTRAINT scan_schedule_every_hours_check CHECK (every_hours >= 1);

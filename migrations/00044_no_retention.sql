-- +goose Up
-- The run-pruning feature is gone: nothing in this application deletes a past
-- scan. A run is the record of what a client exposed on one day, and comparing
-- this month with last year is most of the reason to keep it — so the setting
-- that could throw that away goes too, rather than sitting there waiting to be
-- set by accident. What storage it costs is on the System page instead.
--
-- 00042 added this column; dropping it loses nothing else, since nothing else
-- ever read it.
ALTER TABLE scope DROP COLUMN IF EXISTS retention_days;

-- +goose Down
ALTER TABLE scope ADD COLUMN IF NOT EXISTS retention_days int NOT NULL DEFAULT 0
    CHECK (retention_days >= 0);

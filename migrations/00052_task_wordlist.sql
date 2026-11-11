-- +goose Up
-- +goose StatementBegin

-- The wordlist a brute-force task actually used, written by the gateway when
-- it hands the task out: which list is chosen is only settled then (a
-- directory search takes the run's list at dispatch, or the worker image's
-- own when the run has none). The name is kept as well as the id, so a list
-- deleted later still names what the task ran.
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS wordlist_id uuid REFERENCES wordlist(id) ON DELETE SET NULL;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS wordlist_name text;
-- A DNS brute force also queries through a resolver list.
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS resolvers_name text;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_task DROP COLUMN IF EXISTS resolvers_name;
ALTER TABLE scan_task DROP COLUMN IF EXISTS wordlist_name;
ALTER TABLE scan_task DROP COLUMN IF EXISTS wordlist_id;
-- +goose StatementEnd

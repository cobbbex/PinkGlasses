-- +goose Up
-- +goose StatementBegin

-- This is an external attack-surface monitor. Internal (RFC1918) ranges are out
-- of scope for every worker, local ones included, so the per-scope opt-in is
-- gone and the planner now skips such targets outright.
ALTER TABLE scope DROP COLUMN IF EXISTS allow_private;

-- Local workers no longer carry the 'internal' capability: both worker kinds do
-- the same job (external scanning) and differ only in egress address, trust and
-- how they enrol.
UPDATE worker
   SET capabilities = array_remove(capabilities, 'internal')
 WHERE 'internal' = ANY(capabilities);

-- Pool descriptions seeded by 00005 described local workers as internal-range
-- scanners. Corrected forward here rather than by editing an applied migration.
UPDATE worker_pool SET description =
  'Workers beside the control plane — scan from your own egress address'
 WHERE name = 'local';
UPDATE worker_pool SET description =
  'Rented boxes on the internet — independent egress, true outside-in view'
 WHERE name = 'remote';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scope ADD COLUMN IF NOT EXISTS allow_private boolean NOT NULL DEFAULT false;
-- +goose StatementEnd

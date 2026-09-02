-- +goose Up
-- +goose StatementBegin

-- A finding's identity is its asset, its kind and its title. Without a
-- constraint saying so, UpsertFinding's ON CONFLICT DO NOTHING never fired and
-- every run inserted the same finding again, while its follow-up UPDATE matched
-- on (scope, asset, kind) alone — ignoring the title. Stages that raise one
-- finding per item, such as content discovery raising one per path, therefore
-- had every row rewritten to whichever item was ingested last: five distinct
-- paths became five copies of the same one.

-- Collapse existing duplicates onto the earliest row before the index is built.
DELETE FROM finding f
 USING finding keep
 WHERE f.scope_id = keep.scope_id
   AND f.asset_kind = keep.asset_kind
   AND f.asset_id = keep.asset_id
   AND f.kind = keep.kind
   AND f.title = keep.title
   AND (keep.first_seen, keep.id) < (f.first_seen, f.id);

CREATE UNIQUE INDEX IF NOT EXISTS finding_identity
  ON finding (scope_id, asset_kind, asset_id, kind, title);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS finding_identity;
-- +goose StatementEnd

-- +goose Up
-- Repair HTTP documents whose headers became an array. The merge concatenated
-- an object with a jsonb null (a stage reporting no headers) and `||` makes
-- that a two-element array rather than a merge. Fold the object elements back
-- into one map and drop the nulls; the store now guards the types on write.
UPDATE service_observation so
SET http = so.http || jsonb_build_object('headers', COALESCE((
      SELECT jsonb_object_agg(kv.key, kv.value)
      FROM jsonb_array_elements(so.http->'headers') e, jsonb_each(e) kv
      WHERE jsonb_typeof(e) = 'object'), '{}'::jsonb))
WHERE jsonb_typeof(so.http->'headers') = 'array';

-- A headers value that is null or a scalar is no headers at all.
UPDATE service_observation SET http = http - 'headers'
WHERE http ? 'headers' AND jsonb_typeof(http->'headers') <> 'object';

-- Cookie lists that picked up a null the same way.
UPDATE service_observation so
SET http = so.http || jsonb_build_object('cookies', COALESCE((
      SELECT jsonb_agg(DISTINCT c ORDER BY c) FROM jsonb_array_elements_text(so.http->'cookies') c
      WHERE c IS NOT NULL), '[]'::jsonb))
WHERE jsonb_typeof(so.http->'cookies') = 'array' AND so.http->'cookies' @> 'null'::jsonb;

-- +goose Down
-- Data repair; nothing to undo.

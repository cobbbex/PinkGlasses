-- +goose Up
-- Response headers already recorded name the software behind a site where the
-- page fingerprint did not: "X-Redirect-By: WordPress" on three hosts with no
-- WordPress tag. Workers now read those headers at scan time; this reads what
-- earlier scans stored, so the tag appears without a rescan. A service that
-- already carries the name, at any version, is left alone.
INSERT INTO technology (service_id, name, version, confidence, first_seen, last_seen)
SELECT so.service_id, 'WordPress', '', 80, min(so.observed_at), max(so.observed_at)
FROM service_observation so
WHERE (so.http->'headers'->>'X-Redirect-By' IS NOT NULL
       OR so.http->'headers'->>'Link' ILIKE '%api.w.org%'
       OR so.http->'headers'->>'X-Pingback' ILIKE '%xmlrpc.php%'
       OR so.http->'headers'->>'X-Generator' ILIKE 'WordPress%')
  AND NOT EXISTS (SELECT 1 FROM technology t WHERE t.service_id = so.service_id AND t.name = 'WordPress')
GROUP BY so.service_id
ON CONFLICT DO NOTHING;

INSERT INTO technology (service_id, name, version, confidence, first_seen, last_seen)
SELECT so.service_id, 'Drupal', '', 80, min(so.observed_at), max(so.observed_at)
FROM service_observation so
WHERE (so.http->'headers'->>'X-Drupal-Cache' IS NOT NULL
       OR so.http->'headers'->>'X-Drupal-Dynamic-Cache' IS NOT NULL
       OR so.http->'headers'->>'X-Generator' ILIKE 'Drupal%')
  AND NOT EXISTS (SELECT 1 FROM technology t WHERE t.service_id = so.service_id AND t.name = 'Drupal')
GROUP BY so.service_id
ON CONFLICT DO NOTHING;

-- +goose Down
-- The rows are indistinguishable from scanned ones; nothing to undo.

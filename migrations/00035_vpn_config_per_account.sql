-- +goose Up
-- +goose StatementBegin

-- A VPN configuration belongs to the account that added it, not to a company.
-- One person's tunnel is the same tunnel whichever company they are scanning,
-- and keeping a copy per company meant uploading the same private key several
-- times and deleting it as many. Existing configs go to the account named by
-- created_by, failing that the company's owner, failing that the first
-- administrator; a config nobody can own (an install with no accounts) is
-- dropped, since nothing could ever select it.
ALTER TABLE vpn_config ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES app_user(id) ON DELETE CASCADE;

UPDATE vpn_config v SET owner_id = COALESCE(
    (SELECT u.id FROM app_user u WHERE u.username = v.created_by),
    (SELECT s.owner_id FROM scope s WHERE s.id = v.scope_id),
    (SELECT u.id FROM app_user u WHERE u.role = 'admin' ORDER BY u.created_at LIMIT 1))
WHERE v.owner_id IS NULL;
DELETE FROM vpn_config WHERE owner_id IS NULL;
ALTER TABLE vpn_config ALTER COLUMN owner_id SET NOT NULL;

-- Two companies could each hold a config of the same name from the same
-- person; under one account those names collide, so the later ones are
-- numbered. Whoever owns them can rename or delete.
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY owner_id, name ORDER BY created_at, id) AS rn
    FROM vpn_config)
UPDATE vpn_config v SET name = v.name || ' (' || ranked.rn || ')'
FROM ranked WHERE ranked.id = v.id AND ranked.rn > 1;

ALTER TABLE vpn_config DROP CONSTRAINT IF EXISTS vpn_config_scope_id_name_key;
DROP INDEX IF EXISTS idx_vpn_config_scope;
ALTER TABLE vpn_config DROP COLUMN IF EXISTS scope_id;
ALTER TABLE vpn_config ADD CONSTRAINT vpn_config_owner_id_name_key UNIQUE (owner_id, name);
CREATE INDEX IF NOT EXISTS idx_vpn_config_owner ON vpn_config (owner_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The company a config belonged to is gone; the column comes back empty.
ALTER TABLE vpn_config DROP CONSTRAINT IF EXISTS vpn_config_owner_id_name_key;
DROP INDEX IF EXISTS idx_vpn_config_owner;
ALTER TABLE vpn_config ADD COLUMN IF NOT EXISTS scope_id uuid REFERENCES scope(id) ON DELETE CASCADE;
ALTER TABLE vpn_config DROP COLUMN IF EXISTS owner_id;
-- +goose StatementEnd

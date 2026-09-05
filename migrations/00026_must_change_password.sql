-- +goose Up
-- The default administrator's password is no longer a published constant: it is
-- generated at first boot and printed once. "Still using the default" can no
-- longer be checked against a constant, so it becomes a flag: set when the seed
-- creates the account, cleared when the password is changed.
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
-- Installs seeded under the published default carry the flag until the password
-- is changed. The seed's exact shape identifies them; a hand-made account named
-- admin would be nagged once and be done.
UPDATE app_user SET must_change_password = true
 WHERE username = 'admin' AND display_name = 'Administrator';

-- +goose Down
ALTER TABLE app_user DROP COLUMN IF EXISTS must_change_password;

-- +goose Up
-- +goose StatementBegin
-- Saved scan-parameter presets (Phase 15). params is a whitelisted, validated
-- key->value map (see internal/scanparams); it is NEVER passed to exec raw.
CREATE TABLE scan_profile (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    owner      text,                          -- who saved it (from the proxy identity)
    scope_id   uuid REFERENCES scope(id) ON DELETE CASCADE,  -- null = available to all companies
    params     jsonb NOT NULL DEFAULT '{}',
    is_default boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (coalesce(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), name)
);

-- runs remember which preset they used, for reproducibility.
ALTER TABLE scan_run ADD COLUMN profile_id uuid REFERENCES scan_profile(id) ON DELETE SET NULL;
ALTER TABLE scan_run ADD COLUMN params jsonb NOT NULL DEFAULT '{}';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_run DROP COLUMN IF EXISTS params;
ALTER TABLE scan_run DROP COLUMN IF EXISTS profile_id;
DROP TABLE IF EXISTS scan_profile;
-- +goose StatementEnd

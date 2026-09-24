-- +goose Up
-- +goose StatementBegin

-- A company is either shared — every account on the install can see it, as
-- all companies were until now — or private: only its owner and the accounts
-- it is shared with. Account roles still apply inside: a viewer a private
-- company is shared with can read it, not scan it.
ALTER TABLE scope ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'shared'
    CHECK (visibility IN ('shared','private'));

CREATE TABLE IF NOT EXISTS scope_member (
    scope_id   uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    added_by   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_scope_member_user ON scope_member (user_id);

-- The one rule, used by every query and every route that reaches a company:
-- may this account see it? A private company whose owner's account was
-- removed falls to the administrators, so nothing is stranded.
CREATE OR REPLACE FUNCTION scope_visible(sc uuid, uid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM scope s
        WHERE s.id = sc AND (
            s.visibility = 'shared'
            OR s.owner_id = uid
            OR EXISTS (SELECT 1 FROM scope_member m WHERE m.scope_id = s.id AND m.user_id = uid)
            OR (s.owner_id IS NULL AND EXISTS (SELECT 1 FROM app_user u WHERE u.id = uid AND u.role = 'admin'))
        )
    )
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS scope_visible(uuid, uuid);
DROP TABLE IF EXISTS scope_member;
ALTER TABLE scope DROP COLUMN IF EXISTS visibility;
-- +goose StatementEnd

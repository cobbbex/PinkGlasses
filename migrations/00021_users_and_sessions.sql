-- +goose Up
-- Identity. Until now `actor()` read X-Forwarded-User and otherwise called
-- everyone "local": anything that could reach the API could claim to be anyone,
-- and every created_by column recorded that claim as though it were a fact.
--
-- A scan is an action with consequences for someone else's infrastructure, so
-- "who started this run" has to be a fact rather than a header.

CREATE TABLE IF NOT EXISTS app_user (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Case-insensitive: nobody should be able to register "Admin" beside
    -- "admin" and be mistaken for them.
    username      text NOT NULL,
    display_name  text NOT NULL DEFAULT '',
    -- argon2id, encoded with its own parameters so the cost can be raised
    -- later without invalidating existing hashes. Null for a user that can
    -- only sign in through a trusted proxy.
    password_hash text,
    role          text NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','operator','viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    uuid REFERENCES app_user(id) ON DELETE SET NULL,
    last_login_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_user_username ON app_user (lower(username));

-- Sessions are server-side so that disabling a user, or changing their role,
-- takes effect on their next request rather than whenever a self-contained
-- token happens to expire.
CREATE TABLE IF NOT EXISTS user_session (
    -- sha256 of the cookie value. The cookie itself is never stored, so a
    -- database read does not hand over live sessions.
    token_hash   bytea PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    user_agent   text NOT NULL DEFAULT '',
    ip           inet
);
CREATE INDEX IF NOT EXISTS idx_user_session_user ON user_session (user_id);
CREATE INDEX IF NOT EXISTS idx_user_session_expiry ON user_session (expires_at);

-- Tokens for automation, so scripting the API does not mean sharing a human's
-- session. A token may be narrower than its owner but never wider.
CREATE TABLE IF NOT EXISTS api_token (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea NOT NULL UNIQUE,
    prefix       text NOT NULL,          -- shown in the UI so a token is identifiable
    name         text NOT NULL,
    user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role IN ('admin','operator','viewer')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_api_token_user ON api_token (user_id);

-- Audit that identifies a person, not a string. `actor` stays: it still records
-- what a request called itself, including for the rows written before there
-- were users at all.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES app_user(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (user_id, created_at DESC);

-- Ownership pointing at a user rather than at a free-text actor string.
ALTER TABLE scope ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES app_user(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scope_owner ON scope (owner_id);

-- +goose Down
ALTER TABLE scope DROP COLUMN IF EXISTS owner_id;
ALTER TABLE audit_log DROP COLUMN IF EXISTS user_id;
DROP TABLE IF EXISTS api_token;
DROP TABLE IF EXISTS user_session;
DROP TABLE IF EXISTS app_user;

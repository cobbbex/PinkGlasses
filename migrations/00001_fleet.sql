-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE worker_pool (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text,
    is_default  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE worker (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id         uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    name            text NOT NULL,
    kind            text NOT NULL DEFAULT 'vps',        -- 'local' | 'vps'
    status          text NOT NULL DEFAULT 'pending',    -- pending|active|draining|quarantined|stale|revoked
    capabilities    text[] NOT NULL DEFAULT '{}',       -- raw_socket, browser, ipv6, udp, high_bandwidth
    tools           jsonb NOT NULL DEFAULT '{}',        -- tool -> version
    agent_version   text,
    egress_ip       inet,                               -- observed by gateway, never self-reported
    egress_ip_v6    inet,
    country         text,
    max_concurrency int NOT NULL DEFAULT 8,
    running_tasks   int NOT NULL DEFAULT 0,
    cred_hash       bytea NOT NULL,                     -- argon2id of the agent credential
    cred_rotated_at timestamptz,
    last_seen_at    timestamptz,
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    enrolled_by     uuid,
    notes           text
);

CREATE TABLE enrollment_token (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  bytea NOT NULL UNIQUE,                  -- never store the token itself
    pool_id     uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    created_by  uuid,
    expires_at  timestamptz NOT NULL,
    max_uses    int NOT NULL DEFAULT 1,
    uses        int NOT NULL DEFAULT 0,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO worker_pool (name, description, is_default) VALUES ('default', 'Default worker pool', true);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS enrollment_token;
DROP TABLE IF EXISTS worker;
DROP TABLE IF EXISTS worker_pool;
-- +goose StatementEnd

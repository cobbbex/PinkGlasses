-- +goose Up
-- +goose StatementBegin

-- SSH exits: a VPS reached over SSH that carries a worker for a control plane
-- nothing on the internet can reach — one running at home, behind NAT.
--
-- The connector service holds an SSH session to each one and asks the VPS's
-- sshd to listen on its own loopback (remote_port) and hand every connection
-- back down the session to the gateway. The worker on the VPS talks to
-- http://127.0.0.1:<remote_port>; the gateway is never exposed.
--
-- The private key is sealed (AES-256-GCM under ASM_SECRET_KEY) and never
-- leaves the server. The host key is pinned on first contact.
CREATE TABLE IF NOT EXISTS ssh_exit (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    name            text NOT NULL,
    host            text NOT NULL,
    port            integer NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username        text NOT NULL,
    private_key     bytea NOT NULL,          -- sealed
    public_key      text NOT NULL,           -- authorized_keys line, shown to the user
    host_key        text,                    -- pinned on first contact (SHA256:… fingerprint)
    remote_port     integer NOT NULL DEFAULT 47090 CHECK (remote_port BETWEEN 1024 AND 65535),
    pool_id         uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    worker_name     text NOT NULL,
    -- connector-owned state
    status          text NOT NULL DEFAULT 'connecting',  -- connecting | connected | error
    last_error      text,
    connected_at    timestamptz,
    remote_addr     text,                    -- the address the session reached
    -- install: the api marks it pending; the connector mints a single-use
    -- enrolment token, runs the install over the session and records the outcome
    install_status  text NOT NULL DEFAULT 'none',        -- none | pending | running | done | failed
    install_log     text,
    installed_at    timestamptz,
    deleting        boolean NOT NULL DEFAULT false,      -- connector removes the worker, then the row
    created_by      text NOT NULL DEFAULT 'local',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_id, name)
);

-- An enrolment token minted for an SSH exit was delivered over a session the
-- app itself authenticated, so the worker redeeming it needs no approval, and
-- its egress is the VPS's address rather than the tunnel's private end.
ALTER TABLE enrollment_token ADD COLUMN IF NOT EXISTS preapproved boolean NOT NULL DEFAULT false;
ALTER TABLE enrollment_token ADD COLUMN IF NOT EXISTS egress_hint inet;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE enrollment_token DROP COLUMN IF EXISTS egress_hint;
ALTER TABLE enrollment_token DROP COLUMN IF EXISTS preapproved;
DROP TABLE IF EXISTS ssh_exit;
-- +goose StatementEnd

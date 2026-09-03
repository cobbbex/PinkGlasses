-- +goose Up
-- +goose StatementBegin

-- VPN configurations a scan can leave through.
--
-- The config body is a private key and credentials for somebody's network, so
-- it is stored sealed (AES-256-GCM under ASM_SECRET_KEY) and never returned by
-- the API. What the UI shows is metadata only: name, kind, and the endpoint
-- parsed out of the file so a config is recognisable without opening it.
CREATE TABLE IF NOT EXISTS vpn_config (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id    uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    name        text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('wireguard','openvpn')),
    endpoint    text,                       -- host:port, for display only
    config      bytea NOT NULL,             -- sealed; never leaves the server in the clear
    last_egress_ip text,                    -- what the tunnel was last seen exiting from
    last_checked_at timestamptz,
    created_by  text NOT NULL DEFAULT 'local',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, name)
);
CREATE INDEX IF NOT EXISTS idx_vpn_config_scope ON vpn_config (scope_id);

-- Which VPN a run left through, so a result can be traced back to the address
-- it was collected from.
ALTER TABLE scan_run ADD COLUMN IF NOT EXISTS vpn_config_id uuid
    REFERENCES vpn_config(id) ON DELETE SET NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_run DROP COLUMN IF EXISTS vpn_config_id;
DROP TABLE IF EXISTS vpn_config;
-- +goose StatementEnd

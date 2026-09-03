-- +goose Up
-- +goose StatementBegin

-- Where to send word of a change, per company. The differ has been recording
-- what changed since the first run; until now nothing read it but the run page.
--
-- A channel says which kinds of change are worth a message and, for findings,
-- the least severity worth one. The URL is a secret for Slack — an incoming
-- webhook URL is a bearer token — so the API returns it masked.
CREATE TABLE IF NOT EXISTS notification_channel (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id     uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('webhook','slack')),
    url          text NOT NULL,
    events       text[] NOT NULL DEFAULT ARRAY['new_finding','finding_returned','new_port'],
    min_severity text NOT NULL DEFAULT 'low',
    enabled      boolean NOT NULL DEFAULT true,
    created_by   text NOT NULL DEFAULT 'local',
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_channel_scope ON notification_channel (scope_id);

-- One digest per channel per run, and a record of whether it arrived. A
-- webhook that has been failing for a month should be visible in the UI, not
-- discovered when someone asks why they never heard about the open RDP port.
CREATE TABLE IF NOT EXISTS notification_delivery (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id  uuid NOT NULL REFERENCES notification_channel(id) ON DELETE CASCADE,
    run_id      uuid REFERENCES scan_run(id) ON DELETE SET NULL,
    events      integer NOT NULL DEFAULT 0,
    status      text NOT NULL,          -- 'sent' | 'failed' | 'skipped'
    error       text,
    sent_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (channel_id, run_id)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS notification_delivery;
DROP TABLE IF EXISTS notification_channel;
-- +goose StatementEnd

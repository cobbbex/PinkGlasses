-- +goose Up
-- +goose StatementBegin
CREATE TABLE scope (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scope_target (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id      uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    kind          text NOT NULL,                     -- 'domain' | 'cidr' | 'asn' | 'ip'
    value         text NOT NULL,
    tags          text[] NOT NULL DEFAULT '{}',
    mode          text NOT NULL DEFAULT 'passive_only', -- 'active' | 'passive_only' | 'exclude'
    pool_id       uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    authorized_by text,
    authorized_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, kind, value)
);

CREATE TABLE scan_run (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id        uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    profile         text NOT NULL DEFAULT 'standard', -- 'passive' | 'standard' | 'deep'
    trigger         text NOT NULL DEFAULT 'manual',   -- 'schedule' | 'manual' | 'api'
    status          text NOT NULL DEFAULT 'queued',   -- queued|planning|running|completed|failed|cancelled
    pool_id         uuid REFERENCES worker_pool(id) ON DELETE SET NULL,
    max_concurrency int NOT NULL DEFAULT 32,
    started_at      timestamptz,
    finished_at     timestamptz,
    stats           jsonb NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE run_target (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    value       text NOT NULL,
    status      text NOT NULL DEFAULT 'pending',      -- pending|running|completed|incomplete|failed|skipped
    skip_reason text,
    tasks_total int NOT NULL DEFAULT 0,
    tasks_done  int NOT NULL DEFAULT 0,
    started_at  timestamptz,
    finished_at timestamptz,
    UNIQUE (run_id, kind, value)
);

CREATE TABLE scan_task (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id           uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    stage            text NOT NULL,
    target           jsonb NOT NULL,
    requires         text[] NOT NULL DEFAULT '{}',    -- capabilities: raw_socket, browser, ...
    priority         int  NOT NULL DEFAULT 100,
    status           text NOT NULL DEFAULT 'pending', -- pending|leased|running|done|failed|cancelled
    worker_id        uuid REFERENCES worker(id) ON DELETE SET NULL,
    lease_token      uuid,
    lease_expires_at timestamptz,
    attempts         int NOT NULL DEFAULT 0,
    max_attempts     int NOT NULL DEFAULT 3,
    error            text,
    result           jsonb,
    started_at       timestamptz,
    finished_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE task_origin (
    task_id       uuid REFERENCES scan_task(id) ON DELETE CASCADE,
    run_target_id uuid REFERENCES run_target(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, run_target_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS task_origin;
DROP TABLE IF EXISTS scan_task;
DROP TABLE IF EXISTS run_target;
DROP TABLE IF EXISTS scan_run;
DROP TABLE IF EXISTS scope_target;
DROP TABLE IF EXISTS scope;
-- +goose StatementEnd

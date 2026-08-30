-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- lease hot paths
CREATE INDEX idx_task_pending  ON scan_task (priority, run_id, id) WHERE status = 'pending';
CREATE INDEX idx_task_leased   ON scan_task (lease_expires_at) WHERE status = 'leased';
CREATE INDEX idx_task_run      ON scan_task (run_id, status);

-- fairness helper: tasks per run_target
CREATE INDEX idx_task_origin_target ON task_origin (run_target_id);

-- CIDR containment (addr <<= cidr)
CREATE INDEX idx_ip_addr_gist ON ip_address USING gist (addr inet_ops);
CREATE INDEX idx_ip_scope_seen ON ip_address (scope_id, last_seen);

-- asset lookups
CREATE INDEX idx_domain_scope_seen ON domain (scope_id, last_seen);
CREATE INDEX idx_domain_name_trgm  ON domain USING gin (name gin_trgm_ops);
CREATE INDEX idx_dns_domain        ON dns_record (domain_id);
CREATE INDEX idx_service_ip        ON service (ip_id, port);
CREATE INDEX idx_domain_ip_ip      ON domain_ip (ip_id);

-- search over observations
CREATE INDEX idx_obs_http_gin ON service_observation USING gin (http);
CREATE INDEX idx_obs_tls_gin  ON service_observation USING gin (tls);
CREATE INDEX idx_obs_service  ON service_observation (service_id);

-- findings / changes
CREATE INDEX idx_finding_scope  ON finding (scope_id, status, severity);
CREATE INDEX idx_change_run     ON change_event (run_id);
CREATE INDEX idx_change_scope   ON change_event (scope_id, created_at);

-- worker liveness
CREATE INDEX idx_worker_status ON worker (status, last_seen_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_worker_status;
DROP INDEX IF EXISTS idx_change_scope;
DROP INDEX IF EXISTS idx_change_run;
DROP INDEX IF EXISTS idx_finding_scope;
DROP INDEX IF EXISTS idx_obs_service;
DROP INDEX IF EXISTS idx_obs_tls_gin;
DROP INDEX IF EXISTS idx_obs_http_gin;
DROP INDEX IF EXISTS idx_domain_ip_ip;
DROP INDEX IF EXISTS idx_service_ip;
DROP INDEX IF EXISTS idx_dns_domain;
DROP INDEX IF EXISTS idx_domain_name_trgm;
DROP INDEX IF EXISTS idx_domain_scope_seen;
DROP INDEX IF EXISTS idx_ip_scope_seen;
DROP INDEX IF EXISTS idx_ip_addr_gist;
DROP INDEX IF EXISTS idx_task_origin_target;
DROP INDEX IF EXISTS idx_task_run;
DROP INDEX IF EXISTS idx_task_leased;
DROP INDEX IF EXISTS idx_task_pending;
-- +goose StatementEnd

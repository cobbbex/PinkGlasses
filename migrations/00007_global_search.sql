-- +goose Up
-- +goose StatementBegin
-- Cross-company search (Phase 14) joins scope and filters on company name and
-- on service product/version across all scopes. The existing indexes assume a
-- scope_id prefix; add ones that serve a global scan.
CREATE INDEX IF NOT EXISTS idx_scope_name_trgm ON scope USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_service_port_all ON service (port);
CREATE INDEX IF NOT EXISTS idx_obs_product ON service_observation (product) WHERE product IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_obs_product;
DROP INDEX IF EXISTS idx_service_port_all;
DROP INDEX IF EXISTS idx_scope_name_trgm;
-- +goose StatementEnd

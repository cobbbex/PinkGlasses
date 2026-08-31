-- +goose Up
-- +goose StatementBegin

-- The announcing prefix for a host's ASN, e.g. 93.184.216.0/24. dnsx returns it
-- alongside the AS number and name when resolving, so every subdomain can carry
-- full network provenance without a separate enrichment source.
ALTER TABLE ip_address ADD COLUMN IF NOT EXISTS as_range text;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ip_address DROP COLUMN IF EXISTS as_range;
-- +goose StatementEnd

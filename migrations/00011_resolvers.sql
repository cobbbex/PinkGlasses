-- +goose Up
-- +goose StatementBegin

-- Resolver lists reuse the wordlist registry: they are line-oriented files that
-- need the same upload, storage, presign and per-worker caching. kind keeps them
-- separate from the subdomain wordlists.
INSERT INTO wordlist (name, kind, object_key, source_url, builtin, is_default) VALUES
  ('trickest public resolvers', 'resolvers', 'wordlists/builtin/resolvers.txt',
   'https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt', true, true)
ON CONFLICT (name) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM wordlist WHERE kind = 'resolvers' AND builtin;
-- +goose StatementEnd

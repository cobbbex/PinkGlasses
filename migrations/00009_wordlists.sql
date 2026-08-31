-- +goose Up
-- +goose StatementBegin

-- Registry of wordlists available to scans. Files themselves live in object
-- storage, not in the worker image: the assetnote DNS lists are millions of
-- lines and would bloat every worker. Workers download by presigned URL and
-- cache on disk keyed by sha256, so each list is fetched once per box.
CREATE TABLE wordlist (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    kind        text NOT NULL DEFAULT 'dns',      -- 'dns' | 'dir'
    object_key  text NOT NULL,                    -- key in the artifact bucket
    source_url  text,                             -- where a built-in came from
    sha256      text,                             -- set once fetched; also the cache key
    size_bytes  bigint NOT NULL DEFAULT 0,
    line_count  bigint NOT NULL DEFAULT 0,
    builtin     boolean NOT NULL DEFAULT false,   -- shipped with the app; cannot be deleted
    is_default  boolean NOT NULL DEFAULT false,   -- pre-selected for a standard scan
    status      text NOT NULL DEFAULT 'pending',  -- pending|fetching|ready|failed
    error       text,
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_wordlist_kind ON wordlist (kind, status);

-- The two assetnote DNS lists are the shipped defaults for subdomain
-- brute-forcing. They are registered here and fetched into object storage on
-- first boot; until that completes their status is 'pending' and the planner
-- simply skips them.
INSERT INTO wordlist (name, kind, object_key, source_url, builtin, is_default) VALUES
  ('assetnote best-dns-wordlist', 'dns', 'wordlists/builtin/best-dns-wordlist.txt',
   'https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt', true, true),
  ('assetnote httparchive subdomains', 'dns', 'wordlists/builtin/httparchive_subdomains.txt',
   'https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt', true, true);

-- Which wordlists a run brute-forced with, so a run stays reproducible even if
-- the registry changes afterwards.
CREATE TABLE run_wordlist (
    run_id      uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    wordlist_id uuid NOT NULL REFERENCES wordlist(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, wordlist_id)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS run_wordlist;
DROP TABLE IF EXISTS wordlist;
-- +goose StatementEnd

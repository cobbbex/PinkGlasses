-- +goose Up
-- +goose StatementBegin

-- Directory brute-forcing was the one stage still limited to whatever list was
-- baked into the worker image: the registry already carried its 'dir' kind and
-- the upload endpoint already accepted it, but nothing was ever registered
-- under it and no run delivered one. These two are the shipped defaults, fetched
-- into object storage on first boot like the DNS lists; until that completes
-- their status is 'pending' and the stage falls back to the image's own list.
INSERT INTO wordlist (name, kind, object_key, source_url, builtin, is_default) VALUES
  ('seclists common web content', 'dir', 'wordlists/builtin/dir-common.txt',
   'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
   true, true),
  ('seclists raft medium directories', 'dir', 'wordlists/builtin/dir-raft-medium.txt',
   'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt',
   true, false)
ON CONFLICT (name) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM wordlist WHERE kind = 'dir' AND builtin;
-- +goose StatementEnd

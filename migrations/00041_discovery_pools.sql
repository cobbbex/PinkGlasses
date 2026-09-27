-- +goose Up
-- A pool can be marked to take discovery work — the stages that talk to
-- third-party APIs and public resolvers and never touch the target. Until now
-- those always ran on the standing workers beside the control plane, so on a
-- busy install discovery for every company queued behind one machine. Marking
-- a pool of enrolled workers moves that work onto them.
ALTER TABLE worker_pool ADD COLUMN IF NOT EXISTS takes_discovery boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE worker_pool DROP COLUMN IF EXISTS takes_discovery;

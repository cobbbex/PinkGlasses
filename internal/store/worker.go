package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// CreateEnrollmentToken stores the hash of an enrollment token. The token's
// kind ('local' | 'vps') decides what kind of worker it may mint — the worker
// never gets to claim its own kind.
func (s *Store) CreateEnrollmentToken(ctx context.Context, hash []byte, poolID *uuid.UUID, createdBy *uuid.UUID, ttl time.Duration, maxUses int, kind string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO enrollment_token (token_hash, pool_id, created_by, expires_at, max_uses, kind)
		VALUES ($1,$2,$3, now()+$4::interval, $5, $6) RETURNING id`,
		hash, poolID, createdBy, ttl.String(), maxUses, kind,
	).Scan(&id)
	return id, err
}

// EnsureBootstrapToken upserts the long-lived, multi-use token that local
// workers use to self-enroll. It is shared with worker containers over the
// internal network, so scaling with `docker compose --scale` needs no manual
// token step. Safe to call on every gateway start.
func (s *Store) EnsureBootstrapToken(ctx context.Context, hash []byte, poolID *uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO enrollment_token (token_hash, pool_id, expires_at, max_uses, kind)
		VALUES ($1,$2, now()+interval '10 years', 1000000, 'local')
		ON CONFLICT (token_hash) DO UPDATE SET
		  pool_id=EXCLUDED.pool_id, expires_at=EXCLUDED.expires_at,
		  max_uses=EXCLUDED.max_uses, kind='local', revoked_at=NULL`,
		hash, poolID)
	return err
}

// PoolByName returns a worker pool id by name.
func (s *Store) PoolByName(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM worker_pool WHERE name=$1`, name).Scan(&id)
	return id, err
}

// RedeemEnrollmentToken validates and burns one use of a token, returning the
// pool and the worker kind it grants. Safe under concurrency (atomic update).
func (s *Store) RedeemEnrollmentToken(ctx context.Context, hash []byte) (*uuid.UUID, string, bool, error) {
	var poolID *uuid.UUID
	var kind string
	err := s.Pool.QueryRow(ctx, `
		UPDATE enrollment_token SET uses = uses + 1
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now() AND uses < max_uses
		RETURNING pool_id, kind`, hash).Scan(&poolID, &kind)
	if err != nil {
		return nil, "", false, nil //nolint:nilerr // invalid/expired token
	}
	return poolID, kind, true, nil
}

// CreateWorker inserts a worker with the given status. Remote workers land in
// 'pending' and need human approval; local workers enrolled from inside the
// network are created 'active' (architecture.md §7.2).
func (s *Store) CreateWorker(ctx context.Context, w domain.Worker, credHash []byte, status domain.WorkerStatus) (uuid.UUID, error) {
	tools, _ := json.Marshal(w.Tools)
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO worker (pool_id, name, kind, status, capabilities, tools, agent_version, egress_ip, country, max_concurrency, cred_hash, enrolled_at, last_seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now(), now())
		RETURNING id`,
		w.PoolID, w.Name, w.Kind, status, w.Capabilities, tools, w.AgentVersion, w.EgressIP, w.Country, w.MaxConcurrency, credHash,
	).Scan(&id)
	return id, err
}

// ReapStaleLocalWorkers deletes local workers that stopped heartbeating long
// ago. Scaling with `docker compose --scale` recreates containers, and each
// recreation self-enrolls fresh, so old rows would otherwise pile up. Remote
// workers are never auto-deleted — their history is forensic evidence.
func (s *Store) ReapStaleLocalWorkers(ctx context.Context, cutoff time.Duration) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `
		DELETE FROM worker
		WHERE kind='local' AND status <> 'quarantined'
		  AND last_seen_at < now() - $1::interval`, cutoff.String())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// AuthenticateWorker looks up an active/pending worker by id and verifies the
// caller holds the matching credential hash. Returns the worker on success.
// ErrNoWorker is returned by WorkerForAuth when the row does not exist — as
// opposed to a transient database error. The two must be told apart: a missing
// worker should be sent away to re-enrol, a hiccup should be waited out.
var ErrNoWorker = errors.New("no such worker")

func (s *Store) WorkerForAuth(ctx context.Context, id uuid.UUID) (domain.Worker, []byte, error) {
	var w domain.Worker
	var credHash []byte
	var toolsRaw []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT id, pool_id, name, kind, status, capabilities, tools, agent_version, host(egress_ip), country, max_concurrency, running_tasks, cred_hash, last_seen_at, enrolled_at
		FROM worker WHERE id=$1`, id,
	).Scan(&w.ID, &w.PoolID, &w.Name, &w.Kind, &w.Status, &w.Capabilities, &toolsRaw,
		&w.AgentVersion, &w.EgressIP, &w.Country, &w.MaxConcurrency, &w.RunningTasks, &credHash, &w.LastSeenAt, &w.EnrolledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, nil, ErrNoWorker
	}
	if err != nil {
		return w, nil, err
	}
	_ = json.Unmarshal(toolsRaw, &w.Tools)
	return w, credHash, nil
}

// SetWorkerStatus updates a worker's status.
func (s *Store) SetWorkerStatus(ctx context.Context, id uuid.UUID, status domain.WorkerStatus) error {
	_, err := s.Pool.Exec(ctx, `UPDATE worker SET status=$2 WHERE id=$1`, id, status)
	return err
}

// TouchWorker records a heartbeat and observed egress IP.
func (s *Store) TouchWorker(ctx context.Context, id uuid.UUID, egressIP string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE worker SET last_seen_at=now(),
		  egress_ip = CASE WHEN $2<>'' THEN $2::inet ELSE egress_ip END
		WHERE id=$1`, id, egressIP)
	return err
}

// ListWorkers returns all workers for the fleet page.
func (s *Store) ListWorkers(ctx context.Context) ([]domain.Worker, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT w.id, w.pool_id, w.name, w.kind, w.status, w.capabilities, w.tools, w.agent_version,
		       host(w.egress_ip), w.country, w.max_concurrency, w.running_tasks, w.last_seen_at, w.enrolled_at,
		       coalesce(p.run_scoped, false)
		FROM worker w LEFT JOIN worker_pool p ON p.id = w.pool_id
		ORDER BY w.enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Worker
	for rows.Next() {
		var w domain.Worker
		var toolsRaw []byte
		if err := rows.Scan(&w.ID, &w.PoolID, &w.Name, &w.Kind, &w.Status, &w.Capabilities, &toolsRaw,
			&w.AgentVersion, &w.EgressIP, &w.Country, &w.MaxConcurrency, &w.RunningTasks,
			&w.LastSeenAt, &w.EnrolledAt, &w.RunScoped); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(toolsRaw, &w.Tools)
		out = append(out, w)
	}
	return out, rows.Err()
}

// StaleWorkers marks workers stale after missing heartbeats for the cutoff.
func (s *Store) MarkStaleWorkers(ctx context.Context, cutoff time.Duration) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE worker SET status='stale'
		WHERE status='active' AND last_seen_at < now() - $1::interval`, cutoff.String())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// DefaultPool returns the id of the default worker pool.
func (s *Store) DefaultPool(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM worker_pool WHERE is_default LIMIT 1`).Scan(&id)
	return id, err
}

// DeleteWorker removes a worker record. Its credential dies with it, so the
// agent's next connect fails and it exits.
func (s *Store) DeleteWorker(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM worker WHERE id=$1`, id)
	return err
}

// DeleteLocalWorkersByContainer removes local worker rows whose backing
// container is gone. A worker's name is its container hostname (the short id),
// so a row matches when a removed full container id starts with that name.
//
// Only rows created by a real container are eligible (name length >= 8), and only
// local ones — a VPS worker's record is never removed implicitly.
func (s *Store) DeleteLocalWorkersByContainer(ctx context.Context, containerIDs []string) (int64, error) {
	if len(containerIDs) == 0 {
		return 0, nil
	}
	ct, err := s.Pool.Exec(ctx, `
		DELETE FROM worker
		WHERE kind = 'local'
		  AND length(name) >= 8
		  AND EXISTS (
		        SELECT 1 FROM unnest($1::text[]) AS cid
		        WHERE cid LIKE worker.name || '%'
		      )`, containerIDs)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// ReviveWorker returns a stale worker to active. A worker that has just opened a
// control channel is demonstrably alive, so leaving it stale would bench it
// permanently: the dispatcher only leases to active workers, and nothing else
// moves a worker out of stale.
func (s *Store) ReviveWorker(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE worker SET status='active', last_seen_at=now() WHERE id=$1 AND status='stale'`, id)
	return err
}

// MarkWorkerDisconnected flags an active worker stale the moment its control
// channel closes, rather than waiting for the heartbeat sweep. Only 'active' is
// touched: draining, quarantined and revoked are deliberate states that a
// disconnect must not clear.
func (s *Store) MarkWorkerDisconnected(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE worker SET status='stale' WHERE id=$1 AND status='active'`, id)
	return err
}

// ReleaseWorkerLeases returns a worker's in-flight tasks to the queue at once.
//
// Only called when a worker says it is shutting down: then we know the work is
// not continuing and another worker should pick it up immediately, instead of
// the run stalling for the lease TTL. An abrupt disconnect deliberately does NOT
// use this — the task may still be running, and the lease timeout exists to
// tolerate a brief network blip without duplicating work.
func (s *Store) ReleaseWorkerLeases(ctx context.Context, id uuid.UUID) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET
		  status='pending', lease_token=NULL, worker_id=NULL, lease_expires_at=NULL
		WHERE worker_id=$1 AND status IN ('leased','running')`, id)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// PruneReplacedWorker removes a disconnected local worker that a newly enrolling
// one is replacing.
//
// Local workers hold ephemeral credentials, so a restarted container enrolls
// afresh rather than resuming its old identity. Without this the fleet list
// grows a duplicate row per restart — same name, one stale, one active — which
// is confusing precisely when you are trying to tell whether a worker came back.
// Only stale rows of the same name and kind are removed: an active worker with
// that name is a different, live machine and must not be touched.
func (s *Store) PruneReplacedWorker(ctx context.Context, name, kind string) (int64, error) {
	if name == "" {
		return 0, nil
	}
	ct, err := s.Pool.Exec(ctx, `
		DELETE FROM worker
		WHERE name = $1 AND kind = $2 AND status IN ('stale', 'pending')`, name, kind)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

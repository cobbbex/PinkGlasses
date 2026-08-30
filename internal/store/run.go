package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/domain"
)

// CreateRun inserts a scan run and its per-target rows in one transaction, so a
// run can never be half-created.
func (s *Store) CreateRun(ctx context.Context, run domain.ScanRun, targets []domain.RunTarget) (domain.ScanRun, []domain.RunTarget, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return run, nil, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO scan_run (scope_id, profile, trigger, status, pool_id, max_concurrency)
		VALUES ($1,$2,$3,'queued',$4,$5)
		RETURNING id, status, created_at`,
		run.ScopeID, run.Profile, run.Trigger, run.PoolID, run.MaxConcurrency,
	).Scan(&run.ID, &run.Status, &run.CreatedAt)
	if err != nil {
		return run, nil, err
	}

	out := make([]domain.RunTarget, 0, len(targets))
	for _, t := range targets {
		t.RunID = run.ID
		err = tx.QueryRow(ctx, `
			INSERT INTO run_target (run_id, kind, value, status)
			VALUES ($1,$2,$3,'pending') RETURNING id`,
			t.RunID, t.Kind, t.Value,
		).Scan(&t.ID)
		if err != nil {
			return run, nil, err
		}
		out = append(out, t)
	}
	return run, out, tx.Commit(ctx)
}

// GetRun fetches one run.
func (s *Store) GetRun(ctx context.Context, id uuid.UUID) (domain.ScanRun, error) {
	var r domain.ScanRun
	err := s.Pool.QueryRow(ctx, `
		SELECT id, scope_id, profile, trigger, status, pool_id, max_concurrency, started_at, finished_at, created_at
		FROM scan_run WHERE id=$1`, id,
	).Scan(&r.ID, &r.ScopeID, &r.Profile, &r.Trigger, &r.Status, &r.PoolID,
		&r.MaxConcurrency, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	return r, err
}

// SetRunStatus updates a run's status, stamping timestamps as appropriate.
func (s *Store) SetRunStatus(ctx context.Context, id uuid.UUID, status domain.RunStatus) error {
	var ts string
	switch status {
	case domain.RunRunning:
		ts = ", started_at=coalesce(started_at, now())"
	case domain.RunCompleted, domain.RunFailed, domain.RunCancelled:
		ts = ", finished_at=now()"
	}
	_, err := s.Pool.Exec(ctx, `UPDATE scan_run SET status=$2`+ts+` WHERE id=$1`, id, status)
	return err
}

// ListRunTargets returns the per-target progress rows of a run.
func (s *Store) ListRunTargets(ctx context.Context, runID uuid.UUID) ([]domain.RunTarget, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, run_id, kind, value, status, skip_reason, tasks_total, tasks_done
		FROM run_target WHERE run_id=$1 ORDER BY value`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RunTarget
	for rows.Next() {
		var t domain.RunTarget
		if err := rows.Scan(&t.ID, &t.RunID, &t.Kind, &t.Value, &t.Status,
			&t.SkipReason, &t.TasksTotal, &t.TasksDone); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetRunTargetStatus updates one run target's status and optional skip reason.
func (s *Store) SetRunTargetStatus(ctx context.Context, id uuid.UUID, status domain.TargetStatus, skipReason *string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE run_target SET status=$2, skip_reason=$3,
		  started_at = CASE WHEN $2='running' THEN coalesce(started_at, now()) ELSE started_at END,
		  finished_at = CASE WHEN $2 IN ('completed','incomplete','failed','skipped') THEN now() ELSE finished_at END
		WHERE id=$1`, id, status, skipReason)
	return err
}

// ListRuns returns recent runs for a scope.
func (s *Store) ListRuns(ctx context.Context, scopeID uuid.UUID, limit int) ([]domain.ScanRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, profile, trigger, status, pool_id, max_concurrency, started_at, finished_at, created_at
		FROM scan_run WHERE scope_id=$1 ORDER BY created_at DESC LIMIT $2`, scopeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanRun
	for rows.Next() {
		var r domain.ScanRun
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.Profile, &r.Trigger, &r.Status, &r.PoolID,
			&r.MaxConcurrency, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueuedRuns returns runs waiting to be planned/started (used by scheduler).
func (s *Store) QueuedRuns(ctx context.Context) ([]domain.ScanRun, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, profile, trigger, status, pool_id, max_concurrency, started_at, finished_at, created_at
		FROM scan_run WHERE status='queued' ORDER BY created_at LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanRun
	for rows.Next() {
		var r domain.ScanRun
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.Profile, &r.Trigger, &r.Status, &r.PoolID,
			&r.MaxConcurrency, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunClock returns the previous completed run for a scope before a given time,
// used by the differ as the diff baseline.
func (s *Store) PreviousRun(ctx context.Context, scopeID, exclude uuid.UUID) (uuid.UUID, bool, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		SELECT id FROM scan_run
		WHERE scope_id=$1 AND status='completed' AND id<>$2
		ORDER BY finished_at DESC NULLS LAST LIMIT 1`, scopeID, exclude).Scan(&id)
	if err != nil {
		return uuid.Nil, false, nil //nolint:nilerr // no baseline yet is not an error
	}
	return id, true, nil
}

var _ = time.Now

// RunningRuns returns runs in the running state (used by the scheduler to
// advance the stage machine).
func (s *Store) RunningRuns(ctx context.Context) ([]domain.ScanRun, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, profile, trigger, status, pool_id, max_concurrency, started_at, finished_at, created_at
		FROM scan_run WHERE status='running' ORDER BY created_at LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanRun
	for rows.Next() {
		var r domain.ScanRun
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.Profile, &r.Trigger, &r.Status, &r.PoolID,
			&r.MaxConcurrency, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TryAdvisoryLock grabs a session-level advisory lock so only one scheduler is
// the leader (architecture.md §3.3). Returns true if acquired.
func (s *Store) TryAdvisoryLock(ctx context.Context, key int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok)
	return ok, err
}

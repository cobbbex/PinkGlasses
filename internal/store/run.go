package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
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

// PauseRun holds a running run. Leasing already requires status='running', so
// from the next lease onward no worker is handed one of its tasks; the ones in
// flight finish and report as usual. Returns false when the run was not running.
func (s *Store) PauseRun(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `UPDATE scan_run SET status='paused' WHERE id=$1 AND status='running'`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// ResumeRun lets a paused run continue. Returns false when it was not paused.
func (s *Store) ResumeRun(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `UPDATE scan_run SET status='running' WHERE id=$1 AND status='paused'`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// RerunSpec is what it takes to start a run like an old one: the choices a
// person made in the launch dialog, read back from where the run recorded them.
type RerunSpec struct {
	ScopeID     uuid.UUID
	Profile     string
	ProfileID   *uuid.UUID
	Params      map[string]string
	WordlistIDs []uuid.UUID
	// Exit is "local" when the run had its own fleet (VPNConfigID and Workers
	// come from it), "remote" when it was bound to a standing pool, "" for a
	// passive run.
	Exit        string
	VPNConfigID *uuid.UUID
	PoolID      *uuid.UUID
	Workers     int
}

// RerunSpec reads the launch choices back off a run.
func (s *Store) RerunSpec(ctx context.Context, id uuid.UUID) (RerunSpec, error) {
	var sp RerunSpec
	var raw []byte
	var hadFleet bool
	err := s.Pool.QueryRow(ctx, `
		SELECT r.scope_id, r.profile, r.profile_id, r.params, r.pool_id,
		       f.run_id IS NOT NULL, f.vpn_config_id, COALESCE(f.workers, 0),
		       COALESCE((SELECT array_agg(wordlist_id) FROM run_wordlist WHERE run_id=r.id), '{}')
		FROM scan_run r LEFT JOIN run_fleet f ON f.run_id = r.id
		WHERE r.id=$1`, id).Scan(&sp.ScopeID, &sp.Profile, &sp.ProfileID, &raw, &sp.PoolID,
		&hadFleet, &sp.VPNConfigID, &sp.Workers, &sp.WordlistIDs)
	if err != nil {
		return sp, err
	}
	_ = json.Unmarshal(raw, &sp.Params)
	switch {
	case sp.Profile == "passive":
		sp.Exit = ""
	case hadFleet:
		sp.Exit = "local"
	case sp.PoolID != nil:
		sp.Exit = "remote"
	}
	return sp, nil
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
// RunListItem is a run as the runs table shows it: the run itself, what it is
// scanning, and how far along it is. Targets and progress are aggregated in the
// same query rather than fetched per row, so the list costs one round trip
// however many runs it shows.
type RunListItem struct {
	domain.ScanRun
	Targets     []string `json:"targets"`
	TargetCount int      `json:"target_count"`
	Total       int      `json:"tasks_total"`
	Done        int      `json:"tasks_done"`
	Failed      int      `json:"tasks_failed"`
	Outstanding int      `json:"tasks_outstanding"`
}

// ListRunSummaries returns runs with their targets and task progress.
func (s *Store) ListRunSummaries(ctx context.Context, scopeID uuid.UUID, limit int) ([]RunListItem, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT r.id, r.scope_id, r.profile, r.trigger, r.status, r.pool_id,
		       r.max_concurrency, r.started_at, r.finished_at, r.created_at,
		       COALESCE(t.cnt, 0), COALESCE(t.names, '{}'),
		       COALESCE(p.total, 0), COALESCE(p.done, 0),
		       COALESCE(p.failed, 0), COALESCE(p.outstanding, 0)
		FROM scan_run r
		LEFT JOIN LATERAL (
		  -- a label for the row, not the whole list: a run can cover hundreds
		  SELECT count(*) AS cnt, (array_agg(value ORDER BY value))[1:3] AS names
		  FROM run_target WHERE run_id = r.id
		) t ON true
		LEFT JOIN LATERAL (
		  SELECT count(*) AS total,
		         count(*) FILTER (WHERE status='done') AS done,
		         count(*) FILTER (WHERE status='failed') AS failed,
		         count(*) FILTER (WHERE status IN ('pending','leased','running')) AS outstanding
		  FROM scan_task WHERE run_id = r.id
		) p ON true
		WHERE r.scope_id=$1 ORDER BY r.created_at DESC LIMIT $2`, scopeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunListItem{}
	for rows.Next() {
		var it RunListItem
		r := &it.ScanRun
		if err := rows.Scan(&r.ID, &r.ScopeID, &r.Profile, &r.Trigger, &r.Status, &r.PoolID,
			&r.MaxConcurrency, &r.StartedAt, &r.FinishedAt, &r.CreatedAt,
			&it.TargetCount, &it.Targets,
			&it.Total, &it.Done, &it.Failed, &it.Outstanding); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

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

// FailZombieRuns fails runs that have sat in 'queued' past the grace period
// with no tasks at all.
//
// A run is planned right after it is created; one that still has no tasks
// minutes later had its planning fail after the row was written, and nothing
// will ever advance it — the planner only looks at running runs. Left alone it
// is not merely clutter: ScopeHasActiveRun counts it, so it blocks every
// scheduled scan for its company forever. Two such runs, from 2 and 4 September,
// were doing exactly that.
func (s *Store) FailZombieRuns(ctx context.Context, olderThan time.Duration) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE scan_run r SET status='failed', finished_at=now()
		WHERE r.status='queued'
		  AND r.created_at < now() - $1::interval
		  AND NOT EXISTS (SELECT 1 FROM scan_task t WHERE t.run_id = r.id)`, olderThan.String())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

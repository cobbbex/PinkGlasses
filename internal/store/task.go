package store

import (
	"time"
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/scanproto"
)

// TaskSpec describes a task to insert, with the run targets it originated from.
type TaskSpec struct {
	Stage    scanproto.Stage
	Target   scanproto.Target
	Requires []string
	Priority int
	Origins  []uuid.UUID // run_target ids this task serves
	// Wordlist is the wordlist id a dns_brute task must use. It is stored on
	// the task's target JSON so the gateway can presign the right file when the
	// task is finally dispatched, which may be long after planning.
	Wordlist string
}

// InsertTasks inserts a batch of tasks and their task_origin edges in one
// transaction, and bumps each run_target's tasks_total.
func (s *Store) InsertTasks(ctx context.Context, runID uuid.UUID, specs []TaskSpec) ([]uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	ids := make([]uuid.UUID, 0, len(specs))
	for _, sp := range specs {
		if sp.Requires == nil {
			sp.Requires = []string{} // column is NOT NULL
		}
		target := sp.Target
		if sp.Wordlist != "" {
			target.WordlistID = sp.Wordlist
		}
		tgt, _ := json.Marshal(target)
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan_task (run_id, stage, target, requires, priority, status)
			VALUES ($1,$2,$3,$4,$5,'pending') RETURNING id`,
			runID, sp.Stage, tgt, sp.Requires, sp.Priority,
		).Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		for _, ot := range sp.Origins {
			if ot == uuid.Nil {
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO task_origin (task_id, run_target_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
				id, ot); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx,
				`UPDATE run_target SET tasks_total = tasks_total + 1 WHERE id=$1`, ot); err != nil {
				return nil, err
			}
		}
	}
	return ids, tx.Commit(ctx)
}

// LeaseTasks atomically claims up to `limit` pending tasks for a worker.
//
// It is fair across run_targets: candidates are ordered by how many sibling
// tasks of the same run_target are already in flight, so one huge domain in a
// batch cannot starve the rest. FOR UPDATE SKIP LOCKED lets many workers claim
// concurrently without blocking each other (architecture.md §8.1).
func (s *Store) LeaseTasks(ctx context.Context, workerID uuid.UUID, caps []string, poolID *uuid.UUID, limit, leaseSecs int) ([]scanproto.Job, error) {
	rows, err := s.Pool.Query(ctx, `
		UPDATE scan_task SET
		  status='leased',
		  worker_id=$1,
		  lease_token=gen_random_uuid(),
		  lease_expires_at = now() + make_interval(secs => $5),
		  attempts = attempts + 1,
		  started_at = now()
		WHERE id = ANY (ARRAY(
		  SELECT t.id
		  FROM scan_task t
		  JOIN scan_run r ON r.id = t.run_id
		  WHERE t.status='pending'
		    AND t.requires <@ $2::text[]
		    AND (r.pool_id IS NULL OR $3::uuid IS NULL OR r.pool_id = $3)
		    AND r.status='running'
		  ORDER BY
		    -- fairness: prefer tasks whose run_target has the fewest in-flight
		    -- siblings, so one big target cannot starve the rest of a batch.
		    (SELECT count(*) FROM scan_task t2
		       WHERE t2.status IN ('leased','running')
		         AND EXISTS (
		           SELECT 1 FROM task_origin a JOIN task_origin b ON a.run_target_id=b.run_target_id
		           WHERE a.task_id=t.id AND b.task_id=t2.id)),
		    t.priority, t.id
		  FOR UPDATE SKIP LOCKED
		  LIMIT $4
		))
		RETURNING id, run_id, stage, target, lease_token`,
		workerID, caps, poolID, limit, leaseSecs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []scanproto.Job
	for rows.Next() {
		var (
			id, runID, leaseTok uuid.UUID
			stage               string
			tgtRaw              []byte
		)
		if err := rows.Scan(&id, &runID, &stage, &tgtRaw, &leaseTok); err != nil {
			return nil, err
		}
		var tgt scanproto.Target
		_ = json.Unmarshal(tgtRaw, &tgt)
		jobs = append(jobs, scanproto.Job{
			Schema:     scanproto.JobSchema,
			JobID:      id.String(),
			RunID:      runID.String(),
			TaskID:     id.String(),
			LeaseToken: leaseTok.String(),
			Stage:      scanproto.Stage(stage),
			Targets:    []scanproto.Target{tgt},
		})
	}
	return jobs, rows.Err()
}

// ExtendLeaseForWorker pushes a task's lease expiry forward on the authority of
// the worker holding it. Heartbeats arrive over the worker's authenticated
// control channel and do not carry the lease token, so the worker id is what
// proves ownership here. Without this a task that outlives the lease TTL —
// subfinder alone can — is reaped and retried forever.
func (s *Store) ExtendLeaseForWorker(ctx context.Context, taskID, workerID uuid.UUID, secs int) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET lease_expires_at = now() + make_interval(secs => $3), status='running'
		WHERE id=$1 AND worker_id=$2 AND status IN ('leased','running')`,
		taskID, workerID, secs)
	return err
}

// ExtendLease pushes a task's lease expiry forward (heartbeat).
func (s *Store) ExtendLease(ctx context.Context, taskID, leaseToken uuid.UUID, secs int) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET lease_expires_at = now() + make_interval(secs => $3), status='running'
		WHERE id=$1 AND lease_token=$2 AND status IN ('leased','running')`,
		taskID, leaseToken, secs)
	return err
}

// CompleteTask marks a task done (only if the lease token matches) and bumps
// the tasks_done counter on its run targets.
func (s *Store) CompleteTask(ctx context.Context, taskID, leaseToken uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	ct, err := tx.Exec(ctx, `
		UPDATE scan_task SET status='done', finished_at=now()
		WHERE id=$1 AND lease_token=$2 AND status IN ('leased','running')`, taskID, leaseToken)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return nil // stale lease; ignore
	}
	if _, err := tx.Exec(ctx, `
		UPDATE run_target SET tasks_done = tasks_done + 1
		WHERE id IN (SELECT run_target_id FROM task_origin WHERE task_id=$1)`, taskID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// FailTask records an error. If attempts remain the task returns to pending for
// retry; otherwise it is marked failed.
func (s *Store) FailTask(ctx context.Context, taskID, leaseToken uuid.UUID, msg string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET
		  status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
		  error=$3, lease_token=NULL, worker_id=NULL, lease_expires_at=NULL
		WHERE id=$1 AND lease_token=$2`, taskID, leaseToken, msg)
	return err
}

// ReapExpiredLeases returns expired-lease tasks to pending (or fails them past
// max_attempts). Returns the number reaped. Run by the scheduler.
//
// Both 'leased' and 'running' are reaped: a heartbeat promotes a task to
// 'running', so covering only 'leased' strands every task whose worker dies
// after its first heartbeat — and a stranded task holds the stage barrier, which
// stalls the whole run rather than just losing one task.
func (s *Store) ReapExpiredLeases(ctx context.Context) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET
		  status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
		  lease_token=NULL, worker_id=NULL, lease_expires_at=NULL,
		  error = coalesce(error,'') || ' [lease expired]'
		WHERE status IN ('leased','running') AND lease_expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// CancelRunTasks cancels all unfinished tasks of a run (kill switch / cancel).
func (s *Store) CancelRunTasks(ctx context.Context, runID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET status='cancelled'
		WHERE run_id=$1 AND status IN ('pending','leased','running')`, runID)
	return err
}

// RunProgress reports task counts for a run, used to decide completion.
type RunProgress struct {
	Total, Done, Failed, Outstanding int
}

// RunProgress returns aggregate task progress for a run.
func (s *Store) RunProgress(ctx context.Context, runID uuid.UUID) (RunProgress, error) {
	var p RunProgress
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  count(*),
		  count(*) FILTER (WHERE status='done'),
		  count(*) FILTER (WHERE status='failed'),
		  count(*) FILTER (WHERE status IN ('pending','leased','running'))
		FROM scan_task WHERE run_id=$1`, runID,
	).Scan(&p.Total, &p.Done, &p.Failed, &p.Outstanding)
	return p, err
}

// TaskRow is a lightweight task view for the planner's stage machine.
type TaskRow struct {
	ID     uuid.UUID
	Stage  string
	Status string
	Result []byte
}

// TasksByStage returns tasks of a run at a given stage (with their results).
func (s *Store) TasksByStage(ctx context.Context, runID uuid.UUID, stage scanproto.Stage) ([]TaskRow, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, stage, status, result FROM scan_task WHERE run_id=$1 AND stage=$2`, runID, stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskRow
	for rows.Next() {
		var t TaskRow
		if err := rows.Scan(&t.ID, &t.Stage, &t.Status, &t.Result); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// StageOutstanding returns how many tasks of the given stages are not finished.
func (s *Store) StageOutstanding(ctx context.Context, runID uuid.UUID, stages ...string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM scan_task
		WHERE run_id=$1 AND stage = ANY($2) AND status IN ('pending','leased','running')`,
		runID, stages).Scan(&n)
	return n, err
}

// StageExists reports whether any task of a stage already exists for a run
// (so the planner does not enqueue a barrier stage twice).
func (s *Store) StageExists(ctx context.Context, runID uuid.UUID, stage scanproto.Stage) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM scan_task WHERE run_id=$1 AND stage=$2`, runID, stage).Scan(&n)
	return n > 0, err
}

// SetTaskResult stores a compact stage summary on a task (read by the planner).
func (s *Store) SetTaskResult(ctx context.Context, taskID uuid.UUID, result []byte) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scan_task SET result=$2 WHERE id=$1`, taskID, result)
	return err
}

// OriginsForTask returns the run_target ids a task serves.
func (s *Store) OriginsForTask(ctx context.Context, taskID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, `SELECT run_target_id FROM task_origin WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Activity is one task's live state, joined to the worker executing it. This is
// what answers "which workers are on this scan and what are they doing".
type Activity struct {
	TaskID     uuid.UUID  `json:"task_id"`
	Stage      string     `json:"stage"`
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	Attempts   int        `json:"attempts"`
	WorkerID   *uuid.UUID `json:"worker_id,omitempty"`
	WorkerName *string    `json:"worker_name,omitempty"`
	WorkerKind *string    `json:"worker_kind,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      *string    `json:"error,omitempty"`
}

// RunActivity returns in-flight tasks first, then the most recently finished,
// so the view leads with what is happening right now.
func (s *Store) RunActivity(ctx context.Context, runID uuid.UUID, limit int) ([]Activity, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT t.id, t.stage,
		       COALESCE(t.target->>'domain', t.target->>'ip', t.target->>'url',
		                t.target->>'cidr', ''),
		       t.status, t.attempts,
		       t.worker_id, w.name, w.kind,
		       t.started_at, t.finished_at, t.error
		FROM scan_task t
		LEFT JOIN worker w ON w.id = t.worker_id
		WHERE t.run_id = $1
		ORDER BY
		  CASE t.status WHEN 'running' THEN 0 WHEN 'leased' THEN 1
		                WHEN 'pending' THEN 2 ELSE 3 END,
		  t.finished_at DESC NULLS LAST, t.started_at DESC NULLS LAST
		LIMIT $2`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Activity{}
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.TaskID, &a.Stage, &a.Target, &a.Status, &a.Attempts,
			&a.WorkerID, &a.WorkerName, &a.WorkerKind,
			&a.StartedAt, &a.FinishedAt, &a.Error); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// StageCount summarises progress for one pipeline stage of a run.
type StageCount struct {
	Stage   string `json:"stage"`
	Pending int    `json:"pending"`
	Active  int    `json:"active"`
	Done    int    `json:"done"`
	Failed  int    `json:"failed"`
}

// RunStages returns per-stage counts so the UI can show where a run actually is
// rather than a single undifferentiated progress bar.
func (s *Store) RunStages(ctx context.Context, runID uuid.UUID) ([]StageCount, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT stage,
		       count(*) FILTER (WHERE status='pending'),
		       count(*) FILTER (WHERE status IN ('leased','running')),
		       count(*) FILTER (WHERE status='done'),
		       count(*) FILTER (WHERE status='failed')
		FROM scan_task WHERE run_id=$1
		GROUP BY stage ORDER BY min(priority), stage`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StageCount{}
	for rows.Next() {
		var c StageCount
		if err := rows.Scan(&c.Stage, &c.Pending, &c.Active, &c.Done, &c.Failed); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

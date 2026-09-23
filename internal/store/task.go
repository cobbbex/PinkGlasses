package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/scanproto"
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
	// PoolID is the one pool whose workers may run this task. Set by the
	// planner from the stage class: passive stages go to the standing local
	// pool, active stages to the run's exit pool. Never nil once planned.
	PoolID *uuid.UUID
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
			INSERT INTO scan_task (run_id, stage, target, requires, priority, status, pool_id)
			VALUES ($1,$2,$3,$4,$5,'pending',$6) RETURNING id`,
			runID, sp.Stage, tgt, sp.Requires, sp.Priority, sp.PoolID).Scan(&id); err != nil {
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
// concurrently without blocking each other (wiki/Architecture.md §8.1).
func (s *Store) LeaseTasks(ctx context.Context, workerID uuid.UUID, caps []string, poolID *uuid.UUID, limit, leaseSecs int) ([]scanproto.Job, error) {
	rows, err := s.Pool.Query(ctx, `
		UPDATE scan_task SET
		  status='leased',
		  worker_id=$1,
		  -- worker_id is cleared on retry and nulled if the worker row is ever
		  -- deleted, so the identity is copied onto the task as well. Without it
		  -- a finished run cannot say who ran it (see 00012).
		  worker_name=(SELECT name FROM worker WHERE id=$1),
		  worker_kind=(SELECT kind FROM worker WHERE id=$1),
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
		    -- Strict equality on the task's pool. The old form allowed
		    -- r.pool_id IS NULL for any worker, so a fleet worker inside a VPN
		    -- gateway's namespace could lease an unrelated run's task and scan
		    -- it through the tunnel. A worker with no pool counts as the default
		    -- pool; a task with no pool (pre-00022, never leased) matches nothing.
		    AND t.pool_id = COALESCE($3::uuid, (SELECT id FROM worker_pool WHERE is_default LIMIT 1))
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

		// A batched task stores its pool as `ips`; expand it into one Target per
		// address so the worker sees the same shape either way.
		targets := []scanproto.Target{tgt}
		if len(tgt.IPs) > 0 {
			targets = make([]scanproto.Target, 0, len(tgt.IPs))
			for _, ip := range tgt.IPs {
				targets = append(targets, scanproto.Target{IP: ip})
			}
		}

		jobs = append(jobs, scanproto.Job{
			Schema:     scanproto.JobSchema,
			JobID:      id.String(),
			RunID:      runID.String(),
			TaskID:     id.String(),
			LeaseToken: leaseTok.String(),
			Stage:      scanproto.Stage(stage),
			Targets:    targets,
		})
	}
	return jobs, rows.Err()
}

// ExtendLeaseForWorker pushes a task's lease expiry forward on the authority of
// the worker holding it. Heartbeats arrive over the worker's authenticated
// control channel and do not carry the lease token, so the worker id is what
// proves ownership here. Without this a task that outlives the lease TTL —
// subfinder alone can — is reaped and retried forever.
//
// The bool says whether the task was still this worker's to extend. False
// means the lease had already expired and the task was re-queued, or it was
// leased to someone else — the worker is still working on something it no
// longer holds, and its results will be refused.
func (s *Store) ExtendLeaseForWorker(ctx context.Context, taskID, workerID uuid.UUID, secs int) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET lease_expires_at = now() + make_interval(secs => $3), status='running'
		WHERE id=$1 AND worker_id=$2 AND status IN ('leased','running')`,
		taskID, workerID, secs)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
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
		  error=$3, lease_token=NULL, worker_id=NULL, lease_expires_at=NULL,
		  -- A task going back to the queue belongs to nobody, so its stamped
		  -- worker is cleared too; one that has failed for good keeps the name
		  -- of the worker that last tried it.
		  worker_name = CASE WHEN attempts >= max_attempts THEN worker_name END,
		  worker_kind = CASE WHEN attempts >= max_attempts THEN worker_kind END
		WHERE id=$1 AND lease_token=$2`, taskID, leaseToken, msg)
	return err
}

// ReadoptTask gives a task back to the worker that is still working on it,
// on the lease token it already holds, when the reaper had re-queued it and
// nobody has picked it up since. The worker's results are then accepted as
// if nothing had happened, and no other attempt redoes the work. False when
// the task is no longer there to take back: leased to someone else, done,
// cancelled, or never reaped.
func (s *Store) ReadoptTask(ctx context.Context, taskID, workerID, leaseToken uuid.UUID, secs int) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET
		  status='running', worker_id=$2, lease_token=$3,
		  lease_expires_at = now() + make_interval(secs => $4),
		  worker_name=(SELECT name FROM worker WHERE id=$2),
		  worker_kind=(SELECT kind FROM worker WHERE id=$2)
		WHERE id=$1 AND status='pending' AND lease_token IS NULL
		  AND error LIKE '%[lease expired]%'`,
		taskID, workerID, leaseToken, secs)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// FailTaskPermanently fails a task whatever its attempts: the worker said a
// retry would only repeat the failure. The observations it did report before
// giving up are already ingested; only the retry is forgone.
func (s *Store) FailTaskPermanently(ctx context.Context, taskID, leaseToken uuid.UUID, msg string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_task SET
		  status = 'failed', error=$3, lease_token=NULL, worker_id=NULL, lease_expires_at=NULL,
		  finished_at = now()
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
//
// Each reaped task comes back described — stage, target, the worker that
// held it, how long past its expiry it was noticed, and whether it was
// re-queued or failed for good — so the scheduler can say exactly what
// happened instead of a count. A lease expires when no heartbeat naming the
// task reached the gateway for the lease TTL; the gateway log around that
// time says why (a control channel closed, a heartbeat gap).
func (s *Store) ReapExpiredLeases(ctx context.Context) ([]ReapedLease, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH expired AS (
		  SELECT t.id, t.run_id, t.stage,
		         COALESCE(t.target->>'domain', t.target->>'ip', t.target->>'url', t.target->>'cidr', '') AS target,
		         COALESCE(t.worker_name, '') AS worker_name, t.attempts, t.max_attempts,
		         now() - t.lease_expires_at AS late
		  FROM scan_task t
		  WHERE t.status IN ('leased','running') AND t.lease_expires_at < now()
		  FOR UPDATE SKIP LOCKED)
		UPDATE scan_task s SET
		  status = CASE WHEN s.attempts >= s.max_attempts THEN 'failed' ELSE 'pending' END,
		  lease_token=NULL, worker_id=NULL, lease_expires_at=NULL,
		  worker_name = CASE WHEN s.attempts >= s.max_attempts THEN s.worker_name END,
		  worker_kind = CASE WHEN s.attempts >= s.max_attempts THEN s.worker_kind END,
		  error = coalesce(s.error,'') || ' [lease expired]'
		FROM expired e WHERE s.id = e.id
		RETURNING e.id, e.run_id, e.stage, e.target, e.worker_name, e.attempts, e.max_attempts,
		          EXTRACT(EPOCH FROM e.late), s.status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReapedLease
	for rows.Next() {
		var r ReapedLease
		var late float64
		if err := rows.Scan(&r.TaskID, &r.RunID, &r.Stage, &r.Target, &r.WorkerName,
			&r.Attempts, &r.MaxAttempts, &late, &r.Status); err != nil {
			return nil, err
		}
		r.Late = time.Duration(late * float64(time.Second))
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReapedLease is one task whose lease ran out, as the reaper found it.
type ReapedLease struct {
	TaskID, RunID         uuid.UUID
	Stage, Target         string
	WorkerName            string
	Attempts, MaxAttempts int
	// Late is how long past the expiry the reaper noticed it.
	Late time.Duration
	// Status is what the task became: pending (re-queued) or failed.
	Status string
}

// TaskBrief describes a task for a log line: what it is, who holds it and
// until when. Used where a request about a task is being refused, so the
// refusal can say what the task's state actually was.
type TaskBrief struct {
	Stage, Target, Status, WorkerName string
	Attempts                          int
	LeaseExpiresAt                    *time.Time
}

func (s *Store) TaskBrief(ctx context.Context, id uuid.UUID) (TaskBrief, error) {
	var b TaskBrief
	err := s.Pool.QueryRow(ctx, `
		SELECT stage, COALESCE(target->>'domain', target->>'ip', target->>'url', target->>'cidr', ''),
		       status, COALESCE(worker_name, ''), attempts, lease_expires_at
		FROM scan_task WHERE id=$1`, id).Scan(&b.Stage, &b.Target, &b.Status, &b.WorkerName, &b.Attempts, &b.LeaseExpiresAt)
	return b, err
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
// TaskResult is what a task found, counted: read off the stage summary the
// gateway keeps on the task, so the run view can say "37 names" beside a
// dns_brute task rather than only that it finished.
type TaskResult struct {
	Names     int            `json:"names,omitempty"`
	Addresses int            `json:"addresses,omitempty"`
	Services  int            `json:"services,omitempty"`
	WebURLs   int            `json:"web_urls,omitempty"`
	Sources   map[string]int `json:"sources,omitempty"`
}

// taskResultCounts reads the counts off a stored stage summary. The summary
// is planner.StageSummary; it is decoded here by shape, since store cannot
// import planner.
func taskResultCounts(raw []byte) *TaskResult {
	if len(raw) == 0 {
		return nil
	}
	var sum struct {
		Domains  []json.RawMessage `json:"domains"`
		IPs      []json.RawMessage `json:"ips"`
		Services []json.RawMessage `json:"services"`
		WebURLs  []json.RawMessage `json:"web_urls"`
		Sources  map[string]int    `json:"sources"`
	}
	if err := json.Unmarshal(raw, &sum); err != nil {
		return nil
	}
	r := &TaskResult{Names: len(sum.Domains), Addresses: len(sum.IPs),
		Services: len(sum.Services), WebURLs: len(sum.WebURLs), Sources: sum.Sources}
	if r.Names == 0 && r.Addresses == 0 && r.Services == 0 && r.WebURLs == 0 {
		return nil
	}
	return r
}

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
	// Result is what the task found, when it has reported anything.
	Result *TaskResult `json:"result,omitempty"`
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
		       t.worker_id,
		       COALESCE(w.name, t.worker_name), COALESCE(w.kind, t.worker_kind),
		       t.started_at, t.finished_at, t.error, t.result
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
		var result []byte
		if err := rows.Scan(&a.TaskID, &a.Stage, &a.Target, &a.Status, &a.Attempts,
			&a.WorkerID, &a.WorkerName, &a.WorkerKind,
			&a.StartedAt, &a.FinishedAt, &a.Error, &result); err != nil {
			return nil, err
		}
		a.Result = taskResultCounts(result)
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
	// Found is what the stage's finished tasks reported so far, in the unit
	// that stage produces: names for discovery and brute force, addresses
	// for resolution, open ports for the port scan, web endpoints for the
	// probe. FoundKind names the unit; both are zero for stages whose
	// output is not a count of things (screenshots, technologies, paths).
	Found     int    `json:"found,omitempty"`
	FoundKind string `json:"found_kind,omitempty"`
	// Sources is Found broken down by discovery source, for the stages
	// that have one: "subfinder:crtsh" 120, "shuffledns" 37, "seed" 1.
	Sources map[string]int `json:"sources,omitempty"`
}

// stageFoundKind is the unit each stage's result is counted in.
var stageFoundKind = map[string]string{
	"passive_enum": "names", "dns_brute": "names",
	"dns_resolve": "addresses", "ip_enrich": "addresses",
	"port_scan": "open ports", "service_probe": "web endpoints",
}

// RunStages returns per-stage counts so the UI can show where a run actually is
// rather than a single undifferentiated progress bar.
func (s *Store) RunStages(ctx context.Context, runID uuid.UUID) ([]StageCount, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT stage,
		       count(*) FILTER (WHERE status='pending'),
		       count(*) FILTER (WHERE status IN ('leased','running')),
		       count(*) FILTER (WHERE status='done'),
		       count(*) FILTER (WHERE status='failed'),
		       COALESCE(sum(jsonb_array_length(result->'domains')) FILTER (WHERE jsonb_typeof(result->'domains')='array'), 0),
		       COALESCE(sum(jsonb_array_length(result->'ips')) FILTER (WHERE jsonb_typeof(result->'ips')='array'), 0),
		       COALESCE(sum(jsonb_array_length(result->'services')) FILTER (WHERE jsonb_typeof(result->'services')='array'), 0),
		       COALESCE(sum(jsonb_array_length(result->'web_urls')) FILTER (WHERE jsonb_typeof(result->'web_urls')='array'), 0),
		       COALESCE((SELECT jsonb_object_agg(k, n) FROM (
		           SELECT k, sum(v::int) AS n
		           FROM scan_task t2, jsonb_each_text(t2.result->'sources') AS e(k, v)
		           WHERE t2.run_id = $1 AND t2.stage = scan_task.stage
		             AND jsonb_typeof(t2.result->'sources') = 'object'
		           GROUP BY k) agg), '{}'::jsonb)
		FROM scan_task WHERE run_id=$1
		GROUP BY stage ORDER BY min(priority), stage`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StageCount{}
	for rows.Next() {
		var c StageCount
		var names, addrs, svcs, urls int
		var sources []byte
		if err := rows.Scan(&c.Stage, &c.Pending, &c.Active, &c.Done, &c.Failed,
			&names, &addrs, &svcs, &urls, &sources); err != nil {
			return nil, err
		}
		switch c.FoundKind = stageFoundKind[c.Stage]; c.FoundKind {
		case "names":
			c.Found = names
			_ = json.Unmarshal(sources, &c.Sources)
		case "addresses":
			c.Found = addrs
		case "open ports":
			c.Found = svcs
		case "web endpoints":
			c.Found = urls
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ScannedAddresses returns every address that already has a port-scan task in
// this run, batched or single. Used to scan discoveries incrementally: as each
// discovery task finishes, only the addresses not already queued are scheduled,
// so nothing waits for a barrier and nothing is scanned twice.
func (s *Store) ScannedAddresses(ctx context.Context, runID uuid.UUID) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT ip FROM (
		  SELECT jsonb_array_elements_text(target->'ips') AS ip
		    FROM scan_task WHERE run_id=$1 AND stage='port_scan' AND target ? 'ips'
		  UNION ALL
		  SELECT target->>'ip' AS ip
		    FROM scan_task WHERE run_id=$1 AND stage='port_scan' AND target ? 'ip'
		) s WHERE ip IS NOT NULL`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

// ProbedEndpoints returns the ip:port pairs a run already has a service_probe
// task for, so probes can also be enqueued incrementally without duplicates.
func (s *Store) ProbedEndpoints(ctx context.Context, runID uuid.UUID) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT (target->>'ip') || ':' || (target->>'port')
		FROM scan_task
		WHERE run_id=$1 AND stage='service_probe' AND target ? 'ip'`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out[key] = true
	}
	return out, rows.Err()
}

// Stranded is a run whose pending tasks no active worker can lease: their pool
// has no active worker, or they have no pool at all.
type Stranded struct {
	RunID  uuid.UUID
	PoolID *uuid.UUID
	Stage  string
	Tasks  int
	Oldest time.Time
}

// StrandedTasks lists pending tasks older than `age` that no active worker is
// eligible for. It exists to be logged: a run in this state shows "running"
// in the UI and nothing else, and every stall that has been debugged here so
// far — a fleet that never came up, a pool binding missed at planning — was
// invisible until someone queried the tasks by hand. Passive tasks waiting on
// a standing worker that is merely restarting will show up too, which is why
// the caller applies an age.
func (s *Store) StrandedTasks(ctx context.Context, age time.Duration) ([]Stranded, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT t.run_id, t.pool_id, t.stage, count(*), min(t.created_at)
		FROM scan_task t
		JOIN scan_run r ON r.id = t.run_id
		WHERE t.status = 'pending'
		  AND r.status = 'running'
		  AND t.created_at < now() - $1::interval
		  -- A run queued behind the fleet ceiling is waiting, not stranded:
		  -- its active tasks sit on a pool that gets workers when a slot frees.
		  AND NOT EXISTS (
		    SELECT 1 FROM run_fleet f WHERE f.run_id = t.run_id AND f.status = 'requested')
		  AND NOT EXISTS (
		    SELECT 1 FROM worker w
		    WHERE w.status = 'active'
		      AND w.pool_id IS NOT DISTINCT FROM t.pool_id
		      AND t.requires <@ w.capabilities)
		GROUP BY t.run_id, t.pool_id, t.stage
		ORDER BY min(t.created_at)`, age.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stranded
	for rows.Next() {
		var st Stranded
		if err := rows.Scan(&st.RunID, &st.PoolID, &st.Stage, &st.Tasks, &st.Oldest); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// TaskResult returns a task's stored stage summary, if any.
func (s *Store) TaskResult(ctx context.Context, taskID uuid.UUID) ([]byte, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `SELECT result FROM scan_task WHERE id=$1`, taskID).Scan(&raw)
	return raw, err
}

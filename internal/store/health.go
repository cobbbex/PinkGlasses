package store

import (
	"context"
	"encoding/json"
	"time"
)

// BeatComponent records that a service is alive, with anything it wants the
// health page to show.
func (s *Store) BeatComponent(ctx context.Context, name string, detail map[string]any) error {
	raw, _ := json.Marshal(detail)
	if detail == nil {
		raw = []byte("{}")
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO component_heartbeat (name, last_seen, detail) VALUES ($1, now(), $2)
		ON CONFLICT (name) DO UPDATE SET last_seen = now(), detail = EXCLUDED.detail`, name, raw)
	return err
}

// ComponentBeat is one service's last heartbeat.
type ComponentBeat struct {
	Name     string          `json:"name"`
	LastSeen time.Time       `json:"last_seen"`
	Detail   json.RawMessage `json:"detail"`
}

// ComponentBeats returns every service's last heartbeat.
func (s *Store) ComponentBeats(ctx context.Context) (map[string]ComponentBeat, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name, last_seen, detail FROM component_heartbeat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ComponentBeat{}
	for rows.Next() {
		var b ComponentBeat
		if err := rows.Scan(&b.Name, &b.LastSeen, &b.Detail); err != nil {
			return nil, err
		}
		out[b.Name] = b
	}
	return out, rows.Err()
}

// SchemaVersion is the last applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v)
	return v, err
}

// QueueStage is the work waiting and in flight for one stage, across runs that
// are going.
type QueueStage struct {
	Stage         string  `json:"stage"`
	Pending       int     `json:"pending"`
	InFlight      int     `json:"in_flight"`
	OldestPending float64 `json:"oldest_pending_s"`
}

// HealthQueue returns the queue by stage for running runs.
func (s *Store) HealthQueue(ctx context.Context) ([]QueueStage, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT t.stage,
		       count(*) FILTER (WHERE t.status='pending'),
		       count(*) FILTER (WHERE t.status IN ('leased','running')),
		       COALESCE(EXTRACT(EPOCH FROM now() - min(t.created_at) FILTER (WHERE t.status='pending')), 0)
		FROM scan_task t JOIN scan_run r ON r.id = t.run_id
		WHERE r.status IN ('running','paused') AND t.status IN ('pending','leased','running')
		GROUP BY t.stage ORDER BY min(t.priority)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueueStage{}
	for rows.Next() {
		var q QueueStage
		if err := rows.Scan(&q.Stage, &q.Pending, &q.InFlight, &q.OldestPending); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// HealthCounts are the headline numbers on the health page.
type HealthCounts struct {
	RunsGoing        int `json:"runs_going"`
	LiveFleets       int `json:"live_fleets"`
	LeaseExpiries24h int `json:"lease_expiries_24h"`
	FailedTasks24h   int `json:"failed_tasks_24h"`
	FailedRuns24h    int `json:"failed_runs_24h"`
	WorkersActive    int `json:"workers_active"`
	WorkersStale     int `json:"workers_stale"`
}

func (s *Store) HealthCounts(ctx context.Context) (HealthCounts, error) {
	var h HealthCounts
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM scan_run WHERE status IN ('running','paused','queued')),
		  (SELECT count(*) FROM run_fleet WHERE status IN ('requested','up')),
		  (SELECT count(*) FROM scan_task WHERE error LIKE '%[lease expired]%'
		     AND COALESCE(finished_at, started_at, created_at) > now() - interval '24 hours'),
		  (SELECT count(*) FROM scan_task WHERE status='failed'
		     AND COALESCE(finished_at, started_at, created_at) > now() - interval '24 hours'),
		  (SELECT count(*) FROM scan_run WHERE status='failed' AND created_at > now() - interval '24 hours'),
		  (SELECT count(*) FROM worker WHERE status='active'),
		  (SELECT count(*) FROM worker WHERE status='stale')`).Scan(
		&h.RunsGoing, &h.LiveFleets, &h.LeaseExpiries24h, &h.FailedTasks24h, &h.FailedRuns24h,
		&h.WorkersActive, &h.WorkersStale)
	return h, err
}

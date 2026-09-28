package store

import (
	"context"
	"time"
)

// Metrics is the install's state in numbers, for a monitoring system to
// scrape. Install-wide on purpose: nothing here is labelled by company, so a
// scrape cannot be used to learn the names of private companies.
type Metrics struct {
	SchemaVersion int64

	RunsByStatus    map[string]int // every run, by status
	RunsFinished24h map[string]int // finished in the last 24 hours, by status

	Queue []QueueStage // pending and in flight per stage, on running scans

	WorkersByStatus    map[string]int
	FindingsBySeverity map[string]int // open findings

	Companies int
	Names     int
	Hosts     int
	Services  int

	LeaseExpiries24h int
	FailedTasks24h   int
	FailedRuns24h    int

	// Beats is each service's last heartbeat: gateway, scheduler, backup,
	// every api copy. Exposed as an age so an alert can fire on silence.
	Beats map[string]time.Time
}

// Metrics gathers the numbers in a handful of grouped queries. Every one is a
// count over indexed columns; the handler caches the result for a few seconds
// so a fast scrape interval cannot become load.
func (s *Store) Metrics(ctx context.Context) (Metrics, error) {
	m := Metrics{
		RunsByStatus:       map[string]int{},
		RunsFinished24h:    map[string]int{},
		WorkersByStatus:    map[string]int{},
		FindingsBySeverity: map[string]int{},
		Beats:              map[string]time.Time{},
	}

	rows, err := s.Pool.Query(ctx, `SELECT status, count(*) FROM scan_run GROUP BY status`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return m, err
		}
		m.RunsByStatus[k] = n
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
		SELECT status, count(*) FROM scan_run
		WHERE COALESCE(finished_at, created_at) > now() - interval '24 hours'
		  AND status IN ('completed','failed','cancelled')
		GROUP BY status`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return m, err
		}
		m.RunsFinished24h[k] = n
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT status, count(*) FROM worker GROUP BY status`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return m, err
		}
		m.WorkersByStatus[k] = n
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT severity, count(*) FROM finding WHERE status='open' GROUP BY severity`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return m, err
		}
		m.FindingsBySeverity[k] = n
	}
	rows.Close()

	if err := s.Pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM scope),
		       (SELECT count(*) FROM domain),
		       (SELECT count(*) FROM ip_address),
		       (SELECT count(*) FROM service)`).
		Scan(&m.Companies, &m.Names, &m.Hosts, &m.Services); err != nil {
		return m, err
	}

	if q, err := s.HealthQueue(ctx); err == nil {
		m.Queue = q
	}
	if c, err := s.HealthCounts(ctx); err == nil {
		m.LeaseExpiries24h, m.FailedTasks24h, m.FailedRuns24h = c.LeaseExpiries24h, c.FailedTasks24h, c.FailedRuns24h
	}
	if beats, err := s.ComponentBeats(ctx); err == nil {
		for name, b := range beats {
			m.Beats[name] = b.LastSeen
		}
	}
	if v, err := s.SchemaVersion(ctx); err == nil {
		m.SchemaVersion = v
	}
	return m, nil
}

// Package diff compares a completed run against the prior baseline and records
// change_events. It runs only after a run is marked completed, so a partial run
// never produces false "asset disappeared" alerts (architecture.md §3.4).
package diff

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Differ produces change events for a run.
type Differ struct{ st *store.Store }

// New builds a Differ.
func New(st *store.Store) *Differ { return &Differ{st: st} }

// Diff records change events for everything first seen within the run window.
// Returns the number of events recorded.
func (d *Differ) Diff(ctx context.Context, run domain.ScanRun) (int, error) {
	if run.StartedAt == nil {
		return 0, nil
	}
	since := *run.StartedAt
	// A tiny skew guard so assets created at run start are included.
	since = since.Add(-2 * time.Second)

	n := 0

	// New subdomains.
	if c, err := d.newDomains(ctx, run, since); err != nil {
		return n, err
	} else {
		n += c
	}
	// New open services.
	if c, err := d.newServices(ctx, run, since); err != nil {
		return n, err
	} else {
		n += c
	}
	// New findings.
	if c, err := d.newFindings(ctx, run, since); err != nil {
		return n, err
	} else {
		n += c
	}
	return n, nil
}

func (d *Differ) newDomains(ctx context.Context, run domain.ScanRun, since time.Time) (int, error) {
	rows, err := d.st.Pool.Query(ctx, `
		SELECT id, name FROM domain WHERE scope_id=$1 AND first_seen>=$2`, run.ScopeID, since)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return n, err
		}
		if err := d.st.RecordChangeEvent(ctx, run.ID, nil, run.ScopeID, "new_subdomain", "domain", id,
			nil, map[string]any{"name": name}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func (d *Differ) newServices(ctx context.Context, run domain.ScanRun, since time.Time) (int, error) {
	rows, err := d.st.Pool.Query(ctx, `
		SELECT sv.id, host(ip.addr), sv.port
		FROM service sv JOIN ip_address ip ON ip.id=sv.ip_id
		WHERE ip.scope_id=$1 AND sv.first_seen>=$2`, run.ScopeID, since)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uuid.UUID
		var addr string
		var port int
		if err := rows.Scan(&id, &addr, &port); err != nil {
			return n, err
		}
		if err := d.st.RecordChangeEvent(ctx, run.ID, nil, run.ScopeID, "new_port", "service", id,
			nil, map[string]any{"ip": addr, "port": port}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func (d *Differ) newFindings(ctx context.Context, run domain.ScanRun, since time.Time) (int, error) {
	rows, err := d.st.Pool.Query(ctx, `
		SELECT id, kind, severity, title FROM finding WHERE scope_id=$1 AND first_seen>=$2`, run.ScopeID, since)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uuid.UUID
		var kind, severity, title string
		if err := rows.Scan(&id, &kind, &severity, &title); err != nil {
			return n, err
		}
		if err := d.st.RecordChangeEvent(ctx, run.ID, nil, run.ScopeID, "new_finding", "finding", id,
			nil, map[string]any{"kind": kind, "severity": severity, "title": title}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

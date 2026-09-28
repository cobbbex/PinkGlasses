package store

import (
	"context"
	"time"
)

// DBUsage is how much room the install takes in the database, split into the
// record of past scans and the current picture. Nothing deletes either unless
// a company is given a retention; this exists so growth is watched rather
// than discovered.
type DBUsage struct {
	TotalBytes     int64      `json:"total_bytes"`
	HistoryBytes   int64      `json:"history_bytes"`   // runs and everything they own
	InventoryBytes int64      `json:"inventory_bytes"` // names, hosts, services, findings
	Runs           int        `json:"runs"`
	OldestRunAt    *time.Time `json:"oldest_run_at,omitempty"`
	// PruningCompanies is how many companies have chosen a retention. Zero
	// means nothing on this install is ever removed.
	PruningCompanies int `json:"pruning_companies"`
}

// historyTables are the tables a run owns: everything here goes when a run is
// deleted, and nothing here is part of the current picture.
var historyTables = []string{
	"scan_run", "scan_task", "service_observation", "change_event",
	"finding_observation", "domain_ip_observation", "run_target",
	"run_wordlist", "run_fleet",
}

// inventoryTables are the current picture: what the company exposes now.
var inventoryTables = []string{
	"scope", "domain", "ip_address", "service", "technology", "finding",
	"dns_record", "target_group", "target",
}

// DBUsage measures the database. pg_total_relation_size includes each table's
// indexes and toast, which is what actually occupies the disk.
func (s *Store) DBUsage(ctx context.Context) (DBUsage, error) {
	var u DBUsage
	err := s.Pool.QueryRow(ctx, `
		SELECT pg_database_size(current_database()),
		       COALESCE((SELECT sum(pg_total_relation_size(c.oid))
		                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		                 WHERE n.nspname='public' AND c.relname = ANY($1)), 0),
		       COALESCE((SELECT sum(pg_total_relation_size(c.oid))
		                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		                 WHERE n.nspname='public' AND c.relname = ANY($2)), 0),
		       (SELECT count(*) FROM scan_run),
		       (SELECT min(created_at) FROM scan_run),
		       (SELECT count(*) FROM scope WHERE retention_days > 0)`,
		historyTables, inventoryTables).
		Scan(&u.TotalBytes, &u.HistoryBytes, &u.InventoryBytes, &u.Runs, &u.OldestRunAt, &u.PruningCompanies)
	return u, err
}

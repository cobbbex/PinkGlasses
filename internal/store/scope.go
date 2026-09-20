package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// CreateScope inserts a scope.
func (s *Store) CreateScope(ctx context.Context, name, createdBy string, ownerID *uuid.UUID) (domain.Scope, error) {
	if createdBy == "" {
		createdBy = "local"
	}
	var sc domain.Scope
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO scope (name, created_by, owner_id) VALUES ($1,$2,$3)
		 RETURNING id, name, created_by, created_at, default_exit, default_vpn_config_id, default_pool_id`, name, createdBy, ownerID,
	).Scan(&sc.ID, &sc.Name, &sc.CreatedBy, &sc.CreatedAt, &sc.DefaultExit, &sc.DefaultVPNConfigID, &sc.DefaultPoolID)
	return sc, err
}

// AdoptOwnerlessScopes gives every unowned scope to a user, and is called once,
// when the first administrator is created.
//
// Everything made before there were accounts records created_by 'local', which
// names nobody. Rather than leave those scopes permanently unattributed, the
// person who sets the install up inherits them — they are, by construction, the
// only person who has been using it.
func (s *Store) AdoptOwnerlessScopes(ctx context.Context, ownerID uuid.UUID) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `UPDATE scope SET owner_id=$1 WHERE owner_id IS NULL`, ownerID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// ListScopes returns scopes, optionally only those created by one actor.
//
// An empty owner means every company. The filter is on a free-text actor rather
// than a user id because there is no users table yet (Phase 17); the shape is
// what matters, so the UI does not change when identity becomes verified.
func (s *Store) ListScopes(ctx context.Context, owner string) ([]domain.Scope, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, name, created_by, created_at, default_exit, default_vpn_config_id, default_pool_id FROM scope
		 WHERE ($1 = '' OR created_by = $1) ORDER BY created_at`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Scope
	for rows.Next() {
		var sc domain.Scope
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.CreatedBy, &sc.CreatedAt, &sc.DefaultExit, &sc.DefaultVPNConfigID, &sc.DefaultPoolID); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// GetScope fetches one scope by id.
func (s *Store) GetScope(ctx context.Context, id uuid.UUID) (domain.Scope, error) {
	var sc domain.Scope
	err := s.Pool.QueryRow(ctx,
		`SELECT id, name, created_by, created_at, default_exit, default_vpn_config_id, default_pool_id FROM scope WHERE id=$1`, id,
	).Scan(&sc.ID, &sc.Name, &sc.CreatedBy, &sc.CreatedAt, &sc.DefaultExit, &sc.DefaultVPNConfigID, &sc.DefaultPoolID)
	return sc, err
}

// AddTarget inserts or updates a scope target.
func (s *Store) AddTarget(ctx context.Context, t domain.ScopeTarget) (domain.ScopeTarget, error) {
	if t.Tags == nil {
		t.Tags = []string{} // column is NOT NULL; nil would violate the constraint
	}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO scope_target (scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at, group_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (group_id, kind, value) DO UPDATE
		  SET tags=EXCLUDED.tags, mode=EXCLUDED.mode, pool_id=EXCLUDED.pool_id,
		      authorized_by=EXCLUDED.authorized_by, authorized_at=EXCLUDED.authorized_at
		RETURNING id, created_at`,
		t.ScopeID, t.Kind, t.Value, t.Tags, t.Mode, t.PoolID, t.AuthorizedBy, t.AuthorizedAt, t.GroupID,
	).Scan(&t.ID, &t.CreatedAt)
	return t, err
}

// ScopeFootprint counts what a company owns — what deleting it removes.
type ScopeFootprint struct {
	Name          string `json:"name"`
	TargetGroups  int    `json:"target_groups"`
	Targets       int    `json:"targets"`
	Names         int    `json:"names"`
	Hosts         int    `json:"hosts"`
	Services      int    `json:"services"`
	Runs          int    `json:"runs"`
	ActiveRuns    int    `json:"active_runs"`
	Findings      int    `json:"findings"`
	Screenshots   int    `json:"screenshots"`
	Schedules     int    `json:"schedules"`
	AlertChannels int    `json:"alert_channels"`
	LiveFleets    int    `json:"live_fleets"`
}

// ScopeFootprint reports what a company owns. ActiveRuns and LiveFleets are
// what stands in the way of deleting it.
func (s *Store) ScopeFootprint(ctx context.Context, scopeID uuid.UUID) (ScopeFootprint, bool, error) {
	var f ScopeFootprint
	err := s.Pool.QueryRow(ctx, `
		SELECT sc.name,
		       (SELECT count(*) FROM target_group WHERE scope_id=$1),
		       (SELECT count(*) FROM scope_target WHERE scope_id=$1),
		       (SELECT count(*) FROM domain WHERE scope_id=$1),
		       (SELECT count(*) FROM ip_address WHERE scope_id=$1),
		       (SELECT count(*) FROM service sv JOIN ip_address ip ON ip.id=sv.ip_id WHERE ip.scope_id=$1),
		       (SELECT count(*) FROM scan_run WHERE scope_id=$1),
		       (SELECT count(*) FROM scan_run WHERE scope_id=$1 AND status IN ('queued','planning','running','paused')),
		       (SELECT count(*) FROM finding WHERE scope_id=$1),
		       (SELECT count(*) FROM service_observation so JOIN scan_run r ON r.id=so.run_id
		          WHERE r.scope_id=$1 AND COALESCE(so.screenshot_key,'') <> '' AND so.screenshot_key NOT LIKE '%(not uploaded%'),
		       (SELECT count(*) FROM scan_schedule WHERE scope_id=$1),
		       (SELECT count(*) FROM notification_channel WHERE scope_id=$1),
		       (SELECT count(*) FROM run_fleet f JOIN scan_run r ON r.id=f.run_id WHERE r.scope_id=$1 AND f.status IN ('requested','up'))
		FROM scope sc WHERE sc.id=$1`, scopeID).Scan(&f.Name, &f.TargetGroups, &f.Targets, &f.Names, &f.Hosts, &f.Services,
		&f.Runs, &f.ActiveRuns, &f.Findings, &f.Screenshots, &f.Schedules, &f.AlertChannels, &f.LiveFleets)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, false, nil
	}
	return f, err == nil, err
}

// ScopeArtifactKeys lists the object-storage keys of every run in a company,
// so deleting the company can remove its screenshots and raw output.
func (s *Store) ScopeArtifactKeys(ctx context.Context, scopeID uuid.UUID) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT k FROM (
		  SELECT so.screenshot_key AS k FROM service_observation so JOIN scan_run r ON r.id=so.run_id WHERE r.scope_id=$1
		  UNION SELECT so.raw_key FROM service_observation so JOIN scan_run r ON r.id=so.run_id WHERE r.scope_id=$1
		) x WHERE COALESCE(k,'') <> '' AND k NOT LIKE '%(not uploaded%'`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeleteScope removes a company and, through the foreign keys, everything it
// owns: targets and groups, names and hosts, runs with their tasks and
// observations, findings, schedules, VPN configurations, alert channels.
func (s *Store) DeleteScope(ctx context.Context, scopeID uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM scope WHERE id=$1`, scopeID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// GetTarget returns one target of a scope.
func (s *Store) GetTarget(ctx context.Context, scopeID, targetID uuid.UUID) (domain.ScopeTarget, bool, error) {
	var t domain.ScopeTarget
	err := s.Pool.QueryRow(ctx, `
		SELECT id, scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at, created_at, group_id
		FROM scope_target WHERE id=$1 AND scope_id=$2`, targetID, scopeID,
	).Scan(&t.ID, &t.ScopeID, &t.Kind, &t.Value, &t.Tags, &t.Mode, &t.PoolID, &t.AuthorizedBy, &t.AuthorizedAt, &t.CreatedAt, &t.GroupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil, err
}

// ErrTargetExists is returned when an edit would make a target a duplicate of
// another in the same company.
var ErrTargetExists = errors.New("that value is already a target of this company")

// UpdateTarget changes a target: its value and kind (a typo in a host is fixed
// in place, keeping the row and its tags), its mode, tags and authorization
// record. Scoped by both ids so another company's target cannot be changed
// through this company's route. Returns false when nothing matched.
func (s *Store) UpdateTarget(ctx context.Context, scopeID, targetID uuid.UUID, kind, value string, mode domain.TargetMode, tags []string, authBy *string, authAt *time.Time) (domain.ScopeTarget, bool, error) {
	if tags == nil {
		tags = []string{}
	}
	var t domain.ScopeTarget
	err := s.Pool.QueryRow(ctx, `
		UPDATE scope_target SET kind=$3, value=$4, mode=$5, tags=$6, authorized_by=$7, authorized_at=$8
		WHERE id=$1 AND scope_id=$2
		RETURNING id, scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at, created_at, group_id`,
		targetID, scopeID, kind, value, mode, tags, authBy, authAt,
	).Scan(&t.ID, &t.ScopeID, &t.Kind, &t.Value, &t.Tags, &t.Mode, &t.PoolID, &t.AuthorizedBy, &t.AuthorizedAt, &t.CreatedAt, &t.GroupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return t, false, ErrTargetExists
	}
	return t, err == nil, err
}

// ListTargetsMerged is ListTargets with duplicates across groups folded to one
// row per (kind, value), the way the planner and launcher must see a company:
// see domain.MergeTargets for how authorization combines.
func (s *Store) ListTargetsMerged(ctx context.Context, scopeID uuid.UUID, tag string) ([]domain.ScopeTarget, error) {
	rows, err := s.ListTargets(ctx, scopeID, tag)
	if err != nil {
		return nil, err
	}
	return domain.MergeTargets(rows), nil
}

// DeleteTarget removes a target from its scope. Scoped by both ids so a
// target id from another company cannot be removed through this company's
// route. What earlier runs discovered under it stays: the inventory belongs to
// the scope, and history is the point of keeping it.
func (s *Store) DeleteTarget(ctx context.Context, scopeID, targetID uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM scope_target WHERE id=$1 AND scope_id=$2`, targetID, scopeID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// ListTargets returns the targets of a scope, optionally filtered by tag.
func (s *Store) ListTargets(ctx context.Context, scopeID uuid.UUID, tag string) ([]domain.ScopeTarget, error) {
	q := `SELECT id, scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at, created_at, group_id
	      FROM scope_target WHERE scope_id=$1`
	args := []any{scopeID}
	if tag != "" {
		q += ` AND $2 = ANY(tags)`
		args = append(args, tag)
	}
	q += ` ORDER BY kind, value`
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScopeTarget
	for rows.Next() {
		var t domain.ScopeTarget
		if err := rows.Scan(&t.ID, &t.ScopeID, &t.Kind, &t.Value, &t.Tags, &t.Mode,
			&t.PoolID, &t.AuthorizedBy, &t.AuthorizedAt, &t.CreatedAt, &t.GroupID); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ScopeSummary holds dashboard counters.
type ScopeSummary struct {
	// DomainsResolving is how many of those names currently point at an
	// address. Passive sources return every name they have ever heard of; for a
	// famous domain most are dead, and the bare count buries the ones that matter.
	DomainsResolving int `json:"domains_resolving"`
	Domains          int `json:"domains"`
	IPs              int `json:"ips"`
	Services         int `json:"services"`
	Findings         int `json:"open_findings"`
}

// Summary returns dashboard counters for a scope.
func (s *Store) Summary(ctx context.Context, scopeID uuid.UUID) (ScopeSummary, error) {
	var sum ScopeSummary
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM domain WHERE scope_id=$1),
		  (SELECT count(*) FROM domain d WHERE d.scope_id=$1
		     AND EXISTS (SELECT 1 FROM domain_ip di WHERE di.domain_id = d.id)),
		  (SELECT count(*) FROM ip_address WHERE scope_id=$1),
		  (SELECT count(*) FROM service sv JOIN ip_address ip ON ip.id=sv.ip_id WHERE ip.scope_id=$1),
		  (SELECT count(*) FROM finding WHERE scope_id=$1 AND status='open')`,
		scopeID,
	).Scan(&sum.Domains, &sum.DomainsResolving, &sum.IPs, &sum.Services, &sum.Findings)
	return sum, err
}

// SetScopeDefaults records the exit a company's scheduled runs use and the
// launch dialog pre-selects.
func (s *Store) SetScopeDefaults(ctx context.Context, id uuid.UUID, exit string, vpnID, poolID *uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scope SET default_exit=$2, default_vpn_config_id=$3, default_pool_id=$4 WHERE id=$1`,
		id, exit, vpnID, poolID)
	return err
}

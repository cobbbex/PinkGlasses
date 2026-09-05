package store

import (
	"context"

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
		INSERT INTO scope_target (scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (scope_id, kind, value) DO UPDATE
		  SET tags=EXCLUDED.tags, mode=EXCLUDED.mode, pool_id=EXCLUDED.pool_id,
		      authorized_by=EXCLUDED.authorized_by, authorized_at=EXCLUDED.authorized_at
		RETURNING id, created_at`,
		t.ScopeID, t.Kind, t.Value, t.Tags, t.Mode, t.PoolID, t.AuthorizedBy, t.AuthorizedAt,
	).Scan(&t.ID, &t.CreatedAt)
	return t, err
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
	q := `SELECT id, scope_id, kind, value, tags, mode, pool_id, authorized_by, authorized_at, created_at
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
			&t.PoolID, &t.AuthorizedBy, &t.AuthorizedAt, &t.CreatedAt); err != nil {
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

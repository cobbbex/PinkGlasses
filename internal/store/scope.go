package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/domain"
)

// CreateScope inserts a scope.
func (s *Store) CreateScope(ctx context.Context, name string) (domain.Scope, error) {
	var sc domain.Scope
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO scope (name) VALUES ($1) RETURNING id, name, created_at`, name,
	).Scan(&sc.ID, &sc.Name, &sc.CreatedAt)
	return sc, err
}

// ListScopes returns all scopes.
func (s *Store) ListScopes(ctx context.Context) ([]domain.Scope, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, created_at FROM scope ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Scope
	for rows.Next() {
		var sc domain.Scope
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.CreatedAt); err != nil {
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
		`SELECT id, name, created_at FROM scope WHERE id=$1`, id,
	).Scan(&sc.ID, &sc.Name, &sc.CreatedAt)
	return sc, err
}

// AddTarget inserts or updates a scope target.
func (s *Store) AddTarget(ctx context.Context, t domain.ScopeTarget) (domain.ScopeTarget, error) {
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
	Domains  int `json:"domains"`
	IPs      int `json:"ips"`
	Services int `json:"services"`
	Findings int `json:"open_findings"`
}

// Summary returns dashboard counters for a scope.
func (s *Store) Summary(ctx context.Context, scopeID uuid.UUID) (ScopeSummary, error) {
	var sum ScopeSummary
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM domain WHERE scope_id=$1),
		  (SELECT count(*) FROM ip_address WHERE scope_id=$1),
		  (SELECT count(*) FROM service sv JOIN ip_address ip ON ip.id=sv.ip_id WHERE ip.scope_id=$1),
		  (SELECT count(*) FROM finding WHERE scope_id=$1 AND status='open')`,
		scopeID,
	).Scan(&sum.Domains, &sum.IPs, &sum.Services, &sum.Findings)
	return sum, err
}

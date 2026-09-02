package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// UpsertFinding inserts or refreshes a finding keyed by (scope, asset, kind).
func (s *Store) UpsertFinding(ctx context.Context, scopeID, assetID uuid.UUID, assetKind, kind, severity, title string, evidence map[string]any, at time.Time) error {
	ev, _ := json.Marshal(evidence)
	// A finding is identified by its asset, kind and title (00013). Matching on
	// the asset and kind alone made every finding of a stage that raises one per
	// item — a path per content-discovery hit — collapse onto the last one seen.
	// A resolved finding keeps its timestamps: re-observing it must not quietly
	// reopen something a human has closed.
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO finding (scope_id, asset_kind, asset_id, kind, severity, title, evidence, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
		ON CONFLICT (scope_id, asset_kind, asset_id, kind, title) DO UPDATE SET
		  last_seen = GREATEST(finding.last_seen, EXCLUDED.last_seen),
		  severity = EXCLUDED.severity,
		  evidence = EXCLUDED.evidence
		WHERE finding.status <> 'resolved'`,
		scopeID, assetKind, assetID, kind, severity, title, ev, at)
	return err
}

// ListFindings returns findings for a scope, filterable by status/severity.
func (s *Store) ListFindings(ctx context.Context, scopeID uuid.UUID, status, severity string) ([]domain.Finding, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, asset_kind, asset_id, kind, severity, title, status, first_seen, last_seen
		FROM finding
		WHERE scope_id=$1 AND ($2='' OR status=$2) AND ($3='' OR severity=$3)
		ORDER BY
		  array_position(ARRAY['critical','high','medium','low','info'], severity),
		  last_seen DESC
		LIMIT 500`, scopeID, status, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		var f domain.Finding
		if err := rows.Scan(&f.ID, &f.ScopeID, &f.AssetKind, &f.AssetID, &f.Kind,
			&f.Severity, &f.Title, &f.Status, &f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFindingStatus updates a finding's workflow status.
func (s *Store) SetFindingStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE finding SET status=$2,
		  resolved_at = CASE WHEN $2='resolved' THEN now() ELSE resolved_at END
		WHERE id=$1`, id, status)
	return err
}

// ExpiringCerts finds certificates near expiry, used by the scheduler sweep.
func (s *Store) ExpiringCerts(ctx context.Context, within time.Duration) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id FROM certificate WHERE not_after IS NOT NULL AND not_after < now()+$1::interval`,
		within.String())
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

// RecordChangeEvent inserts a change event (used by the differ).
func (s *Store) RecordChangeEvent(ctx context.Context, runID uuid.UUID, runTargetID *uuid.UUID, scopeID uuid.UUID, kind, assetKind string, assetID uuid.UUID, before, after map[string]any) error {
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO change_event (run_id, run_target_id, scope_id, kind, asset_kind, asset_id, before, after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		runID, runTargetID, scopeID, kind, assetKind, assetID, b, a)
	return err
}

// ListChangeEvents returns the change events produced by a run.
func (s *Store) ListChangeEvents(ctx context.Context, runID uuid.UUID) ([]map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT kind, asset_kind, asset_id, after, created_at
		FROM change_event WHERE run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var kind, assetKind string
		var assetID uuid.UUID
		var after []byte
		var createdAt time.Time
		if err := rows.Scan(&kind, &assetKind, &assetID, &after, &createdAt); err != nil {
			return nil, err
		}
		var a map[string]any
		_ = json.Unmarshal(after, &a)
		out = append(out, map[string]any{
			"kind": kind, "asset_kind": assetKind, "asset_id": assetID, "after": a, "created_at": createdAt,
		})
	}
	return out, rows.Err()
}

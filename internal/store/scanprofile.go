package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ScanProfile is a saved parameter preset.
type ScanProfile struct {
	ID        uuid.UUID         `json:"id"`
	Name      string            `json:"name"`
	Owner     *string           `json:"owner,omitempty"`
	ScopeID   *uuid.UUID        `json:"scope_id,omitempty"`
	Params    map[string]string `json:"params"`
	IsDefault bool              `json:"is_default"`
}

// SaveScanProfile inserts or updates a preset by (scope, name).
func (s *Store) SaveScanProfile(ctx context.Context, p ScanProfile) (uuid.UUID, error) {
	params, _ := json.Marshal(p.Params)
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO scan_profile (name, owner, scope_id, params, is_default)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (coalesce(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), name)
		DO UPDATE SET params=EXCLUDED.params, owner=EXCLUDED.owner, is_default=EXCLUDED.is_default
		RETURNING id`,
		p.Name, p.Owner, p.ScopeID, params, p.IsDefault).Scan(&id)
	return id, err
}

// ListScanProfiles returns presets available to a scope (its own + global).
func (s *Store) ListScanProfiles(ctx context.Context, scopeID uuid.UUID) ([]ScanProfile, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, owner, scope_id, params, is_default
		FROM scan_profile WHERE scope_id IS NULL OR scope_id=$1
		ORDER BY is_default DESC, name`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanProfile
	for rows.Next() {
		var p ScanProfile
		var raw []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Owner, &p.ScopeID, &raw, &p.IsDefault); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &p.Params)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetScanProfileParams returns a preset's params by id.
func (s *Store) GetScanProfileParams(ctx context.Context, id uuid.UUID) (map[string]string, error) {
	var raw []byte
	if err := s.Pool.QueryRow(ctx, `SELECT params FROM scan_profile WHERE id=$1`, id).Scan(&raw); err != nil {
		return nil, err
	}
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

// SetRunParams records the effective params on a run for reproducibility.
func (s *Store) SetRunParams(ctx context.Context, runID uuid.UUID, profileID *uuid.UUID, params map[string]string) error {
	raw, _ := json.Marshal(params)
	_, err := s.Pool.Exec(ctx, `UPDATE scan_run SET profile_id=$2, params=$3 WHERE id=$1`,
		runID, profileID, raw)
	return err
}

// GetRunParams returns the effective scan params recorded on a run.
func (s *Store) GetRunParams(ctx context.Context, runID uuid.UUID) (map[string]string, error) {
	var raw []byte
	if err := s.Pool.QueryRow(ctx, `SELECT params FROM scan_run WHERE id=$1`, runID).Scan(&raw); err != nil {
		return nil, err
	}
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

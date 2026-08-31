package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Wordlist is a registry entry. The file itself lives in object storage.
type Wordlist struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	ObjectKey string    `json:"object_key"`
	SourceURL *string   `json:"source_url,omitempty"`
	SHA256    *string   `json:"sha256,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	LineCount int64     `json:"line_count"`
	Builtin   bool      `json:"builtin"`
	IsDefault bool      `json:"is_default"`
	Status    string    `json:"status"`
	Error     *string   `json:"error,omitempty"`
}

const wordlistCols = `id, name, kind, object_key, source_url, sha256, size_bytes,
	line_count, builtin, is_default, status, error`

func scanWordlist(row interface{ Scan(...any) error }) (Wordlist, error) {
	var w Wordlist
	err := row.Scan(&w.ID, &w.Name, &w.Kind, &w.ObjectKey, &w.SourceURL, &w.SHA256,
		&w.SizeBytes, &w.LineCount, &w.Builtin, &w.IsDefault, &w.Status, &w.Error)
	return w, err
}

// ListWordlists returns the registry, optionally filtered by kind.
func (s *Store) ListWordlists(ctx context.Context, kind string) ([]Wordlist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+wordlistCols+`
		FROM wordlist WHERE ($1='' OR kind=$1)
		ORDER BY builtin DESC, name`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Wordlist{}
	for rows.Next() {
		w, err := scanWordlist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// GetWordlist fetches one entry.
func (s *Store) GetWordlist(ctx context.Context, id uuid.UUID) (Wordlist, error) {
	return scanWordlist(s.Pool.QueryRow(ctx,
		`SELECT `+wordlistCols+` FROM wordlist WHERE id=$1`, id))
}

// DefaultWordlists returns the entries pre-selected for a scan of this kind,
// skipping any that have not finished downloading.
func (s *Store) DefaultWordlists(ctx context.Context, kind string) ([]Wordlist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+wordlistCols+`
		FROM wordlist WHERE kind=$1 AND is_default AND status='ready' ORDER BY name`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Wordlist{}
	for rows.Next() {
		w, err := scanWordlist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// PendingWordlists returns built-ins still awaiting their first download.
func (s *Store) PendingWordlists(ctx context.Context) ([]Wordlist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+wordlistCols+`
		FROM wordlist WHERE status IN ('pending','failed') AND source_url IS NOT NULL
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Wordlist{}
	for rows.Next() {
		w, err := scanWordlist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// CreateWordlist registers a user-supplied list.
func (s *Store) CreateWordlist(ctx context.Context, name, kind, objectKey, createdBy string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO wordlist (name, kind, object_key, status, created_by)
		VALUES ($1,$2,$3,'pending',$4) RETURNING id`,
		name, kind, objectKey, createdBy).Scan(&id)
	return id, err
}

// MarkWordlistReady records the results of a successful fetch or upload.
func (s *Store) MarkWordlistReady(ctx context.Context, id uuid.UUID, sha string, size, lines int64) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE wordlist SET status='ready', sha256=$2, size_bytes=$3, line_count=$4, error=NULL
		WHERE id=$1`, id, sha, size, lines)
	return err
}

// MarkWordlistFailed records why a fetch did not complete.
func (s *Store) MarkWordlistFailed(ctx context.Context, id uuid.UUID, msg string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE wordlist SET status='failed', error=$2 WHERE id=$1`, id, msg)
	return err
}

// SetWordlistStatus moves an entry between lifecycle states.
func (s *Store) SetWordlistStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE wordlist SET status=$2 WHERE id=$1`, id, status)
	return err
}

// SetWordlistDefault toggles whether a list is pre-selected for new scans.
func (s *Store) SetWordlistDefault(ctx context.Context, id uuid.UUID, def bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE wordlist SET is_default=$2 WHERE id=$1`, id, def)
	return err
}

// DeleteWordlist removes a user-supplied list. Built-ins are protected.
func (s *Store) DeleteWordlist(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM wordlist WHERE id=$1 AND NOT builtin`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// SetRunWordlists records which lists a run used.
func (s *Store) SetRunWordlists(ctx context.Context, runID uuid.UUID, ids []uuid.UUID) error {
	for _, id := range ids {
		if _, err := s.Pool.Exec(ctx,
			`INSERT INTO run_wordlist (run_id, wordlist_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			runID, id); err != nil {
			return err
		}
	}
	return nil
}

// RunWordlists returns the ready lists a run was configured with.
func (s *Store) RunWordlists(ctx context.Context, runID uuid.UUID) ([]Wordlist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+prefixed(wordlistCols, "w.")+`
		FROM run_wordlist rw JOIN wordlist w ON w.id = rw.wordlist_id
		WHERE rw.run_id=$1 AND w.status='ready' ORDER BY w.name`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Wordlist{}
	for rows.Next() {
		w, err := scanWordlist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// prefixed qualifies a comma-separated column list with a table alias.
func prefixed(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Schedule is a recurring scan for one company.
type Schedule struct {
	ID          uuid.UUID  `json:"id"`
	ScopeID     uuid.UUID  `json:"scope_id"`
	Profile     string     `json:"profile"`
	Exit        string     `json:"exit"` // "" | local | remote
	VPNConfigID *uuid.UUID `json:"vpn_config_id,omitempty"`
	PoolID      *uuid.UUID `json:"pool_id,omitempty"`
	WorkerCount int        `json:"worker_count"`
	// EveryHours is the cadence; 0 is a one-off at NextRunAt that disables
	// itself once it has started.
	EveryHours int       `json:"every_hours"`
	Enabled    bool      `json:"enabled"`
	NextRunAt  time.Time `json:"next_run_at"`
	// The same choices a run carries, so the dialog that makes both can hand
	// them over unchanged.
	ProfileID   *uuid.UUID        `json:"profile_id,omitempty"`
	Params      map[string]string `json:"params"`
	WordlistIDs []uuid.UUID       `json:"wordlist_ids"`
	LastRunID   *uuid.UUID        `json:"last_run_id,omitempty"`
	LastRunAt   *time.Time        `json:"last_run_at,omitempty"`
	// LastError is why the most recent attempt did not start a run — a deleted
	// VPN config, an empty pool. Cleared when a run does start.
	LastError *string   `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const scheduleCols = `id, scope_id, profile, exit, vpn_config_id, pool_id, worker_count, every_hours,
	enabled, next_run_at, last_run_id, last_run_at, last_error, created_at, profile_id, params, wordlist_ids`

func scanSchedule(row interface{ Scan(...any) error }) (Schedule, error) {
	var sc Schedule
	var raw []byte
	err := row.Scan(&sc.ID, &sc.ScopeID, &sc.Profile, &sc.Exit, &sc.VPNConfigID, &sc.PoolID,
		&sc.WorkerCount, &sc.EveryHours, &sc.Enabled, &sc.NextRunAt, &sc.LastRunID,
		&sc.LastRunAt, &sc.LastError, &sc.CreatedAt, &sc.ProfileID, &raw, &sc.WordlistIDs)
	if err != nil {
		return sc, err
	}
	sc.Params = map[string]string{}
	_ = json.Unmarshal(raw, &sc.Params)
	if sc.WordlistIDs == nil {
		sc.WordlistIDs = []uuid.UUID{}
	}
	return sc, nil
}

// idsOrEmpty keeps a nil slice from being written as NULL into a NOT NULL array.
func idsOrEmpty(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

func paramsJSON(p map[string]string) []byte {
	if p == nil {
		p = map[string]string{}
	}
	raw, _ := json.Marshal(p)
	return raw
}

// CreateSchedule adds a scheduled scan — one-off or recurring. The first run is
// due at once unless a start is given.
func (s *Store) CreateSchedule(ctx context.Context, sc Schedule, createdBy *uuid.UUID) (Schedule, error) {
	if sc.NextRunAt.IsZero() {
		sc.NextRunAt = time.Now()
	}
	return scanSchedule(s.Pool.QueryRow(ctx, `
		INSERT INTO scan_schedule (scope_id, profile, exit, vpn_config_id, pool_id, worker_count,
		                           every_hours, enabled, next_run_at, created_by, profile_id, params, wordlist_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+scheduleCols,
		sc.ScopeID, sc.Profile, sc.Exit, sc.VPNConfigID, sc.PoolID, sc.WorkerCount,
		sc.EveryHours, sc.Enabled, sc.NextRunAt, createdBy, sc.ProfileID, paramsJSON(sc.Params), idsOrEmpty(sc.WordlistIDs)))
}

// UpdateSchedule replaces the editable fields. A non-nil startAt moves the next
// run to that time; otherwise re-enabling, or shortening the cadence, does not
// wait out the old next_run_at — the next tick decides. A one-off keeps its time.
func (s *Store) UpdateSchedule(ctx context.Context, sc Schedule, startAt *time.Time) (Schedule, error) {
	return scanSchedule(s.Pool.QueryRow(ctx, `
		UPDATE scan_schedule SET profile=$2, exit=$3, vpn_config_id=$4, pool_id=$5,
		  worker_count=$6, every_hours=$7, enabled=$8,
		  profile_id=$9, params=$10, wordlist_ids=$11,
		  next_run_at = COALESCE($12, CASE WHEN $7 = 0 THEN next_run_at
		                                   ELSE LEAST(next_run_at, now() + make_interval(hours => $7)) END)
		WHERE id=$1 RETURNING `+scheduleCols,
		sc.ID, sc.Profile, sc.Exit, sc.VPNConfigID, sc.PoolID, sc.WorkerCount, sc.EveryHours, sc.Enabled,
		sc.ProfileID, paramsJSON(sc.Params), idsOrEmpty(sc.WordlistIDs), startAt))
}

// DeleteSchedule removes one.
func (s *Store) DeleteSchedule(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM scan_schedule WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// GetSchedule returns one.
func (s *Store) GetSchedule(ctx context.Context, id uuid.UUID) (Schedule, error) {
	return scanSchedule(s.Pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM scan_schedule WHERE id=$1`, id))
}

// ListSchedules returns a company's schedules.
func (s *Store) ListSchedules(ctx context.Context, scopeID uuid.UUID) ([]Schedule, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+scheduleCols+` FROM scan_schedule WHERE scope_id=$1 ORDER BY created_at`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DueSchedules returns enabled schedules whose time has come.
func (s *Store) DueSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+scheduleCols+` FROM scan_schedule
		WHERE enabled AND next_run_at <= now() ORDER BY next_run_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ScopeHasActiveRun says whether a company already has a run going, so a
// schedule skips its slot rather than stacking a second run on the first.
func (s *Store) ScopeHasActiveRun(ctx context.Context, scopeID uuid.UUID) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM scan_run
		WHERE scope_id=$1 AND status IN ('queued','planning','running','paused')`, scopeID).Scan(&n)
	return n > 0, err
}

// ScheduleStarted records a run the schedule launched and advances next_run_at
// from the planned time — not from now — so a run that started late does not
// push every later one later. A one-off (every_hours = 0) has done its job and
// disables itself, keeping the row as the record of what ran.
func (s *Store) ScheduleStarted(ctx context.Context, id, runID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_schedule SET last_run_id=$2, last_run_at=now(), last_error=NULL,
		  enabled = CASE WHEN every_hours = 0 THEN false ELSE enabled END,
		  next_run_at = CASE WHEN every_hours = 0 THEN next_run_at
		                     ELSE GREATEST(next_run_at + make_interval(hours => every_hours),
		                                   now() + interval '1 minute') END
		WHERE id=$1`, id, runID)
	return err
}

// ScheduleFailed records why a run did not start and defers to the next slot,
// so a broken schedule says so in the UI instead of retrying every tick. A
// one-off has no next slot: it is disabled with the reason on it.
func (s *Store) ScheduleFailed(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_schedule SET last_error=$2,
		  enabled = CASE WHEN every_hours = 0 THEN false ELSE enabled END,
		  next_run_at = CASE WHEN every_hours = 0 THEN next_run_at
		                     ELSE GREATEST(next_run_at + make_interval(hours => every_hours),
		                                   now() + interval '1 minute') END
		WHERE id=$1`, id, reason)
	return err
}

// ScheduleSkipped defers a schedule whose company still has a run going, without
// recording an error: a slow run is not a broken schedule. It re-checks soon
// rather than a whole cadence later.
func (s *Store) ScheduleSkipped(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scan_schedule SET next_run_at = now() + interval '5 minutes' WHERE id=$1`, id)
	return err
}

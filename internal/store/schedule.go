package store

import (
	"context"
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
	EveryHours  int        `json:"every_hours"`
	Enabled     bool       `json:"enabled"`
	NextRunAt   time.Time  `json:"next_run_at"`
	LastRunID   *uuid.UUID `json:"last_run_id,omitempty"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	// LastError is why the most recent attempt did not start a run — a deleted
	// VPN config, an empty pool. Cleared when a run does start.
	LastError *string   `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const scheduleCols = `id, scope_id, profile, exit, vpn_config_id, pool_id, worker_count, every_hours,
	enabled, next_run_at, last_run_id, last_run_at, last_error, created_at`

func scanSchedule(row interface{ Scan(...any) error }) (Schedule, error) {
	var sc Schedule
	err := row.Scan(&sc.ID, &sc.ScopeID, &sc.Profile, &sc.Exit, &sc.VPNConfigID, &sc.PoolID,
		&sc.WorkerCount, &sc.EveryHours, &sc.Enabled, &sc.NextRunAt, &sc.LastRunID,
		&sc.LastRunAt, &sc.LastError, &sc.CreatedAt)
	return sc, err
}

// CreateSchedule adds a recurring scan. The first run is due at once unless a
// start is given.
func (s *Store) CreateSchedule(ctx context.Context, sc Schedule, createdBy *uuid.UUID) (Schedule, error) {
	if sc.NextRunAt.IsZero() {
		sc.NextRunAt = time.Now()
	}
	return scanSchedule(s.Pool.QueryRow(ctx, `
		INSERT INTO scan_schedule (scope_id, profile, exit, vpn_config_id, pool_id, worker_count,
		                           every_hours, enabled, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+scheduleCols,
		sc.ScopeID, sc.Profile, sc.Exit, sc.VPNConfigID, sc.PoolID, sc.WorkerCount,
		sc.EveryHours, sc.Enabled, sc.NextRunAt, createdBy))
}

// UpdateSchedule replaces the editable fields.
func (s *Store) UpdateSchedule(ctx context.Context, sc Schedule) (Schedule, error) {
	return scanSchedule(s.Pool.QueryRow(ctx, `
		UPDATE scan_schedule SET profile=$2, exit=$3, vpn_config_id=$4, pool_id=$5,
		  worker_count=$6, every_hours=$7, enabled=$8,
		  -- Re-enabling, or shortening the cadence, should not wait out the old
		  -- next_run_at; the next tick decides.
		  next_run_at = LEAST(next_run_at, now() + make_interval(hours => $7))
		WHERE id=$1 RETURNING `+scheduleCols,
		sc.ID, sc.Profile, sc.Exit, sc.VPNConfigID, sc.PoolID, sc.WorkerCount, sc.EveryHours, sc.Enabled))
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
		WHERE scope_id=$1 AND status IN ('queued','planning','running')`, scopeID).Scan(&n)
	return n > 0, err
}

// ScheduleStarted records a run the schedule launched and advances next_run_at
// from the planned time — not from now — so a run that started late does not
// push every later one later.
func (s *Store) ScheduleStarted(ctx context.Context, id, runID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_schedule SET last_run_id=$2, last_run_at=now(), last_error=NULL,
		  next_run_at = GREATEST(next_run_at + make_interval(hours => every_hours),
		                         now() + interval '1 minute')
		WHERE id=$1`, id, runID)
	return err
}

// ScheduleFailed records why a run did not start and defers to the next slot,
// so a broken schedule says so in the UI instead of retrying every tick.
func (s *Store) ScheduleFailed(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_schedule SET last_error=$2,
		  next_run_at = GREATEST(next_run_at + make_interval(hours => every_hours),
		                         now() + interval '1 minute')
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

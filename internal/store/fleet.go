package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RunFleet is the set of containers a run brought up for itself: its own
// workers, and a VPN gateway when the run scans through a tunnel.
type RunFleet struct {
	RunID uuid.UUID `json:"run_id"`
	// PoolID is null once the fleet has been torn down: the pool is transient,
	// the record of what the fleet did is not (migration 00020).
	PoolID      *uuid.UUID `json:"pool_id,omitempty"`
	Workers     int        `json:"workers"`
	EnrollToken string     `json:"-"` // never leaves the server
	VPNConfigID *uuid.UUID `json:"vpn_config_id,omitempty"`
	Status      string     `json:"status"` // requested|up|failed|torn_down
	Error       *string    `json:"error,omitempty"`
	EgressIP    *string    `json:"egress_ip,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ReadyAt     *time.Time `json:"ready_at,omitempty"`
}

const fleetCols = `run_id, pool_id, workers, enroll_token, vpn_config_id, status, error, egress_ip, created_at, ready_at`

func scanFleet(row interface{ Scan(...any) error }) (RunFleet, error) {
	var f RunFleet
	err := row.Scan(&f.RunID, &f.PoolID, &f.Workers, &f.EnrollToken, &f.VPNConfigID,
		&f.Status, &f.Error, &f.EgressIP, &f.CreatedAt, &f.ReadyAt)
	return f, err
}

// CreateRunPool makes a pool that exists only for one run, so the run's workers
// can be routed work no other run can take, and so teardown can remove the pool
// without touching one an operator made.
func (s *Store) CreateRunPool(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO worker_pool (name, description, run_scoped) VALUES ($1,$2,true) RETURNING id`,
		name, "workers created for a single scan run").Scan(&id)
	return id, err
}

// CreateRunFleet records that a run wants its own fleet. The scheduler picks it
// up from here, so a control-plane restart between the request and the
// containers existing is recoverable rather than a run that waits forever.
func (s *Store) CreateRunFleet(ctx context.Context, f RunFleet) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO run_fleet (run_id, pool_id, workers, enroll_token, vpn_config_id, status)
		VALUES ($1,$2,$3,$4,$5,'requested')`,
		f.RunID, f.PoolID, f.Workers, f.EnrollToken, f.VPNConfigID)
	return err
}

// GetRunFleet returns a run's fleet, if it has one.
func (s *Store) GetRunFleet(ctx context.Context, runID uuid.UUID) (RunFleet, bool, error) {
	f, err := scanFleet(s.Pool.QueryRow(ctx, `SELECT `+fleetCols+` FROM run_fleet WHERE run_id=$1`, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return RunFleet{}, false, nil
	}
	return f, err == nil, err
}

// FleetsToBuild returns fleets that have been asked for but not yet created.
func (s *Store) FleetsToBuild(ctx context.Context) ([]RunFleet, error) {
	return s.fleetsWhere(ctx, `f.status='requested' AND r.status IN ('queued','planning','running')`)
}

// FleetsToTearDown returns fleets whose run has finished but whose containers
// are still around.
func (s *Store) FleetsToTearDown(ctx context.Context) ([]RunFleet, error) {
	return s.fleetsWhere(ctx,
		`f.status IN ('up','failed','requested') AND r.status NOT IN ('queued','planning','running')`)
}

// LiveFleets returns fleets whose run is still going, for supervision.
func (s *Store) LiveFleets(ctx context.Context) ([]RunFleet, error) {
	return s.fleetsWhere(ctx, `f.status='up' AND r.status IN ('queued','planning','running')`)
}

func (s *Store) fleetsWhere(ctx context.Context, cond string) ([]RunFleet, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+prefixed(fleetCols, "f.")+`
		FROM run_fleet f JOIN scan_run r ON r.id = f.run_id
		WHERE `+cond+` ORDER BY f.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunFleet{}
	for rows.Next() {
		f, err := scanFleet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFleetStatus records what happened to a fleet.
func (s *Store) SetFleetStatus(ctx context.Context, runID uuid.UUID, status string, errMsg, egressIP *string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE run_fleet SET status=$2, error=$3,
		  egress_ip = COALESCE($4, egress_ip),
		  ready_at = CASE WHEN $2='up' AND ready_at IS NULL THEN now() ELSE ready_at END,
		  torn_down_at = CASE WHEN $2='torn_down' THEN now() ELSE torn_down_at END
		WHERE run_id=$1`, runID, status, errMsg, egressIP)
	return err
}

// CountLiveFleets is the concurrency ceiling's input: how many runs actually
// hold containers right now.
//
// Only 'up' counts. A 'requested' row is an intention with nothing running
// behind it, and counting those would have every fleet in a batch see the
// others as already built and refuse itself.
func (s *Store) CountLiveFleets(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM run_fleet WHERE status='up'`).Scan(&n)
	return n, err
}

// MarkFleetTornDown records that a fleet's containers are gone.
//
// Separate from SetFleetStatus because teardown must not touch `error`: a fleet
// that failed is torn down immediately afterwards, and writing the status
// through the general setter would replace the reason the run failed with null
// — losing the only explanation the operator gets.
func (s *Store) MarkFleetTornDown(ctx context.Context, runID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE run_fleet SET status='torn_down', torn_down_at=now() WHERE run_id=$1`, runID)
	return err
}

// DeleteRunPoolAndWorkers removes the worker rows a run's fleet enrolled and the
// pool they were in. Task attribution survives it: the worker's name and kind
// are stamped onto each task when it is leased (00012), so a finished run still
// says who ran what after its workers are gone.
func (s *Store) DeleteRunPoolAndWorkers(ctx context.Context, poolID uuid.UUID) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM worker WHERE pool_id=$1`, poolID)
	if err != nil {
		return 0, err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM worker_pool WHERE id=$1 AND run_scoped`, poolID); err != nil {
		return ct.RowsAffected(), err
	}
	return ct.RowsAffected(), nil
}

// ActiveWorkersInPool counts the workers of a fleet that are currently usable,
// which is how a dead fleet is told from a slow one.
func (s *Store) ActiveWorkersInPool(ctx context.Context, poolID uuid.UUID) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM worker WHERE pool_id=$1 AND status='active'`, poolID).Scan(&n)
	return n, err
}

// SetRunPool binds a run to a pool, so only that pool's workers may lease its
// tasks. The lease query has always filtered on this; nothing used to set it.
func (s *Store) SetRunPool(ctx context.Context, runID, poolID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scan_run SET pool_id=$2 WHERE id=$1`, runID, poolID)
	return err
}

// RunHasFleet reports whether a run's traffic leaves through containers the run
// brought up for itself.
//
// This is the one fact the planner, the dispatcher and the worker all have to
// agree on, so they all read it from here. Where a run has a fleet the tunnel
// lives in its gateway container and the workers inherit it by sharing that
// namespace: they must not be asked for the `vpn` capability, which they do not
// hold, and must not be handed a config to build a tunnel they cannot build.
//
// Callers fail closed on error — they keep the tunnel requirement — because a
// wrong "no fleet" answer stalls tasks visibly, while a wrong "has fleet" one
// would scan from the worker's own address.
func (s *Store) RunHasFleet(ctx context.Context, runID uuid.UUID) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM run_fleet WHERE run_id=$1`, runID).Scan(&n)
	return n > 0, err
}

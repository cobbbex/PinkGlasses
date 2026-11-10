package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WorkerPool is a set of workers a task can be routed to.
type WorkerPool struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	IsDefault   bool      `json:"is_default"`
	// ActiveWorkers is how many of its workers can take work right now — what
	// decides whether a run may choose this pool as its exit.
	ActiveWorkers int `json:"active_workers"`
	// TakesDiscovery marks a pool that runs the stages which never touch the
	// target, moving that work off the control-plane host.
	TakesDiscovery bool `json:"takes_discovery"`
	// OwnerID is the account whose remote workers these are; only that
	// account's runs are routed here. Nil for the shared pools.
	OwnerID   *uuid.UUID `json:"owner_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// PassivePool is where a run's passive stages run: the standing local
// workers, which the bootstrap token enrols into the shared pool named
// `local`. If an install has renamed or removed it, the default pool stands in.
//
// Passive stages never send a packet at the target — they talk to third-party
// APIs and public resolvers — so they need no chosen exit, and running them on
// the standing pool means a run does not wait for its fleet to come up before
// discovery starts.
// A pool of the run's own account marked to take discovery is preferred, but
// only while it has an active worker: a pool whose machines have gone away
// must not swallow the account's discovery, so the standing workers take it
// back. Another account's pool is never chosen, whatever it is marked.
func (s *Store) PassivePool(ctx context.Context, owner *uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	if owner != nil {
		err := s.Pool.QueryRow(ctx, `
			SELECT p.id FROM worker_pool p
			WHERE p.takes_discovery AND NOT p.run_scoped AND p.owner_id = $1
			  AND EXISTS (SELECT 1 FROM worker w WHERE w.pool_id = p.id AND w.status = 'active')
			ORDER BY p.name LIMIT 1`, *owner).Scan(&id)
		if err == nil {
			return id, nil
		}
	}
	if id, err := s.PoolByName(ctx, "local"); err == nil {
		return id, nil
	}
	return s.DefaultPool(ctx)
}

// SetPoolTakesDiscovery marks one of the owner's pools as taking that
// account's discovery work, or stops it. Another account's pool, a shared one
// and a run-scoped one are refused (false).
func (s *Store) SetPoolTakesDiscovery(ctx context.Context, id, owner uuid.UUID, v bool) (bool, error) {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE worker_pool SET takes_discovery=$2 WHERE id=$1 AND owner_id=$3 AND NOT run_scoped`, id, v, owner)
	return ct.RowsAffected() > 0, err
}

// ListExitPools returns the pools a run of this account may choose as its
// remote exit — the account's own, never another's or a run's — with a live
// worker count so the UI can grey out an empty one rather than let a run bind
// to it and stall.
//
// The count is of remote workers only. A worker of kind `local` is a standing
// container on the control-plane host, there to run passive stages; letting an
// active scan bind to its pool would send packets at the target from this
// host's own address, which is exactly what the exit design exists to prevent.
func (s *Store) ListExitPools(ctx context.Context, owner uuid.UUID) ([]WorkerPool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+exitPoolCols+`
		FROM worker_pool p
		WHERE NOT p.run_scoped AND p.owner_id = $1
		ORDER BY p.is_default DESC, p.name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WorkerPool{}
	for rows.Next() {
		p, err := scanExitPool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

const exitPoolCols = `p.id, p.name, p.description, p.is_default, p.created_at,
	(SELECT count(*) FROM worker w WHERE w.pool_id = p.id AND w.status='active' AND w.kind <> 'local'),
	p.takes_discovery, p.owner_id`

func scanExitPool(row interface{ Scan(...any) error }) (WorkerPool, error) {
	var p WorkerPool
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.IsDefault, &p.CreatedAt,
		&p.ActiveWorkers, &p.TakesDiscovery, &p.OwnerID)
	return p, err
}

// GetExitPool returns one of the owner's pools a run may bind its active
// stages to. Another account's pool, a shared one and a run's own are all
// "not found": a run never scans from workers that are not its account's.
func (s *Store) GetExitPool(ctx context.Context, id, owner uuid.UUID) (WorkerPool, bool, error) {
	p, err := scanExitPool(s.Pool.QueryRow(ctx, `SELECT `+exitPoolCols+`
		FROM worker_pool p WHERE p.id=$1 AND p.owner_id=$2 AND NOT p.run_scoped`, id, owner))
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkerPool{}, false, nil
	}
	if err != nil {
		return WorkerPool{}, false, err
	}
	return p, true, nil
}

// OwnPool returns the account's own pool for remote workers, named "remote",
// making it the first time: where an account's workers enrol unless it names
// another of its pools.
func (s *Store) OwnPool(ctx context.Context, owner uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO worker_pool (name, description, owner_id) VALUES ('remote', 'Your remote workers', $1)
		ON CONFLICT (owner_id, name) WHERE owner_id IS NOT NULL DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, owner).Scan(&id)
	return id, err
}

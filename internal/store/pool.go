package store

import (
	"context"
	"time"

	"github.com/google/uuid"
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
	TakesDiscovery bool      `json:"takes_discovery"`
	CreatedAt      time.Time `json:"created_at"`
}

// PassivePool is where passive stages run: the standing local workers, which
// the bootstrap token enrols into the pool named `local`. If an install has
// renamed or removed it, the default pool stands in.
//
// Passive stages never send a packet at the target — they talk to third-party
// APIs and public resolvers — so they need no chosen exit, and running them on
// the standing pool means a run does not wait for its fleet to come up before
// discovery starts.
// A pool marked to take discovery is preferred, but only while it has an
// active worker: a pool whose machines have gone away must not swallow every
// company's discovery, so the standing workers take it back.
func (s *Store) PassivePool(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		SELECT p.id FROM worker_pool p
		WHERE p.takes_discovery AND NOT p.run_scoped
		  AND EXISTS (SELECT 1 FROM worker w WHERE w.pool_id = p.id AND w.status = 'active')
		ORDER BY p.name LIMIT 1`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if id, err := s.PoolByName(ctx, "local"); err == nil {
		return id, nil
	}
	return s.DefaultPool(ctx)
}

// SetPoolTakesDiscovery marks a pool as taking discovery work, or stops it.
// A run-scoped pool is refused: it exists for one run's own workers.
func (s *Store) SetPoolTakesDiscovery(ctx context.Context, id uuid.UUID, v bool) (bool, error) {
	ct, err := s.Pool.Exec(ctx,
		`UPDATE worker_pool SET takes_discovery=$2 WHERE id=$1 AND NOT run_scoped`, id, v)
	return ct.RowsAffected() > 0, err
}

// ListExitPools returns the pools a run may choose as its remote exit: every
// pool that is not one a run built for itself, with a live worker count so the
// UI can grey out an empty one rather than let a run bind to it and stall.
//
// The count is of remote workers only. A worker of kind `local` is a standing
// container on the control-plane host, there to run passive stages; letting an
// active scan bind to its pool would send packets at the target from this
// host's own address, which is exactly what the exit design exists to prevent.
func (s *Store) ListExitPools(ctx context.Context) ([]WorkerPool, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT p.id, p.name, p.description, p.is_default, p.created_at,
		       (SELECT count(*) FROM worker w WHERE w.pool_id = p.id AND w.status='active' AND w.kind <> 'local'),
		       p.takes_discovery
		FROM worker_pool p
		WHERE NOT p.run_scoped
		ORDER BY p.is_default DESC, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WorkerPool{}
	for rows.Next() {
		var p WorkerPool
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.IsDefault, &p.CreatedAt,
			&p.ActiveWorkers, &p.TakesDiscovery); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetExitPool returns one pool a run may bind its active stages to, refusing a
// run-scoped pool — those belong to the run that made them.
func (s *Store) GetExitPool(ctx context.Context, id uuid.UUID) (WorkerPool, bool, error) {
	var p WorkerPool
	err := s.Pool.QueryRow(ctx, `
		SELECT p.id, p.name, p.description, p.is_default, p.created_at,
		       (SELECT count(*) FROM worker w WHERE w.pool_id = p.id AND w.status='active' AND w.kind <> 'local'),
		       p.takes_discovery
		FROM worker_pool p WHERE p.id=$1 AND NOT p.run_scoped`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.IsDefault, &p.CreatedAt, &p.ActiveWorkers, &p.TakesDiscovery)
	if err != nil {
		return WorkerPool{}, false, nil //nolint:nilerr // not found, or run-scoped
	}
	return p, true, nil
}

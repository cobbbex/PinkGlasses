// Package dispatch turns lease/heartbeat/complete operations into a small
// service used by the gateway. The heavy SQL lives in store; this layer adds
// worker running-task accounting and capability matching.
package dispatch

import (
	"context"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/scanproto"
	"github.com/benlik386/asm/internal/store"
)

// Dispatcher assigns work to workers.
type Dispatcher struct {
	st       *store.Store
	leaseTTL int // seconds
}

// New builds a Dispatcher.
func New(st *store.Store, leaseTTLSeconds int) *Dispatcher {
	return &Dispatcher{st: st, leaseTTL: leaseTTLSeconds}
}

// Lease claims up to `limit` tasks for a worker matching its capabilities.
func (d *Dispatcher) Lease(ctx context.Context, workerID uuid.UUID, caps []string, poolID *uuid.UUID, limit int) ([]scanproto.Job, error) {
	return d.st.LeaseTasks(ctx, workerID, caps, poolID, limit, d.leaseTTL)
}

// Heartbeat extends the lease on a running task.
func (d *Dispatcher) Heartbeat(ctx context.Context, taskID, leaseToken uuid.UUID) error {
	return d.st.ExtendLease(ctx, taskID, leaseToken, d.leaseTTL)
}

// Complete closes a task and stores its stage summary for the planner.
func (d *Dispatcher) Complete(ctx context.Context, taskID, leaseToken uuid.UUID, summary []byte) error {
	if len(summary) > 0 {
		_ = d.st.SetTaskResult(ctx, taskID, summary)
	}
	return d.st.CompleteTask(ctx, taskID, leaseToken)
}

// Fail records a task error (retried until max_attempts).
func (d *Dispatcher) Fail(ctx context.Context, taskID, leaseToken uuid.UUID, msg string) error {
	return d.st.FailTask(ctx, taskID, leaseToken, msg)
}

// CanRun reports whether a worker's capabilities satisfy a stage's requirements.
func CanRun(caps []string, stage scanproto.Stage) bool {
	have := map[string]bool{}
	for _, c := range caps {
		have[c] = true
	}
	for _, req := range scanproto.StageRequires(stage) {
		if !have[string(req)] {
			return false
		}
	}
	return true
}

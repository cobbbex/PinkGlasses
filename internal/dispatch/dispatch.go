// Package dispatch turns lease/heartbeat/complete operations into a small
// service used by the gateway. The heavy SQL lives in store; this layer adds
// worker running-task accounting and capability matching.
package dispatch

import (
	"context"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/scanproto"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Dispatcher assigns work to workers.
type Dispatcher struct {
	st       *store.Store
	leaseTTL int // seconds
	// bruteCap is how many dns_brute tasks one worker may hold at once.
	bruteCap int
}

// New builds a Dispatcher.
func New(st *store.Store, leaseTTLSeconds int) *Dispatcher {
	return &Dispatcher{st: st, leaseTTL: leaseTTLSeconds, bruteCap: 1}
}

// WithBruteCap sets how many brute-force tasks a worker may run at once.
func (d *Dispatcher) WithBruteCap(n int) *Dispatcher {
	if n < 1 {
		n = 1
	}
	d.bruteCap = n
	return d
}

// Lease claims up to `limit` tasks for a worker matching its capabilities.
//
// Brute-force tasks are leased apart from the rest and never more than the
// worker's cap at a time. Each is thousands of DNS queries a second from the
// machine the worker runs on; three domains and two wordlists used to mean
// six at once on the standing worker, beside the database and the web app.
// They wait in the queue instead, and discovery still starts at once: the
// other stages lease as before.
func (d *Dispatcher) Lease(ctx context.Context, workerID uuid.UUID, caps []string, poolID *uuid.UUID, limit int) ([]scanproto.Job, error) {
	var jobs []scanproto.Job
	if room, err := d.st.BruteRoom(ctx, workerID, d.bruteCap); err == nil && room > 0 {
		n := room
		if n > limit {
			n = limit
		}
		brute, err := d.st.LeaseTasksWhere(ctx, workerID, caps, poolID, n, d.leaseTTL, store.OnlyBrute)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, brute...)
	}
	if rest := limit - len(jobs); rest > 0 {
		more, err := d.st.LeaseTasksWhere(ctx, workerID, caps, poolID, rest, d.leaseTTL, store.NoBrute)
		if err != nil {
			return jobs, err
		}
		jobs = append(jobs, more...)
	}
	return jobs, nil
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

// FailForGood records a failure the worker said a retry would only repeat.
func (d *Dispatcher) FailForGood(ctx context.Context, taskID, leaseToken uuid.UUID, msg string) error {
	return d.st.FailTaskPermanently(ctx, taskID, leaseToken, msg)
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

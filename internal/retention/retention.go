// Package retention removes the detail of runs a company no longer wants to
// keep: their tasks, per-run observations, change events, screenshots and raw
// output. What a company currently exposes — its names, hosts, services and
// findings — is never touched; only the record of the runs that saw it.
//
// Without this, storage grows with clients times scans times time, and the
// disk is the first thing to fail on a busy install.
package retention

import (
	"context"
	"log/slog"

	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Pruner deletes runs past their company's retention.
type Pruner struct {
	st  *store.Store
	obj *obj.Store
	// perSweep caps how many runs one pass removes, so a company that has
	// just turned retention on does not hold the sweep for minutes.
	perSweep int
}

// New builds a Pruner. A perSweep of zero or less takes the default.
func New(st *store.Store, o *obj.Store, perSweep int) *Pruner {
	if perSweep <= 0 {
		perSweep = 25
	}
	return &Pruner{st: st, obj: o, perSweep: perSweep}
}

// Sweep removes what is past retention and reports how many runs went and how
// many stored objects with them.
func (p *Pruner) Sweep(ctx context.Context) (runs, artifacts int) {
	due, err := p.st.RunsPastRetention(ctx, p.perSweep)
	if err != nil {
		slog.Error("could not list runs past retention", "err", err)
		return 0, 0
	}
	for _, r := range due {
		// The keys first: once the rows are gone nothing knows what the run
		// had stored, and the objects would sit there forever.
		keys, err := p.st.RunArtifactKeys(ctx, r.RunID)
		if err != nil {
			slog.Warn("could not list a run's artifacts; leaving it", "run", r.RunID, "err", err)
			continue
		}
		ok, err := p.st.DeleteRun(ctx, r.RunID)
		if err != nil {
			slog.Warn("could not prune a run", "run", r.RunID, "company", r.Scope, "err", err)
			continue
		}
		if !ok {
			continue
		}
		runs++
		for _, k := range keys {
			if p.obj == nil {
				break
			}
			if err := p.obj.Delete(ctx, k); err != nil {
				slog.Warn("could not remove a pruned run's artifact", "run", r.RunID, "key", k, "err", err)
				continue
			}
			artifacts++
		}
		slog.Info("pruned a run past its company's retention",
			"run", r.RunID, "company", r.Scope, "age_days", r.Age, "artifacts", len(keys))
	}
	if runs > 0 {
		slog.Info("retention sweep", "runs_pruned", runs, "artifacts_removed", artifacts)
	}
	return runs, artifacts
}

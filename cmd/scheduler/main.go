// Command scheduler is the leader-elected control loop: it advances running
// scan runs through the stage machine, reaps expired leases, marks stale
// workers, runs the differ on completion, and performs periodic sweeps
// (wiki/Architecture.md §3.3).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/diff"
	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/fleet"
	"github.com/benlik386/pinkglasses/internal/launch"
	"github.com/benlik386/pinkglasses/internal/notify"
	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/planner"
	"github.com/benlik386/pinkglasses/internal/retention"
	"github.com/benlik386/pinkglasses/internal/store"
	"github.com/benlik386/pinkglasses/internal/wordlists"
)

// cfgTick is the configured tick, reported on the health page.
var cfgTick time.Duration

func main() {
	cfg := config.LoadScheduler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db open", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Fetch any wordlist still missing its file (the shipped assetnote lists on
	// first boot, or a retry after a failed download). Runs in the background so
	// a slow CDN never delays the scheduler loop.
	seeder := wordlists.NewSeeder(st, obj.New(objConfigFromEnv()))
	go seeder.Run(ctx)

	pl := planner.New(st)
	df := diff.New(st)
	// Digests go out after the differ has recorded what a run changed. The
	// senders existed since the first build; nothing called them.
	nt := notify.New(st, os.Getenv("ASM_PUBLIC_URL"))
	// Per-company retention: what a company no longer wants to keep.
	pruner := retention.New(st, obj.New(objConfigFromEnv()), 0)
	// Runs that bring up their own workers. The scheduler owns this rather than
	// the api because it has to outlive the request that asked for it: the
	// containers must come down when the run ends, whatever happened in between.
	fl := fleet.New(st, cfg.ProvisionerURL, cfg.ProvisionerToken, cfg.MaxRunFleets)
	// Recurring scans start here, through the same code the API uses, so a
	// scheduled run is refused for exactly the reasons a manual one would be.
	ln := launch.New(st, pl)
	if fl.Enabled() {
		slog.Info("run fleets enabled", "max_concurrent", cfg.MaxRunFleets)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	cfgTick = cfg.Tick
	ticker := time.NewTicker(cfg.Tick)
	defer ticker.Stop()
	host, _ := os.Hostname()
	slog.Info("scheduler started", "tick", cfg.Tick, "instance", host)

	sweepEvery := 5 * time.Minute
	lastSweep := time.Now().Add(-sweepEvery)

	// Exactly one scheduler plans work: two would start every scheduled scan
	// twice and reap every lease twice. The lock lives in Postgres, so any
	// number of copies may run; the others stand by and one takes over the
	// moment the leader's connection is gone.
	var leader *store.Leader
	defer func() { leader.Release(context.Background()) }()

	for {
		select {
		case <-stop:
			slog.Info("scheduler stopping")
			return
		case <-ticker.C:
			if leader != nil && !leader.Alive(ctx) {
				slog.Warn("lost the leader lock: the database connection holding it is gone; standing by")
				leader = nil
			}
			if leader == nil {
				l, held, err := st.TryLeadScheduler(ctx)
				switch {
				case err != nil:
					slog.Error("could not try for the leader lock", "err", err)
					continue
				case !held:
					// Say so on the health page too, under this instance's name.
					_ = st.BeatComponent(ctx, "scheduler-standby:"+host, map[string]any{"leader": false})
					continue
				}
				leader = l
				slog.Info("this instance is the scheduler leader", "instance", host)
				if fl.Enabled() {
					go fl.SweepOrphans(ctx)
				}
			}
			ln.Due(ctx)
			tick(ctx, st, pl, df, nt)
			// After tick, so a run that just finished has its containers
			// removed on this pass rather than the next one.
			fl.Tick(ctx)
			if time.Since(lastSweep) >= sweepEvery {
				sweep(ctx, st, seeder, nt, pruner)
				fl.SweepOrphans(ctx)
				lastSweep = time.Now()
			}
		}
	}
}

func tick(ctx context.Context, st *store.Store, pl *planner.Planner, df *diff.Differ, nt *notify.Notifier) {
	// Liveness for the health page: the scheduler has no endpoint to call.
	host, _ := os.Hostname()
	_ = st.BeatComponent(ctx, "scheduler", map[string]any{"tick_s": cfgTick.Seconds(), "leader": true, "instance": host})
	// 1. Reap expired leases so dead workers' tasks get reassigned. Each one
	// is logged in full: a lease expires only when no heartbeat naming the
	// task reached the gateway for the whole lease TTL, which is a worker
	// that died, lost its control channel, or a gateway that was down — and
	// the gateway log around this time says which.
	if reaped, err := st.ReapExpiredLeases(ctx); err == nil {
		for _, r := range reaped {
			what := "task re-queued for another attempt"
			if r.Status == "failed" {
				what = "task failed: no attempts left"
			}
			slog.Warn("lease expired — "+what,
				"task", r.TaskID, "run", r.RunID, "stage", r.Stage, "target", r.Target,
				"held_by", r.WorkerName, "attempt", r.Attempts, "max_attempts", r.MaxAttempts,
				"noticed_after", r.Late.Round(time.Second).String(),
				"why", "no heartbeat named this task for the lease TTL; look for 'control channel closed' or 'heartbeat gap' from that worker in the gateway log")
		}
	} else if err != nil {
		slog.Error("reaping expired leases", "err", err)
	}
	// 2. Advance each running run through its stage machine.
	runs, err := st.RunningRuns(ctx)
	if err != nil {
		slog.Error("running runs", "err", err)
		return
	}
	for _, run := range runs {
		finished, err := pl.Advance(ctx, run)
		if err != nil {
			slog.Error("advance", "run", run.ID, "err", err)
			continue
		}
		if finished {
			// Re-read to get finished timestamps, then diff against baseline.
			done, _ := st.GetRun(ctx, run.ID)
			if done.Status == domain.RunCompleted {
				if n, err := df.Diff(ctx, done); err == nil {
					slog.Info("run completed", "run", run.ID, "changes", n)
					if sent, err := nt.Notify(ctx, done); err != nil {
						slog.Error("notify", "run", run.ID, "err", err)
					} else if sent > 0 {
						slog.Info("digests sent", "run", run.ID, "channels", sent)
					}
				}
			}
		}
	}
}

func sweep(ctx context.Context, st *store.Store, seeder *wordlists.Seeder, nt *notify.Notifier, pr *retention.Pruner) {
	// Runs past their company's retention, with their artifacts.
	pr.Sweep(ctx)
	// Daily digests, for channels that asked for one message a day rather
	// than one per run.
	if n, err := nt.SendDueDigests(ctx, time.Now()); err != nil {
		slog.Error("daily digests", "err", err)
	} else if n > 0 {
		slog.Info("daily digests sent", "channels", n)
	}
	// Retry any wordlist still missing its file. Downloads fail for transient
	// reasons (object storage not up yet, a slow CDN); without this a failure
	// at boot would need a restart to clear.
	go seeder.Run(ctx)

	// Mark workers stale after 90s without a heartbeat.
	if n, err := st.MarkStaleWorkers(ctx, 90*time.Second); err == nil && n > 0 {
		slog.Info("marked stale workers", "count", n)
	}
	// Local workers are cattle: scaling recreates containers and each recreation
	// self-enrolls fresh. Scaling down deletes their rows directly; this is the
	// backstop for containers that died on their own. Remote workers are kept.
	if n, err := st.ReapStaleLocalWorkers(ctx, 10*time.Minute); err == nil && n > 0 {
		slog.Info("reaped stale local workers", "count", n)
	}
	// Runs that were created but never planned. Nothing advances a queued run
	// with no tasks, and it blocks every scheduled scan for its company.
	if n, err := st.FailZombieRuns(ctx, 10*time.Minute); err == nil && n > 0 {
		slog.Warn("failed runs that were queued with no tasks", "count", n)
	}
	// Sessions that have aged out. Lookup already refuses an expired session,
	// so this is housekeeping rather than enforcement — but a table that only
	// ever grows is its own problem.
	if n, err := st.ReapExpiredSessions(ctx); err == nil && n > 0 {
		slog.Info("reaped expired sessions", "count", n)
	}
	// Sign-in attempts past the window they are counted in. Same reason: the
	// limiter never reads them again, the table would only grow.
	if n, err := st.PruneLoginAttempts(ctx, time.Hour); err == nil && n > 0 {
		slog.Debug("pruned old sign-in attempts", "count", n)
	}
	// Say so when a run has tasks nobody can lease. The run shows "running"
	// in the UI and nothing progresses; without this line the only way to
	// tell was to query scan_task and worker by hand.
	if stranded, err := st.StrandedTasks(ctx, 2*time.Minute); err == nil {
		for _, s := range stranded {
			pool := "none"
			if s.PoolID != nil {
				pool = s.PoolID.String()
			}
			slog.Warn("tasks pending with no active worker able to lease them",
				"run", s.RunID, "stage", s.Stage, "tasks", s.Tasks, "pool", pool,
				"waiting_since", s.Oldest.UTC().Format(time.RFC3339))
		}
	}
	// Cert-expiry finding sweep would run here (ExpiringCerts).
	_, _ = st.ExpiringCerts(ctx, 14*24*time.Hour)
}

// objConfigFromEnv builds the object-storage config the seeder uploads through.
func objConfigFromEnv() config.S3 {
	return config.LoadAPI().S3
}

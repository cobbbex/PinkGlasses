// Command scheduler is the leader-elected control loop: it advances running
// scan runs through the stage machine, reaps expired leases, marks stale
// workers, runs the differ on completion, and performs periodic sweeps
// (architecture.md §3.3).
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
	"github.com/benlik386/pinkglasses/internal/notify"
	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/planner"
	"github.com/benlik386/pinkglasses/internal/store"
	"github.com/benlik386/pinkglasses/internal/wordlists"
)

const schedulerLockKey = 0x4153_4d31 // "ASM1"

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

	// Leader election via advisory lock: only one scheduler drives the loop.
	locked, err := st.TryAdvisoryLock(ctx, schedulerLockKey)
	if err != nil || !locked {
		slog.Info("another scheduler holds the leader lock; standing by")
	}

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
	// Runs that bring up their own workers. The scheduler owns this rather than
	// the api because it has to outlive the request that asked for it: the
	// containers must come down when the run ends, whatever happened in between.
	fl := fleet.New(st, cfg.ProvisionerURL, cfg.ProvisionerToken, cfg.MaxRunFleets)
	if fl.Enabled() {
		slog.Info("run fleets enabled", "max_concurrent", cfg.MaxRunFleets)
		// Containers whose run ended while this was not running.
		go fl.SweepOrphans(ctx)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.Tick)
	defer ticker.Stop()
	slog.Info("scheduler started", "tick", cfg.Tick)

	sweepEvery := 5 * time.Minute
	lastSweep := time.Now().Add(-sweepEvery)

	for {
		select {
		case <-stop:
			slog.Info("scheduler stopping")
			return
		case <-ticker.C:
			tick(ctx, st, pl, df, nt)
			// After tick, so a run that just finished has its containers
			// removed on this pass rather than the next one.
			fl.Tick(ctx)
			if time.Since(lastSweep) >= sweepEvery {
				sweep(ctx, st, seeder)
				fl.SweepOrphans(ctx)
				lastSweep = time.Now()
			}
		}
	}
}

func tick(ctx context.Context, st *store.Store, pl *planner.Planner, df *diff.Differ, nt *notify.Notifier) {
	// 1. Reap expired leases so dead workers' tasks get reassigned.
	if n, err := st.ReapExpiredLeases(ctx); err == nil && n > 0 {
		slog.Info("reaped expired leases", "count", n)
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

func sweep(ctx context.Context, st *store.Store, seeder *wordlists.Seeder) {
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
	// Cert-expiry finding sweep would run here (ExpiringCerts).
	_, _ = st.ExpiringCerts(ctx, 14*24*time.Hour)
}

// objConfigFromEnv builds the object-storage config the seeder uploads through.
func objConfigFromEnv() config.S3 {
	return config.LoadAPI().S3
}

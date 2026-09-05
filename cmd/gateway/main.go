// Command gateway is the agent-facing service (the only internet-facing one).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/benlik386/pinkglasses/internal/agentapi"
	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/store"
)

func main() {
	cfg := config.LoadGateway()
	ctx := context.Background()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db open", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	gw := agentapi.New(st, cfg)
	// Register the shared local-worker bootstrap token so containers on the
	// internal network self-enroll (docker compose --scale worker=N). Retried
	// until it lands: on a fresh install the gateway can come up while the
	// migrator is still adding the columns this write needs, and a seed that
	// gave up once left every local worker refused with 401 forever.
	go func() {
		for attempt := 1; ; attempt++ {
			err := gw.SeedBootstrapToken(ctx)
			if err == nil {
				if attempt > 1 {
					slog.Info("local bootstrap token seeded", "attempts", attempt)
				}
				return
			}
			slog.Warn("could not seed local bootstrap token; retrying", "err", err, "attempt", attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	srv := &http.Server{Addr: cfg.Addr, Handler: gw.Routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("gateway listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("gateway serve", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

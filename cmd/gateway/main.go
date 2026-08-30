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

	"github.com/benlik386/asm/internal/agentapi"
	"github.com/benlik386/asm/internal/config"
	"github.com/benlik386/asm/internal/store"
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
	// internal network self-enroll (docker compose --scale worker=N).
	if err := gw.SeedBootstrapToken(ctx); err != nil {
		slog.Warn("could not seed local bootstrap token", "err", err)
	}
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

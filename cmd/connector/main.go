// Command connector carries workers on VPS boxes for a control plane that is
// not reachable from the internet. For each SSH exit it holds a session to
// the VPS, asks it to listen on its own loopback, and hands each connection
// back to the gateway (and the object store) on this side. It installs and
// removes the worker over the same session. See internal/sshexit.
//
// It reads the database and opens sealed private keys, so it needs
// ASM_DATABASE_URL and ASM_SECRET_KEY; it needs no inbound port.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/benlik386/pinkglasses/internal/secret"
	"github.com/benlik386/pinkglasses/internal/sshexit"
	"github.com/benlik386/pinkglasses/internal/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if !secret.Available() {
		// Without the key no exit's private key can be opened; say so once
		// and stay up, so the stack does not restart-loop over an optional
		// feature.
		slog.Warn("ASM_SECRET_KEY is not set: SSH exits cannot be used until it is")
	}
	st, err := store.Open(ctx, env("ASM_DATABASE_URL", "postgres://asm:asm@postgres:5432/asm?sslmode=disable"))
	if err != nil {
		slog.Error("database", "err", err)
		os.Exit(1)
	}

	cfg := sshexit.Config{
		Gateway:     env("ASM_CONNECTOR_GATEWAY", "gateway:8090"),
		WorkerImage: env("ASM_REMOTE_WORKER_IMAGE", "ghcr.io/cobbbex/pinkglasses-worker:latest"),
	}
	// Workers upload screenshots to a presigned URL that names the store as
	// the stack sees it (http://minio:9000/…). The VPS gets the same name and
	// port on its loopback, carried by the same session.
	if u, err := url.Parse(env("ASM_S3_ENDPOINT", "http://minio:9000")); err == nil && u.Hostname() != "" {
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = 80
			if u.Scheme == "https" {
				port = 443
			}
		}
		if net.ParseIP(u.Hostname()) == nil && sshexit.ValidName(u.Hostname()) && port >= 1024 {
			cfg.Store = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
			cfg.StoreHost, cfg.StorePort = u.Hostname(), port
		} else {
			slog.Warn("the object store endpoint cannot be carried to a VPS; screenshots from SSH exits will not upload",
				"endpoint", u.String())
		}
	}
	slog.Info("connector starting", "gateway", cfg.Gateway, "store", cfg.Store, "worker_image", cfg.WorkerImage)
	if err := sshexit.New(st, cfg).Run(ctx); err != nil {
		slog.Error("connector exited", "err", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

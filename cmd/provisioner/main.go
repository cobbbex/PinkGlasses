// Command provisioner creates and removes local worker containers on request
// from the api. It is the only component with access to the Docker socket, and
// it is deliberately isolated from the api for that reason (see the package doc
// and wiki/Architecture.md §7.3).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/benlik386/pinkglasses/internal/provisioner"
)

func main() {
	cfg := provisioner.Config{
		Addr:        env("ASM_PROVISIONER_ADDR", ":8091"),
		Token:       env("ASM_PROVISIONER_TOKEN", ""),
		Socket:      env("ASM_DOCKER_SOCKET", "/var/run/docker.sock"),
		Image:       env("ASM_WORKER_IMAGE", "pinkglasses-worker"),
		Network:     env("ASM_WORKER_NETWORK", "pinkglasses_default"),
		CacheVolume: env("ASM_WORKER_CACHE_VOLUME", "scan_tool_wordlistcache"),
		// Each run worker is capped so a scan cannot starve the database and
		// the web app on the same host. 0 lifts a limit.
		WorkerCPUs:     envFloat("ASM_FLEET_WORKER_CPUS", 2),
		WorkerMemoryMB: envInt("ASM_FLEET_WORKER_MEMORY_MB", 2048),
		GatewayURL:     env("ASM_GATEWAY_URL", "http://gateway:8090"),
		EnrollToken:    env("ASM_LOCAL_BOOTSTRAP_TOKEN", ""),
		MaxWorkers:     envInt("ASM_PROVISIONER_MAX_WORKERS", 20),
	}
	if cfg.Token == "" {
		slog.Error("ASM_PROVISIONER_TOKEN is required; refusing to expose the Docker socket unauthenticated")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; cancel() }()

	if err := provisioner.New(cfg).Run(ctx); err != nil {
		slog.Error("provisioner exited", "err", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

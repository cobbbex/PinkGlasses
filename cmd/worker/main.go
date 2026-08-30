// Command worker is the scan box: one binary carrying the whole pipeline. It
// connects outbound to the gateway, runs leased jobs, and posts confined
// results. No inbound ports; works behind NAT (architecture.md §6, §8.2).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/benlik386/asm/internal/config"
	"github.com/benlik386/asm/internal/scanner"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "0.1.0-dev"

func main() {
	cfg := config.LoadWorker()
	agent := scanner.NewAgent(scanner.AgentConfig{
		GatewayURL:     cfg.GatewayURL,
		CredentialFile: cfg.CredentialFile,
		Name:           cfg.Name,
		EnrollToken:    os.Getenv("ASM_ENROLL_TOKEN"),
		MaxConcurrency: cfg.MaxConcurrency,
		Version:        version,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; cancel() }()

	slog.Info("worker starting", "gateway", cfg.GatewayURL, "version", version)
	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("worker exited", "err", err)
		os.Exit(1)
	}
}

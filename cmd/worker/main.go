// Command worker is the scan box: one binary carrying the whole pipeline. It
// connects outbound to the gateway, runs leased jobs, and posts confined
// results. No inbound ports; works behind NAT (architecture.md §6, §8.2).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/benlik386/asm/internal/config"
	"github.com/benlik386/asm/internal/scanner"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "0.1.0-dev"

// setupLogging honours ASM_LOG_LEVEL (debug|info|warn|error). Scan runs are
// long and mostly opaque, so the default is info — every tool invocation and
// stage summary — and debug adds the individual findings behind them.
func setupLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("ASM_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func main() {
	setupLogging()

	// Single-stage test mode: run one tool locally and print its observations.
	// Backs `make tool-test` and the Phase 13 gates.
	stage := flag.String("stage", "", "run one pipeline stage locally and exit")
	target := flag.String("target", "", "target for -stage (domain, IP or URL)")
	timeout := flag.Duration("timeout", 5*time.Minute, "timeout for -stage")
	flag.Parse()

	if *stage != "" {
		if *target == "" {
			slog.Error("-target is required with -stage")
			os.Exit(2)
		}
		os.Exit(runStageTest(*stage, *target, *timeout))
	}

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

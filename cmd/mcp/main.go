// Command mcp is the MCP server: a thin adapter over the HTTP API that lets an
// AI client do what the web UI does, under a PinkGlasses API token.
//
//	stdio (local clients):  ASM_API_URL=… ASM_MCP_TOKEN=pgt_… mcp
//	HTTP (shared):          ASM_MCP_TRANSPORT=http ASM_MCP_ADDR=:8092 mcp
//	                        — each request carries its own token as
//	                        Authorization: Bearer pgt_…; nothing is shared.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/benlik386/pinkglasses/internal/mcpserver"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	base := env("ASM_API_URL", "http://localhost:8080")
	opts := mcpserver.Options{AllowDeleteCompany: os.Getenv("ASM_MCP_ALLOW_DELETE_COMPANY") == "true"}
	// Logs go to stderr: stdout is the protocol channel in stdio mode.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	switch env("ASM_MCP_TRANSPORT", "stdio") {
	case "stdio":
		token := os.Getenv("ASM_MCP_TOKEN")
		if token == "" {
			slog.Error("ASM_MCP_TOKEN is required: a PinkGlasses API token (Accounts → API tokens)")
			os.Exit(2)
		}
		srv := mcpserver.NewServer(mcpserver.NewClient(base, token), opts)
		if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			slog.Error("mcp", "err", err)
			os.Exit(1)
		}
	case "http":
		addr := env("ASM_MCP_ADDR", ":8092")
		// One server per request, bound to the caller's own token. A request
		// without a token gets a client that the API refuses, which surfaces
		// as the API's own 401 sentence in the tool result.
		handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			return mcpserver.NewServer(mcpserver.NewClient(base, token), opts)
		}, &mcp.StreamableHTTPOptions{Stateless: true})
		mux := http.NewServeMux()
		mux.Handle("/mcp", handler)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			slog.Info("mcp listening", "addr", addr, "path", "/mcp", "api", base)
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("mcp serve", "err", err)
				os.Exit(1)
			}
		}()
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	default:
		slog.Error("ASM_MCP_TRANSPORT must be stdio or http")
		os.Exit(2)
	}
}

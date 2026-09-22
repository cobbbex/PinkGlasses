// Command api serves the user-facing REST + SSE surface and the SPA.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/httpapi"
	"github.com/benlik386/pinkglasses/internal/mcpserver"
	"github.com/benlik386/pinkglasses/internal/store"
)

func main() {
	cfg := config.LoadAPI()
	ctx := context.Background()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db open", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	seedDefaultAdmin(ctx, st)

	api := httpapi.New(st)
	// Run events arrive as Postgres notifications raised by triggers on
	// scan_task, scan_run and run_fleet — from whichever process made the
	// change — and are fanned out to browsers subscribed to that run.
	go st.Listen(ctx, "run_events", api.PublishRunEvent)
	mux := http.NewServeMux()
	routes := api.Routes()
	mux.Handle("/api/", routes)
	mux.Handle("/healthz", routes)
	// The MCP server, on this same port at /mcp: one server per request,
	// bound to the caller's own API token, talking to the router in-process.
	// A request without a token gets the API's own refusal in the tool
	// result. Nothing extra to deploy; it is up whenever the web app is.
	mcpOpts := mcpserver.Options{AllowDeleteCompany: os.Getenv("ASM_MCP_ALLOW_DELETE_COMPANY") == "true"}
	api.SetMCP(mcpProvider{opts: mcpOpts})
	// Serve the built SPA if present. The app's own MCP page lives at /mcp
	// too: a browser asking for HTML there gets the page, an MCP client
	// asking for an event stream or posting messages gets the server.
	var spa http.Handler = http.NotFoundHandler()
	if _, err := os.Stat("web/dist"); err == nil {
		spa = spaHandler("web/dist")
		mux.Handle("/", spa)
	}
	mux.Handle("/mcp", mcpHandler(routes, mcpOpts, spa))

	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("api listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api serve", "err", err)
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

// mcpProvider describes the MCP server to the router's MCP page.
type mcpProvider struct{ opts mcpserver.Options }

func (p mcpProvider) Tools() []httpapi.MCPTool {
	var out []httpapi.MCPTool
	for _, t := range mcpserver.Tools(p.opts) {
		out = append(out, httpapi.MCPTool{Name: t.Name, Description: t.Description, ReadOnly: t.ReadOnly, Destructive: t.Destructive})
	}
	return out
}
func (p mcpProvider) SkillZip() ([]byte, error) { return mcpserver.SkillZip(p.opts) }
func (p mcpProvider) AllowsDeleteCompany() bool { return p.opts.AllowDeleteCompany }

// mcpHandler serves the MCP server on one path over both HTTP transports.
//
// Streamable HTTP (the current transport) is a POST per message. The older
// SSE transport opens a hanging GET for the event stream and POSTs messages
// to a per-session endpoint, here /mcp?sessionid=…. Clients differ in which
// they speak — some try the old one first and give up on a 405 — so both are
// answered on the same path: a GET asking for an event stream, or a POST
// carrying a session id, is the old transport; any other POST is the new one.
// A GET asking for anything else is a browser opening the app's MCP page,
// which shares the path. Either way each session is bound to the token on
// the request that opened it.
func mcpHandler(routes http.Handler, opts mcpserver.Options, page http.Handler) http.Handler {
	getServer := func(r *http.Request) *mcp.Server {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		return mcpserver.NewServer(mcpserver.NewInProcessClient(routes, token), opts)
	}
	// The SDK's DNS-rebinding guard rejects a request that arrives on a
	// loopback address with a non-loopback Host header — which is what a
	// reverse proxy on the same box sends. The guard protects servers with
	// ambient credentials; this one has none: every session is bound to the
	// bearer token on its own request, and the browser's session cookie is
	// never read here, so a page on another origin gains nothing by reaching
	// it. Off, so a proxy in front works.
	streamable := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless: true, DisableLocalhostProtection: true})
	legacy := mcp.NewSSEHandler(getServer, &mcp.SSEOptions{DisableLocalhostProtection: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A person's browser: it wants HTML, not an event stream.
		if r.Method == http.MethodGet && r.URL.Query().Get("sessionid") == "" &&
			!strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			page.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet || r.URL.Query().Get("sessionid") != "" {
			legacy.ServeHTTP(w, r)
			return
		}
		streamable.ServeHTTP(w, r)
	})
}

// spaHandler serves static files, falling back to index.html for client routes.
//
// Cache headers are what make a redeploy reach open browsers. The shell
// (index.html, and every client route that falls back to it) is served with
// no-cache, so the browser revalidates it on each load and picks up the new
// bundle name; the bundles under /assets carry a content hash in their name
// and may be cached for a year. Without this, a browser kept running the
// previous build after an update — the page looked unchanged, and features
// that only existed in the new build were "missing".
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			fs.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		if _, err := os.Stat(dir + r.URL.Path); os.IsNotExist(err) && r.URL.Path != "/" {
			http.ServeFile(w, r, dir+"/index.html")
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// seedDefaultAdmin creates the starting account on an empty database.
//
// The password is the operator's choice from ASM_DEFAULT_ADMIN_PASSWORD or,
// unset, one generated here and printed exactly once — this log line is the
// only place it ever appears. The account carries a must-change flag until the
// password is replaced, and every start says so while it is: a credential that
// nobody is reminded about is how a scanner ends up reachable with the password
// it was born with.
func seedDefaultAdmin(ctx context.Context, st *store.Store) {
	if auth.SeedDisabled() {
		slog.Info("no default administrator will be created (ASM_DEFAULT_ADMIN_PASSWORD=-); " +
			"the first visit will ask you to create one")
		return
	}
	password, chosen := auth.DefaultAdminPassword(), true
	if password == "" {
		var err error
		if password, err = auth.GeneratePassword(); err != nil {
			slog.Error("could not generate the default administrator's password", "err", err)
			return
		}
		chosen = false
	}
	created, err := st.EnsureDefaultAdmin(ctx, auth.DefaultUsername, password)
	if err != nil {
		slog.Error("could not create the default administrator", "err", err)
		return
	}
	if created {
		u, _, err := st.UserByUsername(ctx, auth.DefaultUsername)
		if err == nil {
			_ = st.SetMustChangePassword(ctx, u.ID, true)
			if n, err := st.AdoptOwnerlessScopes(ctx, u.ID); err == nil && n > 0 {
				slog.Info("assigned existing companies to the default administrator", "count", n)
			}
		}
		if chosen {
			slog.Warn("created the default administrator account",
				"username", auth.DefaultUsername, "password", "(from ASM_DEFAULT_ADMIN_PASSWORD)")
		} else {
			// Printed once. Not stored anywhere else, not repeated on later
			// starts. Lose it and tools/pwhash writes a new hash directly.
			slog.Warn("created the default administrator account — this password is printed ONCE, here, and nowhere else",
				"username", auth.DefaultUsername, "password", password)
		}
	}
	if n, err := st.CountMustChangePassword(ctx); err == nil && n > 0 {
		slog.Warn("an account still has the password it was created with; change it in the UI "+
			"(Change password, at the foot of the sidebar)", "accounts", n)
	}
}

// Command api serves the user-facing REST + SSE surface and the SPA.
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

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/httpapi"
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
	mux.Handle("/api/", api.Routes())
	mux.Handle("/healthz", api.Routes())
	// Serve the built SPA if present.
	if _, err := os.Stat("web/dist"); err == nil {
		mux.Handle("/", spaHandler("web/dist"))
	}

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

// spaHandler serves static files, falling back to index.html for client routes.
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			"(password, at the foot of the sidebar)", "accounts", n)
	}
}

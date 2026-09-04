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

// seedDefaultAdmin creates the starting account on an empty database, and says
// so every time the password is still the shipped one.
//
// The noise is the point. A default credential that nobody is reminded about is
// how an attack-surface scanner — holding a complete map of somebody's external
// attack surface — ends up reachable with a password from a public README.
func seedDefaultAdmin(ctx context.Context, st *store.Store) {
	if auth.SeedDisabled() {
		slog.Info("no default administrator will be created (ASM_DEFAULT_ADMIN_PASSWORD=-); " +
			"the first visit will ask you to create one")
		return
	}
	password := auth.DefaultAdminPassword()
	created, err := st.EnsureDefaultAdmin(ctx, auth.DefaultUsername, password)
	if err != nil {
		slog.Error("could not create the default administrator", "err", err)
		return
	}
	if created {
		slog.Warn("created the default administrator account",
			"username", auth.DefaultUsername,
			"password", describeSeedPassword(password))
		// Same reasoning as the first-run setup form: anything created before
		// there were accounts records created_by 'local', which names nobody.
		if u, _, err := st.UserByUsername(ctx, auth.DefaultUsername); err == nil {
			if n, err := st.AdoptOwnerlessScopes(ctx, u.ID); err == nil && n > 0 {
				slog.Info("assigned existing companies to the default administrator", "count", n)
			}
		}
	}

	// Whether it was created now or six months ago, say it while it is still
	// in use. Silence after the first boot is how this gets forgotten.
	u, _, err := st.UserByUsername(ctx, auth.DefaultUsername)
	if err == nil && password == auth.DefaultPassword && st.UsingDefaultPassword(ctx, u.ID, password) {
		slog.Warn("THE DEFAULT PASSWORD IS STILL IN USE — anyone who can reach this " +
			"install can sign in as an administrator. Change it in the UI, or set " +
			"ASM_DEFAULT_ADMIN_PASSWORD before first boot.")
	}
}

// describeSeedPassword avoids writing an operator's own secret into the log
// while still being useful about the published one.
func describeSeedPassword(p string) string {
	if p == auth.DefaultPassword {
		return p + " (the published default — change it)"
	}
	return "(from ASM_DEFAULT_ADMIN_PASSWORD)"
}

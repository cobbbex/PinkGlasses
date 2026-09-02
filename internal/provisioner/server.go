package provisioner

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
)

// Config for the provisioner service.
type Config struct {
	Addr        string
	Token       string // shared secret; the api must present it
	Socket      string
	Image       string
	Network     string
	GatewayURL  string
	EnrollToken string
	MaxWorkers  int // hard ceiling, so a UI bug cannot fork-bomb the host
}

// Server exposes the narrow provisioning API.
type Server struct {
	cfg Config
	d   *Docker
}

// New builds a provisioner server.
func New(cfg Config) *Server {
	return &Server{cfg: cfg, d: NewDocker(cfg.Socket)}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/v1/workers", s.auth(s.workers)) // GET list
	mux.HandleFunc("/v1/scale", s.auth(s.scale))     // POST {count}
	mux.HandleFunc("/v1/remove", s.auth(s.remove))   // POST {name}
	return mux
}

// auth enforces the shared secret. The provisioner is never exposed outside the
// internal network; this is defence in depth for the socket it holds.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Provisioner-Token")
		if s.cfg.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) workers(w http.ResponseWriter, r *http.Request) {
	list, err := s.d.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "containers": list})
}

// scale converges the number of running local workers to the requested count.
func (s *Server) scale(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if in.Count < 0 {
		in.Count = 0
	}
	if in.Count > s.cfg.MaxWorkers {
		http.Error(w, "count exceeds ASM_PROVISIONER_MAX_WORKERS", http.StatusBadRequest)
		return
	}

	current, err := s.d.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Partition by state. Docker's container list includes exited containers,
	// and counting those as existing workers used to make "give me 2" create
	// nothing when one had previously crashed. Only live containers count
	// toward the target; dead ones are garbage and are always cleaned up.
	var alive, dead []Container
	for _, c := range current {
		switch c.State {
		case "running", "created", "restarting", "paused":
			alive = append(alive, c)
		default: // exited, dead
			dead = append(dead, c)
		}
	}

	created, removed := 0, 0
	removedIDs := []string{}

	for _, c := range dead {
		if err := s.d.Remove(r.Context(), c.ID); err != nil {
			slog.Warn("could not remove dead worker container", "id", c.ID, "err", err)
			continue
		}
		slog.Info("cleaned up dead worker container", "id", c.ID)
		removedIDs = append(removedIDs, c.ID)
		removed++
	}

	switch {
	case len(alive) < in.Count:
		spec := Spec{
			Image:       s.cfg.Image,
			GatewayURL:  s.cfg.GatewayURL,
			EnrollToken: s.cfg.EnrollToken,
			Network:     s.cfg.Network,
			NamePrefix:  "pinkglasses-worker",
		}
		for i := len(alive); i < in.Count; i++ {
			if _, err := s.d.Create(r.Context(), spec, i); err != nil {
				slog.Error("create worker", "err", err)
				// Report what did get created rather than failing wholesale.
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"target": in.Count, "created": created, "removed": removed,
					"removed_ids": removedIDs, "error": err.Error(),
				})
				return
			}
			created++
		}
	case len(alive) > in.Count:
		// Remove newest first so long-lived workers keep their in-flight leases.
		sort.Slice(alive, func(a, b int) bool { return alive[a].ID > alive[b].ID })
		for i := 0; i < len(alive)-in.Count; i++ {
			if err := s.d.Remove(r.Context(), alive[i].ID); err != nil {
				slog.Error("remove worker", "err", err)
				continue
			}
			removedIDs = append(removedIDs, alive[i].ID)
			removed++
		}
	}

	slog.Info("scaled local workers", "target", in.Count, "created", created, "removed", removed)
	writeJSON(w, http.StatusOK, map[string]any{
		"target": in.Count, "created": created, "removed": removed,
		"removed_ids": removedIDs,
	})
}

// remove deletes one managed container, identified by the worker name (which is
// the container hostname, i.e. its short id) or by container name. Only
// containers carrying our label are visible here, so this cannot touch anything
// else on the host.
func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	list, err := s.d.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for _, c := range list {
		match := strings.HasPrefix(c.ID, in.Name)
		for _, n := range c.Names {
			if strings.TrimPrefix(n, "/") == in.Name {
				match = true
			}
		}
		if !match {
			continue
		}
		if err := s.d.Remove(r.Context(), c.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		slog.Info("removed local worker container", "id", c.ID)
		writeJSON(w, http.StatusOK, map[string]any{"removed": c.ID})
		return
	}
	// Not finding it is fine: the container may already be gone.
	writeJSON(w, http.StatusOK, map[string]any{"removed": ""})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Run starts the service.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.Addr, Handler: s.Routes()}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	slog.Info("provisioner listening", "addr", s.cfg.Addr, "socket", s.cfg.Socket, "image", s.cfg.Image)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

var _ = os.Getenv

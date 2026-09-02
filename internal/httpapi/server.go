// Package httpapi is the user-facing REST + SSE surface consumed by the SPA.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/benlik386/pinkglasses/internal/audit"
	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/planner"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Server holds dependencies for the API handlers.
type Server struct {
	st      *store.Store
	planner *planner.Planner
	audit   *audit.Logger
	hub     *SSEHub
	obj     *obj.Store // wordlist uploads land here, not in the database
}

// New builds the API server.
func New(st *store.Store) *Server {
	return &Server{
		st:      st,
		planner: planner.New(st),
		audit:   audit.New(st),
		hub:     NewSSEHub(),
		obj:     obj.New(config.LoadAPI().S3),
	}
}

// Routes returns the HTTP handler for the api binary.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	r.Route("/api/v1", func(r chi.Router) {
		// scopes & targets
		r.Post("/scopes", s.createScope)
		r.Get("/scopes", s.listScopes)
		r.Get("/scopes/{scopeID}/summary", s.scopeSummary)
		r.Post("/scopes/{scopeID}/targets", s.addTarget)
		r.Get("/scopes/{scopeID}/targets", s.listTargets)

		// runs (multi-target)
		r.Get("/scan-params", s.listScanParamSpecs)
		r.Get("/scopes/{scopeID}/scan-profiles", s.listScanProfiles)
		r.Post("/scopes/{scopeID}/scan-profiles", s.saveScanProfile)
		r.Post("/scopes/{scopeID}/runs", s.createRun)
		r.Get("/scopes/{scopeID}/runs", s.listRuns)
		r.Get("/runs/{runID}", s.getRun)
		r.Get("/runs/{runID}/targets", s.runTargets)
		r.Get("/runs/{runID}/events", s.runEvents)
		r.Get("/runs/{runID}/activity", s.runActivity)
		r.Get("/runs/{runID}/diff", s.runDiff)
		r.Post("/runs/{runID}/cancel", s.cancelRun)

		// assets
		r.Get("/scopes/{scopeID}/domains", s.listDomains)
		r.Get("/scopes/{scopeID}/graph", s.domainGraph)
		r.Get("/scopes/{scopeID}/hosts", s.listHosts)
		r.Get("/scopes/{scopeID}/hostrows", s.listHostRows)
		r.Get("/hosts/{ipID}/services", s.hostServices)
		r.Get("/scopes/{scopeID}/search", s.search)
		r.Get("/search", s.searchGlobal) // cross-company, Shodan-style
		r.Get("/scopes/{scopeID}/findings", s.listFindings)
		r.Patch("/findings/{findingID}", s.patchFinding)

		// fleet
		// wordlists
		r.Get("/wordlists", s.listWordlists)
		r.Post("/wordlists", s.uploadWordlist)
		r.Patch("/wordlists/{wordlistID}", s.patchWordlist)
		r.Get("/wordlists/{wordlistID}/content", s.getWordlistContent)
		r.Put("/wordlists/{wordlistID}/content", s.putWordlistContent)
		r.Delete("/wordlists/{wordlistID}", s.deleteWordlist)

		r.Get("/workers", s.listWorkers)
		r.Post("/workers/enrollment-tokens", s.createEnrollmentToken)
		r.Get("/workers/provision", s.getProvisionStatus)
		r.Post("/workers/provision", s.scaleLocalWorkers)
		r.Post("/workers/{workerID}/{action}", s.workerAction)
		r.Delete("/workers/{workerID}", s.deleteWorker)
	})
	return r
}

// --- helpers ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attacker-controlled banners/titles are rendered as text by the SPA;
		// these headers harden the app shell itself (architecture.md §10.2).
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonArrays(v))
}

// jsonArrays replaces nil slices with empty ones so a list endpoint with
// nothing to report answers [] rather than null.
//
// Go marshals a nil slice as null, which every store method returns when a
// query matches no rows. The SPA's types promise arrays and read .length off
// them, so an empty result crashed the page instead of rendering "none yet" —
// a scope with no findings, a run whose targets are not planned yet. Doing it
// here fixes the whole class at once; a new list handler cannot reintroduce it.
//
// Composite payloads are built as map[string]any (run activity, the asset
// graph), so those are walked too. Slices nested inside structs are not
// reachable this way and are initialized at their construction site.
func jsonArrays(v any) any {
	if m, ok := v.(map[string]any); ok {
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = jsonArrays(val)
		}
		return out
	}
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice && rv.IsNil() {
		return reflect.MakeSlice(rv.Type(), 0, 0).Interface()
	}
	return v
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return readJSONLimit(r, v, 1<<20)
}

// readJSONLimit decodes a JSON body with an explicit size ceiling. Most
// endpoints take small documents and use readJSON's 1 MB default; the wordlist
// editor posts whole files and needs a larger one, and without this a list
// between 1 MB and the editor's own limit fails to decode and is reported as a
// missing field rather than an oversized one.
func readJSONLimit(r *http.Request, v any, max int64) error {
	defer r.Body.Close()
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, max)).Decode(v)
}

var _ = slog.Default
var _ = time.Now
var _ = domain.RunQueued

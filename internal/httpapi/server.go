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
	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/config"
	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/obj"
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
	logins  *loginLimiter
}

// New builds the API server.
func New(st *store.Store) *Server {
	return &Server{
		st:      st,
		planner: planner.New(st),
		audit:   audit.New(st),
		hub:     NewSSEHub(),
		obj:     obj.New(config.LoadAPI().S3),
		logins:  newLoginLimiter(),
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
		// The only unauthenticated endpoints. `status` says whether the install
		// needs its first administrator; `setup` creates that one account and
		// refuses once any account exists; `login` is the front door.
		r.Get("/auth/status", s.authStatus)
		r.Post("/auth/setup", s.setup)
		r.Post("/auth/login", s.login)

		// Everything past here needs an identity. The whole surface is wrapped
		// at once rather than endpoint by endpoint, so an endpoint somebody
		// forgets to guard is unreachable rather than public.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)

			r.Post("/auth/logout", s.logout)
			r.Get("/auth/me", s.me)
			r.Post("/auth/password", s.changePassword)

			// --- viewer: read everything, change nothing ---
			r.Group(func(r chi.Router) {
				r.Use(require(auth.RoleViewer))

				r.Get("/scopes", s.listScopes)
				r.Get("/scopes/{scopeID}/summary", s.scopeSummary)
				r.Get("/scopes/{scopeID}/targets", s.listTargets)

				r.Get("/scan-params", s.listScanParamSpecs)
				r.Get("/scopes/{scopeID}/scan-profiles", s.listScanProfiles)
				r.Get("/scopes/{scopeID}/runs", s.listRuns)
				r.Get("/runs/{runID}", s.getRun)
				r.Get("/runs/{runID}/targets", s.runTargets)
				r.Get("/runs/{runID}/events", s.runEvents)
				r.Get("/runs/{runID}/activity", s.runActivity)
				r.Get("/runs/{runID}/diff", s.runDiff)

				r.Get("/scopes/{scopeID}/domains", s.listDomains)
				r.Get("/scopes/{scopeID}/graph", s.domainGraph)
				r.Get("/scopes/{scopeID}/hosts", s.listHosts)
				r.Get("/scopes/{scopeID}/hostrows", s.listHostRows)
				r.Get("/hosts/{ipID}", s.hostDetail)
				r.Get("/hosts/{ipID}/services", s.hostServices)
				r.Get("/services/{serviceID}/screenshot", s.serviceScreenshot)
				r.Get("/scopes/{scopeID}/search", s.search)
				r.Get("/search", s.searchGlobal)
				r.Get("/scopes/{scopeID}/findings", s.listFindings)

				r.Get("/scopes/{scopeID}/notifications", s.listChannels)
				r.Get("/scopes/{scopeID}/notifications/deliveries", s.listDeliveries)
				r.Get("/wordlists", s.listWordlists)
				r.Get("/wordlists/{wordlistID}/content", s.getWordlistContent)
				r.Get("/workers", s.listWorkers)

				// A tunnel's name and last egress, never its body. Reading
				// which exits exist is not the same as being able to use one.
				r.Get("/scopes/{scopeID}/vpn-configs", s.listVPNConfigs)

				// Your own tokens; an administrator sees everyone's.
				r.Get("/tokens", s.listTokens)
				r.Post("/tokens", s.createToken)
				r.Delete("/tokens/{tokenID}", s.revokeToken)
			})

			// --- operator: everything about finding things ---
			r.Group(func(r chi.Router) {
				r.Use(require(auth.RoleOperator))

				r.Post("/scopes", s.createScope)
				r.Post("/scopes/{scopeID}/targets", s.addTarget)
				r.Post("/scopes/{scopeID}/scan-profiles", s.saveScanProfile)
				// Starting a run sends packets at somebody's infrastructure,
				// which is why it is the boundary between reading and acting.
				r.Post("/scopes/{scopeID}/runs", s.createRun)
				r.Post("/runs/{runID}/cancel", s.cancelRun)

				r.Post("/scopes/{scopeID}/notifications", s.createChannel)
				r.Patch("/notifications/{channelID}", s.patchChannel)
				r.Delete("/notifications/{channelID}", s.deleteChannel)
				r.Post("/notifications/{channelID}/test", s.testChannel)
				r.Patch("/findings/{findingID}", s.patchFinding)

				r.Post("/wordlists", s.uploadWordlist)
				r.Patch("/wordlists/{wordlistID}", s.patchWordlist)
				r.Put("/wordlists/{wordlistID}/content", s.putWordlistContent)
				r.Delete("/wordlists/{wordlistID}", s.deleteWordlist)
			})

			// --- admin: everything that changes what the system can do ---
			r.Group(func(r chi.Router) {
				r.Use(require(auth.RoleAdmin))

				r.Get("/users", s.listUsers)
				r.Post("/users", s.createUser)
				r.Patch("/users/{userID}", s.patchUser)
				r.Delete("/users/{userID}", s.deleteUser)

				// Credentials for somebody else's network.
				r.Post("/scopes/{scopeID}/vpn-configs", s.createVPNConfig)
				r.Delete("/vpn-configs/{vpnID}", s.deleteVPNConfig)

				// Enrolling a worker hands out a credential; scaling them
				// creates containers on the host.
				r.Post("/workers/enrollment-tokens", s.createEnrollmentToken)
				r.Get("/workers/provision", s.getProvisionStatus)
				r.Post("/workers/provision", s.scaleLocalWorkers)
				r.Post("/workers/{workerID}/{action}", s.workerAction)
				r.Delete("/workers/{workerID}", s.deleteWorker)
			})
		})
	})
	return r
}

// --- helpers ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attacker-controlled banners/titles are rendered as text by the SPA;
		// these headers harden the app shell itself (architecture.md §10.3).
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

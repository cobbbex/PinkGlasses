// Package agentapi is the agent-facing gateway: the only internet-facing
// component. It terminates worker WebSocket control channels, leases and
// dispatches scan tasks, ingests confined results, and issues presigned
// artifact URLs (architecture.md §3.2, §7, §8).
package agentapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/benlik386/asm/internal/config"
	"github.com/benlik386/asm/internal/dispatch"
	"github.com/benlik386/asm/internal/domain"
	"github.com/benlik386/asm/internal/ingest"
	"github.com/benlik386/asm/internal/obj"
	"github.com/benlik386/asm/internal/planner"
	"github.com/benlik386/asm/internal/scanproto"
	"github.com/benlik386/asm/internal/store"
)

// Gateway serves the agent-facing API.
type Gateway struct {
	st       *store.Store
	cfg      config.Gateway
	disp     *dispatch.Dispatcher
	ingest   *ingest.Ingestor
	obj      *obj.Store
	upgrader websocket.Upgrader

	mu    sync.Mutex
	conns map[uuid.UUID]*websocket.Conn // workerID -> control channel

	pmu       sync.Mutex
	runParams map[string]map[string]string // runID -> effective params (cache)
}

// New builds a Gateway.
func New(st *store.Store, cfg config.Gateway) *Gateway {
	return &Gateway{
		st:     st,
		cfg:    cfg,
		disp:   dispatch.New(st, int(cfg.LeaseTTL.Seconds())),
		ingest: ingest.New(st),
		obj:    obj.New(cfg.S3),
		conns:     map[uuid.UUID]*websocket.Conn{},
		runParams: map[string]map[string]string{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(*http.Request) bool { return true }, // agents are non-browser
		},
	}
}

// SeedBootstrapToken registers the shared local-worker bootstrap token so
// containers on the internal network self-enroll without a manual token step.
// No-op when unconfigured.
func (g *Gateway) SeedBootstrapToken(ctx context.Context) error {
	if g.cfg.LocalBootstrapToken == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(g.cfg.LocalBootstrapToken))
	var poolID *uuid.UUID
	if id, err := g.st.PoolByName(ctx, "local"); err == nil {
		poolID = &id
	}
	return g.st.EnsureBootstrapToken(ctx, sum[:], poolID)
}

// isPrivateAddr reports whether an address is RFC1918/loopback/link-local, i.e.
// the worker connected from inside your network rather than the internet.
func isPrivateAddr(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// Routes returns the gateway HTTP handler.
func (g *Gateway) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r.Get("/install.sh", g.installScript)
	r.Route("/agent/v1", func(r chi.Router) {
		r.Post("/enroll", g.enroll)
		r.Get("/connect", g.connect)
		r.Post("/results", g.results)
		r.Post("/artifacts/presign", g.presign)
	})
	return r
}

// enroll redeems a one-time token and returns a worker identity + credential.
func (g *Gateway) enroll(w http.ResponseWriter, r *http.Request) {
	var req scanproto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(req.Token))
	poolID, kind, ok, _ := g.st.RedeemEnrollmentToken(r.Context(), sum[:])
	if !ok {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	if kind == "" {
		kind = string(scanproto.KindVPS)
	}

	raw, hash := newCredential()
	caps := make([]string, len(req.Capabilities))
	for i, c := range req.Capabilities {
		caps[i] = string(c)
	}

	srcIP := observedIP(r)
	isLocal := kind == string(scanproto.KindLocal)

	// A local worker is only trusted as local if it actually connected from a
	// private address. A bootstrap token that leaked to the internet therefore
	// cannot mint an auto-approved worker on someone else's machine.
	trustedLocal := isLocal && isPrivateAddr(srcIP)
	if isLocal && !trustedLocal {
		kind = string(scanproto.KindVPS)
		slog.Warn("local token redeemed from a public address; treating as remote", "src", srcIP)
	}

	status := domain.WorkerPending
	if trustedLocal {
		status = domain.WorkerActive // no human approval needed on your own network
	}

	worker := domain.Worker{
		PoolID:         poolID,
		Name:           firstNonEmpty(req.Name, req.Hostname, "worker"),
		Kind:           kind,
		Capabilities:   caps,
		Tools:          req.Tools,
		AgentVersion:   req.AgentVersion,
		MaxConcurrency: 8,
	}
	if srcIP != "" {
		worker.EgressIP = &srcIP
	}
	id, err := g.st.CreateWorker(r.Context(), worker, hash, status)
	if err != nil {
		http.Error(w, "enroll failed", http.StatusInternalServerError)
		return
	}
	slog.Info("worker enrolled", "worker", id, "kind", kind, "status", status, "src", srcIP)
	writeJSON(w, http.StatusCreated, scanproto.EnrollResponse{WorkerID: id.String(), Credential: raw})
}

// connect authenticates a worker and runs its control channel + dispatch loop.
func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	workerID, worker, ok := g.authWorker(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if worker.Status == domain.WorkerRevoked || worker.Status == domain.WorkerQuarantined {
		http.Error(w, "worker not permitted", http.StatusForbidden)
		return
	}
	conn, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	g.register(workerID, conn)
	defer g.unregister(workerID)
	_ = g.st.TouchWorker(r.Context(), workerID, observedIP(r))

	// reader: heartbeats and acks
	go g.readLoop(workerID, conn)

	// dispatch loop: lease tasks and push them while the worker is active.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, credOK := g.reloadWorker(ctx, workerID)
			if !credOK || cur.Status != domain.WorkerActive {
				continue // pending/draining/quarantined: hold, no new leases
			}
			slots := cur.MaxConcurrency - cur.RunningTasks
			if slots <= 0 {
				continue
			}
			jobs, err := g.disp.Lease(ctx, workerID, cur.Capabilities, cur.PoolID, slots)
			if err != nil {
				slog.Error("lease failed", "worker", workerID, "err", err)
				continue
			}
			if len(jobs) == 0 {
				continue
			}
			for i := range jobs {
				job := &jobs[i]
				job.Ingest = scanproto.IngestInfo{URL: g.cfg.PublicGatewayURL + "/agent/v1/results"}
				job.Params.Tool = g.paramsForRun(ctx, job.RunID)
				env := scanproto.Envelope{Type: "job", Job: job}
				if err := conn.WriteJSON(env); err != nil {
					return
				}
			}
			_ = g.st.TouchWorker(ctx, workerID, "")
		}
	}
}

// paramsForRun returns a run's validated scan params, cached to avoid a DB hit
// per lease. Params were whitelisted server-side before storage.
func (g *Gateway) paramsForRun(ctx context.Context, runID string) map[string]string {
	g.pmu.Lock()
	if p, ok := g.runParams[runID]; ok {
		g.pmu.Unlock()
		return p
	}
	g.pmu.Unlock()
	id, err := uuid.Parse(runID)
	if err != nil {
		return nil
	}
	p, err := g.st.GetRunParams(ctx, id)
	if err != nil {
		return nil
	}
	g.pmu.Lock()
	g.runParams[runID] = p
	g.pmu.Unlock()
	return p
}

func (g *Gateway) readLoop(workerID uuid.UUID, conn *websocket.Conn) {
	for {
		var hb scanproto.Heartbeat
		if err := conn.ReadJSON(&hb); err != nil {
			return
		}
		ctx := context.Background()
		_ = g.st.TouchWorker(ctx, workerID, "")
		for _, tid := range hb.RunningTasks {
			if id, err := uuid.Parse(tid); err == nil {
				// heartbeat extends lease; lease token verified on result submit
				_ = g.st.ExtendLease(ctx, id, uuid.Nil, int(g.cfg.LeaseTTL.Seconds()))
			}
		}
	}
}

// results ingests a batch of observations under lease-token authentication and
// result confinement.
func (g *Gateway) results(w http.ResponseWriter, r *http.Request) {
	workerID, _, ok := g.authWorker(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var res scanproto.Result
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&res); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	taskID, err := uuid.Parse(res.TaskID)
	if err != nil {
		http.Error(w, "bad task id", http.StatusBadRequest)
		return
	}
	leaseTok, err := uuid.Parse(res.LeaseToken)
	if err != nil {
		http.Error(w, "bad lease token", http.StatusBadRequest)
		return
	}

	// Verify the worker actually holds this task's lease.
	task, err := g.loadTask(r.Context(), taskID, workerID, leaseTok)
	if err != nil {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}

	// Result confinement: reject assets outside the assigned target.
	if bad, why := confineViolation(task.target, res.Observations); bad {
		slog.Warn("confinement violation; quarantining worker", "worker", workerID, "why", why)
		_ = g.st.SetWorkerStatus(r.Context(), workerID, domain.WorkerQuarantined)
		http.Error(w, "confinement violation", http.StatusForbidden)
		return
	}

	summary, err := g.ingest.Process(r.Context(), task.runID, &workerID, scanproto.Stage(task.stage), res.Observations)
	if err != nil {
		http.Error(w, "ingest error", http.StatusInternalServerError)
		return
	}

	if res.Final {
		sumJSON, _ := json.Marshal(summary)
		_ = g.disp.Complete(r.Context(), taskID, leaseTok, sumJSON)
	} else {
		_ = g.disp.Heartbeat(r.Context(), taskID, leaseTok)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": len(res.Observations)})
}

// presign issues a presigned PUT URL for a raw artifact or screenshot.
func (g *Gateway) presign(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := g.authWorker(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var in struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}
	url, err := g.obj.PresignPut(in.Key, 15*time.Minute, time.Now())
	if err != nil {
		http.Error(w, "presign failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url, "key": in.Key})
}

func (g *Gateway) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	_, _ = w.Write([]byte(installSh))
}

// --- worker auth + connection registry ---

type taskInfo struct {
	runID  uuid.UUID
	stage  string
	target []byte
}

func (g *Gateway) loadTask(ctx context.Context, taskID, workerID, leaseTok uuid.UUID) (taskInfo, error) {
	var ti taskInfo
	err := g.st.Pool.QueryRow(ctx, `
		SELECT run_id, stage, target FROM scan_task
		WHERE id=$1 AND worker_id=$2 AND lease_token=$3 AND status IN ('leased','running')`,
		taskID, workerID, leaseTok).Scan(&ti.runID, &ti.stage, &ti.target)
	return ti, err
}

func (g *Gateway) authWorker(r *http.Request) (uuid.UUID, domain.Worker, bool) {
	wid := r.Header.Get("X-Worker-Id")
	cred := r.Header.Get("X-Worker-Credential")
	if wid == "" || cred == "" {
		// also allow query params for the WSS handshake
		wid = firstNonEmpty(wid, r.URL.Query().Get("worker_id"))
		cred = firstNonEmpty(cred, r.URL.Query().Get("credential"))
	}
	id, err := uuid.Parse(wid)
	if err != nil {
		return uuid.Nil, domain.Worker{}, false
	}
	worker, hash, err := g.st.WorkerForAuth(r.Context(), id)
	if err != nil || !verifyCredential(cred, hash) {
		return uuid.Nil, domain.Worker{}, false
	}
	return id, worker, true
}

func (g *Gateway) reloadWorker(ctx context.Context, id uuid.UUID) (domain.Worker, bool) {
	worker, _, err := g.st.WorkerForAuth(ctx, id)
	if err != nil {
		return domain.Worker{}, false
	}
	return worker, true
}

func (g *Gateway) register(id uuid.UUID, conn *websocket.Conn) {
	g.mu.Lock()
	g.conns[id] = conn
	g.mu.Unlock()
	_ = g.st.SetWorkerStatus(context.Background(), id, keepStatus(g.st, id))
}

func (g *Gateway) unregister(id uuid.UUID) {
	g.mu.Lock()
	delete(g.conns, id)
	g.mu.Unlock()
}

// keepStatus returns the worker's current status (registration must not
// silently activate a pending worker — approval is a human action, §7.2).
func keepStatus(st *store.Store, id uuid.UUID) domain.WorkerStatus {
	w, _, err := st.WorkerForAuth(context.Background(), id)
	if err != nil {
		return domain.WorkerPending
	}
	return w.Status
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func observedIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if host, _, err := net.SplitHostPort(xff); err == nil {
			return host
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ = planner.Apex

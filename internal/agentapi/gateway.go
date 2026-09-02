// Package agentapi is the agent-facing gateway: the only internet-facing
// component. It terminates worker WebSocket control channels, leases and
// dispatches scan tasks, ingests confined results, and issues presigned
// artifact URLs (architecture.md §3.2, §7, §8).
package agentapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
		st:        st,
		cfg:       cfg,
		disp:      dispatch.New(st, int(cfg.LeaseTTL.Seconds())),
		ingest:    ingest.New(st),
		obj:       obj.New(cfg.S3),
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
	// A restarted container re-enrols under the same hostname; drop the row it
	// left behind so the fleet shows one entry per worker rather than a growing
	// column of duplicates.
	if n, _ := g.st.PruneReplacedWorker(r.Context(), worker.Name, worker.Kind); n > 0 {
		slog.Info("replaced a disconnected worker of the same name",
			"name", worker.Name, "removed", n)
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
	// closed when the reader gives up, which is how a dead worker ends this
	// handler: the HTTP request context does not cancel on a killed peer, so
	// without this the dispatch loop would keep running against a corpse and
	// unregister would never fire.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		g.readLoop(workerID, conn)
	}()

	// dispatch loop: lease tasks and push them while the worker is active.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-gone:
			return
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
				g.attachWordlist(ctx, job)
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
// attachWordlist gives a dns_brute job a short-lived download URL for the list
// it must use. The URL is minted at dispatch rather than at planning time so it
// is still valid when the task is actually leased, which may be much later.
func (g *Gateway) attachWordlist(ctx context.Context, job *scanproto.Job) {
	if job.Stage != scanproto.StageDNSBrute || len(job.Targets) == 0 {
		return
	}
	rawID := job.Targets[0].WordlistID
	if rawID == "" {
		return
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return
	}
	wl, err := g.st.GetWordlist(ctx, id)
	if err != nil || wl.Status != "ready" {
		return
	}
	url, err := g.obj.PresignGet(wl.ObjectKey, 2*time.Hour, time.Now())
	if err != nil {
		slog.Warn("could not presign wordlist", "wordlist", wl.Name, "err", err)
		return
	}
	job.Params.WordlistURL = url
	job.Params.WordlistName = wl.Name
	if wl.SHA256 != nil {
		job.Params.WordlistSHA = *wl.SHA256
	}

	// Every brute task also needs resolvers. Take the run's selection; the
	// worker falls back to the list baked into its image if none is attached.
	runID, err := uuid.Parse(job.RunID)
	if err != nil {
		return
	}
	res, err := g.st.RunWordlistsByKind(ctx, runID, "resolvers")
	if err != nil || len(res) == 0 {
		return
	}
	rl := res[0]
	rurl, err := g.obj.PresignGet(rl.ObjectKey, 2*time.Hour, time.Now())
	if err != nil {
		slog.Warn("could not presign resolvers", "list", rl.Name, "err", err)
		return
	}
	job.Params.ResolversURL = rurl
	job.Params.ResolversName = rl.Name
	if rl.SHA256 != nil {
		job.Params.ResolversSHA = *rl.SHA256
	}
}

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

// controlIdleTimeout is how long the gateway waits for any message from a worker
// before treating the connection as dead. Workers heartbeat every 15s, so this
// allows two misses. Without a deadline a killed worker leaves the read blocked
// on a TCP connection that never closes, so the fleet keeps showing it active
// and its connection is never released.
const controlIdleTimeout = 45 * time.Second

func (g *Gateway) readLoop(workerID uuid.UUID, conn *websocket.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(controlIdleTimeout))
	for {
		var hb scanproto.Heartbeat
		if err := conn.ReadJSON(&hb); err != nil {
			slog.Info("control channel closed", "worker", workerID, "err", err)
			return
		}
		// Any message proves the worker is alive; push the deadline out.
		_ = conn.SetReadDeadline(time.Now().Add(controlIdleTimeout))
		ctx := context.Background()

		if hb.Stopping {
			// The worker is shutting down cleanly, so its tasks are not
			// continuing. Re-queue them now instead of stalling the run until
			// each lease expires.
			n, err := g.st.ReleaseWorkerLeases(ctx, workerID)
			if err != nil {
				slog.Warn("could not release leases on worker shutdown",
					"worker", workerID, "err", err)
			}
			slog.Info("worker is stopping", "worker", workerID, "requeued_tasks", n)
			_ = g.st.MarkWorkerDisconnected(ctx, workerID)
			return
		}

		_ = g.st.TouchWorker(ctx, workerID, "")
		for _, tid := range hb.RunningTasks {
			if id, err := uuid.Parse(tid); err == nil {
				// The heartbeat proves ownership by worker identity, not by lease
				// token (the agent does not echo it back), so extend on that.
				_ = g.st.ExtendLeaseForWorker(ctx, id, workerID, int(g.cfg.LeaseTTL.Seconds()))
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

	// Merge every batch into the task's stored summary. Results arrive in
	// chunks and the closing batch carries no observations, so computing the
	// summary from one batch stored an empty one — which silently left the
	// planner with no addresses to scan and no services to probe.
	merged, err := g.mergeTaskSummary(r.Context(), taskID, summary)
	if err != nil {
		slog.Warn("could not merge task summary", "task", taskID, "err", err)
	}

	if res.Final {
		_ = g.disp.Complete(r.Context(), taskID, leaseTok, merged)
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
	// A worker holding an open channel is demonstrably alive, so lift a stale
	// mark. Nothing else does, and the dispatcher only leases to active workers,
	// so leaving it stale benches a healthy worker permanently. Pending,
	// draining, quarantined and revoked are deliberate states and are untouched
	// — registration must never silently approve a pending worker (§7.2).
	if err := g.st.ReviveWorker(context.Background(), id); err != nil {
		slog.Warn("could not revive worker", "worker", id, "err", err)
	}
}

func (g *Gateway) unregister(id uuid.UUID) {
	g.mu.Lock()
	delete(g.conns, id)
	g.mu.Unlock()
	// Reflect the disconnect at once rather than leaving the fleet list claiming
	// the worker is active until the heartbeat sweep notices 90 seconds later.
	if err := g.st.MarkWorkerDisconnected(context.Background(), id); err != nil {
		slog.Warn("could not mark worker disconnected", "worker", id, "err", err)
	}
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

// mergeTaskSummary folds a batch's summary into whatever the task has already
// recorded, de-duplicating as it goes, and returns the merged JSON.
func (g *Gateway) mergeTaskSummary(ctx context.Context, taskID uuid.UUID, add planner.StageSummary) ([]byte, error) {
	var cur planner.StageSummary
	if raw, err := g.st.TaskResult(ctx, taskID); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &cur)
	}

	cur.Domains = mergeStrings(cur.Domains, add.Domains)
	cur.IPs = mergeStrings(cur.IPs, add.IPs)
	cur.WebURLs = mergeStrings(cur.WebURLs, add.WebURLs)

	seen := make(map[string]bool, len(cur.Services))
	for _, s := range cur.Services {
		seen[fmt.Sprintf("%s:%d", s.IP, s.Port)] = true
	}
	for _, s := range add.Services {
		if k := fmt.Sprintf("%s:%d", s.IP, s.Port); !seen[k] {
			seen[k] = true
			cur.Services = append(cur.Services, s)
		}
	}

	out, err := json.Marshal(cur)
	if err != nil {
		return nil, err
	}
	return out, g.st.SetTaskResult(ctx, taskID, out)
}

// mergeStrings appends the values of b not already in a.
func mergeStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	return a
}

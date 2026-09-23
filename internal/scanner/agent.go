package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// AgentConfig configures the worker runtime.
type AgentConfig struct {
	GatewayURL     string
	CredentialFile string
	Name           string
	EnrollToken    string
	MaxConcurrency int
	Version        string
}

// Agent is the worker runtime: it enrolls, connects the control channel, runs
// leased jobs, and posts confined results back to the gateway.
type Agent struct {
	// downSince is when the control channel was last lost, zero while it is
	// up; it lets the reconnect say how long the gateway went without us.
	downSince time.Time
	// connected is set once a control channel came up, so a drop after a
	// working session is retried at once rather than backed off.
	connected bool
	cfg       AgentConfig
	caps      map[scanproto.Capability]bool
	scanner   *Scanner
	client    *http.Client

	workerID string
	cred     string

	// providerConfig is subfinder's generated provider-config.yaml, or "" when
	// no API keys are configured.
	providerConfig string

	mu      sync.Mutex
	running map[string]string // task id -> lease token

	// spool holds result batches the gateway could not be reached for, replayed
	// when the control channel comes back and on a timer meanwhile.
	spool *spool

	// A worker in a run fleet never uses this: its egress comes from the
	// gateway container whose network namespace it shares.

	// writeMu serialises control-channel writes. gorilla/websocket permits one
	// concurrent writer, and the heartbeat ticker and the shutdown announcement
	// can otherwise reach the socket at the same moment.
	writeMu sync.Mutex
}

// sendControl writes one control-channel message under the write lock.
func (a *Agent) sendControl(conn *websocket.Conn, hb scanproto.Heartbeat) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return conn.WriteJSON(hb)
}

// runningTasks snapshots the ids currently executing.
func (a *Agent) runningTasks() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, 0, len(a.running))
	for id := range a.running {
		ids = append(ids, id)
	}
	return ids
}

// NewAgent builds a worker agent, detecting capabilities and tools and
// rendering the passive-source API keys into subfinder's provider config.
func NewAgent(cfg AgentConfig) *Agent {
	caps := DetectCapabilities()

	// Keys come from the environment; the file is 0600 and its contents are
	// never logged, only the source names.
	pcPath, sources, err := WriteProviderConfig(filepath.Dir(cfg.CredentialFile))
	if err != nil {
		slog.Warn("could not write subfinder provider config", "err", err)
	} else if len(sources) > 0 {
		slog.Info("passive sources configured", "count", len(sources), "sources", sources)
	} else {
		slog.Info("no passive-source API keys set; using free sources only")
	}

	// Ask subfinder whether it still recognises the names we key the config by.
	// A renamed or removed source is ignored silently, so an operator who pasted
	// a key would get no error and simply fewer results — which is exactly what
	// happened with zoomeye, hunter and binaryedge.
	if unknown := CheckSourceNames(context.Background()); len(unknown) > 0 {
		slog.Error("this subfinder does not recognise some sources we configure; "+
			"their API keys will be ignored. Update providerSources to match "+
			"`subfinder -ls`.", "sources", unknown)
	}

	a := &Agent{
		providerConfig: pcPath,
		cfg:            cfg,
		caps:           caps,
		scanner:        &Scanner{Detected: caps, ProviderConfig: pcPath},
		// Upload set below once the Agent exists (needs a.cfg/a.cred).
		client:  &http.Client{Timeout: 30 * time.Second},
		running: map[string]string{},
	}
	a.scanner.Upload = a.uploadArtifact
	a.scanner.Authorize = func(req *http.Request) {
		// Only the gateway gets the credential; a presigned store URL or a
		// tool's own download must never carry it.
		if strings.HasPrefix(req.URL.String(), a.cfg.GatewayURL) {
			req.Header.Set("X-Worker-Id", a.workerID)
			req.Header.Set("X-Worker-Credential", a.cred)
		}
	}
	a.spool = newSpool(envOr("ASM_SPOOL_DIR", "/var/cache/asm/spool"))
	if n := len(a.spool.pending()); n > 0 {
		slog.Info("results spooled by a previous run are waiting", "batches", n)
	}
	return a
}

// uploadArtifact stores bytes in object storage: it asks the gateway to presign
// a PUT and uploads directly, so artifacts never transit the gateway
// (wiki/Architecture.md §3.2). Returns the object key on success.
func (a *Agent) uploadArtifact(ctx context.Context, key string, data []byte) (string, error) {
	body, _ := json.Marshal(map[string]string{"key": key})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.GatewayURL+"/agent/v1/artifacts/presign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Id", a.workerID)
	req.Header.Set("X-Worker-Credential", a.cred)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	var pr struct{ URL, Key string }
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()
	if pr.URL == "" {
		return "", fmt.Errorf("presign returned no url")
	}

	put, _ := http.NewRequestWithContext(ctx, http.MethodPut, pr.URL, bytes.NewReader(data))
	put.Header.Set("Content-Type", "image/png")
	pResp, err := a.client.Do(put)
	if err != nil {
		return "", err
	}
	pResp.Body.Close()
	if pResp.StatusCode >= 300 {
		return "", fmt.Errorf("artifact PUT failed: %s", pResp.Status)
	}
	return pr.Key, nil
}

// Run enrols if needed and then maintains the control channel forever.
// Enrolment lives inside the loop so a worker whose server-side record has gone
// can recover by enrolling again instead of retrying a dead credential forever.
func (a *Agent) Run(ctx context.Context) error {
	// A dropped channel is retried at once — the first heartbeat after a
	// reconnect is what keeps, or wins back, the leases of running tasks —
	// and only repeated failures back off.
	wait := time.Duration(0)
	for {
		if err := a.ensureEnrolled(ctx); err != nil {
			slog.Error("enrolment failed", "err", err)
			wait = 5 * time.Second
		} else if err := a.connect(ctx, a.prefetchWordlists); err != nil {
			if a.connected {
				wait, a.connected = 0, false // it worked until now: try again at once
			} else if wait < 5*time.Second {
				wait += time.Second
			}
			// The gateway closes with this code when it has no record of us any
			// more. Forget the credential now rather than after the reconnect's
			// 401, so the log says what happened instead of "dropped".
			if a.downSince.IsZero() {
				a.downSince = time.Now()
			}
			if websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
				a.forgetCredential("the control plane no longer knows this worker")
			} else {
				slog.Warn("control channel dropped; reconnecting", "err", err,
					"running_tasks", len(a.runningTasks()),
					"note", "the leases of running tasks are not extended while the channel is down; they expire after the gateway's lease TTL")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// forgetCredential discards the stored identity so the next loop re-enrols.
func (a *Agent) forgetCredential(why string) {
	slog.Warn("discarding worker credential; will re-enrol", "reason", why, "worker", a.workerID)
	a.workerID, a.cred = "", ""
	if err := os.Remove(a.cfg.CredentialFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not delete credential file", "err", err)
	}
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if a.workerID != "" && a.cred != "" {
		return nil
	}
	if b, err := os.ReadFile(a.cfg.CredentialFile); err == nil {
		var saved struct{ WorkerID, Credential string }
		if json.Unmarshal(b, &saved) == nil && saved.WorkerID != "" {
			a.workerID, a.cred = saved.WorkerID, saved.Credential
			slog.Info("loaded worker credential", "worker", a.workerID)
			return nil
		}
	}
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("no credential and no enrollment token provided")
	}
	req := scanproto.EnrollRequest{
		Token:        a.cfg.EnrollToken,
		Hostname:     hostname(),
		Name:         a.cfg.Name,
		Capabilities: capsList(a.caps),
		Tools:        DetectTools(),
		AgentVersion: a.cfg.Version,
	}
	body, _ := json.Marshal(req)
	resp, err := a.client.Post(a.cfg.GatewayURL+"/agent/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("enroll rejected: %s", resp.Status)
	}
	var er scanproto.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	a.workerID, a.cred = er.WorkerID, er.Credential
	saved, _ := json.Marshal(er)
	if err := os.WriteFile(a.cfg.CredentialFile, saved, 0o600); err != nil {
		slog.Warn("could not persist credential", "err", err)
	}
	slog.Info("enrolled; awaiting approval in the UI", "worker", a.workerID)
	return nil
}

// prefetchWordlists fills the on-disk cache with every ready list at start,
// so a scan never has to download one — a fleet worker inside a VPN namespace
// and a VPS worker both only ever need to reach the gateway. Cached lists are
// skipped by hash; the cache directory is shared between a run's workers and
// the standing one, so in the common case there is nothing to fetch at all.
func (a *Agent) prefetchWordlists(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.GatewayURL+"/agent/v1/wordlists", nil)
	if err != nil {
		return
	}
	a.scanner.Authorize(req)
	resp, err := a.client.Do(req)
	if err != nil {
		slog.Warn("wordlists: could not list", "err", err)
		return
	}
	defer resp.Body.Close()
	var lists []struct {
		Name, Kind, SHA256, URL string
		SizeBytes               int64 `json:"size_bytes"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&lists) != nil {
		slog.Warn("wordlists: list refused", "status", resp.Status)
		return
	}
	fetched, present := 0, 0
	for _, l := range lists {
		had := a.scanner.listCached(l.SHA256, l.Name)
		if _, err := a.scanner.cachedList(ctx, l.URL, l.SHA256, l.Name, ""); err != nil {
			slog.Warn("wordlists: could not cache", "name", l.Name, "err", err)
			continue
		}
		if had {
			present++
		} else {
			fetched++
		}
	}
	slog.Info("wordlists cached and ready", "lists", len(lists), "fetched_now", fetched, "already_present", present)
}

func (a *Agent) connect(ctx context.Context, onConnected func(context.Context)) error {
	wsURL := toWS(a.cfg.GatewayURL) + "/agent/v1/connect?worker_id=" + a.workerID + "&credential=" + a.cred
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				// Our record is gone or the credential was rotated away. Re-enrol.
				a.forgetCredential("gateway rejected the credential (401)")
			case http.StatusForbidden:
				// Quarantined or revoked. Deliberately do NOT re-enrol: that
				// would let a worker the operator cut off rejoin the fleet.
				slog.Error("this worker is quarantined or revoked; not re-enrolling",
					"worker", a.workerID)
			}
		}
		return err
	}
	defer conn.Close()
	a.connected = true
	if a.downSince.IsZero() {
		slog.Info("control channel up")
	} else {
		// How long the gateway did not hear from us is what decides whether
		// the tasks we kept running still belong to us.
		slog.Info("control channel up again", "was_down", time.Since(a.downSince).Round(time.Second).String(),
			"tasks_kept_running", len(a.runningTasks()))
		a.downSince = time.Time{}
	}

	// heartbeat ticker
	hbCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.heartbeat(hbCtx, conn)
	if onConnected != nil {
		// Once now, and again a little later: on a fresh install the seeder
		// may still be loading lists when the worker connects, and a list that
		// became ready in between would otherwise wait for its first scan.
		go func() {
			onConnected(hbCtx)
			for _, d := range []time.Duration{time.Minute, 5 * time.Minute} {
				select {
				case <-hbCtx.Done():
					return
				case <-time.After(d):
					onConnected(hbCtx)
				}
			}
		}()
	}

	// The gateway is reachable again, so anything spooled while it was not can
	// go now — and again every minute, in case results arrive faster than the
	// channel notices an outage ending.
	go a.flushSpool(hbCtx)

	// On a clean shutdown, tell the gateway before the socket closes: it then
	// re-queues whatever this worker held instead of the run stalling until each
	// lease times out, and the fleet list stops showing us as active.
	//
	// This has to be a watcher rather than a defer. The loop below blocks in
	// ReadJSON, which cancelling the context does not interrupt — so the process
	// would be killed with the announcement still undelivered. Closing the
	// connection here is what unblocks the reader.
	go func() {
		<-ctx.Done()
		cancel() // stop the heartbeat before taking the write lock ourselves
		ids := a.runningTasks()
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err := a.sendControl(conn, scanproto.Heartbeat{
			WorkerID: a.workerID, RunningTasks: ids, Stopping: true, At: time.Now(),
		}); err != nil {
			slog.Warn("could not announce shutdown", "err", err)
		} else {
			slog.Info("announced shutdown to the gateway", "handing_back", len(ids))
		}
		_ = conn.Close()
	}()

	for {
		var env scanproto.Envelope
		if err := conn.ReadJSON(&env); err != nil {
			return err
		}
		if env.Type == "job" && env.Job != nil {
			go a.execJob(ctx, *env.Job)
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context, conn *websocket.Conn) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	failing := false
	// The first beat goes at once, not a tick later: after a reconnect the
	// gateway should learn what we are still running as soon as it can, so
	// leases are extended — or handed back — before anything else expires.
	first := make(chan struct{}, 1)
	first <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-first:
		case <-t.C:
		}
		{
			running := a.runningTasks()
			err := a.sendControl(conn, scanproto.Heartbeat{
				WorkerID: a.workerID, RunningTasks: running, Leases: a.heldLeases(), At: time.Now(),
			})
			// A heartbeat that cannot be sent is what an expired lease looks
			// like from this side; log the first failure and the recovery,
			// not every tick in between.
			if err != nil && !failing {
				failing = true
				slog.Warn("heartbeat could not be sent; the leases of running tasks are not being extended",
					"err", err, "running_tasks", len(running))
			} else if err == nil && failing {
				failing = false
				slog.Info("heartbeats flowing again", "running_tasks", len(running))
			}
		}
	}
}

func (a *Agent) execJob(ctx context.Context, job scanproto.Job) {
	a.mark(job.TaskID, job.LeaseToken, true)
	defer a.mark(job.TaskID, "", false)

	// One line in, one line out per task, both carrying the target — enough to
	// follow a scan in `docker compose logs worker` without turning on debug.
	target := describeTarget(job)
	started := time.Now()
	slog.Info("task started",
		"stage", job.Stage, "target", target, "task", job.TaskID, "run", job.RunID)

	// Where this traffic leaves from is not the worker's decision. A run's
	// active stages reach a worker only through the pool they were routed to:
	// an ephemeral fleet inside a VPN gateway's namespace, or a pool of remote
	// workers. Passive stages run on the standing pool and never touch the
	// target. The worker used to raise tunnels itself; that path is gone
	// (wiki/Architecture.md §7.6).
	obs, err := a.scanner.Run(ctx, job)
	status := "ok"
	var errs []string
	perm := false
	if err != nil {
		status = "error"
		errs = append(errs, err.Error())
		perm = isPermanent(err)
	}
	logArgs := []any{
		"stage", job.Stage, "target", target, "task", job.TaskID,
		"status", status, "observations", len(obs),
		"took", time.Since(started).Round(time.Millisecond).String(),
	}
	if err != nil {
		slog.Error("task failed", append(logArgs, "err", err)...)
	} else {
		slog.Info("task finished", logArgs...)
	}
	// Chunk large result sets; send a final closing batch.
	const batch = 500
	seq := 0
	for i := 0; i < len(obs); i += batch {
		end := i + batch
		if end > len(obs) {
			end = len(obs)
		}
		a.postResult(ctx, job, scanproto.Result{
			Schema: scanproto.ResultSchema, JobID: job.JobID, TaskID: job.TaskID,
			LeaseToken: job.LeaseToken, Seq: seq, Final: false, Status: status,
			Worker:       scanproto.WorkerRef{ID: a.workerID, Version: a.cfg.Version},
			Observations: obs[i:end],
		})
		seq++
	}
	// final batch (closes the task / releases the lease)
	a.postResult(ctx, job, scanproto.Result{
		Schema: scanproto.ResultSchema, JobID: job.JobID, TaskID: job.TaskID,
		LeaseToken: job.LeaseToken, Seq: seq, Final: true, Status: status,
		Worker: scanproto.WorkerRef{ID: a.workerID, Version: a.cfg.Version}, Errors: errs,
		Permanent: perm,
	})
}

// postResult ships one batch of observations to the gateway, spooling it if
// the gateway cannot be reached.
//
// The response status is checked and classified. It was once ignored, so a
// batch the gateway refused was dropped without a trace: the stage logged the
// observations it had made, the task still finished "ok", and nothing reached
// the database. A refusal (4xx) is still final and logged as such; a transport
// error or 5xx now goes to the spool instead of being lost.
func (a *Agent) postResult(ctx context.Context, job scanproto.Job, res scanproto.Result) {
	url := job.Ingest.URL
	if url == "" {
		url = a.cfg.GatewayURL + "/agent/v1/results"
	}
	// A task's batches must land in order, and the last one closes the task. If
	// an earlier batch of this task is still spooled, this one joins it rather
	// than overtaking it — otherwise the final batch completes the task while
	// its observations are still on disk, and they can never be replayed.
	if a.spool.hasPending(res.TaskID) {
		if err := a.spool.put(url, res); err == nil {
			slog.Warn("earlier batch of this task is still spooled; queued behind it",
				"stage", job.Stage, "task", res.TaskID, "seq", res.Seq,
				"observations", len(res.Observations))
			return
		}
	}
	switch o, why := a.post(ctx, url, res); o {
	case delivered:
	case refused:
		note := ""
		if strings.Contains(why, "lease") {
			note = "this worker no longer holds the task: its lease expired while the control channel was down, or the task was reassigned; the gateway log for this task says which, and another attempt will redo the work"
		}
		slog.Error("gateway refused results — observations discarded",
			"stage", job.Stage, "task", job.TaskID, "target", describeTarget(job),
			"observations", len(res.Observations), "reason", why, "note", note)
	case unreachable:
		if err := a.spool.put(url, res); err != nil {
			slog.Error("gateway unreachable and spool unavailable — observations lost",
				"stage", job.Stage, "task", job.TaskID,
				"observations", len(res.Observations), "post", why, "spool", err)
			return
		}
		slog.Warn("gateway unreachable; results spooled for replay",
			"stage", job.Stage, "task", job.TaskID, "seq", res.Seq,
			"observations", len(res.Observations), "reason", why)
	}
}

// post performs one delivery attempt and classifies the result.
func (a *Agent) post(ctx context.Context, url string, res scanproto.Result) (outcome, string) {
	body, _ := json.Marshal(res)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return refused, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Id", a.workerID)
	req.Header.Set("X-Worker-Credential", a.cred)
	resp, err := a.client.Do(req)
	if err != nil {
		return unreachable, err.Error()
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		_, _ = io.Copy(io.Discard, resp.Body)
		return delivered, ""
	case resp.StatusCode/100 == 5:
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return unreachable, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(reason)))
	default:
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return refused, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(reason)))
	}
}

// flushSpool replays spooled batches now and then once a minute until ctx ends.
func (a *Agent) flushSpool(ctx context.Context) {
	a.spool.replay(ctx, a.post)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.spool.replay(ctx, a.post)
		}
	}
}

func (a *Agent) mark(taskID, leaseToken string, running bool) {
	a.mu.Lock()
	if running {
		a.running[taskID] = leaseToken
	} else {
		delete(a.running, taskID)
	}
	a.mu.Unlock()
}

// heldLeases is what the heartbeat carries: every running task with the
// lease it is held on.
func (a *Agent) heldLeases() []scanproto.HeldLease {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]scanproto.HeldLease, 0, len(a.running))
	for id, tok := range a.running {
		out = append(out, scanproto.HeldLease{TaskID: id, LeaseToken: tok})
	}
	return out
}

// describeTarget renders a job's target for logs: whichever of domain, ip, url
// or cidr the stage actually works on.
func describeTarget(job scanproto.Job) string {
	if len(job.Targets) == 0 {
		return ""
	}
	t := job.Targets[0]
	switch {
	case t.Domain != "":
		if job.Params.WordlistName != "" {
			return t.Domain + " [" + job.Params.WordlistName + "]"
		}
		return t.Domain
	case t.URL != "":
		return t.URL
	case t.IP != "":
		if t.Port != 0 {
			return fmt.Sprintf("%s:%d", t.IP, t.Port)
		}
		return t.IP
	case t.CIDR != "":
		return t.CIDR
	}
	return ""
}

// --- capability & tool detection (wiki/Worker-Pipeline.md, wiki/Architecture.md §6.2) ---

// DetectCapabilities self-detects what this box can do.
func DetectCapabilities() map[scanproto.Capability]bool {
	caps := map[scanproto.Capability]bool{}
	// raw socket: presence of naabu with cap, or running as root
	if os.Geteuid() == 0 || have("naabu") {
		caps[scanproto.CapRawSocket] = true
	}
	// browser: chromium/chrome or httpx present
	for _, b := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if have(b) {
			caps[scanproto.CapBrowser] = true
		}
	}
	// ipv6: a routable v6 source
	if hasIPv6() {
		caps[scanproto.CapIPv6] = true
	}
	return caps
}

// DetectTools reports the versions of installed scan tools for the fleet UI.
func DetectTools() map[string]string {
	tools := map[string]string{}
	for _, t := range []string{
		"subfinder", "shuffledns", "dnsx", "gobuster",
		"naabu", "nmap", "katana", "urlfinder", "httpx", "nuclei",
		"ffuf", "feroxbuster", "massdns",
	} {
		if have(t) {
			tools[t] = toolVersion(t)
		}
	}
	return tools
}

func toolVersion(name string) string {
	out, err := exec.Command(name, "-version").CombinedOutput()
	if err != nil || len(out) == 0 {
		return "present"
	}
	line := string(bytes.SplitN(out, []byte("\n"), 2)[0])
	if len(line) > 40 {
		line = line[:40]
	}
	return line
}

func capsList(m map[scanproto.Capability]bool) []scanproto.Capability {
	var out []scanproto.Capability
	for c, ok := range m {
		if ok {
			out = append(out, c)
		}
	}
	return out
}

func hasIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip := ipnet.IP; ip.To4() == nil && ip.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func toWS(u string) string {
	if len(u) > 8 && u[:8] == "https://" {
		return "wss://" + u[8:]
	}
	if len(u) > 7 && u[:7] == "http://" {
		return "ws://" + u[7:]
	}
	return u
}

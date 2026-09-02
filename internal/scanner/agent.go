package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/benlik386/asm/internal/scanproto"
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
	cfg     AgentConfig
	caps    map[scanproto.Capability]bool
	scanner *Scanner
	client  *http.Client

	workerID string
	cred     string

	// providerConfig is subfinder's generated provider-config.yaml, or "" when
	// no API keys are configured.
	providerConfig string

	mu      sync.Mutex
	running map[string]bool

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

	a := &Agent{
		providerConfig: pcPath,
		cfg:            cfg,
		caps:           caps,
		scanner:        &Scanner{Detected: caps, ProviderConfig: pcPath},
		// Upload set below once the Agent exists (needs a.cfg/a.cred).
		client:  &http.Client{Timeout: 30 * time.Second},
		running: map[string]bool{},
	}
	a.scanner.Upload = a.uploadArtifact
	return a
}

// uploadArtifact stores bytes in object storage: it asks the gateway to presign
// a PUT and uploads directly, so artifacts never transit the gateway
// (architecture.md §3.2). Returns the object key on success.
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
	for {
		if err := a.ensureEnrolled(ctx); err != nil {
			slog.Error("enrolment failed", "err", err)
		} else if err := a.connect(ctx); err != nil {
			slog.Warn("control channel dropped; reconnecting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
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

func (a *Agent) connect(ctx context.Context) error {
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
	slog.Info("control channel up")

	// heartbeat ticker
	hbCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.heartbeat(hbCtx, conn)

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
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = a.sendControl(conn, scanproto.Heartbeat{
				WorkerID: a.workerID, RunningTasks: a.runningTasks(), At: time.Now(),
			})
		}
	}
}

func (a *Agent) execJob(ctx context.Context, job scanproto.Job) {
	a.mark(job.TaskID, true)
	defer a.mark(job.TaskID, false)

	// One line in, one line out per task, both carrying the target — enough to
	// follow a scan in `docker compose logs worker` without turning on debug.
	target := describeTarget(job)
	started := time.Now()
	slog.Info("task started",
		"stage", job.Stage, "target", target, "task", job.TaskID, "run", job.RunID)

	obs, err := a.scanner.Run(ctx, job)
	status := "ok"
	var errs []string
	if err != nil {
		status = "error"
		errs = append(errs, err.Error())
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
	})
}

func (a *Agent) postResult(ctx context.Context, job scanproto.Job, res scanproto.Result) {
	url := job.Ingest.URL
	if url == "" {
		url = a.cfg.GatewayURL + "/agent/v1/results"
	}
	body, _ := json.Marshal(res)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Id", a.workerID)
	req.Header.Set("X-Worker-Credential", a.cred)
	resp, err := a.client.Do(req)
	if err != nil {
		slog.Warn("post result failed (spooling would retry)", "err", err)
		return
	}
	resp.Body.Close()
}

func (a *Agent) mark(taskID string, running bool) {
	a.mu.Lock()
	if running {
		a.running[taskID] = true
	} else {
		delete(a.running, taskID)
	}
	a.mu.Unlock()
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

// --- capability & tool detection (worker-pipeline.md, architecture.md §6.2) ---

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

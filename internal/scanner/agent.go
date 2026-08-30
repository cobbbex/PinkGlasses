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

	mu      sync.Mutex
	running map[string]bool
}

// NewAgent builds a worker agent, detecting capabilities and tools.
func NewAgent(cfg AgentConfig) *Agent {
	caps := DetectCapabilities()
	return &Agent{
		cfg:     cfg,
		caps:    caps,
		scanner: New(caps),
		client:  &http.Client{Timeout: 30 * time.Second},
		running: map[string]bool{},
	}
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
			a.mu.Lock()
			ids := make([]string, 0, len(a.running))
			for id := range a.running {
				ids = append(ids, id)
			}
			a.mu.Unlock()
			_ = conn.WriteJSON(scanproto.Heartbeat{WorkerID: a.workerID, RunningTasks: ids, At: time.Now()})
		}
	}
}

func (a *Agent) execJob(ctx context.Context, job scanproto.Job) {
	a.mark(job.TaskID, true)
	defer a.mark(job.TaskID, false)
	slog.Info("running job", "stage", job.Stage, "task", job.TaskID)

	obs, err := a.scanner.Run(ctx, job)
	status := "ok"
	var errs []string
	if err != nil {
		status = "error"
		errs = append(errs, err.Error())
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
	for _, t := range []string{"subfinder", "dnsx", "naabu", "httpx", "nuclei", "katana", "nmap", "ffuf", "feroxbuster"} {
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

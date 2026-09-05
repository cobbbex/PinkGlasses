// Package fleet manages the containers a scan run brings up for itself.
//
// A run can ask for its own workers, and — when it scans through a VPN — a
// gateway container holding the tunnel whose network namespace those workers
// share. The privilege stays in the gateway: a worker in a fleet holds no more
// than any other worker, it simply finds itself in a namespace whose default
// route is a tunnel.
//
// The lifecycle lives here rather than in the API because it has to survive a
// restart. The API records that a run wants a fleet; this builds it, watches
// it, and takes it down when the run is over — including fleets whose run
// ended while the control plane was not running.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Manager builds, watches and removes run fleets through the provisioner.
type Manager struct {
	st    *store.Store
	url   string
	token string
	http  *http.Client
	// maxLive caps how many runs may hold containers at once, so a burst of
	// scheduled scans cannot fill the host with containers.
	maxLive int
	// graceAfter is how long a fleet may have no live worker before its run is
	// failed. Workers sharing a dead gateway's namespace lose every route,
	// including the one back here, so they cannot report this themselves.
	graceAfter time.Duration
	deadSince  map[uuid.UUID]time.Time
}

// New builds a Manager. An empty url or token disables fleet management, which
// is the right behaviour wherever no provisioner is running.
func New(st *store.Store, url, token string, maxLive int) *Manager {
	if maxLive <= 0 {
		maxLive = 3
	}
	return &Manager{
		st: st, url: url, token: token,
		http:       &http.Client{Timeout: 3 * time.Minute},
		maxLive:    maxLive,
		graceAfter: 2 * time.Minute,
		deadSince:  map[uuid.UUID]time.Time{},
	}
}

// Enabled reports whether fleets can be managed at all.
func (m *Manager) Enabled() bool { return m.url != "" && m.token != "" }

// Tick builds pending fleets, watches live ones and removes finished ones.
func (m *Manager) Tick(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	m.buildPending(ctx)
	m.superviseLive(ctx)
	m.tearDownFinished(ctx)
}

func (m *Manager) buildPending(ctx context.Context) {
	pending, err := m.st.FleetsToBuild(ctx)
	if err != nil || len(pending) == 0 {
		return
	}
	// The ceiling is on fleets that already hold containers, so the ones about
	// to be built here are not among them yet.
	live, err := m.st.CountLiveFleets(ctx)
	if err != nil {
		return
	}
	holding := live
	for _, f := range pending {
		if wait, note := ceilingDecision(holding, m.maxLive); wait {
			_ = m.st.SetFleetStatus(ctx, f.RunID, "requested", &note, nil)
			continue
		}
		if m.build(ctx, f) {
			holding++
		}
	}
}

// ceilingDecision says whether a pending fleet must wait, and why.
//
// Every active run needs a fleet now, so the ceiling is a queue rather than an
// error: the run stays 'running' with its active tasks pending — nothing else
// can lease them — and is built when a slot frees. The reason is written where
// the run view shows it, so a run that sits at "Starting…" says why.
func ceilingDecision(holding, max int) (wait bool, note string) {
	if holding < max {
		return false, ""
	}
	return true, fmt.Sprintf("waiting for a slot: %d of %d runs already hold their own workers "+
		"(ASM_MAX_RUN_FLEETS)", holding, max)
}

// build brings up one fleet, reporting whether it now holds containers.
func (m *Manager) build(ctx context.Context, f store.RunFleet) bool {
	req := map[string]any{
		"run_id":       f.RunID.String(),
		"workers":      f.Workers,
		"enroll_token": f.EnrollToken,
	}
	if f.VPNConfigID != nil {
		vc, err := m.st.GetVPNConfig(ctx, *f.VPNConfigID)
		if err != nil {
			m.fail(ctx, f, "the chosen VPN configuration no longer exists")
			return false
		}
		body, err := m.st.OpenVPNConfigBody(ctx, *f.VPNConfigID)
		if err != nil {
			// Never quote the body or the key into the message.
			m.fail(ctx, f, "the VPN configuration could not be decrypted; "+
				"it was sealed with a different ASM_SECRET_KEY than this server holds")
			return false
		}
		req["vpn_kind"], req["vpn_config"] = vc.Kind, string(body)
	}

	var out struct {
		Gateway  string   `json:"gateway"`
		Workers  []string `json:"workers"`
		EgressIP string   `json:"egress_ip"`
		Error    string   `json:"error"`
	}
	if err := m.call(ctx, "/v1/fleet/create", req, &out); err != nil {
		m.fail(ctx, f, err.Error())
		return false
	}
	if out.Error != "" {
		m.fail(ctx, f, out.Error)
		return false
	}
	var egress *string
	if out.EgressIP != "" {
		egress = &out.EgressIP
		if f.VPNConfigID != nil {
			_ = m.st.RecordVPNEgress(ctx, *f.VPNConfigID, out.EgressIP)
		}
	}
	_ = m.st.SetFleetStatus(ctx, f.RunID, "up", nil, egress)
	slog.Info("run fleet up", "run", f.RunID, "workers", len(out.Workers),
		"gateway", out.Gateway != "", "egress", out.EgressIP)
	return true
}

// fail marks the fleet failed and fails the run with the same reason.
//
// A run that cannot get the workers it asked for must not sit in 'running'
// forever waiting for them: its tasks are routed to a pool that will never have
// a member, so nothing else can pick them up.
func (m *Manager) fail(ctx context.Context, f store.RunFleet, reason string) {
	slog.Error("run fleet could not be built", "run", f.RunID, "reason", reason)
	_ = m.st.SetFleetStatus(ctx, f.RunID, "failed", &reason, nil)
	_ = m.st.CancelRunTasks(ctx, f.RunID)
	_ = m.st.SetRunStatus(ctx, f.RunID, domain.RunFailed)
	m.remove(ctx, f)
}

// superviseLive fails runs whose fleet has stopped having live workers.
func (m *Manager) superviseLive(ctx context.Context) {
	live, err := m.st.LiveFleets(ctx)
	if err != nil {
		return
	}
	seen := map[uuid.UUID]bool{}
	for _, f := range live {
		seen[f.RunID] = true
		if f.PoolID == nil {
			continue // already torn down; nothing to supervise
		}
		n, err := m.st.ActiveWorkersInPool(ctx, *f.PoolID)
		if err != nil {
			continue
		}
		if n > 0 {
			delete(m.deadSince, f.RunID)
			continue
		}
		// A fleet that has just been created has not enrolled yet, so absence
		// is only evidence once it has persisted for the grace period.
		since, ok := m.deadSince[f.RunID]
		if !ok {
			m.deadSince[f.RunID] = time.Now()
			continue
		}
		if time.Since(since) >= m.graceAfter {
			delete(m.deadSince, f.RunID)
			m.fail(ctx, f, fmt.Sprintf(
				"this run's own workers stopped reporting for %s. If it was scanning "+
					"through a VPN, the gateway container holds the only route they had, "+
					"so a tunnel that dropped takes the workers with it", m.graceAfter))
		}
	}
	for id := range m.deadSince {
		if !seen[id] {
			delete(m.deadSince, id)
		}
	}
}

// tearDownFinished removes the containers of runs that have ended.
func (m *Manager) tearDownFinished(ctx context.Context) {
	done, err := m.st.FleetsToTearDown(ctx)
	if err != nil {
		return
	}
	for _, f := range done {
		m.remove(ctx, f)
	}
}

// remove destroys a fleet's containers and the worker rows they enrolled.
//
// Task attribution survives this: a worker's name and kind are stamped on each
// task when it is leased, so a finished run still says who ran what long after
// the container that did it is gone.
func (m *Manager) remove(ctx context.Context, f store.RunFleet) {
	if err := m.call(ctx, "/v1/fleet/remove", map[string]any{"run_id": f.RunID.String()}, nil); err != nil {
		// Leave the row live so the next tick retries; SweepOrphans is the
		// backstop if this server never comes back.
		slog.Warn("could not remove a run's containers", "run", f.RunID, "err", err)
		return
	}
	var n int64
	if f.PoolID != nil {
		var err error
		if n, err = m.st.DeleteRunPoolAndWorkers(ctx, *f.PoolID); err != nil {
			slog.Warn("could not remove a run's worker rows", "run", f.RunID, "err", err)
		}
	}
	_ = m.st.MarkFleetTornDown(ctx, f.RunID)
	slog.Info("run fleet torn down", "run", f.RunID, "worker_rows", n)
}

// SweepOrphans removes containers whose run no longer wants them — what a
// control-plane crash between building a fleet and tearing it down leaves
// behind. Run at startup and periodically.
func (m *Manager) SweepOrphans(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	var out struct {
		Runs map[string]int `json:"runs"`
	}
	if err := m.call(ctx, "/v1/fleet/orphans", nil, &out); err != nil {
		return
	}
	for raw := range out.Runs {
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		f, ok, err := m.st.GetRunFleet(ctx, id)
		if err != nil {
			continue
		}
		if ok && (f.Status == "requested" || f.Status == "up") {
			continue // still wanted
		}
		slog.Info("removing containers left over from a finished run", "run", id)
		_ = m.call(ctx, "/v1/fleet/remove", map[string]any{"run_id": raw}, nil)
		if ok && f.PoolID != nil {
			_, _ = m.st.DeleteRunPoolAndWorkers(ctx, *f.PoolID)
		}
	}
}

func (m *Manager) call(ctx context.Context, path string, body, out any) error {
	method, rdr := http.MethodPost, bytes.NewReader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, m.url+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Provisioner-Token", m.token)
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("the provisioner is unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(&io.LimitedReader{R: resp.Body, N: 4 << 10})
		// The provisioner answers a failed build with {"error": "..."} whose
		// text is written for an operator to read — a gateway's last log lines,
		// say. Surface that rather than the status line wrapped around JSON.
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(buf.Bytes(), &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("the provisioner refused: %s: %s",
			resp.Status, strings.TrimSpace(buf.String()))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

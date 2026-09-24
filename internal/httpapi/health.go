package httpapi

import (
	"context"
	"github.com/benlik386/pinkglasses/internal/version"
	"net/http"
	"os"
	"strings"
	"time"
)

// systemHealth is the admin health page: is each part of the install up, are
// the workers heartbeating, is work flowing. Every probe has a short timeout
// so one dead component cannot hang the page.
func (s *Server) systemHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	type component struct {
		Name   string         `json:"name"`
		Status string         `json:"status"` // ok | degraded | down | off
		Detail string         `json:"detail"`
		Extra  map[string]any `json:"extra,omitempty"`
	}
	var comps []component
	comps = append(comps, component{Name: "api", Status: "ok", Detail: "answering this request", Extra: map[string]any{"version": version.Version, "commit": version.Commit}})

	// Database: round trip and schema version.
	t0 := time.Now()
	if v, err := s.st.SchemaVersion(ctx); err != nil {
		comps = append(comps, component{Name: "database", Status: "down", Detail: err.Error()})
	} else {
		ms := time.Since(t0).Milliseconds()
		st := "ok"
		if ms > 500 {
			st = "degraded"
		}
		comps = append(comps, component{Name: "database", Status: st,
			Detail: "schema version " + itoa(int(v)) + ", " + itoa(int(ms)) + " ms round trip"})
	}

	// Object storage: any answer at all, even 404 for a key that is not
	// there, means it is reachable and signing works.
	comps = append(comps, s.probeObjectStorage(ctx))

	// Services without an endpoint here: the age of their heartbeat row.
	beats, _ := s.st.ComponentBeats(ctx)
	for _, name := range []string{"gateway", "scheduler"} {
		b, ok := beats[name]
		switch {
		case !ok:
			comps = append(comps, component{Name: name, Status: "down", Detail: "has never reported"})
		default:
			age := time.Since(b.LastSeen)
			st := "ok"
			if age > 90*time.Second {
				st = "down"
			} else if age > 45*time.Second {
				st = "degraded"
			}
			comps = append(comps, component{Name: name, Status: st,
				Detail: "last heartbeat " + age.Round(time.Second).String() + " ago",
				Extra:  map[string]any{"detail": b.Detail}})
		}
	}

	// Provisioner: its own health endpoint, when this install has one.
	if u := os.Getenv("ASM_PROVISIONER_URL"); u != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(u, "/")+"/healthz", nil)
		c := &http.Client{Timeout: 3 * time.Second}
		if resp, err := c.Do(req); err != nil {
			comps = append(comps, component{Name: "provisioner", Status: "down", Detail: err.Error()})
		} else {
			resp.Body.Close()
			st := "ok"
			if resp.StatusCode >= 400 {
				st = "down"
			}
			comps = append(comps, component{Name: "provisioner", Status: st, Detail: "HTTP " + resp.Status})
		}
	} else {
		comps = append(comps, component{Name: "provisioner", Status: "off",
			Detail: "not configured (ASM_PROVISIONER_URL): runs cannot build their own workers"})
	}

	counts, _ := s.st.HealthCounts(ctx)
	queue, _ := s.st.HealthQueue(ctx)
	workers, _ := s.st.ListWorkers(ctx)
	type workerRow struct {
		Name         string  `json:"name"`
		Kind         string  `json:"kind"`
		Status       string  `json:"status"`
		RunFleet     bool    `json:"run_fleet"`
		Running      int     `json:"running_tasks"`
		HeartbeatAge float64 `json:"heartbeat_age_s"`
		Version      string  `json:"version"`
	}
	var wrows []workerRow
	for _, wk := range workers {
		row := workerRow{Name: wk.Name, Kind: string(wk.Kind), Status: string(wk.Status), RunFleet: wk.RunScoped,
			Running: wk.RunningTasks, Version: wk.AgentVersion}
		if wk.LastSeenAt != nil {
			row.HeartbeatAge = time.Since(*wk.LastSeenAt).Seconds()
		} else {
			row.HeartbeatAge = -1
		}
		wrows = append(wrows, row)
	}
	stranded, _ := s.st.StrandedTasks(ctx, 2*time.Minute)

	overall := "ok"
	for _, c := range comps {
		if c.Status == "down" {
			overall = "down"
			break
		}
		if c.Status == "degraded" {
			overall = "degraded"
		}
	}
	if overall == "ok" && (len(stranded) > 0 || counts.WorkersActive == 0) {
		overall = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": overall, "checked_at": time.Now().UTC(),
		"components": comps, "counts": counts, "queue": queue, "workers": wrows, "stranded": stranded,
	})
}

func (s *Server) probeObjectStorage(ctx context.Context) (c struct {
	Name   string         `json:"name"`
	Status string         `json:"status"`
	Detail string         `json:"detail"`
	Extra  map[string]any `json:"extra,omitempty"`
}) {
	c.Name = "object storage"
	if s.obj == nil {
		c.Status, c.Detail = "off", "not configured"
		return
	}
	u, err := s.obj.PresignGet("health/probe", time.Minute, time.Now())
	if err != nil {
		c.Status, c.Detail = "down", err.Error()
		return
	}
	// GET, because the URL is signed for GET; a HEAD would be refused for
	// its signature, not for anything wrong with the store.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		c.Status, c.Detail = "down", err.Error()
		return
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode < 300:
		c.Status, c.Detail = "ok", "reachable, requests signed and accepted"
	case resp.StatusCode == http.StatusForbidden:
		c.Status, c.Detail = "degraded", "reachable, but the credentials were refused (HTTP 403)"
	default:
		c.Status, c.Detail = "degraded", "HTTP "+resp.Status
	}
	return
}

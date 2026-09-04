package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// provisionClient talks to the isolated provisioner sidecar. The api never
// touches the Docker socket itself (architecture.md §7.3) — it can only ask for
// a worker count, and the provisioner enforces its own ceiling.
type provisionClient struct {
	url   string
	token string
	http  *http.Client
}

func newProvisionClient() *provisionClient {
	return &provisionClient{
		url:   os.Getenv("ASM_PROVISIONER_URL"),
		token: os.Getenv("ASM_PROVISIONER_TOKEN"),
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *provisionClient) enabled() bool { return p.url != "" && p.token != "" }

func (p *provisionClient) call(method, path string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, p.url+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Provisioner-Token", p.token)
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return &strErr{"provisioner: " + resp.Status + ": " + buf.String()}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// removeContainer asks the provisioner to destroy the container backing a local
// worker. Best-effort: a worker row can always be deleted even if the container
// is already gone or the provisioner is not running.
func (p *provisionClient) removeContainer(name string) error {
	if !p.enabled() || name == "" {
		return nil
	}
	return p.call(http.MethodPost, "/v1/remove", map[string]string{"name": name}, nil)
}

// getProvisionStatus reports whether the button is available and how many local
// worker containers are currently running.
func (s *Server) getProvisionStatus(w http.ResponseWriter, r *http.Request) {
	pc := newProvisionClient()
	if !pc.enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"reason":  "provisioner not configured; scale local workers with: docker compose up -d --scale worker=N",
		})
		return
	}
	var out map[string]any
	if err := pc.call(http.MethodGet, "/v1/workers", nil, &out); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "count": out["count"]})
}

// scaleLocalWorkers is the UI button: converge local worker containers to N.
func (s *Server) scaleLocalWorkers(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Count int `json:"count"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "count required")
		return
	}
	pc := newProvisionClient()
	if !pc.enabled() {
		writeErr(w, http.StatusServiceUnavailable,
			"provisioner not enabled; run: docker compose up -d --scale worker="+itoa(in.Count))
		return
	}
	var out struct {
		Target     int      `json:"target"`
		Created    int      `json:"created"`
		Removed    int      `json:"removed"`
		RemovedIDs []string `json:"removed_ids"`
		Error      string   `json:"error"`
	}
	if err := pc.call(http.MethodPost, "/v1/scale", map[string]int{"count": in.Count}, &out); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	// Drop the worker rows whose containers just went away. Without this the
	// fleet list keeps showing workers that no longer exist until the
	// scheduler's stale sweep eventually reaps them.
	orphans, err := s.st.DeleteLocalWorkersByContainer(r.Context(), out.RemovedIDs)
	if err != nil {
		orphans = 0 // non-fatal: the stale sweep will catch them
	}

	s.auditReq(r, "worker.scale_local", "",
		map[string]any{"count": in.Count, "created": out.Created, "removed": out.Removed})

	writeJSON(w, http.StatusOK, map[string]any{
		"target": out.Target, "created": out.Created,
		"removed": out.Removed, "rows_removed": orphans,
		"error": out.Error,
	})
}

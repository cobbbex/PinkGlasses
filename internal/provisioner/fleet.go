package provisioner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// A run fleet is the set of containers one scan brought up for itself: its own
// workers, and — when the run scans through a VPN — a gateway container holding
// the tunnel that the workers share a network namespace with.
//
// The privilege lives in the gateway alone. A worker in a fleet gets no more
// than a standing worker does; it simply finds itself in a namespace whose
// default route is a tunnel. That is the point of the shape: the container
// running nmap, chromium and nuclei is the one most likely to be exploited, and
// it is the one that should hold the least.

// FleetRequest asks for a run's containers.
type FleetRequest struct {
	RunID       string `json:"run_id"`
	Workers     int    `json:"workers"`
	EnrollToken string `json:"enroll_token"`
	Concurrency string `json:"concurrency"`
	// VPN, when set, is the tunnel the fleet scans through.
	VPNKind   string `json:"vpn_kind"`
	VPNConfig string `json:"vpn_config"`
}

// FleetResult reports what was created.
type FleetResult struct {
	Gateway  string   `json:"gateway,omitempty"`
	Workers  []string `json:"workers"`
	EgressIP string   `json:"egress_ip,omitempty"`
}

// createFleet builds a run's containers: the VPN gateway first if one is
// wanted, then the workers, which are only started once the gateway reports a
// tunnel that actually changed its address.
func (s *Server) createFleet(w http.ResponseWriter, r *http.Request) {
	var in FleetRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RunID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}
	if in.Workers < 1 {
		in.Workers = 1
	}
	if in.Workers > s.cfg.MaxWorkers {
		http.Error(w, fmt.Sprintf("a fleet of %d exceeds ASM_PROVISIONER_MAX_WORKERS (%d)",
			in.Workers, s.cfg.MaxWorkers), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	out := FleetResult{Workers: []string{}}

	// Anything left from a previous attempt at this run goes first, so a retry
	// cannot end up with two gateways and a namespace pointing at the wrong one.
	s.removeFleetContainers(ctx, in.RunID)

	netns := ""
	if in.VPNKind != "" {
		gwID, egress, err := s.startGateway(ctx, in)
		if err != nil {
			// The gateway is removed on failure: a half-built fleet whose
			// tunnel never came up must not be left for workers to join.
			s.removeFleetContainers(ctx, in.RunID)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		out.Gateway, out.EgressIP, netns = gwID, egress, gwID
	}

	for i := 0; i < in.Workers; i++ {
		id, err := s.d.Create(ctx, Spec{
			Image:          s.cfg.Image,
			GatewayURL:     s.cfg.GatewayURL,
			EnrollToken:    in.EnrollToken,
			Network:        s.cfg.Network,
			NamePrefix:     "pinkglasses-run-" + short(in.RunID),
			Concurrency:    in.Concurrency,
			RunID:          in.RunID,
			NetnsContainer: netns,
			Role:           roleWorker,
		}, i)
		if err != nil {
			s.removeFleetContainers(ctx, in.RunID)
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": fmt.Sprintf("creating worker %d of %d: %v", i+1, in.Workers, err)})
			return
		}
		out.Workers = append(out.Workers, id)
	}

	slog.Info("run fleet created", "run", in.RunID, "workers", len(out.Workers),
		"gateway", out.Gateway != "", "egress", out.EgressIP)
	writeJSON(w, http.StatusOK, out)
}

// startGateway creates the tunnel container and waits for Docker to call it
// healthy, which the gateway only reports once its address has changed.
func (s *Server) startGateway(ctx context.Context, in FleetRequest) (id, egress string, err error) {
	id, err = s.d.Create(ctx, Spec{
		Image:      s.cfg.Image,
		Network:    s.cfg.Network,
		NamePrefix: "pinkglasses-vpn-" + short(in.RunID),
		RunID:      in.RunID,
		Role:       roleVPNGateway,
		VPNKind:    in.VPNKind,
		VPNConfig:  in.VPNConfig,
	}, 0)
	if err != nil {
		return "", "", fmt.Errorf("creating the VPN gateway: %w", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		c, err := s.d.Inspect(ctx, id)
		if err != nil {
			continue
		}
		switch {
		case c.Health == "healthy":
			return id, c.EgressIP, nil
		case c.State == "exited" || c.State == "dead":
			// The healthcheck log says nothing useful about a container that
			// died before it ever ran; the gateway's own stderr is where
			// openvpn or wg explains itself.
			detail := s.d.Logs(ctx, id, 15)
			if detail == "" {
				detail = c.LastLog
			}
			return "", "", fmt.Errorf("the VPN gateway stopped before its tunnel came up: %s", detail)
		}
	}
	return "", "", fmt.Errorf("the VPN gateway did not report a working tunnel within 90s: %s",
		firstLine(s.d.Logs(ctx, id, 15), "no output"))
}

// removeFleet destroys every container belonging to a run.
func (s *Server) removeFleet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunID string `json:"run_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RunID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}
	n := s.removeFleetContainers(r.Context(), in.RunID)
	slog.Info("run fleet removed", "run", in.RunID, "containers", n)
	writeJSON(w, http.StatusOK, map[string]any{"removed": n})
}

// removeFleetContainers deletes a run's containers, workers before the gateway
// so nothing is left in a namespace that has gone.
func (s *Server) removeFleetContainers(ctx context.Context, runID string) int {
	list, err := s.d.List(ctx)
	if err != nil {
		return 0
	}
	var workers, gateways []Container
	for _, c := range list {
		if c.RunID() != runID {
			continue
		}
		if c.Role() == roleVPNGateway {
			gateways = append(gateways, c)
		} else {
			workers = append(workers, c)
		}
	}
	n := 0
	for _, c := range append(workers, gateways...) {
		if err := s.d.Remove(ctx, c.ID); err != nil {
			slog.Warn("could not remove fleet container", "run", runID, "id", c.ID, "err", err)
			continue
		}
		n++
	}
	return n
}

// orphans lists run ids that still have containers, so the scheduler can tell
// which fleets outlived their run — after a control-plane restart, say.
func (s *Server) orphans(w http.ResponseWriter, r *http.Request) {
	list, err := s.d.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	runs := map[string]int{}
	for _, c := range list {
		if id := c.RunID(); id != "" {
			runs[id]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// firstLine keeps a multi-line log readable inside a one-line error, without
// throwing away the part that says what went wrong: tools complain last.
func firstLine(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 3 {
		lines = lines[n-3:]
	}
	return strings.Join(lines, " | ")
}

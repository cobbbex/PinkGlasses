package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/scanproto"
)

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListWorkers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// createEnrollmentToken mints a token and returns the command the user runs to
// bring the worker up. Two flows share one mechanism (architecture.md §7.1):
//
//   local — a container beside the control plane. Multi-use bootstrap token,
//           self-enrolls, auto-approved. Scans from your own egress address.
//   vps   — a rented box. Single-use short-TTL token, installer script, and a
//           human must approve it before it can lease any work.
func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind    string `json:"kind"` // "local" | "vps" (default)
		PoolID  string `json:"pool_id"`
		Name    string `json:"name"`
		TTLMins int    `json:"ttl_mins"`
		MaxUses int    `json:"max_uses"`
		Count   int    `json:"count"` // local only: desired replica count
	}
	_ = readJSON(r, &in)

	kind := in.Kind
	if kind != string(scanproto.KindLocal) {
		kind = string(scanproto.KindVPS)
	}

	// --- local: no token to hand out; the bootstrap token is already shared
	// with worker containers over the internal network. Just show the command.
	if kind == string(scanproto.KindLocal) {
		count := in.Count
		if count < 1 {
			count = 2
		}
		s.audit.Log(r.Context(), actor(r), "worker.scale_local", "", map[string]any{"count": count})
		writeJSON(w, http.StatusCreated, map[string]any{
			"kind":            kind,
			"install_command": "docker compose up -d --scale worker=" + itoa(count),
			"note": "Local workers self-enroll over the internal network and are approved " +
				"automatically. They scan your external targets from your own egress address.",
		})
		return
	}

	// --- vps: single-use, short-TTL token + installer one-liner.
	ttl := time.Duration(in.TTLMins) * time.Minute
	if ttl == 0 {
		ttl = time.Hour
	}
	maxUses := in.MaxUses
	if maxUses == 0 {
		maxUses = 1
	}

	raw := "WRKENROLL_" + randToken(24)
	sum := sha256.Sum256([]byte(raw))

	var poolID *uuid.UUID
	if in.PoolID != "" {
		if id, err := uuid.Parse(in.PoolID); err == nil {
			poolID = &id
		}
	}
	if poolID == nil {
		// Remote workers default to the 'remote' pool, falling back to default.
		if id, err := s.st.PoolByName(r.Context(), "remote"); err == nil {
			poolID = &id
		} else if id, err := s.st.DefaultPool(r.Context()); err == nil {
			poolID = &id
		}
	}

	if _, err := s.st.CreateEnrollmentToken(r.Context(), sum[:], poolID, nil, ttl, maxUses, kind); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "worker.enroll_token", "", map[string]any{"ttl": ttl.String(), "kind": kind})

	gwURL := os.Getenv("ASM_PUBLIC_GATEWAY_URL")
	if gwURL == "" {
		gwURL = "https://gw.asm.example.com"
	}
	name := in.Name
	if name == "" {
		name = "vps-1"
	}
	install := "curl -sSfL " + gwURL + "/install.sh | sudo bash -s -- --url " + gwURL +
		" --token " + raw + " --name " + name

	writeJSON(w, http.StatusCreated, map[string]any{
		"kind":            kind,
		"token":           raw, // shown once
		"expires_in":      ttl.String(),
		"install_command": install,
		"note":            "Run this on the VPS, then approve the worker in the fleet list.",
	})
}

// itoa is a tiny int-to-string helper (avoids importing strconv here).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// workerAction runs a lifecycle transition on a worker.
func (s *Server) workerAction(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad worker id")
		return
	}
	action := chi.URLParam(r, "action")
	var status domain.WorkerStatus
	switch action {
	case "approve", "resume":
		status = domain.WorkerActive
	case "drain":
		status = domain.WorkerDraining
	case "quarantine":
		status = domain.WorkerQuarantined
	case "revoke":
		status = domain.WorkerRevoked
	default:
		writeErr(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err := s.st.SetWorkerStatus(r.Context(), id, status); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "worker."+action, id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": string(status)})
}

// deleteWorker removes a worker from the fleet. For a local worker the backing
// container is destroyed first, otherwise it would simply re-enroll and
// reappear moments later.
func (s *Server) deleteWorker(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad worker id")
		return
	}
	worker, _, err := s.st.WorkerForAuth(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "worker not found")
		return
	}
	if worker.Kind == string(scanproto.KindLocal) {
		if err := newProvisionClient().removeContainer(worker.Name); err != nil {
			// Not fatal: the row still goes, and the container may already be gone.
			writeJSON(w, http.StatusAccepted, map[string]any{
				"deleted": false,
				"warning": "could not remove the container: " + err.Error() +
					" — delete the worker again once the provisioner is reachable, or remove it with docker rm",
			})
			return
		}
	}
	if err := s.st.DeleteWorker(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "worker.delete", id.String(),
		map[string]any{"name": worker.Name, "kind": worker.Kind})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

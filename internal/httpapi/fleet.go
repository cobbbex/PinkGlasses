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

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// Remote workers belong to the account that brought them up: only it sees
// them, and only its runs are sent to them. An administrator sees all of them,
// with the owner named, so a compromised machine can be drained or revoked —
// but scans only from its own, like anyone else.

// workerViewer is whose remote workers the requester sees: nil for every
// account's (an administrator).
func workerViewer(r *http.Request) *uuid.UUID {
	if currentUser(r).Role == auth.RoleAdmin {
		return nil
	}
	if id := userIDOf(r); id != nil {
		return id
	}
	none := uuid.Nil
	return &none
}

// mayManageWorker says whether the requester may act on a worker: a shared
// local worker, any operator; a remote one, its owner or an administrator.
func mayManageWorker(r *http.Request, wk domain.Worker) bool {
	if currentUser(r).Role == auth.RoleAdmin {
		return true
	}
	if wk.OwnerID == nil {
		return wk.Kind == string(scanproto.KindLocal)
	}
	uid := userIDOf(r)
	return uid != nil && *uid == *wk.OwnerID
}

// ownsPool checks that a pool named in a request is the requester's own.
// Another account's pool is reported as not found.
func (s *Server) ownsPool(r *http.Request, id uuid.UUID) *exitErr {
	uid := userIDOf(r)
	if uid == nil {
		return &exitErr{http.StatusUnauthorized, "sign in to continue"}
	}
	_, ok, err := s.st.GetExitPool(r.Context(), id, *uid)
	if err != nil {
		return &exitErr{http.StatusInternalServerError, err.Error()}
	}
	if !ok {
		return &exitErr{http.StatusNotFound, "that pool is not one of yours (or no longer exists): remote workers and their pools belong to the account that added them"}
	}
	return nil
}

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListWorkers(r.Context(), workerViewer(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// createEnrollmentToken mints a token and returns the command the user runs to
// bring the worker up. Two flows share one mechanism (wiki/Architecture.md §7.1):
//
//	local — a container beside the control plane. Multi-use bootstrap token,
//	        self-enrolls, auto-approved. Scans from your own egress address.
//	vps   — a rented box. Single-use short-TTL token, installer script, and a
//	        human must approve it before it can lease any work.
func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind    string `json:"kind"` // "local" | "vps" (default)
		PoolID  string `json:"pool_id"`
		Name    string `json:"name"`
		TTLMins int    `json:"ttl_mins"`
		MaxUses int    `json:"max_uses"`
	}
	_ = readJSON(r, &in)

	kind := in.Kind
	if kind != string(scanproto.KindLocal) {
		kind = string(scanproto.KindVPS)
	}

	// --- local: nothing to enrol by hand. The standing worker service enrols
	// itself with the bootstrap token, and a run's own workers are built and
	// enrolled by the scheduler for the life of that run.
	if kind == string(scanproto.KindLocal) {
		writeErr(w, http.StatusBadRequest, "local workers are not enrolled by hand: the standing worker "+
			"service enrols itself, and an active scan builds its own workers for the run")
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

	// The worker is the requester's: it enrols into one of their pools —
	// the one named, or their own "remote" pool — and nobody else sees it or
	// sends it work.
	uid := userIDOf(r)
	if uid == nil {
		writeErr(w, http.StatusUnauthorized, "sign in to continue: a remote worker belongs to the account that adds it")
		return
	}
	var poolID uuid.UUID
	if in.PoolID != "" {
		id, err := uuid.Parse(in.PoolID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad pool_id")
			return
		}
		if e := s.ownsPool(r, id); e != nil {
			writeErr(w, e.status, e.msg)
			return
		}
		poolID = id
	} else {
		id, err := s.st.OwnPool(r.Context(), *uid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		poolID = id
	}

	if _, err := s.st.CreateEnrollmentToken(r.Context(), sum[:], &poolID, uid, ttl, maxUses, kind); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "worker.enroll_token", "", map[string]any{"ttl": ttl.String(), "kind": kind})

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
		"note":            "Run this on the VPS, then approve the worker in the fleet list. It is yours: only you see it, and only your scans run on it.",
	})
}

// itoa is a tiny int-to-string helper (avoids importing strconv here).
// listFleets is the Workers page's view of runs' own containers: the VPN
// gateway (never a worker, so listed nowhere else) and the workers beside it.
func (s *Server) listFleets(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListFleetViews(r.Context(), viewerOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

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
	wk, _, err := s.st.WorkerForAuth(r.Context(), id)
	if err != nil || !mayManageWorker(r, wk) {
		writeErr(w, http.StatusNotFound, "worker not found")
		return
	}
	if err := s.st.SetWorkerStatus(r.Context(), id, status); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "worker."+action, id.String(), nil)
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
	if err != nil || !mayManageWorker(r, worker) {
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
	s.auditReq(r, "worker.delete", id.String(),
		map[string]any{"name": worker.Name, "kind": worker.Kind})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

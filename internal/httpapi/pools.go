package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// listPools returns the requester's own pools — the ones a run of theirs may
// choose as its remote exit — with live worker counts so the launch dialog
// can say which ones can actually run something. Another account's pools are
// never listed, an administrator's request included: those are for that
// account's scans only.
func (s *Server) listPools(w http.ResponseWriter, r *http.Request) {
	uid := userIDOf(r)
	if uid == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	list, err := s.st.ListExitPools(r.Context(), *uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// patchPool marks one of the requester's pools as taking their runs'
// discovery work, or stops it. Discovery never touches a target, so this is
// about where the load sits, not about what a scan is allowed to reach; it
// moves only this account's discovery, never another's.
func (s *Server) patchPool(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "poolID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad pool id")
		return
	}
	var in struct {
		TakesDiscovery *bool `json:"takes_discovery"`
	}
	if err := readJSON(r, &in); err != nil || in.TakesDiscovery == nil {
		writeErr(w, http.StatusBadRequest, "takes_discovery required")
		return
	}
	uid := userIDOf(r)
	if uid == nil {
		writeErr(w, http.StatusUnauthorized, "sign in to continue")
		return
	}
	ok, err := s.st.SetPoolTakesDiscovery(r.Context(), id, *uid, *in.TakesDiscovery)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such pool of yours (another account's pool, a shared one or a run's own cannot be changed)")
		return
	}
	s.auditReq(r, "pool.discovery", id.String(), map[string]any{"takes_discovery": *in.TakesDiscovery})
	writeJSON(w, http.StatusOK, map[string]bool{"takes_discovery": *in.TakesDiscovery})
}

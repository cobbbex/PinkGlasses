package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// listPools returns the pools a run may choose as its remote exit, with live
// worker counts so the launch dialog can say which ones can actually run
// something.
func (s *Server) listPools(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListExitPools(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// patchPool marks a pool as taking discovery work, or stops it. Discovery
// never touches a target, so this is about where the load sits, not about
// what a scan is allowed to reach.
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
	ok, err := s.st.SetPoolTakesDiscovery(r.Context(), id, *in.TakesDiscovery)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such pool (a run's own pool cannot be changed)")
		return
	}
	s.auditReq(r, "pool.discovery", id.String(), map[string]any{"takes_discovery": *in.TakesDiscovery})
	writeJSON(w, http.StatusOK, map[string]bool{"takes_discovery": *in.TakesDiscovery})
}

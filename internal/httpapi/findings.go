package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	q := r.URL.Query()
	list, err := s.st.ListFindings(r.Context(), scopeID, q.Get("status"), q.Get("severity"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) patchFinding(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "findingID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if err := readJSON(r, &in); err != nil || in.Status == "" {
		writeErr(w, http.StatusBadRequest, "status required")
		return
	}
	switch in.Status {
	case "open", "acknowledged", "resolved", "accepted_risk":
	default:
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	if err := s.st.SetFindingStatus(r.Context(), id, in.Status); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "finding.status", id.String(), map[string]any{"status": in.Status})
	writeJSON(w, http.StatusOK, map[string]string{"status": in.Status})
}

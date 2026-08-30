package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/scanparams"
	"github.com/benlik386/asm/internal/store"
)

// listScanParamSpecs returns the settable parameters and their bounds, so the
// UI can render an editor that only offers valid options.
func (s *Server) listScanParamSpecs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, scanparams.Specs)
}

func (s *Server) listScanProfiles(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListScanProfiles(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) saveScanProfile(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Name    string            `json:"name"`
		Params  map[string]string `json:"params"`
		Global  bool              `json:"global"`
		Default bool              `json:"default"`
	}
	if err := readJSON(r, &in); err != nil || in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name and params required")
		return
	}
	// Whitelist + validate before anything is stored (Phase 15.7).
	clean, err := scanparams.Validate(in.Params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid parameter: "+err.Error())
		return
	}
	owner := actor(r)
	p := store.ScanProfile{Name: in.Name, Owner: &owner, Params: clean, IsDefault: in.Default}
	if !in.Global {
		p.ScopeID = &scopeID
	}
	id, err := s.st.SaveScanProfile(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), owner, "scanprofile.save", id.String(), map[string]any{"name": in.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/domain"
)

func (s *Server) createScope(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil || in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	sc, err := s.st.CreateScope(r.Context(), in.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "scope.create", sc.ID.String(), map[string]any{"name": sc.Name})
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListScopes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) scopeSummary(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	sum, err := s.st.Summary(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) addTarget(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Kind         string   `json:"kind"`
		Value        string   `json:"value"`
		Values       []string `json:"values"` // bulk import
		Tags         []string `json:"tags"`
		Mode         string   `json:"mode"`
		Authorize    bool     `json:"authorize"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	values := in.Values
	if in.Value != "" {
		values = append(values, in.Value)
	}
	if len(values) == 0 {
		writeErr(w, http.StatusBadRequest, "value or values required")
		return
	}
	mode := domain.TargetMode(in.Mode)
	if mode == "" {
		mode = domain.ModePassiveOnly
	}
	var authBy *string
	var authAt *time.Time
	if in.Authorize && mode == domain.ModeActive {
		a := actor(r)
		now := time.Now()
		authBy = &a
		authAt = &now
	}
	var out []domain.ScopeTarget
	for _, v := range values {
		kind := in.Kind
		if kind == "" {
			kind = guessKind(v)
		}
		t := domain.ScopeTarget{
			ScopeID: scopeID, Kind: kind, Value: v, Tags: in.Tags, Mode: mode,
			AuthorizedBy: authBy, AuthorizedAt: authAt,
		}
		saved, err := s.st.AddTarget(r.Context(), t)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, saved)
	}
	s.audit.Log(r.Context(), actor(r), "target.add", scopeID.String(), map[string]any{"count": len(out)})
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListTargets(r.Context(), scopeID, r.URL.Query().Get("tag"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

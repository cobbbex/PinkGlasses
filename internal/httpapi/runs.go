package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/domain"
	"github.com/benlik386/asm/internal/scanparams"
)

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Profile   string            `json:"profile"`
		Targets   []string          `json:"targets"` // explicit values; empty + Tag/All below
		Tag       string            `json:"tag"`
		All       bool              `json:"all"`
		ProfileID string            `json:"profile_id"` // saved preset
		Params    map[string]string `json:"params"`     // ad-hoc overrides
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	profile := domain.RunProfile(in.Profile)
	if profile == "" {
		profile = domain.ProfileStandard
	}

	// Resolve the target set from scope targets (never scan exclude-mode ones).
	scopeTargets, err := s.st.ListTargets(r.Context(), scopeID, in.Tag)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	want := map[string]bool{}
	for _, v := range in.Targets {
		want[v] = true
	}
	var runTargets []domain.RunTarget
	for _, t := range scopeTargets {
		if t.Mode == domain.ModeExclude {
			continue
		}
		if in.All || in.Tag != "" || want[t.Value] {
			runTargets = append(runTargets, domain.RunTarget{Kind: t.Kind, Value: t.Value})
		}
	}
	if len(runTargets) == 0 {
		writeErr(w, http.StatusBadRequest, "no matching targets (use all=true, a tag, or explicit targets)")
		return
	}

	// Resolve scan parameters: a saved preset (if any) overlaid with ad-hoc
	// overrides, then whitelisted + validated (Phase 15.7) before use.
	rawParams := map[string]string{}
	var profileID *uuid.UUID
	if in.ProfileID != "" {
		if id, err := uuid.Parse(in.ProfileID); err == nil {
			if pp, err := s.st.GetScanProfileParams(r.Context(), id); err == nil {
				rawParams = pp
				profileID = &id
			}
		}
	}
	for k, v := range in.Params {
		rawParams[k] = v
	}
	cleanParams, err := scanparams.Validate(rawParams)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid scan parameter: "+err.Error())
		return
	}
	effective := scanparams.WithDefaults(cleanParams)

	run := domain.ScanRun{ScopeID: scopeID, Profile: profile, Trigger: "manual", MaxConcurrency: 32}
	run, saved, err := s.st.CreateRun(r.Context(), run, runTargets)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.st.SetRunParams(r.Context(), run.ID, profileID, effective); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Plan the initial stage synchronously so tasks exist immediately; the
	// scheduler drives it forward from there.
	if err := s.planner.PlanInitial(r.Context(), run, saved, scopeTargets); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "run.create", run.ID.String(),
		map[string]any{"profile": profile, "targets": len(saved)})
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListRuns(r.Context(), scopeID, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	prog, _ := s.st.RunProgress(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "progress": prog})
}

func (s *Server) runTargets(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	list, err := s.st.ListRunTargets(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "runID")
	s.hub.stream(w, r, id)
}

func (s *Server) runDiff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	events, err := s.st.ListChangeEvents(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	if err := s.st.CancelRunTasks(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.st.SetRunStatus(r.Context(), id, domain.RunCancelled)
	s.audit.Log(r.Context(), actor(r), "run.cancel", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

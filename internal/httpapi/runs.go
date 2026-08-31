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
		WordlistIDs []string        `json:"wordlist_ids"` // DNS bruteforce lists; empty = the defaults
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
		// Distinguish "this scope is empty" from "your filter matched nothing".
		// The first is by far the common case and the fix is completely
		// different, so saying which one it is matters.
		all, _ := s.st.ListTargets(r.Context(), scopeID, "")
		usable := 0
		for _, t := range all {
			if t.Mode != domain.ModeExclude {
				usable++
			}
		}
		switch {
		case usable == 0:
			writeErr(w, http.StatusBadRequest,
				"this scope has no targets yet — add a domain or CIDR on the Dashboard before scanning")
		case in.Tag != "":
			writeErr(w, http.StatusBadRequest,
				"no targets carry the tag \""+in.Tag+"\"")
		default:
			writeErr(w, http.StatusBadRequest,
				"none of the selected targets are in this scope")
		}
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
	// Which wordlists this run brute-forces with. An empty selection means the
	// registry defaults, so a standard scan picks up the shipped assetnote
	// lists without the caller having to name them.
	var wlIDs []uuid.UUID
	for _, raw := range in.WordlistIDs {
		if id, err := uuid.Parse(raw); err == nil {
			wlIDs = append(wlIDs, id)
		}
	}
	if len(wlIDs) == 0 {
		for _, kind := range []string{"dns", "resolvers"} {
			if defs, err := s.st.DefaultWordlists(r.Context(), kind); err == nil {
				for _, d := range defs {
					wlIDs = append(wlIDs, d.ID)
				}
			}
		}
	} else if res, err := s.st.DefaultWordlists(r.Context(), "resolvers"); err == nil {
		// An explicit wordlist choice still needs resolvers to brute-force with.
		for _, d := range res {
			wlIDs = append(wlIDs, d.ID)
		}
	}
	if err := s.st.SetRunWordlists(r.Context(), run.ID, wlIDs); err != nil {
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

// runActivity answers "which workers are on this scan, and what are they doing".
func (s *Server) runActivity(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	acts, err := s.st.RunActivity(r.Context(), id, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	stages, err := s.st.RunStages(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Roll the tasks up per worker so the caller does not have to.
	type workerBusy struct {
		Name    string   `json:"name"`
		Kind    string   `json:"kind"`
		Running int      `json:"running"`
		Done    int      `json:"done"`
		Stages  []string `json:"stages"`
	}
	byWorker := map[string]*workerBusy{}
	seenStage := map[string]bool{}
	for _, a := range acts {
		if a.WorkerName == nil {
			continue
		}
		wb := byWorker[*a.WorkerName]
		if wb == nil {
			kind := ""
			if a.WorkerKind != nil {
				kind = *a.WorkerKind
			}
			wb = &workerBusy{Name: *a.WorkerName, Kind: kind}
			byWorker[*a.WorkerName] = wb
		}
		switch a.Status {
		case "running", "leased":
			wb.Running++
			if k := *a.WorkerName + "|" + a.Stage; !seenStage[k] {
				seenStage[k] = true
				wb.Stages = append(wb.Stages, a.Stage)
			}
		case "done":
			wb.Done++
		}
	}
	workers := []workerBusy{}
	for _, wb := range byWorker {
		workers = append(workers, *wb)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tasks": acts, "stages": stages, "workers": workers,
	})
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

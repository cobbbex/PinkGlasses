package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/launch"
)

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Profile     string            `json:"profile"`
		Targets     []string          `json:"targets"`
		Tag         string            `json:"tag"`
		All         bool              `json:"all"`
		ProfileID   string            `json:"profile_id"`
		Params      map[string]string `json:"params"`
		WordlistIDs []string          `json:"wordlist_ids"`
		// Exit is where the run's active stages leave from — "local" with a
		// VPNConfigID, or "remote" with a PoolID. A passive run needs neither
		// (architecture.md §7.6).
		Exit        string `json:"exit"`
		VPNConfigID string `json:"vpn_config_id"`
		PoolID      string `json:"pool_id"`
		WorkerCount int    `json:"worker_count"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	// One way to start a run, shared with the scheduler, so a scheduled run is
	// refused for exactly the reasons a manual one would be.
	run, ref := s.launcher.Start(r.Context(), scopeID, launch.Options{
		Profile: in.Profile, Targets: in.Targets, Tag: in.Tag, All: in.All,
		ProfileID: in.ProfileID, Params: in.Params, WordlistIDs: in.WordlistIDs,
		Exit: in.Exit, VPNConfigID: in.VPNConfigID, PoolID: in.PoolID, WorkerCount: in.WorkerCount,
		Trigger: "manual",
	})
	if ref != nil {
		writeErr(w, ref.Status, ref.Msg)
		return
	}
	s.auditReq(r, "run.create", run.ID.String(), map[string]any{"profile": run.Profile})
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListRunSummaries(r.Context(), scopeID, 50)
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
	out := map[string]any{"run": run, "progress": prog}
	// A run with its own containers carries its explanation here and nowhere
	// else: scan_run has no error column, so a fleet that failed to come up is
	// the only record of why the run did. The enrollment token is not part of
	// the JSON (see store.RunFleet).
	if f, ok, err := s.st.GetRunFleet(r.Context(), id); err == nil && ok {
		out["fleet"] = f
	}
	writeJSON(w, http.StatusOK, out)
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
			// Stages is filled only from running tasks, so a worker whose
			// work has all finished would serialize as null and break a
			// caller reading its length — which is every run, at the end.
			wb = &workerBusy{Name: *a.WorkerName, Kind: kind, Stages: []string{}}
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

// pauseRun holds a running run: nothing more is leased, what is in flight
// finishes, the run's own containers stay up. Only a running run can pause.
func (s *Server) pauseRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	ok, err := s.st.PauseRun(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "only a running run can be paused")
		return
	}
	s.auditReq(r, "run.pause", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

// resumeRun lets a paused run continue where it stopped.
func (s *Server) resumeRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	ok, err := s.st.ResumeRun(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "only a paused run can be resumed")
		return
	}
	s.auditReq(r, "run.resume", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
}

// rerunRun starts a new run with an old one's choices — profile, parameters,
// wordlists, exit — through the same path a fresh click takes, so it is
// refused for the same reasons (a VPN config since removed, an emptied pool).
func (s *Server) rerunRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad run id")
		return
	}
	sp, err := s.st.RerunSpec(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	o := launch.Options{Profile: sp.Profile, All: true, Params: sp.Params, Exit: sp.Exit, WorkerCount: sp.Workers, Trigger: "manual"}
	if sp.ProfileID != nil {
		o.ProfileID = sp.ProfileID.String()
	}
	for _, w := range sp.WordlistIDs {
		o.WordlistIDs = append(o.WordlistIDs, w.String())
	}
	switch sp.Exit {
	case "local":
		if sp.VPNConfigID == nil {
			writeErr(w, http.StatusConflict, "that run scanned through a VPN configuration that has since been removed; start a new scan and pick another")
			return
		}
		o.VPNConfigID = sp.VPNConfigID.String()
	case "remote":
		o.PoolID = sp.PoolID.String()
	}
	run, ref := s.launcher.Start(r.Context(), sp.ScopeID, o)
	if ref != nil {
		writeErr(w, ref.Status, ref.Msg)
		return
	}
	s.auditReq(r, "run.rerun", run.ID.String(), map[string]any{"of": id.String(), "profile": run.Profile})
	writeJSON(w, http.StatusCreated, run)
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
	s.auditReq(r, "run.cancel", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

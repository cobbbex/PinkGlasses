package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/scanparams"
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
		// Lists of any kind. A kind not named here falls back to its defaults.
		WordlistIDs []string `json:"wordlist_ids"`
		// VPNConfigID routes this run's traffic through a tunnel.
		VPNConfigID string `json:"vpn_config_id"`
		// OwnWorkers asks for containers brought up for this run alone and
		// destroyed with it. Implied by choosing a VPN: the tunnel lives in a
		// gateway container the run's workers share a namespace with.
		OwnWorkers  bool `json:"own_workers"`
		WorkerCount int  `json:"worker_count"`
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
	// Which lists this run uses. A caller may name lists of any kind; every kind
	// it stays silent about falls back to the registry defaults, so a plain scan
	// needs no wordlist knowledge at all while a manual one can override just
	// the subdomain lists and leave resolvers alone.
	chosen := map[string]bool{}
	var wlIDs []uuid.UUID
	for _, raw := range in.WordlistIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		wl, err := s.st.GetWordlist(r.Context(), id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unknown wordlist "+raw)
			return
		}
		if wl.Status != "ready" {
			writeErr(w, http.StatusBadRequest,
				"wordlist \""+wl.Name+"\" is not ready ("+wl.Status+")")
			return
		}
		chosen[wl.Kind] = true
		wlIDs = append(wlIDs, id)
	}
	for _, kind := range []string{"dns", "resolvers", "dir"} {
		if chosen[kind] {
			continue
		}
		if defs, err := s.st.DefaultWordlists(r.Context(), kind); err == nil {
			for _, d := range defs {
				wlIDs = append(wlIDs, d.ID)
			}
		}
	}
	if err := s.st.SetRunWordlists(r.Context(), run.ID, wlIDs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var vpnID *uuid.UUID
	if in.VPNConfigID != "" {
		parsed, err := uuid.Parse(in.VPNConfigID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad vpn config id")
			return
		}
		vpnID = &parsed
		vc, err := s.st.GetVPNConfig(r.Context(), *vpnID)
		if err != nil || vc.ScopeID != scopeID {
			writeErr(w, http.StatusBadRequest, "unknown vpn config")
			return
		}
		if err := s.st.SetRunVPN(r.Context(), run.ID, *vpnID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// A run with its own fleet gets a pool nothing else can lease from, and an
	// enrollment token bound to it. That is all the routing needs: the lease
	// query already refuses to give a pooled worker another run's tasks.
	//
	// A tunnel implies a fleet, because the tunnel lives in a gateway container
	// the run's own workers share a namespace with — except where there is no
	// provisioner to build one. There the older path still works: the run's
	// traffic tasks demand the `vpn` capability and are leased by a worker
	// privileged to raise the tunnel itself (architecture.md §7.6).
	prov := newProvisionClient().enabled()
	if in.OwnWorkers && !prov {
		writeErr(w, http.StatusBadRequest,
			"this run asked for workers of its own, but no provisioner is configured "+
				"to create them: set ASM_PROVISIONER_URL and ASM_PROVISIONER_TOKEN")
		return
	}
	if in.OwnWorkers || (in.VPNConfigID != "" && prov) {
		if err := s.requestRunFleet(r.Context(), run, in.WorkerCount, vpnID); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not request workers for this run: "+err.Error())
			return
		}
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
	s.auditReq(r, "run.create", run.ID.String(),
		map[string]any{"profile": profile, "targets": len(saved)})
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

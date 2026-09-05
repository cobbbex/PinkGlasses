package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/store"
)

// Recurring scans: a schedule per company, started by the scheduler through the
// same code a person's click uses.

type scheduleInput struct {
	Profile     string  `json:"profile"`
	Exit        string  `json:"exit"`
	VPNConfigID *string `json:"vpn_config_id"`
	PoolID      *string `json:"pool_id"`
	WorkerCount int     `json:"worker_count"`
	EveryHours  int     `json:"every_hours"`
	Enabled     *bool   `json:"enabled"`
}

func (in scheduleInput) apply(sc *store.Schedule) *exitErr {
	if in.Profile != "" {
		sc.Profile = in.Profile
	}
	if sc.Profile == "" {
		sc.Profile = "standard"
	}
	switch in.Exit {
	case "", "local", "remote":
		sc.Exit = in.Exit
	default:
		return &exitErr{http.StatusBadRequest, "exit must be \"local\", \"remote\" or empty for a passive profile"}
	}
	if sc.Profile != "passive" && sc.Exit == "" {
		return &exitErr{http.StatusBadRequest, "a scheduled " + sc.Profile + " scan sends traffic at its targets and needs an exit: local (with a VPN config) or remote (with a pool)"}
	}
	sc.VPNConfigID, sc.PoolID = nil, nil
	if in.VPNConfigID != nil && *in.VPNConfigID != "" {
		id, err := uuid.Parse(*in.VPNConfigID)
		if err != nil {
			return &exitErr{http.StatusBadRequest, "bad vpn config id"}
		}
		sc.VPNConfigID = &id
	}
	if in.PoolID != nil && *in.PoolID != "" {
		id, err := uuid.Parse(*in.PoolID)
		if err != nil {
			return &exitErr{http.StatusBadRequest, "bad pool id"}
		}
		sc.PoolID = &id
	}
	if sc.Exit == "local" && sc.VPNConfigID == nil {
		return &exitErr{http.StatusBadRequest, "a local exit needs vpn_config_id"}
	}
	if sc.Exit == "remote" && sc.PoolID == nil {
		return &exitErr{http.StatusBadRequest, "a remote exit needs pool_id"}
	}
	if in.WorkerCount > 0 {
		sc.WorkerCount = in.WorkerCount
	}
	if sc.WorkerCount <= 0 {
		sc.WorkerCount = 2
	}
	if sc.WorkerCount > 8 {
		return &exitErr{http.StatusBadRequest, "worker_count is at most 8"}
	}
	if in.EveryHours > 0 {
		sc.EveryHours = in.EveryHours
	}
	if sc.EveryHours < 1 {
		return &exitErr{http.StatusBadRequest, "every_hours must be at least 1"}
	}
	if in.Enabled != nil {
		sc.Enabled = *in.Enabled
	}
	return nil
}

type exitErr struct {
	status int
	msg    string
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListSchedules(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in scheduleInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	sc := store.Schedule{ScopeID: scopeID, Enabled: true}
	if e := in.apply(&sc); e != nil {
		writeErr(w, e.status, e.msg)
		return
	}
	saved, err := s.st.CreateSchedule(r.Context(), sc, userIDOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "schedule.create", saved.ID.String(),
		map[string]any{"profile": saved.Profile, "exit": saved.Exit, "every_hours": saved.EveryHours})
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) patchSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scheduleID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad schedule id")
		return
	}
	sc, err := s.st.GetSchedule(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "schedule not found")
		return
	}
	var in scheduleInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	// A patch that names no exit keeps the current one.
	if in.Exit == "" {
		in.Exit = sc.Exit
		if in.VPNConfigID == nil && sc.VPNConfigID != nil {
			v := sc.VPNConfigID.String()
			in.VPNConfigID = &v
		}
		if in.PoolID == nil && sc.PoolID != nil {
			v := sc.PoolID.String()
			in.PoolID = &v
		}
	}
	if e := in.apply(&sc); e != nil {
		writeErr(w, e.status, e.msg)
		return
	}
	saved, err := s.st.UpdateSchedule(r.Context(), sc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "schedule.update", id.String(), map[string]any{"enabled": saved.Enabled, "every_hours": saved.EveryHours})
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scheduleID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad schedule id")
		return
	}
	ok, err := s.st.DeleteSchedule(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "schedule not found")
		return
	}
	s.auditReq(r, "schedule.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// patchScope sets a company's default exit — what its schedules use and what
// the launch dialog pre-selects.
func (s *Server) patchScope(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		DefaultExit        string  `json:"default_exit"`
		DefaultVPNConfigID *string `json:"default_vpn_config_id"`
		DefaultPoolID      *string `json:"default_pool_id"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	switch in.DefaultExit {
	case "", "local", "remote":
	default:
		writeErr(w, http.StatusBadRequest, "default_exit must be \"local\", \"remote\" or empty")
		return
	}
	var vpnID, poolID *uuid.UUID
	if in.DefaultVPNConfigID != nil && *in.DefaultVPNConfigID != "" {
		id, err := uuid.Parse(*in.DefaultVPNConfigID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad vpn config id")
			return
		}
		vpnID = &id
	}
	if in.DefaultPoolID != nil && *in.DefaultPoolID != "" {
		id, err := uuid.Parse(*in.DefaultPoolID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad pool id")
			return
		}
		poolID = &id
	}
	if err := s.st.SetScopeDefaults(r.Context(), scopeID, in.DefaultExit, vpnID, poolID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "scope.defaults", scopeID.String(), map[string]any{"default_exit": in.DefaultExit})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

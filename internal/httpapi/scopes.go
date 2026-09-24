package httpapi

import (
	"errors"
	"github.com/benlik386/pinkglasses/internal/auth"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

func (s *Server) createScope(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		// Private: only the creator, and the accounts they share it with.
		Private bool `json:"private"`
	}
	if err := readJSON(r, &in); err != nil || in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	vis := "shared"
	if in.Private {
		if userIDOf(r) == nil {
			writeErr(w, http.StatusBadRequest, "a private company needs an account to belong to")
			return
		}
		vis = "private"
	}
	sc, err := s.st.CreateScope(r.Context(), in.Name, actor(r), userIDOf(r), vis)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "scope.create", sc.ID.String(), map[string]any{"name": sc.Name, "visibility": sc.Visibility})
	writeJSON(w, http.StatusCreated, sc)
}

// scopeFootprint says what a company owns, so the delete confirmation can
// list it and say what stands in the way.
func (s *Server) scopeFootprint(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	f, ok, err := s.st.ScopeFootprint(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "company not found")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// deleteScope removes a company with everything it owns. Refused while a run
// of it is going or its own containers are still up — stop those first — so
// nothing is left scanning on behalf of a company that no longer exists.
// Screenshots and raw output of its runs are removed from object storage
// after the rows, best effort.
func (s *Server) deleteScope(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	// A shared company is everyone's, so deleting it is an administrator's
	// call; a private one is its owner's (or an administrator's once the
	// owner's account is gone).
	if sc, err := s.st.GetScope(r.Context(), scopeID); err == nil {
		if sc.Visibility == "private" {
			if ok, _ := s.canManageAccess(r, scopeID); !ok {
				writeErr(w, http.StatusForbidden, "only the owner of a private company can delete it")
				return
			}
		} else if currentUser(r).Role != auth.RoleAdmin {
			writeErr(w, http.StatusForbidden, "deleting a shared company needs the admin role")
			return
		}
	}
	f, ok, err := s.st.ScopeFootprint(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "company not found")
		return
	}
	if f.ActiveRuns > 0 || f.LiveFleets > 0 {
		writeErr(w, http.StatusConflict, "the company still has a run going; stop it before deleting the company")
		return
	}
	keys, err := s.st.ScopeArtifactKeys(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ok, err := s.st.DeleteScope(r.Context(), scopeID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeErr(w, http.StatusNotFound, "company not found")
		return
	}
	removed, failed := 0, 0
	for _, k := range keys {
		if err := s.obj.Delete(r.Context(), k); err != nil {
			failed++
			slog.Warn("could not remove a deleted company's artifact", "scope", scopeID, "key", k, "err", err)
			continue
		}
		removed++
	}
	s.auditReq(r, "scope.delete", scopeID.String(), map[string]any{
		"name": f.Name, "runs": f.Runs, "hosts": f.Hosts, "findings": f.Findings,
		"artifacts_removed": removed, "artifacts_failed": failed})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "artifacts_removed": removed, "artifacts_failed": failed})
}

// listScopes returns every company, or only the caller's own with ?mine=true.
//
// "Own" means created by the same actor, which today is whatever
// X-Forwarded-User says or "local" — so this narrows a shared list, it does not
// protect anything. Until Phase 17 verifies identity, a caller can see any
// company by simply not asking for the filter.
func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) {
	owner := ""
	if r.URL.Query().Get("mine") == "true" {
		owner = actor(r)
	}
	list, err := s.st.ListScopes(r.Context(), owner, viewerOf(r))
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

// patchTarget edits a target: the host or range itself (a typo fixed in place,
// kind re-detected), its mode, tags and authorization. Authorization is
// explicit: a switch to active carries authorize:true to be recorded as
// authorized; any other mode clears the record, since it no longer means
// anything.
func (s *Server) patchTarget(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "targetID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad target id")
		return
	}
	var in struct {
		Value     *string  `json:"value"`
		Mode      *string  `json:"mode"`
		Tags      []string `json:"tags"`
		Authorize *bool    `json:"authorize"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	cur, ok, err := s.st.GetTarget(r.Context(), scopeID, targetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "target not found in this company")
		return
	}
	kind, value := cur.Kind, cur.Value
	if in.Value != nil {
		v := strings.TrimSpace(strings.ToLower(*in.Value))
		if v == "" {
			writeErr(w, http.StatusBadRequest, "value cannot be empty")
			return
		}
		if v != cur.Value {
			value, kind = v, guessKind(v)
		}
	}
	mode := cur.Mode
	if in.Mode != nil {
		switch domain.TargetMode(*in.Mode) {
		case domain.ModeActive, domain.ModePassiveOnly, domain.ModeExclude:
			mode = domain.TargetMode(*in.Mode)
		default:
			writeErr(w, http.StatusBadRequest, "mode must be active, passive_only or exclude")
			return
		}
	}
	tags := cur.Tags
	if in.Tags != nil {
		tags = in.Tags
	}
	authBy, authAt := cur.AuthorizedBy, cur.AuthorizedAt
	switch {
	case mode != domain.ModeActive:
		authBy, authAt = nil, nil
	case in.Authorize != nil && *in.Authorize:
		a := actor(r)
		now := time.Now()
		authBy, authAt = &a, &now
	case in.Authorize != nil && !*in.Authorize:
		authBy, authAt = nil, nil
	}
	t, ok, err := s.st.UpdateTarget(r.Context(), scopeID, targetID, kind, value, mode, tags, authBy, authAt)
	if errors.Is(err, store.ErrTargetExists) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "target not found in this company")
		return
	}
	detail := map[string]any{"value": t.Value, "mode": string(t.Mode), "authorized": t.Authorized(), "tags": t.Tags}
	if t.Value != cur.Value {
		detail["was"] = cur.Value
	}
	s.auditReq(r, "target.update", targetID.String(), detail)
	writeJSON(w, http.StatusOK, t)
}

// deleteTarget takes a target out of a company. Future runs no longer cover it;
// what earlier runs found under it stays in the inventory.
func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "targetID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad target id")
		return
	}
	ok, err := s.st.DeleteTarget(r.Context(), scopeID, targetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "target not found in this company")
		return
	}
	s.auditReq(r, "target.delete", targetID.String(), map[string]any{"scope_id": scopeID.String()})
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) addTarget(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Kind      string   `json:"kind"`
		Value     string   `json:"value"`
		Values    []string `json:"values"` // bulk import
		Tags      []string `json:"tags"`
		Mode      string   `json:"mode"`
		Authorize bool     `json:"authorize"`
		// Group names the group the values join, created if needed; without
		// it each value is a group of its own, named after itself.
		Group string `json:"group"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	values := in.Values
	if in.Value != "" {
		values = append(values, in.Value)
	}
	values = cleanValues(values)
	if len(values) == 0 {
		writeErr(w, http.StatusBadRequest, "value or values required")
		return
	}
	authorize := in.Authorize && (in.Mode == "" || domain.TargetMode(in.Mode) == domain.ModeActive)
	var groupID *uuid.UUID
	if g := strings.TrimSpace(in.Group); g != "" {
		id, err := s.st.EnsureTargetGroup(r.Context(), scopeID, g)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		groupID = &id
	}
	out, err := s.addTargetValues(r, scopeID, groupID, values, in.Tags, authorize)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if domain.TargetMode(in.Mode) == domain.ModeExclude {
		for i := range out {
			t, _, err := s.st.UpdateTarget(r.Context(), scopeID, out[i].ID, out[i].Kind, out[i].Value, domain.ModeExclude, out[i].Tags, nil, nil)
			if err == nil {
				out[i] = t
			}
		}
	}
	s.auditReq(r, "target.add", scopeID.String(), map[string]any{"count": len(out), "authorized": authorize})
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

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/auth"
)

// Company access. A company is shared (every account sees it) or private (its
// owner and the accounts it is shared with). Every route that names a company,
// or anything inside one, passes through guard: the company is resolved from
// the route and checked against the requester with the database's
// scope_visible, the same rule the list and search queries use. A company the
// requester may not see answers 404, as if it did not exist, so a private
// company's existence is not given away. API tokens and the MCP server act as
// their account, so they follow the same rule.

// scopeParams maps a route parameter to how its company is found. The first
// parameter present in a route decides; {scopeID} is checked first.
var scopeParams = []struct {
	param string
	query string // "" for {scopeID} itself
	what  string
}{
	{"scopeID", "", "company"},
	{"runID", `SELECT scope_id FROM scan_run WHERE id=$1`, "run"},
	{"scheduleID", `SELECT scope_id FROM scan_schedule WHERE id=$1`, "schedule"},
	{"channelID", `SELECT scope_id FROM notification_channel WHERE id=$1`, "alert channel"},
	{"findingID", `SELECT scope_id FROM finding WHERE id=$1`, "finding"},
	{"ipID", `SELECT scope_id FROM ip_address WHERE id=$1`, "host"},
	{"serviceID", `SELECT ip.scope_id FROM service sv JOIN ip_address ip ON ip.id = sv.ip_id WHERE sv.id=$1`, "service"},
}

type scopeCtxKey struct{}

// guardFor wraps a handler whose route names a company or something in one.
// Routes naming neither are returned unwrapped.
func (s *Server) guardFor(pattern string, h http.HandlerFunc) http.HandlerFunc {
	for _, g := range scopeParams {
		if !strings.Contains(pattern, "{"+g.param+"}") {
			continue
		}
		g := g
		return func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, g.param))
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad "+g.what+" id")
				return
			}
			scopeID := id
			if g.query != "" {
				scopeID, err = s.st.ScopeOfEntity(r.Context(), g.query, id)
				if errors.Is(err, pgx.ErrNoRows) {
					writeErr(w, http.StatusNotFound, g.what+" not found")
					return
				}
				if err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
			ok, err := s.st.ScopeVisibleTo(r.Context(), scopeID, viewerOf(r))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !ok {
				writeErr(w, http.StatusNotFound, g.what+" not found")
				return
			}
			h(w, r.WithContext(context.WithValue(r.Context(), scopeCtxKey{}, scopeID)))
		}
	}
	return h
}

// viewerOf is the requester's account id, or the zero id, which sees shared
// companies only.
func viewerOf(r *http.Request) uuid.UUID {
	if id := userIDOf(r); id != nil {
		return *id
	}
	return uuid.Nil
}

// canManageAccess says whether the requester decides who else sees a company:
// its owner, or an administrator once the owner's account is gone.
func (s *Server) canManageAccess(r *http.Request, scopeID uuid.UUID) (bool, error) {
	sc, err := s.st.GetScope(r.Context(), scopeID)
	if err != nil {
		return false, err
	}
	me := viewerOf(r)
	if sc.OwnerID != nil {
		return *sc.OwnerID == me, nil
	}
	return currentUser(r).Role == auth.RoleAdmin, nil
}

// scopeAccess reports a company's visibility, owner and members.
func (s *Server) scopeAccess(w http.ResponseWriter, r *http.Request) {
	scopeID, _ := uuid.Parse(chi.URLParam(r, "scopeID"))
	sc, err := s.st.GetScope(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "company not found")
		return
	}
	members, err := s.st.ScopeMembers(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	can, _ := s.canManageAccess(r, scopeID)
	writeJSON(w, http.StatusOK, map[string]any{
		"visibility": sc.Visibility, "owner_id": sc.OwnerID, "owner": sc.Owner,
		"members": members, "can_manage": can,
	})
}

// addScopeMember shares a company with an account, by username.
func (s *Server) addScopeMember(w http.ResponseWriter, r *http.Request) {
	scopeID, _ := uuid.Parse(chi.URLParam(r, "scopeID"))
	if ok, err := s.canManageAccess(r, scopeID); err != nil || !ok {
		writeErr(w, http.StatusForbidden, "only the company's owner decides who it is shared with")
		return
	}
	var in struct {
		Username string `json:"username"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Username) == "" {
		writeErr(w, http.StatusBadRequest, "username required")
		return
	}
	u, _, err := s.st.UserByUsername(r.Context(), strings.TrimSpace(in.Username))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no account named \""+strings.TrimSpace(in.Username)+"\"")
		return
	}
	if sc, err := s.st.GetScope(r.Context(), scopeID); err == nil && sc.OwnerID != nil && *sc.OwnerID == u.ID {
		writeErr(w, http.StatusBadRequest, u.Username+" owns this company already")
		return
	}
	if err := s.st.AddScopeMember(r.Context(), scopeID, u.ID, actor(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "scope.share", scopeID.String(), map[string]any{"with": u.Username})
	s.scopeAccess(w, r)
}

// removeScopeMember stops sharing a company with an account. The owner may
// remove anyone; a member may remove themselves.
func (s *Server) removeScopeMember(w http.ResponseWriter, r *http.Request) {
	scopeID, _ := uuid.Parse(chi.URLParam(r, "scopeID"))
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	can, _ := s.canManageAccess(r, scopeID)
	if !can && userID != viewerOf(r) {
		writeErr(w, http.StatusForbidden, "only the company's owner decides who it is shared with")
		return
	}
	ok, err := s.st.RemoveScopeMember(r.Context(), scopeID, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "that account does not have access through sharing")
		return
	}
	s.auditReq(r, "scope.unshare", scopeID.String(), map[string]any{"user": userID.String()})
	writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

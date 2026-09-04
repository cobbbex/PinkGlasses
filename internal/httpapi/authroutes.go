package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/store"
)

// authStatus tells the SPA what to render before anyone has signed in: a login
// form, or the first-run form that creates the first administrator.
//
// It is the one endpoint that answers without authentication, and it says as
// little as possible — whether an account exists, and who you are if you are
// already signed in.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"setup_required": n == 0}
	if id, ok := s.authenticate(r); ok {
		out["user"] = map[string]any{
			"id": id.UserID, "username": id.Username, "role": id.Role, "via": id.Via,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// setup creates the first administrator, and only the first.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := checkUsername(in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auth.CheckPasswordPolicy(in.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// firstOnly makes this conditional on the table still being empty, in the
	// insert itself: two requests arriving together cannot both succeed.
	u, err := s.st.CreateUser(r.Context(), in.Username, in.DisplayName, in.Password, auth.RoleAdmin, nil, true)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	// Everything created before there were accounts says created_by 'local',
	// which names nobody. The person setting the install up inherits it.
	adopted, err := s.st.AdoptOwnerlessScopes(r.Context(), u.ID)
	if err != nil {
		slog.Error("could not assign existing scopes to the first administrator", "err", err)
	}
	s.audit.LogUser(r.Context(), u.ID, u.Username, "user.setup", u.ID.String(),
		map[string]any{"adopted_scopes": adopted})
	s.signIn(w, r, u)
}

// login exchanges a username and password for a session.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	in.Username = strings.TrimSpace(in.Username)

	// Rate limited by username and by source address: limiting one alone is
	// walked around by varying the other.
	ipKey := "ip:" + clientIP(r)
	userKey := "user:" + strings.ToLower(in.Username)
	if !s.logins.allow(ipKey, userKey) {
		writeErr(w, http.StatusTooManyRequests,
			"too many sign-in attempts; wait a few minutes and try again")
		return
	}

	u, hash, err := s.st.UserByUsername(r.Context(), in.Username)
	if err != nil || hash == "" {
		// Same work and the same answer as a wrong password, so neither timing
		// nor wording says whether the account exists.
		auth.VerifyAgainstNothing(in.Password)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	ok, err := auth.VerifyPassword(hash, in.Password)
	if err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if u.Disabled {
		writeErr(w, http.StatusForbidden, "this account is disabled")
		return
	}
	s.logins.succeeded(ipKey, userKey)
	s.st.TouchLogin(r.Context(), u.ID)
	s.audit.LogUser(r.Context(), u.ID, u.Username, "user.login", u.ID.String(), nil)
	s.signIn(w, r, u)
}

func (s *Server) signIn(w http.ResponseWriter, r *http.Request, u store.User) {
	secret, err := s.st.CreateSession(r.Context(), u.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	setSessionCookie(w, r, secret, store.SessionTTL)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

// logout ends this session.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil && c.Value != "" {
		_ = s.st.DeleteSession(r.Context(), c.Value)
	}
	setSessionCookie(w, r, "", 0)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// me returns the signed-in user.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := currentUser(r)
	u, err := s.st.GetUser(r.Context(), id.UserID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "via": id.Via})
}

// changePassword lets a signed-in user replace their own password.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	id := currentUser(r)
	u, hash, err := s.st.UserByUsername(r.Context(), id.Username)
	if err != nil || hash == "" {
		writeErr(w, http.StatusBadRequest, "this account has no password to change")
		return
	}
	// The current password is required even though they are signed in: a
	// borrowed browser should not be enough to take the account over.
	if ok, err := auth.VerifyPassword(hash, in.Current); err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return
	}
	if err := auth.CheckPasswordPolicy(in.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetPassword(r.Context(), u.ID, in.New); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Every other session is dropped; this browser gets a fresh one, so
	// changing your password does not sign you out of the tab you are in.
	_ = s.st.DeleteUserSessions(r.Context(), u.ID)
	s.audit.LogUser(r.Context(), u.ID, u.Username, "user.password_change", u.ID.String(), nil)
	s.signIn(w, r, u)
}

// --- user administration ---

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := checkUsername(in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	role := auth.Role(in.Role)
	if !role.Valid() {
		writeErr(w, http.StatusBadRequest, "role must be admin, operator or viewer")
		return
	}
	if in.Password != "" {
		if err := auth.CheckPasswordPolicy(in.Password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	me := currentUser(r)
	u, err := s.st.CreateUser(r.Context(), in.Username, in.DisplayName, in.Password, role, &me.UserID, false)
	if err != nil {
		status := http.StatusInternalServerError
		if err == store.ErrUsernameTaken {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	s.audit.LogUser(r.Context(), me.UserID, me.Username, "user.create", u.ID.String(),
		map[string]any{"username": u.Username, "role": u.Role})
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	var in struct {
		Username    *string `json:"username"`
		DisplayName *string `json:"display_name"`
		Role        *string `json:"role"`
		Disabled    *bool   `json:"disabled"`
		Password    *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if in.Username != nil {
		v := strings.TrimSpace(*in.Username)
		if err := checkUsername(v); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		in.Username = &v
	}
	var role *auth.Role
	if in.Role != nil {
		v := auth.Role(*in.Role)
		if !v.Valid() {
			writeErr(w, http.StatusBadRequest, "role must be admin, operator or viewer")
			return
		}
		role = &v
	}
	// Refuse to remove the last way in. Demoting or disabling the only
	// administrator would lock everyone out of an install with no recovery
	// path short of editing the database.
	losingAdmin := (role != nil && *role != auth.RoleAdmin) || (in.Disabled != nil && *in.Disabled)
	if losingAdmin {
		if cur, err := s.st.GetUser(r.Context(), id); err == nil && cur.Role == auth.RoleAdmin && !cur.Disabled {
			others, err := s.st.CountAdmins(r.Context(), id)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			if others == 0 {
				writeErr(w, http.StatusConflict,
					"this is the only administrator; promote someone else first")
				return
			}
		}
	}
	if in.Password != nil {
		if err := auth.CheckPasswordPolicy(*in.Password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.st.SetPassword(r.Context(), id, *in.Password); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.st.DeleteUserSessions(r.Context(), id)
	}
	u, err := s.st.UpdateUser(r.Context(), id, in.Username, in.DisplayName, role, in.Disabled)
	if errors.Is(err, store.ErrUsernameTaken) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	me := currentUser(r)
	detail := map[string]any{"role": u.Role, "disabled": u.Disabled, "password_reset": in.Password != nil}
	if in.Username != nil {
		// Worth recording explicitly: after this, the audit trail shows a name
		// that did not exist before, and only the user id ties the two together.
		detail["renamed_to"] = u.Username
	}
	s.audit.LogUser(r.Context(), me.UserID, me.Username, "user.update", id.String(), detail)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	me := currentUser(r)
	if id == me.UserID {
		writeErr(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	if cur, err := s.st.GetUser(r.Context(), id); err == nil && cur.Role == auth.RoleAdmin && !cur.Disabled {
		others, err := s.st.CountAdmins(r.Context(), id)
		if err == nil && others == 0 {
			writeErr(w, http.StatusConflict, "this is the only administrator; promote someone else first")
			return
		}
	}
	ok, err := s.st.DeleteUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	s.audit.LogUser(r.Context(), me.UserID, me.Username, "user.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// --- API tokens ---

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	// An administrator sees every token, because revoking one is their job.
	// Everyone else sees only their own.
	var forUser *uuid.UUID
	if !me.Role.AtLeast(auth.RoleAdmin) {
		forUser = &me.UserID
	}
	list, err := s.st.ListAPITokens(r.Context(), forUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Role    string `json:"role"`
		TTLDays int    `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "give the token a name, so it can be recognised later")
		return
	}
	me := currentUser(r)
	role := auth.Role(in.Role)
	if role == "" {
		role = me.Role
	}
	var ttl time.Duration
	if in.TTLDays > 0 {
		ttl = time.Duration(in.TTLDays) * 24 * time.Hour
	}
	t, secret, err := s.st.CreateAPIToken(r.Context(), me.UserID, in.Name, role, me.Role, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit.LogUser(r.Context(), me.UserID, me.Username, "token.create", t.ID.String(),
		map[string]any{"name": t.Name, "role": t.Role})
	// The only time the secret is ever returned.
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": secret})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad token id")
		return
	}
	me := currentUser(r)
	var onlyUser *uuid.UUID
	if !me.Role.AtLeast(auth.RoleAdmin) {
		onlyUser = &me.UserID
	}
	ok, err := s.st.RevokeAPIToken(r.Context(), id, onlyUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "token not found, or already revoked")
		return
	}
	s.audit.LogUser(r.Context(), me.UserID, me.Username, "token.revoke", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// checkUsername keeps usernames to something that can be typed, logged and
// looked up unambiguously.
func checkUsername(u string) error {
	if len(u) < 2 || len(u) > 64 {
		return errString("username must be between 2 and 64 characters")
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == '@':
		default:
			return errString("username may contain only letters, digits and . - _ @")
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

// clientIP is the address a request came from, honouring the proxy header only
// when a proxy secret is configured — otherwise anyone could spoof their way
// around the login rate limit.
func clientIP(r *http.Request) string {
	if proxySecret() != "" {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

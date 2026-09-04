package httpapi

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/auth"
)

// Authentication for the user-facing API.
//
// Three ways in, in order of preference:
//
//   - a session cookie, which is how the SPA authenticates;
//   - an API token, for automation;
//   - a trusted proxy header, but only when the proxy proves it is the proxy.
//
// The third used to be the only one, and it was believed unconditionally.
// X-Forwarded-User is a request header: anything able to reach the API could
// set it and be anyone. It is now ignored unless the request also carries the
// shared secret in ASM_TRUSTED_PROXY_SECRET, which a client cannot know.

// proxySecret is the secret a reverse proxy must present alongside
// X-Forwarded-User. Empty disables header authentication entirely.
func proxySecret() string { return strings.TrimSpace(os.Getenv("ASM_TRUSTED_PROXY_SECRET")) }

// authenticate resolves who is making a request, or reports that nobody is.
func (s *Server) authenticate(r *http.Request) (auth.Identity, bool) {
	ctx := r.Context()

	if c, err := r.Cookie(auth.SessionCookie); err == nil && c.Value != "" {
		if id, ok, err := s.st.LookupSession(ctx, c.Value); err != nil {
			slog.Error("could not check a session", "err", err)
		} else if ok {
			return id, true
		}
	}

	if tok := auth.BearerToken(r); tok != "" {
		if id, ok, err := s.st.LookupAPIToken(ctx, tok); err != nil {
			slog.Error("could not check an API token", "err", err)
		} else if ok {
			return id, true
		}
	}

	if secret := proxySecret(); secret != "" {
		got := r.Header.Get("X-Proxy-Secret")
		user := strings.TrimSpace(r.Header.Get("X-Forwarded-User"))
		if user != "" && subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1 {
			// The proxy vouched for this name. The account still has to exist
			// and be enabled: the proxy says who, this says what they may do.
			u, _, err := s.st.UserByUsername(ctx, user)
			if err == nil && !u.Disabled {
				return auth.Identity{UserID: u.ID, Username: u.Username, Role: u.Role, Via: "proxy"}, true
			}
			slog.Warn("a trusted proxy vouched for an unknown or disabled account",
				"user", user)
		} else if user != "" {
			// Worth saying loudly: this is either a misconfigured proxy or
			// somebody trying the old, unauthenticated path.
			slog.Warn("X-Forwarded-User presented without the proxy secret; ignoring",
				"claimed", user, "remote", r.RemoteAddr)
		}
	}

	return auth.Identity{}, false
}

// requireAuth rejects unauthenticated requests.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "sign in to continue")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

// require returns middleware demanding at least the given role.
//
// Applied per route rather than per handler, so a new endpoint that nobody
// remembers to guard is unreachable rather than public: everything under
// /api/v1 sits inside requireAuth already, and this only narrows further.
func require(min auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := auth.FromContext(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "sign in to continue")
				return
			}
			if !id.Role.AtLeast(min) {
				writeErr(w, http.StatusForbidden,
					"this needs the "+string(min)+" role; you have "+string(id.Role))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// setSessionCookie writes the session cookie.
//
// Secure is set when the request arrived over TLS or through a proxy that says
// it did. It is not set unconditionally, because a cookie marked Secure is
// dropped on plain http and the app would be unusable on a local install.
func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isTLS(r),
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	}
	if value == "" {
		c.Expires, c.MaxAge = time.Unix(0, 0), -1
	}
	http.SetCookie(w, c)
}

func isTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// loginLimiter slows down password guessing.
//
// Per username and per source address, because limiting only one of them is
// easy to walk around: a botnet spreads the addresses, and a single address can
// walk the user list.
type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{hits: map[string][]time.Time{}} }

const (
	loginWindow   = 15 * time.Minute
	loginMaxTries = 10
)

// allow records an attempt and reports whether it may proceed.
func (l *loginLimiter) allow(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	ok := true
	for _, k := range keys {
		kept := l.hits[k][:0]
		for _, t := range l.hits[k] {
			if now.Sub(t) < loginWindow {
				kept = append(kept, t)
			}
		}
		kept = append(kept, now)
		l.hits[k] = kept
		if len(kept) > loginMaxTries {
			ok = false
		}
	}
	// Bound the map so a flood of distinct usernames cannot grow it forever.
	if len(l.hits) > 4096 {
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= loginWindow {
				delete(l.hits, k)
			}
		}
	}
	return ok
}

// succeeded clears the counters after a correct password, so one person
// mistyping does not lock out their own next attempt.
func (l *loginLimiter) succeeded(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.hits, k)
	}
}

// currentUser is the identity of the requester. Handlers use this rather than
// the old actor() string.
func currentUser(r *http.Request) auth.Identity {
	id, _ := auth.FromContext(r.Context())
	return id
}

// userIDOf returns the requester's user id for a foreign key, or nil.
func userIDOf(r *http.Request) *uuid.UUID {
	id, ok := auth.FromContext(r.Context())
	if !ok || id.UserID == uuid.Nil {
		return nil
	}
	return &id.UserID
}

// auditReq records an audit entry against the authenticated user.
//
// Every handler goes through this rather than audit.Log with a name, so the
// trail points at an account that cannot be claimed by setting a header.
func (s *Server) auditReq(r *http.Request, action, subject string, detail map[string]any) {
	id := currentUser(r)
	s.audit.LogUser(r.Context(), id.UserID, id.Username, action, subject, detail)
}

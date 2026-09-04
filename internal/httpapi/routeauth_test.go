package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// publicRoutes are the only endpoints that may answer without authentication,
// and each is here for a stated reason.
var publicRoutes = map[string]string{
	"GET /api/v1/auth/status": "says whether the install still needs its first administrator",
	"POST /api/v1/auth/setup": "creates that first administrator, and refuses once one exists",
	"POST /api/v1/auth/login": "the front door",
	"GET /healthz":            "liveness, for the container runtime",
}

// TestEveryRouteRequiresAuth walks the real router and checks that every
// endpoint refuses an unauthenticated request.
//
// This is the test that keeps the hole closed. The previous build had no
// authentication at all, and the way that comes back is not somebody deciding
// to remove it — it is somebody adding a handler outside the authenticated
// group and nobody noticing. A new route fails this test until it is either
// placed under requireAuth or listed above with a reason.
func TestEveryRouteRequiresAuth(t *testing.T) {
	// The store is never reached: with no cookie, no bearer token and no proxy
	// secret configured, authentication fails before it queries anything.
	t.Setenv("ASM_TRUSTED_PROXY_SECRET", "")
	srv := &Server{logins: newLoginLimiter()}
	h := srv.Routes()

	var checked int
	err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		key := method + " " + route
		if _, ok := publicRoutes[key]; ok {
			return nil
		}
		// Substitute something parseable for path parameters so the request
		// reaches the middleware rather than dying in the router.
		path := route
		for _, p := range []string{"{scopeID}", "{runID}", "{ipID}", "{serviceID}", "{wordlistID}",
			"{workerID}", "{channelID}", "{findingID}", "{vpnID}", "{userID}", "{tokenID}", "{action}"} {
			path = strings.ReplaceAll(path, p, "00000000-0000-0000-0000-000000000000")
		}
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d unauthenticated, want 401.\n"+
				"Put it inside the requireAuth group in Routes(), or add it to "+
				"publicRoutes with a reason.", key, rec.Code)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 30 {
		t.Fatalf("only walked %d routes; the walk is not seeing the API surface", checked)
	}
	t.Logf("%d routes checked, all refused unauthenticated access", checked)
}

// TestForwardedUserIsNotBelieved is the specific hole this phase closed.
//
// X-Forwarded-User is a request header. Before this, anything that could reach
// the API could set it and be anyone, and every created_by column recorded that
// claim as a fact.
func TestForwardedUserIsNotBelieved(t *testing.T) {
	t.Setenv("ASM_TRUSTED_PROXY_SECRET", "")
	srv := &Server{logins: newLoginLimiter()}
	h := srv.Routes()

	req := httptest.NewRequest("GET", "/api/v1/scopes", nil)
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("X-Forwarded-User alone was accepted (%d); it must prove the "+
			"proxy sent it", rec.Code)
	}
}

// TestForwardedUserNeedsTheProxySecret checks the header is still ignored when
// a secret is configured but the request does not carry the right one.
func TestForwardedUserNeedsTheProxySecret(t *testing.T) {
	t.Setenv("ASM_TRUSTED_PROXY_SECRET", "the-real-secret")
	srv := &Server{logins: newLoginLimiter()}
	h := srv.Routes()

	for _, presented := range []string{"", "wrong", "the-real-secre"} {
		req := httptest.NewRequest("GET", "/api/v1/scopes", nil)
		req.Header.Set("X-Forwarded-User", "admin")
		if presented != "" {
			req.Header.Set("X-Proxy-Secret", presented)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("proxy secret %q was accepted (%d)", presented, rec.Code)
		}
	}
}

// TestLoginRateLimit checks that guessing is slowed on both axes: limiting only
// the username lets a botnet spread out, limiting only the address lets one
// host walk the user list.
func TestLoginRateLimit(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < loginMaxTries; i++ {
		if !l.allow("ip:198.51.100.7", "user:alice") {
			t.Fatalf("blocked after only %d attempts", i)
		}
	}
	if l.allow("ip:198.51.100.7", "user:alice") {
		t.Error("attempt beyond the limit was allowed")
	}
	// A different user from the same address is still blocked by the address.
	if l.allow("ip:198.51.100.7", "user:bob") {
		t.Error("the source address limit did not apply to a second username")
	}
	// The same user from a different address is still blocked by the username.
	if l.allow("ip:203.0.113.9", "user:alice") {
		t.Error("the username limit did not apply from a second address")
	}
	// An unrelated pair is unaffected.
	if !l.allow("ip:203.0.113.9", "user:carol") {
		t.Error("an unrelated sign-in was blocked")
	}
	// A correct password clears the counters, so one typo does not lock you out.
	l.succeeded("ip:198.51.100.7", "user:alice")
	if !l.allow("ip:198.51.100.7", "user:alice") {
		t.Error("counters were not cleared after a successful sign-in")
	}
}

package httpapi

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestAPIDocCoversEveryRoute walks the live router and checks that every route
// appears in wiki/API.md as a backticked `METHOD /path`.
//
// The previous API documentation was a design-time sketch in architecture.md
// that listed endpoints which never existed and omitted most of the ones that
// did, and nothing noticed for months. A reference nobody checks against the
// code becomes fiction; this keeps the two in step by failing the build when a
// route is added without a line describing it.
func TestAPIDocCoversEveryRoute(t *testing.T) {
	doc, err := os.ReadFile("../../wiki/API.md")
	if err != nil {
		t.Skipf("wiki/API.md not readable: %v", err)
	}
	text := string(doc)

	srv := &Server{logins: newLoginLimiter()}
	var missing []string
	var checked int
	err = chi.Walk(srv.Routes().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		if route == "/healthz" {
			return nil
		}
		// The doc writes routes relative to /api/v1, as callers see them.
		rel := strings.TrimPrefix(route, "/api/v1")
		token := "`" + method + " " + rel + "`"
		checked++
		if !strings.Contains(text, token) {
			missing = append(missing, token)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range missing {
		t.Errorf("route %s is served but not documented in wiki/API.md", m)
	}
	if checked < 30 {
		t.Fatalf("only %d routes walked; the router is not being seen", checked)
	}

	// And the other direction: a documented route that does not exist is the
	// exact failure the old sketch had.
	documented := regexp.MustCompile("`(GET|POST|PUT|PATCH|DELETE) (/[^`]*)`").FindAllStringSubmatch(text, -1)
	served := map[string]bool{}
	_ = chi.Walk(srv.Routes().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		served[method+" "+strings.TrimPrefix(strings.ReplaceAll(route, "/*/", "/"), "/api/v1")] = true
		return nil
	})
	for _, d := range documented {
		key := d[1] + " " + d[2]
		if strings.HasPrefix(d[2], "/agent/") || strings.HasPrefix(d[2], "/v1/") || d[2] == "/healthz" || d[2] == "/install.sh" {
			continue // the gateway's and provisioner's routers, documented on the same page
		}
		if !served[key] {
			t.Errorf("wiki/API.md documents %s but the router does not serve it", key)
		}
	}
}

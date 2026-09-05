package httpapi

import (
	"os"
	"strings"
	"testing"
)

// The committed OpenAPI document must match what the router generates. A spec
// that drifts from the code is worse than none — it is the failure the old
// architecture.md sketch had — so this fails the build until it is regenerated.
func TestOpenAPIDocIsCurrent(t *testing.T) {
	committed, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Skipf("docs/openapi.yaml not readable: %v", err)
	}
	md, _ := os.ReadFile("../../wiki/API.md")
	want := OpenAPI(RouteTable(), PurposesFromDoc(string(md)))
	if strings.TrimSpace(string(committed)) != strings.TrimSpace(want) {
		t.Fatal("docs/openapi.yaml is out of date with the router or wiki/API.md; run: go run ./tools/openapi > docs/openapi.yaml")
	}
}

// Every route records a role; the public set is exactly the three the
// authentication design allows.
func TestRouteTableRoles(t *testing.T) {
	public := map[string]bool{}
	for _, r := range RouteTable() {
		if r.Role == "" {
			t.Errorf("%s %s has no role recorded", r.Method, r.Path)
		}
		if r.Role == RolePublic {
			public[r.Method+" "+r.Path] = true
		}
	}
	want := []string{"GET /api/v1/auth/status", "POST /api/v1/auth/setup", "POST /api/v1/auth/login"}
	if len(public) != len(want) {
		t.Errorf("public routes = %v, want exactly %v", public, want)
	}
	for _, w := range want {
		if !public[w] {
			t.Errorf("%s should be public", w)
		}
	}
}

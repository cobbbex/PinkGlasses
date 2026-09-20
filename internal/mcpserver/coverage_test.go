package mcpserver

import (
	"strings"
	"testing"

	"github.com/benlik386/pinkglasses/internal/httpapi"
)

// Every viewer and operator route (and the two admin routes that manage a
// company's own things) must be reachable through some tool or resource, or
// be listed here with the reason it is not. Adding a route without wiring it
// in fails the build, which is the only way the MCP server stays complete.
var notExposed = map[string]string{
	"GET /runs/{runID}/events":             "server-sent events: a browser stream; wait_for_run polls instead",
	"GET /scopes/{scopeID}/graph":          "the name→address map drawing; list_hosts carries the same pairs",
	"PATCH /scopes/{scopeID}":              "a company's default exit is a launch-dialog preselection",
	"POST /scopes/{scopeID}/scan-profiles": "saving presets is a UI convenience; params on start_scan cover it",
	"POST /scopes/{scopeID}/notifications": "alert channels carry webhook secrets; managed in the UI",
	"PATCH /notifications/{channelID}":     "same",
	"DELETE /notifications/{channelID}":    "same",
	"POST /notifications/{channelID}/test": "same",
	"POST /wordlists":                      "uploading wordlists is a file-management task for the UI",
	"PATCH /wordlists/{wordlistID}":        "same",
	"GET /wordlists/{wordlistID}/content":  "same",
	"PUT /wordlists/{wordlistID}/content":  "same",
	"DELETE /wordlists/{wordlistID}":       "same",
	"GET /tokens":                          "API tokens are credentials; the UI issues and revokes them",
	"POST /tokens":                         "same",
	"DELETE /tokens/{tokenID}":             "same",
	"POST /vpn-configs":                    "a VPN configuration is a credential; the UI uploads it",
	"DELETE /vpn-configs/{vpnID}":          "same",
	"POST /scopes":                         "creating a company is done in the UI, where the picker follows it",
	"GET /scopes/{scopeID}/footprint":      "covered by company_summary",
}

func TestEveryRouteIsExposedOrExplained(t *testing.T) {
	covered := CoveredRoutes()
	var missing []string
	for _, r := range httpapi.RouteTable() {
		if r.Role != "viewer" && r.Role != "operator" {
			continue // admin-only routes hand out credentials and are deliberately not exposed
		}
		key := r.Method + " " + strings.TrimPrefix(r.Path, "/api/v1")
		if covered[key] {
			continue
		}
		if _, ok := notExposed[key]; ok {
			continue
		}
		missing = append(missing, key)
	}
	if len(missing) > 0 {
		t.Fatalf("routes no MCP tool or resource reaches and no explanation covers:\n  %s\n(tools: %s)",
			strings.Join(missing, "\n  "), strings.Join(toolNames(), ", "))
	}
}

func TestToolNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range Tools(Options{AllowDeleteCompany: true}) {
		if seen[tl.Name] {
			t.Errorf("duplicate tool %s", tl.Name)
		}
		seen[tl.Name] = true
		if tl.Description == "" || tl.Schema == nil || tl.Run == nil {
			t.Errorf("tool %s is incomplete", tl.Name)
		}
	}
}

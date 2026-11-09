package httpapi

import "testing"

// Operators run the fleet their scans need: workers, enrollment, pools and
// SSH exits. Accounts and the install's health stay with administrators.
// A route moved by accident in either direction fails here, not in review.
func TestFleetIsOperatorsAccountsAreAdmins(t *testing.T) {
	want := map[string]string{
		"POST /api/v1/workers/enrollment-tokens":   "operator",
		"POST /api/v1/workers/{workerID}/{action}": "operator",
		"DELETE /api/v1/workers/{workerID}":        "operator",
		"PATCH /api/v1/pools/{poolID}":             "operator",
		"GET /api/v1/ssh-exits":                    "operator",
		"POST /api/v1/ssh-exits":                   "operator",
		"POST /api/v1/ssh-exits/{exitID}/install":  "operator",
		"DELETE /api/v1/ssh-exits/{exitID}":        "operator",
		"POST /api/v1/vpn-configs":                 "operator",
		"DELETE /api/v1/vpn-configs/{vpnID}":       "operator",
		"GET /api/v1/workers":                      "viewer",
		"GET /api/v1/users":                        "admin",
		"POST /api/v1/users":                       "admin",
		"PATCH /api/v1/users/{userID}":             "admin",
		"DELETE /api/v1/users/{userID}":            "admin",
		"GET /api/v1/system/health":                "admin",
	}
	got := map[string]string{}
	for _, r := range RouteTable() {
		got[r.Method+" "+r.Path] = r.Role
	}
	for route, role := range want {
		if got[route] != role {
			t.Errorf("%s needs %q, want %q", route, got[route], role)
		}
	}
}

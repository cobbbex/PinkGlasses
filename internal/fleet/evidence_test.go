package fleet

import (
	"strings"
	"testing"
)

// The one-line cause names what the containers point at.
func TestSummarizeEvidence(t *testing.T) {
	cases := []struct {
		name string
		in   []containerEvidence
		want string
	}{
		{"nothing left", nil, "no containers were left"},
		{"oom", []containerEvidence{{Name: "w0", Role: "worker", State: "exited", ExitCode: 137, OOMKilled: true}},
			"worker w0 was killed for running out of memory"},
		{"gateway exited", []containerEvidence{
			{Name: "gw", Role: "vpn-gateway", State: "exited", ExitCode: 1, Logs: "starting\nwg: handshake failed"},
			{Name: "w0", Role: "worker", State: "running"}},
			"VPN gateway gw exited with code 1 (wg: handshake failed)"},
		{"killed", []containerEvidence{{Name: "gw", Role: "vpn-gateway", State: "exited", ExitCode: 137}},
			"was killed from outside"},
		{"unhealthy tunnel", []containerEvidence{{Name: "gw", Role: "vpn-gateway", State: "running", Health: "unhealthy"}},
			"its tunnel no longer carries traffic"},
		{"all running", []containerEvidence{{Name: "w0", Role: "worker", State: "running"}},
			"could not reach the control plane"},
	}
	for _, c := range cases {
		if got := summarizeEvidence(c.in); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.name, got, c.want)
		}
	}
}

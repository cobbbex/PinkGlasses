package agentapi

import (
	"net/http/httptest"
	"testing"
)

// A remote worker arriving from a private address came through a tunnel or a
// relay: the address is that end's, and recording it would replace the VPS's
// real address with something like 172.18.0.9.
func TestEgressToRecord(t *testing.T) {
	cases := []struct{ kind, src, want string }{
		{"vps", "203.0.113.7", "203.0.113.7"},
		{"vps", "172.18.0.9", ""},
		{"vps", "127.0.0.1", ""},
		{"local", "172.18.0.9", "172.18.0.9"},
	}
	for _, c := range cases {
		if got := egressToRecord(c.kind, c.src); got != c.want {
			t.Errorf("%s from %s: got %q, want %q", c.kind, c.src, got, c.want)
		}
	}
}

// A worker is told to post results to the address it used to reach the
// gateway, whatever the gateway's configured public URL says.
func TestWorkerBase(t *testing.T) {
	g := &Gateway{}
	g.cfg.PublicGatewayURL = "http://gateway:8090"
	cases := []struct {
		host, proto, want string
	}{
		{"127.0.0.1:47090", "", "http://127.0.0.1:47090"}, // through an SSH exit
		{"100.64.0.1:8090", "", "http://100.64.0.1:8090"}, // a mesh VPN
		{"gw.example.org", "https", "https://gw.example.org"},
		{"", "", "http://gateway:8090"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/agent/v1/connect", nil)
		r.Host = c.host
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if got := g.workerBase(r); got != c.want {
			t.Errorf("host %q: got %q, want %q", c.host, got, c.want)
		}
	}
}

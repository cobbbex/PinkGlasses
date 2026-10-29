package agentapi

import (
	"errors"
	"net"
	"net/http/httptest"
	"testing"
)

func req(remote string, xff ...string) *httptest.ResponseRecorder { return nil }

func clientOf(t *trustedProxies, remote string, xff ...string) string {
	r := httptest.NewRequest("GET", "/agent/v1/enroll", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return t.clientIP(r)
}

// The attack this exists for: a worker on the internet claiming, in a header,
// to be a container on this host — which is what earns a local token's
// worker approval without anyone looking.
func TestForwardedForIgnoredFromAnyoneButAProxy(t *testing.T) {
	none := parseTrustedProxies("")
	if got := clientOf(none, "198.51.100.9:40000", "10.0.0.1"); got != "198.51.100.9" {
		t.Fatalf("with no trusted proxy the header was believed: %s", got)
	}
	caddy := parseTrustedProxies("172.18.0.40")
	if got := clientOf(caddy, "198.51.100.9:40000", "10.0.0.1"); got != "198.51.100.9" {
		t.Fatalf("a client that is not the proxy was believed: %s", got)
	}
	if isPrivateAddr(clientOf(caddy, "198.51.100.9:40000", "10.0.0.1")) {
		t.Fatal("an internet client passed for a private address")
	}
}

func TestForwardedForFromTheProxy(t *testing.T) {
	p := parseTrustedProxies("172.18.0.0/16, 127.0.0.1")
	// Caddy appends the real client; anything before it came from the client.
	if got := clientOf(p, "172.18.0.40:5000", "10.0.0.1, 203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("got %s, want the address the proxy appended", got)
	}
	if got := clientOf(p, "172.18.0.40:5000", "10.0.0.1", "203.0.113.8"); got != "203.0.113.8" {
		t.Errorf("several headers: got %s, want the last", got)
	}
	if got := clientOf(p, "172.18.0.40:5000"); got != "172.18.0.40" {
		t.Errorf("no header: got %s", got)
	}
	if got := clientOf(p, "172.18.0.40:5000", "garbage"); got != "172.18.0.40" {
		t.Errorf("unparseable header: got %s", got)
	}
	if got := clientOf(p, "[::ffff:127.0.0.1]:5000", "203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("IPv4-mapped proxy address: got %s", got)
	}
}

// A name is resolved, and one that does not resolve (Caddy not running)
// trusts nobody.
func TestTrustedProxyByName(t *testing.T) {
	p := parseTrustedProxies("caddy")
	p.lookup = func(n string) ([]net.IP, error) {
		if n == "caddy" {
			return []net.IP{net.ParseIP("172.18.0.40")}, nil
		}
		return nil, errors.New("no such host")
	}
	if got := clientOf(p, "172.18.0.40:5000", "203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("caddy by name: got %s", got)
	}
	if got := clientOf(p, "172.18.0.41:5000", "10.0.0.1"); got != "172.18.0.41" {
		t.Errorf("another container was believed: %s", got)
	}

	gone := parseTrustedProxies("caddy")
	gone.lookup = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
	if got := clientOf(gone, "172.18.0.40:5000", "10.0.0.1"); got != "172.18.0.40" {
		t.Errorf("an unresolvable name trusted someone: %s", got)
	}
}

// A gateway built without proxies (as tests build it) trusts nobody.
func TestNilProxiesTrustNobody(t *testing.T) {
	var p *trustedProxies
	if got := clientOf(p, "198.51.100.9:1", "10.0.0.1"); got != "198.51.100.9" {
		t.Errorf("got %s", got)
	}
}

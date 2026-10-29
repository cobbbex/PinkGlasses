package agentapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// X-Forwarded-For is a claim, and only a proxy we put in front of the gateway
// is entitled to make it. It was once read from anybody: a worker on the
// internet holding the leaked local bootstrap token could send
// "X-Forwarded-For: 10.0.0.1", pass for a container on this host, and be
// approved with no human in the loop — and any worker could set the egress
// address the fleet shows for it.
//
// Now the header counts only when the connection itself comes from a trusted
// proxy: ASM_TRUSTED_PROXIES, a comma-separated list of addresses, CIDRs and
// host names. A name is looked up again every 30 seconds, because the
// compose stack's Caddy is "caddy" on Docker's network and its address
// changes with every recreate. Empty, the header is ignored entirely and
// the connection's own address is the client.

type trustedProxies struct {
	prefixes []netip.Prefix
	names    []string

	mu       sync.Mutex
	resolved []netip.Addr
	at       time.Time
	lookup   func(string) ([]net.IP, error)
}

func parseTrustedProxies(spec string) *trustedProxies {
	t := &trustedProxies{lookup: net.LookupIP}
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(f)
		switch {
		case f == "":
		case strings.Contains(f, "/"):
			if p, err := netip.ParsePrefix(f); err == nil {
				t.prefixes = append(t.prefixes, p.Masked())
			}
		default:
			if a, err := netip.ParseAddr(f); err == nil {
				t.prefixes = append(t.prefixes, netip.PrefixFrom(a, a.BitLen()))
			} else {
				t.names = append(t.names, f)
			}
		}
	}
	return t
}

func (t *trustedProxies) empty() bool {
	return t == nil || (len(t.prefixes) == 0 && len(t.names) == 0)
}

func (t *trustedProxies) trusts(peer netip.Addr) bool {
	if t.empty() {
		return false
	}
	peer = peer.Unmap()
	for _, p := range t.prefixes {
		if p.Contains(peer) {
			return true
		}
	}
	if len(t.names) == 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.at) > 30*time.Second {
		t.resolved = t.resolved[:0]
		for _, n := range t.names {
			ips, err := t.lookup(n)
			if err != nil {
				continue // not running (the https profile is off): trust nobody by that name
			}
			for _, ip := range ips {
				if a, ok := netip.AddrFromSlice(ip); ok {
					t.resolved = append(t.resolved, a.Unmap())
				}
			}
		}
		t.at = time.Now()
	}
	for _, a := range t.resolved {
		if a == peer {
			return true
		}
	}
	return false
}

// clientIP is the address a request came from: the connection's own, or —
// when that is a trusted proxy — the last address the proxy appended to
// X-Forwarded-For. The last, not the first: everything before it was sent by
// the client and is whatever the client wanted it to be.
func (t *trustedProxies) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !t.trusts(peer) {
		return host
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return host
	}
	parts := strings.Split(xff[len(xff)-1], ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if a, err := netip.ParseAddr(last); err == nil {
		return a.Unmap().String()
	}
	return host
}

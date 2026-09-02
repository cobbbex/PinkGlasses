// Package scopeguard enforces what may be actively scanned. It runs at planning
// time, at dispatch time, and inside the worker (architecture.md §10.1).
package scopeguard

import (
	"net"
	"net/netip"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// Decision is the outcome of a scope check for one target.
type Decision struct {
	Allowed bool   // active scanning permitted
	Reason  string // when not allowed: 'not_authorized' | 'excluded' | 'private' | 'shared'
}

// privateBlocks are never scanned. This is an external attack-surface monitor:
// internal ranges are out of scope for every worker, which also closes the
// scanner-as-SSRF hole (architecture.md §10.1).
var privateBlocks = mustPrefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/8",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// Guard holds the exclusion set for a scope evaluation.
type Guard struct {
	Exclusions []netip.Prefix
}

// New builds a guard from scope targets in 'exclude' mode.
func New(targets []domain.ScopeTarget) *Guard {
	g := &Guard{}
	for _, t := range targets {
		if t.Mode != domain.ModeExclude {
			continue
		}
		if p, err := netip.ParsePrefix(t.Value); err == nil {
			g.Exclusions = append(g.Exclusions, p)
			continue
		}
		if a, err := netip.ParseAddr(t.Value); err == nil {
			g.Exclusions = append(g.Exclusions, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return g
}

// CheckIP decides whether an IP may be actively scanned. `shared` marks
// CDN/shared-hosting addresses discovered during enrichment.
func (g *Guard) CheckIP(ip string, shared bool) Decision {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Decision{false, "invalid"}
	}
	for _, p := range privateBlocks {
		if p.Contains(addr) {
			return Decision{false, "private"}
		}
	}
	// exclusions win, applied last
	for _, p := range g.Exclusions {
		if p.Contains(addr) {
			return Decision{false, "excluded"}
		}
	}
	if shared {
		return Decision{false, "shared"} // do not port-scan someone else's box
	}
	return Decision{true, ""}
}

// TargetAuthorized reports whether a scope target may be actively scanned at
// all (authorization record present, not exclude mode).
func TargetAuthorized(t domain.ScopeTarget) Decision {
	if t.Mode == domain.ModeExclude {
		return Decision{false, "excluded"}
	}
	if !t.Authorized() {
		return Decision{false, "not_authorized"}
	}
	return Decision{true, ""}
}

// ExpandCIDRHosts enumerates host addresses in a CIDR for scanning, capped to
// avoid runaway expansion of large blocks.
func ExpandCIDRHosts(cidr string, cap int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var out []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		out = append(out, ip.String())
		if len(out) >= cap {
			break
		}
	}
	return out
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

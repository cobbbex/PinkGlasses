package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ASNInfo is the network provenance of an address.
type ASNInfo struct {
	Number  int
	Name    string
	Prefix  string
	Country string
}

// asnResolver looks up ASN details over Team Cymru's DNS interface.
//
// dnsx has an -asn flag, but it depends on a data source this image does not
// carry and silently returns nothing. Cymru needs no extra binary, no API key
// and no database file — just TXT queries — so it works on any worker.
type asnResolver struct {
	res   net.Resolver
	mu    sync.Mutex
	names map[int]string // AS number -> name, cached per process
}

// cymruResolvers are queried directly instead of whatever /etc/resolv.conf
// points at. In a container that is Docker's embedded resolver (127.0.0.11),
// which does not reliably answer TXT queries — the lookups silently return
// nothing and every address ends up with no ASN.
var cymruResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

func newASNResolver() *asnResolver {
	var idx uint32
	return &asnResolver{
		names: map[int]string{},
		res: net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Round-robin so one unreachable resolver cannot stall lookups.
				var lastErr error
				n := atomic.AddUint32(&idx, 1)
				for i := range cymruResolvers {
					addr := cymruResolvers[(int(n)+i)%len(cymruResolvers)]
					c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
					if err == nil {
						return c, nil
					}
					lastErr = err
				}
				return nil, lastErr
			},
		},
	}
}

// Lookup returns the ASN, announcing prefix, country and AS name for an address.
func (a *asnResolver) Lookup(ctx context.Context, ip string) (ASNInfo, bool) {
	q, ok := cymruOriginQuery(ip)
	if !ok {
		return ASNInfo{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	txts, err := a.res.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return ASNInfo{}, false
	}
	// "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
	parts := splitCymru(txts[0])
	if len(parts) < 3 {
		return ASNInfo{}, false
	}
	// The first field can list several ASNs for multi-homed prefixes; take the
	// first, which is the one actually announcing.
	num, err := strconv.Atoi(strings.Fields(parts[0])[0])
	if err != nil {
		return ASNInfo{}, false
	}
	info := ASNInfo{Number: num, Prefix: parts[1], Country: parts[2]}
	info.Name = a.name(ctx, num)
	return info, true
}

// name resolves an AS number to its organisation name, cached for the process.
func (a *asnResolver) name(ctx context.Context, num int) string {
	a.mu.Lock()
	if n, ok := a.names[num]; ok {
		a.mu.Unlock()
		return n
	}
	a.mu.Unlock()

	txts, err := a.res.LookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", num))
	name := ""
	if err == nil && len(txts) > 0 {
		// "13335 | AU | apnic | 2011-08-11 | CLOUDFLARENET, US"
		if parts := splitCymru(txts[0]); len(parts) >= 5 {
			name = parts[4]
		}
	}
	a.mu.Lock()
	a.names[num] = name
	a.mu.Unlock()
	return name
}

func splitCymru(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// cymruOriginQuery builds the origin lookup name: reversed octets for IPv4,
// reversed nibbles against origin6 for IPv6.
func cymruOriginQuery(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	if addr.Is4() {
		o := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", o[3], o[2], o[1], o[0]), true
	}
	b := addr.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", b[i]&0x0f, b[i]>>4))
	}
	return sb.String() + "origin6.asn.cymru.com", true
}

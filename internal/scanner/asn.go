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
	res     net.Resolver
	mu      sync.Mutex
	names   map[int]string        // AS number -> name, cached per process
	pending map[int]chan struct{} // AS numbers currently being looked up
}

// cymruResolvers are queried directly instead of whatever /etc/resolv.conf
// points at. In a container that is Docker's embedded resolver (127.0.0.11),
// which does not reliably answer TXT queries — the lookups silently return
// nothing and every address ends up with no ASN.
var cymruResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

func newASNResolver() *asnResolver {
	var idx uint32
	return &asnResolver{
		names:   map[int]string{},
		pending: map[int]chan struct{}{},
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

// cymruAttempts is how many times an origin lookup is retried before giving up.
// Cymru rate-limits and answers over UDP, so a single dropped reply is normal
// under load; without a retry that silently costs an address its whole ASN.
const cymruAttempts = 3

// Lookup returns the ASN, announcing prefix, country and AS name for an address.
// The error is returned rather than a bare false so a systematic failure (no
// egress, rate limiting) is distinguishable from an address genuinely having no
// route, which is the difference between a bug and a fact.
func (a *asnResolver) Lookup(ctx context.Context, ip string) (ASNInfo, error) {
	q, ok := cymruOriginQuery(ip)
	if !ok {
		return ASNInfo{}, fmt.Errorf("not an IP address")
	}

	var lastErr error
	for attempt := 0; attempt < cymruAttempts; attempt++ {
		if attempt > 0 {
			// Brief, growing pause: retrying instantly into a rate limiter just
			// earns another refusal.
			select {
			case <-ctx.Done():
				return ASNInfo{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		txts, err := a.res.LookupTXT(qctx, q)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if len(txts) == 0 {
			// An empty answer is authoritative: the address has no origin record.
			return ASNInfo{}, fmt.Errorf("no origin record")
		}
		// "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
		parts := splitCymru(txts[0])
		if len(parts) < 3 {
			return ASNInfo{}, fmt.Errorf("unexpected origin record %q", txts[0])
		}
		// The first field can list several ASNs for multi-homed prefixes; take
		// the first, which is the one actually announcing.
		num, err := strconv.Atoi(strings.Fields(parts[0])[0])
		if err != nil {
			return ASNInfo{}, fmt.Errorf("unparsable AS number in %q", txts[0])
		}
		info := ASNInfo{Number: num, Prefix: parts[1], Country: parts[2]}
		info.Name = a.name(ctx, num)
		return info, nil
	}
	return ASNInfo{}, lastErr
}

// name resolves an AS number to its organisation name, cached for the process.
//
// The lookup is single-flighted. Addresses in a scan overwhelmingly share a
// handful of ASNs, so without this every concurrent lookup misses the cache at
// the same moment and queries for the same AS — doubling the load on a service
// that rate-limits, which is what loses the origin answers we actually need.
func (a *asnResolver) name(ctx context.Context, num int) string {
	a.mu.Lock()
	if n, ok := a.names[num]; ok {
		a.mu.Unlock()
		return n
	}
	wait, inFlight := a.pending[num]
	if !inFlight {
		wait = make(chan struct{})
		a.pending[num] = wait
	}
	a.mu.Unlock()

	if inFlight {
		// Someone else is already asking; wait for their answer.
		select {
		case <-wait:
		case <-ctx.Done():
			return ""
		}
		a.mu.Lock()
		n := a.names[num]
		a.mu.Unlock()
		return n
	}

	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	txts, err := a.res.LookupTXT(qctx, fmt.Sprintf("AS%d.asn.cymru.com", num))
	cancel()
	name := ""
	if err == nil && len(txts) > 0 {
		// "13335 | AU | apnic | 2011-08-11 | CLOUDFLARENET, US"
		if parts := splitCymru(txts[0]); len(parts) >= 5 {
			name = parts[4]
		}
	}
	a.mu.Lock()
	// Only cache a real answer, so a rate-limited miss does not pin an empty
	// name for the rest of the process.
	if name != "" {
		a.names[num] = name
	}
	delete(a.pending, num)
	a.mu.Unlock()
	close(wait)
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

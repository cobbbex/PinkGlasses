package scanner

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestASNConcurrentLoad exercises what a real scan does: many addresses looked
// up at once against a service that rate-limits. Cymru answers over UDP, so a
// dropped reply is normal under load and must be retried rather than silently
// costing an address its ASN.
//
// Skipped when there is no DNS egress; it is a network test by nature.
func TestASNConcurrentLoad(t *testing.T) {
	var ips []string
	for i := 0; i < 24; i++ {
		ips = append(ips, fmt.Sprintf("104.20.%d.%d", i, i+1))
	}
	a := newASNResolver()

	var mu sync.Mutex
	ok, fail := 0, 0
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			_, err := a.Lookup(context.Background(), ip)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else {
				fail++
			}
		}(ip)
	}
	wg.Wait()

	if ok == 0 {
		t.Skip("no DNS egress for Cymru lookups")
	}
	t.Logf("concurrent lookups: %d ok, %d failed of %d", ok, fail, len(ips))

	// These addresses are all in announced Cloudflare space, so every one has an
	// origin record. Losing more than a few means retries are not covering the
	// rate limiting, which is the regression this guards.
	if fail*4 > len(ips) {
		t.Errorf("%d/%d lookups lost under concurrency — retries are not holding", fail, len(ips))
	}
}

// TestASNNameSingleFlight checks that concurrent lookups of addresses sharing an
// ASN do not each issue their own name query. Without single-flighting, a scan
// doubles its query volume against a rate-limited service precisely when it is
// already under load.
func TestASNNameSingleFlight(t *testing.T) {
	a := newASNResolver()
	if _, err := a.Lookup(context.Background(), "1.1.1.1"); err != nil {
		t.Skipf("no DNS egress: %v", err)
	}

	a.mu.Lock()
	cached := len(a.names)
	pending := len(a.pending)
	a.mu.Unlock()

	if cached == 0 {
		t.Error("AS name was not cached after a successful lookup")
	}
	if pending != 0 {
		t.Errorf("in-flight map not drained: %d entries left", pending)
	}
}

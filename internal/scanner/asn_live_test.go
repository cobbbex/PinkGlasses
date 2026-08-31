package scanner

import (
	"context"
	"testing"
)

// TestASNLookupLive exercises the Team Cymru path against a well-known address.
// Skipped automatically when there is no DNS egress.
func TestASNLookupLive(t *testing.T) {
	a := newASNResolver()
	info, ok := a.Lookup(context.Background(), "1.1.1.1")
	if !ok {
		t.Skip("no DNS egress for Cymru lookups")
	}
	if info.Number != 13335 {
		t.Errorf("AS number = %d, want 13335", info.Number)
	}
	if info.Prefix == "" {
		t.Error("no announcing prefix returned")
	}
	if info.Name == "" {
		t.Error("no AS name returned")
	}
	t.Logf("AS%d %q prefix=%s country=%s", info.Number, info.Name, info.Prefix, info.Country)
}

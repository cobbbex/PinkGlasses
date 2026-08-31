package scanner

import (
	"context"
	"testing"

	"github.com/benlik386/asm/internal/scanproto"
)

// TestEnrichAddresses checks that address enrichment turns into the ObsIP
// observations ingest expects, carrying AS number, name and announcing prefix.
// dnsx may be absent in a test environment; the ASN half still runs.
func TestEnrichAddresses(t *testing.T) {
	s := New(map[scanproto.Capability]bool{})
	obs := s.enrichAddresses(context.Background(), []string{"1.1.1.1"}, params{})
	if len(obs) == 0 {
		t.Skip("no DNS egress for enrichment lookups")
	}
	var got scanproto.Observation
	for _, o := range obs {
		if o.IP == "1.1.1.1" {
			got = o
		}
	}
	if got.Type != scanproto.ObsIP {
		t.Fatalf("expected an ObsIP observation, got %q", got.Type)
	}
	if got.ASN != 13335 {
		t.Errorf("ASN = %d, want 13335", got.ASN)
	}
	if got.ASRange == "" {
		t.Error("no announcing prefix on the observation")
	}
	if got.ASOrg == "" {
		t.Error("no AS name on the observation")
	}
	t.Logf("ip=%s ptr=%q AS%d %q range=%s", got.IP, got.PTR, got.ASN, got.ASOrg, got.ASRange)
}

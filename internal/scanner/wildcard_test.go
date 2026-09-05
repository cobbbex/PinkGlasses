package scanner

import (
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// Under a wildcard apex, a name that resolves only to the wildcard address is a
// phantom and goes; a name with any other address, or a CNAME, is real and stays
// with all its records. Names that never resolved are untouched.
func TestDropPhantoms(t *testing.T) {
	wild := map[string]bool{"203.0.113.9": true}
	sub := func(n string) scanproto.Observation {
		return scanproto.Observation{Type: scanproto.ObsSubdomain, Domain: n}
	}
	rec := func(n, rt, v string) scanproto.Observation {
		return scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: n, RType: rt, Value: v}
	}
	cands := []scanproto.Observation{sub("phantom.example"), sub("real.example"), sub("aliased.example"), sub("dead.example")}
	records := []scanproto.Observation{
		rec("phantom.example", "A", "203.0.113.9"),
		rec("real.example", "A", "203.0.113.9"), rec("real.example", "A", "198.51.100.4"),
		rec("aliased.example", "CNAME", "cdn.example.net."),
	}
	keptC, keptR, dropped := dropPhantoms(cands, records, wild)
	if dropped != 1 {
		t.Fatalf("dropped %d, want 1", dropped)
	}
	names := map[string]bool{}
	for _, c := range keptC {
		names[c.Domain] = true
	}
	for _, want := range []string{"real.example", "aliased.example", "dead.example"} {
		if !names[want] {
			t.Errorf("%s should have been kept", want)
		}
	}
	if names["phantom.example"] {
		t.Error("phantom.example should have been dropped")
	}
	n := 0
	for _, r := range keptR {
		if r.Domain == "phantom.example" {
			t.Error("phantom's record should have gone with it")
		}
		if r.Domain == "real.example" {
			n++
		}
	}
	// real.example keeps both addresses: the evidence it is real is the other
	// address, not the absence of the wildcard one.
	if n != 2 {
		t.Errorf("real.example kept %d records, want 2", n)
	}
	c2, r2, d2 := dropPhantoms(cands, records, map[string]bool{})
	if d2 != 0 || len(c2) != len(cands) || len(r2) != len(records) {
		t.Error("with no wildcard set nothing may be dropped")
	}
}

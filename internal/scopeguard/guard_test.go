package scopeguard

import "testing"

// The private-range check is the SSRF defence: a name under an authorized
// target can still resolve to 127.0.0.1 or a link-local metadata address, and
// scanning that would point the tool at its own host. This test exists because
// the check was written, documented, and then never called by anything.
func TestCheckIPRefusesPrivateRanges(t *testing.T) {
	g := New(nil)
	AllowPrivate = false

	for _, ip := range []string{
		"127.0.0.1", "10.1.2.3", "172.17.0.5", "192.168.1.1",
		"169.254.169.254", // cloud metadata
		"::1", "fc00::1", "fe80::1", "0.0.0.0",
	} {
		if d := g.CheckIP(ip, false); d.Allowed {
			t.Errorf("%s was allowed; reason=%q", ip, d.Reason)
		} else if d.Reason != "private" {
			t.Errorf("%s refused for %q, want \"private\"", ip, d.Reason)
		}
	}

	for _, ip := range []string{"45.33.32.156", "1.1.1.1", "2606:4700::1111"} {
		if d := g.CheckIP(ip, false); !d.Allowed {
			t.Errorf("public address %s was refused: %q", ip, d.Reason)
		}
	}

	if d := g.CheckIP("45.33.32.156", true); d.Allowed || d.Reason != "shared" {
		t.Errorf("a shared address should be refused, got %+v", d)
	}
	if d := g.CheckIP("not-an-ip", false); d.Allowed || d.Reason != "invalid" {
		t.Errorf("a malformed address should be refused, got %+v", d)
	}
}

// The lab switch opens private ranges deliberately, and nothing else.
func TestAllowPrivateOpensOnlyPrivateRanges(t *testing.T) {
	g := New(nil)
	AllowPrivate = true
	defer func() { AllowPrivate = false }()

	if d := g.CheckIP("172.18.0.7", false); !d.Allowed {
		t.Errorf("with the lab switch on, a private address should be allowed: %q", d.Reason)
	}
	if d := g.CheckIP("172.18.0.7", true); d.Allowed {
		t.Error("the lab switch must not override the shared-infrastructure check")
	}
	if d := g.CheckIP("nonsense", false); d.Allowed {
		t.Error("the lab switch must not make a malformed address scannable")
	}
}

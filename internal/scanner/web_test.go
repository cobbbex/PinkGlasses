package scanner

import (
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// Web stages are addressed by URL, but every observation they make is stored
// against a service keyed by address and port. A target that cannot yield an
// address produced observations that ingest rejected, taking the whole batch —
// and the stage's results — with it.
func TestTargetIPPortDerivesAddressFromURL(t *testing.T) {
	cases := []struct {
		name     string
		target   scanproto.Target
		wantIP   string
		wantPort int
	}{
		{"explicit ip wins", scanproto.Target{IP: "1.2.3.4", Port: 8080, URL: "http://9.9.9.9:80"}, "1.2.3.4", 8080},
		{"url with port", scanproto.Target{URL: "http://45.33.32.156:80"}, "45.33.32.156", 80},
		{"https default port", scanproto.Target{URL: "https://45.33.32.156"}, "45.33.32.156", 443},
		{"http default port", scanproto.Target{URL: "http://45.33.32.156"}, "45.33.32.156", 80},
		{"ipv6 literal loses its brackets", scanproto.Target{URL: "http://[2600:3c01::f03c:91ff:fe18:bb2f]:8080"},
			"2600:3c01::f03c:91ff:fe18:bb2f", 8080},
		{"no url at all", scanproto.Target{}, "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip, port := targetIPPort(scanproto.Job{Targets: []scanproto.Target{c.target}})
			if ip != c.wantIP || port != c.wantPort {
				t.Errorf("targetIPPort = (%q, %d), want (%q, %d)", ip, port, c.wantIP, c.wantPort)
			}
		})
	}
}

// A Server header is a banner, not a product name. Storing it whole put the
// version in the product field and then again beside it ("Apache/2.4.7
// (Ubuntu) 2.4.7"), and left version search with nothing to match.
func TestSplitProductVersion(t *testing.T) {
	cases := []struct{ in, product, version string }{
		{"Apache/2.4.7 (Ubuntu)", "Apache", "2.4.7"},
		{"nginx/1.25.3", "nginx", "1.25.3"},
		{"Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"},
		{"cloudflare", "cloudflare", ""},
		{"", "", ""},
		{"gws/", "gws", ""},
		{"  nginx/1.2  ", "nginx", "1.2"},
	}
	for _, c := range cases {
		p, v := splitProductVersion(c.in)
		if p != c.product || v != c.version {
			t.Errorf("splitProductVersion(%q) = (%q, %q), want (%q, %q)", c.in, p, v, c.product, c.version)
		}
	}
}

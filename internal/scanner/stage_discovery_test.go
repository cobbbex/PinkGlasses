package scanner

import "testing"

// A passive source returning an unrelated domain must never widen the scan.
// This guards the label-boundary bug found by the Step 1 gate: a plain suffix
// match accepted "notexample.com" as a subdomain of "example.com", which
// produced ~25k out-of-scope names for a domain that has a handful.
func TestInScope(t *testing.T) {
	const root = "example.com"
	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"a.b.example.com", true},
		{"WWW.EXAMPLE.COM", true}, // normalised before the check
		{"www.example.com.", true},
		{"notexample.com", false},
		{"evilexample.com", false},
		{"example.com.attacker.net", false},
		{"example.org", false},
		{"", false},
	}
	for _, c := range cases {
		if got := inScope(normalizeHost(c.name), root); got != c.want {
			t.Errorf("inScope(%q, %q) = %v, want %v", c.name, root, got, c.want)
		}
	}
}

// nmap's greppable output concatenates product, version and extra info into one
// field. Splitting it is what makes `version:` searches work at all.
func TestSplitNmapProduct(t *testing.T) {
	cases := []struct{ in, product, version string }{
		{"OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)", "OpenSSH", "6.6.1p1"},
		{"Apache httpd 2.4.7 ((Ubuntu))", "Apache httpd", "2.4.7"},
		{"nginx 1.25.3", "nginx", "1.25.3"},
		{"Postfix smtpd", "Postfix smtpd", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		p, v := splitNmapProduct(c.in)
		if p != c.product || v != c.version {
			t.Errorf("splitNmapProduct(%q) = (%q,%q), want (%q,%q)", c.in, p, v, c.product, c.version)
		}
	}
}

// cleanPath must reject the text fragments a crawler scrapes from page bodies
// (the dir_brute gate produced 900+ junk "paths" like /", and Cyrillic prose).
func TestCleanPath(t *testing.T) {
	keep := []struct{ in, want string }{
		{"/admin", "/admin"},
		{"admin", "/admin"},
		{"/a/b/c.js", "/a/b/c.js"},
		{"/search?q=1", "/search"},
		{"/page#top", "/page"},
	}
	for _, c := range keep {
		if got := cleanPath(c.in); got != c.want {
			t.Errorf("cleanPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	drop := []string{`/"`, `/",`, "/x y", "/упом", `/<script>`, "", "   "}
	for _, in := range drop {
		if got := cleanPath(in); got != "" {
			t.Errorf("cleanPath(%q) = %q, want empty", in, got)
		}
	}
}

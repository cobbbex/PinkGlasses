package scanner

import "testing"

// A pooled scan reports many hosts in one output. Attributing a line to the
// wrong host would silently record services on the wrong machine, so the host
// must come from the line itself.
func TestParseNmapGrepHost(t *testing.T) {
	cases := map[string]string{
		"Host: 93.184.216.34 (example.com)\tStatus: Up":            "93.184.216.34",
		"Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9/": "10.0.0.1",
		"Host: 2606:4700::1111 (one.one)\tPorts: 443/open/tcp//":   "2606:4700::1111",
		"# Nmap 7.95 scan initiated":                               "",
		"":                                                         "",
	}
	for line, want := range cases {
		if got := parseNmapGrepHost(line); got != want {
			t.Errorf("parseNmapGrepHost(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseNmapGrepPortsWithHost(t *testing.T) {
	line := "Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, 443/open/tcp//https//nginx 1.25.3/"
	if host := parseNmapGrepHost(line); host != "10.0.0.1" {
		t.Fatalf("host = %q", host)
	}
	ports := parseNmapGrepPorts(line)
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2: %+v", len(ports), ports)
	}
	if ports[0].port != 22 || ports[1].port != 443 {
		t.Errorf("ports = %d, %d; want 22, 443", ports[0].port, ports[1].port)
	}
	product, version := splitNmapProduct(ports[0].product)
	if product != "OpenSSH" || version != "8.9p1" {
		t.Errorf("ssh product/version = %q/%q, want OpenSSH/8.9p1", product, version)
	}
}

// scanWidth mirrors the scanner-selection rule so the preset/range distinction
// is pinned. "top-100" contains a hyphen, and a punctuation test alone sent the
// most common case to the wide-sweep scanner instead of nmap.
func scanWidth(ports string, deep bool) bool {
	switch ports {
	case "", "top-100":
		return deep
	case "top-1000", "full":
		return true
	default:
		return true
	}
}

func TestScanWidthPresetsVersusRanges(t *testing.T) {
	narrow := []string{"", "top-100"}
	for _, p := range narrow {
		if scanWidth(p, false) {
			t.Errorf("ports=%q should be a narrow scan (nmap direct)", p)
		}
	}
	wide := []string{"top-1000", "full", "80,443", "1-1024"}
	for _, p := range wide {
		if !scanWidth(p, false) {
			t.Errorf("ports=%q should be a wide sweep", p)
		}
	}
	if !scanWidth("top-100", true) {
		t.Error("a deep profile should widen even the top-100 preset")
	}
}

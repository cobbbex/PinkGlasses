package scanner

import (
	"errors"
	"strings"
	"testing"
	"time"
)

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

// The sweep's time budget comes from the work, not from a constant. The case
// that started this: top-1000 over two addresses at the shipped rate of 20
// packets per second used to be given a flat 30 minutes, ran out of it, and
// reported the ports it happened to reach as if they were all of them.
func TestPortScanBudgetFollowsTheWork(t *testing.T) {
	const max = 4 * time.Hour
	// Shipped defaults: rate 20, 1s port timeout, 1 retry, concurrency 4.
	wide := portScanBudget(1000, 2, 20, 1000, 1, 4, max)
	if wide <= 30*time.Minute {
		t.Errorf("top-1000 over 2 addresses at the shipped rate got %s; that is the case that"+
			" truncated at 30 minutes, so the budget must exceed it", wide)
	}
	// Raising concurrency is what makes that sweep quick, so it must need less.
	fast := portScanBudget(1000, 2, 500, 1000, 1, 25, max)
	if fast >= wide {
		t.Errorf("at concurrency 25 the budget is %s, not less than %s at concurrency 4", fast, wide)
	}
	// A small sweep is never cut off by arithmetic.
	if small := portScanBudget(2, 1, 20, 1000, 1, 4, max); small < 15*time.Minute {
		t.Errorf("two ports on one address got %s; the floor is 15 minutes", small)
	}
	// And nothing exceeds the ceiling, however hopeless the request.
	if huge := portScanBudget(65535, 64, 20, 1000, 1, 4, max); huge != max {
		t.Errorf("a full sweep of 64 addresses got %s, want the %s ceiling", huge, max)
	}
}

func TestPortCount(t *testing.T) {
	cases := []struct {
		ports string
		deep  bool
		want  int
	}{
		{"", false, 100},
		{"top-100", false, 100},
		{"top-1000", false, 1000},
		{"full", false, 65535},
		{"top-100", true, 65535}, // deep is a full sweep whatever the selection says
		{"80,443", false, 2},
		{"1-1024", false, 1024},
		{"80,443,8000-8010", false, 13},
		{"nonsense", false, 65535}, // unknown: assume the worst, so the budget is generous
	}
	for _, c := range cases {
		if got := portCount(c.ports, c.deep); got != c.want {
			t.Errorf("portCount(%q, deep=%v) = %d, want %d", c.ports, c.deep, got, c.want)
		}
	}
}

// Service detection gets its time from the work too, and never less than the
// flat budgets it used to have.
func TestNmapBudget(t *testing.T) {
	const max = 4 * time.Hour
	if got := nmapBudget(2, 1, false, max); got != 20*time.Minute {
		t.Errorf("two ports on one address got %s, want the 20-minute floor", got)
	}
	if got := nmapBudget(2, 1, true, max); got != 60*time.Minute {
		t.Errorf("deep on a small pool got %s, want the 60-minute floor", got)
	}
	big := nmapBudget(1000, 64, false, max)
	if big <= 20*time.Minute {
		t.Errorf("1000 ports over 64 addresses got %s, which is no more than the floor", big)
	}
	if got := nmapBudget(65535, 640, true, max); got != max {
		t.Errorf("a hopeless deep scan got %s, want the %s ceiling", got, max)
	}
}

// Both tools in the stage can run out of time, and then both reasons matter.
// Whatever is combined must still be marked not worth retrying: the same scan
// at the same settings takes the same time.
func TestPermanentJoinKeepsBothReasonsAndPermanence(t *testing.T) {
	a := permanent(errors.New("the sweep ran out"))
	b := permanent(errors.New("nmap ran out"))
	got := permanentJoin(a, nil, b)
	if !isPermanent(got) {
		t.Error("the combined error is retryable; the same scan would only take the same time again")
	}
	for _, want := range []string{"the sweep ran out", "nmap ran out"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("combined error %q lost %q", got, want)
		}
	}
	if permanentJoin(nil, nil) != nil {
		t.Error("nothing wrong should combine to nil")
	}
	if got := permanentJoin(nil, a); got != a {
		t.Errorf("one error should come back as itself, got %v", got)
	}
}

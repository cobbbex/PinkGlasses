package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Minimum severity applies to findings only; ports and names have none and are
// governed by the event list alone.
func TestWanted(t *testing.T) {
	events := []string{"new_finding", "new_port"}
	cases := []struct {
		e    Event
		min  string
		want bool
	}{
		{Event{Kind: "new_finding", Severity: "high"}, "low", true},
		{Event{Kind: "new_finding", Severity: "info"}, "low", false},
		{Event{Kind: "new_finding", Severity: "low"}, "low", true},
		{Event{Kind: "new_port"}, "critical", true},   // no severity: list decides
		{Event{Kind: "new_subdomain"}, "info", false}, // not subscribed
		{Event{Kind: "finding_returned", Severity: "critical"}, "info", false},
	}
	for _, c := range cases {
		if got := Wanted(events, c.min, c.e); got != c.want {
			t.Errorf("Wanted(%v, %q, %+v) = %v, want %v", events, c.min, c.e, got, c.want)
		}
	}
}

// Regressions lead the digest, then new findings by severity; a flood of names
// is counted, not listed.
func TestBuildOrdersAndTruncates(t *testing.T) {
	var in []Event
	for i := 0; i < 40; i++ {
		in = append(in, Event{Kind: "new_subdomain", Title: "x"})
	}
	in = append(in,
		Event{Kind: "new_finding", Severity: "low", Title: "low one"},
		Event{Kind: "finding_returned", Severity: "medium", Title: "back"},
		Event{Kind: "new_finding", Severity: "critical", Title: "crit"},
	)
	d := Build("acme", "s", "r", "standard", time.Now(), "", in)
	if d.Summary["new_subdomain"] != 40 || d.Summary["new_finding"] != 2 || d.Summary["finding_returned"] != 1 {
		t.Errorf("summary = %v", d.Summary)
	}
	if len(d.Events) != maxEvents || d.Truncated != 43-maxEvents {
		t.Errorf("events=%d truncated=%d", len(d.Events), d.Truncated)
	}
	if d.Events[0].Kind != "finding_returned" || d.Events[1].Title != "crit" || d.Events[2].Title != "low one" {
		t.Errorf("order wrong: %+v", d.Events[:3])
	}
	txt := SlackText(d)
	if !strings.Contains(txt, "*returned*") || !strings.Contains(txt, "and 18 more") {
		t.Errorf("slack text:\n%s", txt)
	}
}

// A destination that answers non-2xx is a failure. The previous sender
// ignored the status, so a dead webhook counted as delivered.
func TestSendReportsHTTPFailure(t *testing.T) {
	var got string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Content-Type")
		w.WriteHeader(204)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such hook", 404)
	}))
	defer bad.Close()

	d := Build("acme", "s", "r", "standard", time.Now(), "", []Event{{Kind: "new_port", Title: "1.2.3.4:22 open"}})
	if err := NewWebhook(ok.URL).Send(context.Background(), d); err != nil {
		t.Fatalf("2xx should succeed: %v", err)
	}
	if got != "application/json" {
		t.Errorf("content type %q", got)
	}
	err := NewSlack(bad.URL).Send(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("404 should fail with the status in the error, got %v", err)
	}
}

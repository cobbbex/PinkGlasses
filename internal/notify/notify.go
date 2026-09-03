// Package notify delivers change digests to external sinks: a generic JSON
// webhook, or a Slack incoming webhook. One digest per run per channel.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Event is one change in a digest.
type Event struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title"`
}

// Digest is everything a run changed that a channel asked to hear about.
type Digest struct {
	Scope     string         `json:"scope"`
	ScopeID   string         `json:"scope_id"`
	RunID     string         `json:"run_id"`
	Profile   string         `json:"profile"`
	Finished  time.Time      `json:"finished_at"`
	Summary   map[string]int `json:"summary"`
	Events    []Event        `json:"events"`
	Truncated int            `json:"truncated,omitempty"`
	Link      string         `json:"link,omitempty"`
}

// Sink delivers digests.
type Sink interface {
	Send(ctx context.Context, d Digest) error
}

// maxEvents bounds a digest. A first scan of a large domain produces thousands
// of new_subdomain events, and nobody wants them one per line in Slack.
const maxEvents = 25

// Webhook posts the digest as JSON.
type Webhook struct {
	URL    string
	Client *http.Client
}

// NewWebhook builds a webhook sink.
func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, Client: &http.Client{Timeout: 10 * time.Second}}
}

// Send posts the digest and treats any non-2xx as failure. The previous
// version ignored the status, so a webhook returning 404 for a month counted
// as delivered.
func (w *Webhook) Send(ctx context.Context, d Digest) error {
	body, _ := json.Marshal(d)
	return post(ctx, w.Client, w.URL, body)
}

// Slack posts a Slack incoming-webhook message.
type Slack struct{ *Webhook }

// NewSlack builds a Slack sink.
func NewSlack(url string) *Slack { return &Slack{NewWebhook(url)} }

// Send renders the digest as Slack text: a header, one line per event up to the
// cap, and a count of the rest.
func (s *Slack) Send(ctx context.Context, d Digest) error {
	body, _ := json.Marshal(map[string]string{"text": SlackText(d)})
	return post(ctx, s.Client, s.URL, body)
}

// SlackText renders a digest for a chat message.
func SlackText(d Digest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s* — scan finished (%s): ", d.Scope, d.Profile)
	parts := []string{}
	for _, k := range []string{"finding_returned", "new_finding", "finding_gone", "new_port", "new_subdomain"} {
		if n := d.Summary[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(k, "_", " ")))
		}
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n")
	for _, e := range d.Events {
		switch e.Kind {
		case "finding_returned":
			fmt.Fprintf(&b, "• :rotating_light: *returned* [%s] %s\n", e.Severity, e.Title)
		case "new_finding":
			fmt.Fprintf(&b, "• new [%s] %s\n", e.Severity, e.Title)
		case "finding_gone":
			fmt.Fprintf(&b, "• gone [%s] %s\n", e.Severity, e.Title)
		default:
			fmt.Fprintf(&b, "• %s %s\n", strings.ReplaceAll(e.Kind, "_", " "), e.Title)
		}
	}
	if d.Truncated > 0 {
		fmt.Fprintf(&b, "… and %d more\n", d.Truncated)
	}
	if d.Link != "" {
		b.WriteString(d.Link)
	}
	return b.String()
}

func post(ctx context.Context, c *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Severity rank for the minimum-severity filter. Events without a severity —
// new ports, new names — are governed by the event list alone.
var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Wanted reports whether a channel configured with these events and minimum
// severity wants to hear about this event.
func Wanted(events []string, minSeverity string, e Event) bool {
	ok := false
	for _, k := range events {
		if k == e.Kind {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if e.Severity == "" {
		return true
	}
	return sevRank[strings.ToLower(e.Severity)] >= sevRank[strings.ToLower(minSeverity)]
}

// Build assembles a digest from wanted events, capping the list.
func Build(scope, scopeID, runID, profile string, finished time.Time, link string, wanted []Event) Digest {
	d := Digest{Scope: scope, ScopeID: scopeID, RunID: runID, Profile: profile,
		Finished: finished, Summary: map[string]int{}, Events: []Event{}, Link: link}
	for _, e := range wanted {
		d.Summary[e.Kind]++
	}
	// Regressions first, then new findings by severity, then the rest.
	order := func(e Event) int {
		switch e.Kind {
		case "finding_returned":
			return 0
		case "new_finding":
			return 1
		case "finding_gone":
			return 2
		default:
			return 3
		}
	}
	sorted := append([]Event(nil), wanted...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0; j-- {
			a, b := sorted[j-1], sorted[j]
			if order(a) > order(b) || (order(a) == order(b) && sevRank[a.Severity] < sevRank[b.Severity]) {
				sorted[j-1], sorted[j] = b, a
			} else {
				break
			}
		}
	}
	if len(sorted) > maxEvents {
		d.Truncated = len(sorted) - maxEvents
		sorted = sorted[:maxEvents]
	}
	d.Events = sorted
	return d
}

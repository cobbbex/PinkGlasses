package notify

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Notifier turns a completed run's change events into one digest per channel.
type Notifier struct {
	st      *store.Store
	baseURL string // the UI, for a link in the message; may be empty
}

// New builds a Notifier. baseURL is where the UI lives, used only for links.
func New(st *store.Store, baseURL string) *Notifier { return &Notifier{st: st, baseURL: baseURL} }

// Notify sends this run's digest to every enabled channel of its scope that
// wants at least one of the run's events. Each (channel, run) is attempted
// once; the outcome is recorded whether it arrived or not, so a failing
// destination is visible rather than silent.
func (n *Notifier) Notify(ctx context.Context, run domain.ScanRun) (int, error) {
	channels, err := n.st.ListChannels(ctx, run.ScopeID)
	if err != nil {
		return 0, err
	}
	if len(channels) == 0 {
		return 0, nil
	}
	events, err := n.st.RunChangeEvents(ctx, run.ID)
	if err != nil {
		return 0, err
	}
	scope, _ := n.st.GetScope(ctx, run.ScopeID)
	finished := time.Now()
	if run.FinishedAt != nil {
		finished = *run.FinishedAt
	}
	all := toEvents(events)

	sent := 0
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		if done, _ := n.st.DeliveryExists(ctx, ch.ID, run.ID); done {
			continue
		}
		var wanted []Event
		for _, e := range all {
			if Wanted(ch.Events, ch.MinSeverity, e) {
				wanted = append(wanted, e)
			}
		}
		runID := run.ID
		if len(wanted) == 0 {
			// Nothing this channel asked about. Recorded so the UI can show the
			// run was considered, and so a re-diff does not reconsider it.
			_ = n.st.RecordDelivery(ctx, ch.ID, &runID, 0, "skipped", nil)
			continue
		}
		link := ""
		if n.baseURL != "" {
			link = fmt.Sprintf("%s/runs", n.baseURL)
		}
		d := Build(scope.Name, run.ScopeID.String(), run.ID.String(), string(run.Profile), finished, link, wanted)
		err := n.sinkFor(ch).Send(ctx, d)
		if err != nil {
			msg := err.Error()
			_ = n.st.RecordDelivery(ctx, ch.ID, &runID, len(wanted), "failed", &msg)
			slog.Warn("notification failed", "channel", ch.Name, "kind", ch.Kind, "run", run.ID, "err", err)
			continue
		}
		_ = n.st.RecordDelivery(ctx, ch.ID, &runID, len(wanted), "sent", nil)
		slog.Info("notification sent", "channel", ch.Name, "kind", ch.Kind, "run", run.ID, "events", len(wanted))
		sent++
	}
	return sent, nil
}

// Test sends a sample digest to one channel so a destination can be checked
// before a real change ever happens. Recorded with a nil run.
func (n *Notifier) Test(ctx context.Context, ch store.NotificationChannel) error {
	scope, _ := n.st.GetScope(ctx, ch.ScopeID)
	d := Build(scope.Name, ch.ScopeID.String(), "test", "test", time.Now(), "", []Event{
		{Kind: "finding_returned", Severity: "high", Title: "Test: a finding that was gone is back"},
		{Kind: "new_port", Title: "Test: 203.0.113.10:3389 opened"},
	})
	err := n.sinkFor(ch).Send(ctx, d)
	var msg *string
	status := "sent"
	if err != nil {
		s := err.Error()
		msg, status = &s, "failed"
	}
	_ = n.st.RecordDelivery(ctx, ch.ID, nil, len(d.Events), status, msg)
	return err
}

func (n *Notifier) sinkFor(ch store.NotificationChannel) Sink {
	if ch.Kind == "slack" {
		return NewSlack(ch.URL)
	}
	return NewWebhook(ch.URL)
}

// toEvents flattens change events into digest lines. finding_gone carries its
// detail in before; everything else in after.
func toEvents(in []store.ChangeEvent) []Event {
	out := make([]Event, 0, len(in))
	for _, ce := range in {
		src := ce.After
		if ce.Kind == "finding_gone" {
			src = ce.Before
		}
		e := Event{Kind: ce.Kind}
		if v, ok := src["severity"].(string); ok {
			e.Severity = v
		}
		switch ce.Kind {
		case "new_subdomain":
			e.Title, _ = src["name"].(string)
		case "new_port":
			ip, _ := src["ip"].(string)
			port, _ := src["port"].(float64)
			e.Title = fmt.Sprintf("%s:%d open", ip, int(port))
		default:
			e.Title, _ = src["title"].(string)
		}
		if e.Title == "" {
			e.Title = uuid.UUID(ce.AssetID).String()
		}
		out = append(out, e)
	}
	return out
}

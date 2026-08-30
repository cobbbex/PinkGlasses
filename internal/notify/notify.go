// Package notify delivers alerts to external sinks (Slack, generic webhook,
// email). Change events and saved-search matches flow through here.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Alert is a single notification.
type Alert struct {
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	ScopeID  string         `json:"scope_id"`
	RunID    string         `json:"run_id,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// Sink delivers alerts.
type Sink interface {
	Send(ctx context.Context, a Alert) error
}

// Webhook posts alerts as JSON to a URL (works for Slack incoming webhooks too,
// which accept a {"text": ...} body — see SlackWebhook).
type Webhook struct {
	URL    string
	Client *http.Client
}

// NewWebhook builds a webhook sink.
func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, Client: &http.Client{Timeout: 10 * time.Second}}
}

// Send posts the alert as JSON.
func (w *Webhook) Send(ctx context.Context, a Alert) error {
	body, _ := json.Marshal(a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// SlackWebhook posts a Slack-formatted message.
type SlackWebhook struct{ *Webhook }

// NewSlack builds a Slack webhook sink.
func NewSlack(url string) *SlackWebhook { return &SlackWebhook{NewWebhook(url)} }

// Send posts a Slack {"text":...} payload.
func (s *SlackWebhook) Send(ctx context.Context, a Alert) error {
	body, _ := json.Marshal(map[string]string{"text": "[" + a.Severity + "] " + a.Title})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Multi fans an alert out to several sinks; individual failures are ignored.
type Multi struct{ Sinks []Sink }

// Send delivers to all sinks.
func (m *Multi) Send(ctx context.Context, a Alert) error {
	for _, s := range m.Sinks {
		_ = s.Send(ctx, a)
	}
	return nil
}

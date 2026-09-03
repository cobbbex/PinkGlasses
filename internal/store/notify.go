package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// NotificationChannel is one destination for change digests.
type NotificationChannel struct {
	ID          uuid.UUID `json:"id"`
	ScopeID     uuid.UUID `json:"scope_id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"` // webhook | slack
	URL         string    `json:"-"`    // never serialized; see MaskedURL
	MaskedURL   string    `json:"url"`
	Events      []string  `json:"events"`
	MinSeverity string    `json:"min_severity"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

const channelCols = `id, scope_id, name, kind, url, events, min_severity, enabled, created_by, created_at`

func scanChannel(row interface{ Scan(...any) error }) (NotificationChannel, error) {
	var c NotificationChannel
	err := row.Scan(&c.ID, &c.ScopeID, &c.Name, &c.Kind, &c.URL, &c.Events, &c.MinSeverity,
		&c.Enabled, &c.CreatedBy, &c.CreatedAt)
	if c.Events == nil {
		c.Events = []string{}
	}
	return c, err
}

// CreateChannel registers a destination.
func (s *Store) CreateChannel(ctx context.Context, c NotificationChannel) (NotificationChannel, error) {
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO notification_channel (scope_id, name, kind, url, events, min_severity, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+channelCols,
		c.ScopeID, c.Name, c.Kind, c.URL, c.Events, c.MinSeverity, c.Enabled, c.CreatedBy)
	return scanChannel(row)
}

// ListChannels returns a scope's destinations, enabled or not.
func (s *Store) ListChannels(ctx context.Context, scopeID uuid.UUID) ([]NotificationChannel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM notification_channel
		WHERE scope_id=$1 ORDER BY created_at`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChannel returns one destination.
func (s *Store) GetChannel(ctx context.Context, id uuid.UUID) (NotificationChannel, error) {
	return scanChannel(s.Pool.QueryRow(ctx, `SELECT `+channelCols+` FROM notification_channel WHERE id=$1`, id))
}

// SetChannelEnabled flips a destination on or off without deleting its history.
func (s *Store) SetChannelEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE notification_channel SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

// DeleteChannel removes a destination and its delivery history.
func (s *Store) DeleteChannel(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM notification_channel WHERE id=$1`, id)
	return ct.RowsAffected() > 0, err
}

// NotificationDelivery is the record of one digest attempt.
type NotificationDelivery struct {
	ID        uuid.UUID  `json:"id"`
	ChannelID uuid.UUID  `json:"channel_id"`
	Channel   string     `json:"channel"`
	RunID     *uuid.UUID `json:"run_id,omitempty"`
	Events    int        `json:"events"`
	Status    string     `json:"status"`
	Error     *string    `json:"error,omitempty"`
	SentAt    time.Time  `json:"sent_at"`
}

// RecordDelivery notes a digest attempt. One per (channel, run): a run diffed
// twice must not notify twice, so a repeat is a no-op.
func (s *Store) RecordDelivery(ctx context.Context, channelID uuid.UUID, runID *uuid.UUID, events int, status string, errMsg *string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO notification_delivery (channel_id, run_id, events, status, error)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (channel_id, run_id) DO UPDATE SET
		  events=EXCLUDED.events, status=EXCLUDED.status, error=EXCLUDED.error, sent_at=now()`,
		channelID, runID, events, status, errMsg)
	return err
}

// DeliveryExists reports whether a run has already been delivered (or
// deliberately skipped) on a channel.
func (s *Store) DeliveryExists(ctx context.Context, channelID, runID uuid.UUID) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_delivery WHERE channel_id=$1 AND run_id=$2`,
		channelID, runID).Scan(&n)
	return n > 0, err
}

// ListDeliveries returns a scope's recent digest attempts, newest first.
func (s *Store) ListDeliveries(ctx context.Context, scopeID uuid.UUID, limit int) ([]NotificationDelivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT d.id, d.channel_id, c.name, d.run_id, d.events, d.status, d.error, d.sent_at
		FROM notification_delivery d JOIN notification_channel c ON c.id = d.channel_id
		WHERE c.scope_id=$1 ORDER BY d.sent_at DESC LIMIT $2`, scopeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationDelivery{}
	for rows.Next() {
		var d NotificationDelivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.Channel, &d.RunID, &d.Events, &d.Status, &d.Error, &d.SentAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ChangeEvent is one recorded change, with both sides of it.
type ChangeEvent struct {
	Kind      string         `json:"kind"`
	AssetKind string         `json:"asset_kind"`
	AssetID   uuid.UUID      `json:"asset_id"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// RunChangeEvents returns every change event a run produced, with before and
// after — finding_gone carries its detail in before, the others in after.
func (s *Store) RunChangeEvents(ctx context.Context, runID uuid.UUID) ([]ChangeEvent, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT kind, asset_kind, asset_id, before, after, created_at
		FROM change_event WHERE run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChangeEvent{}
	for rows.Next() {
		var e ChangeEvent
		var b, a []byte
		if err := rows.Scan(&e.Kind, &e.AssetKind, &e.AssetID, &b, &a, &e.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(b, &e.Before)
		_ = json.Unmarshal(a, &e.After)
		out = append(out, e)
	}
	return out, rows.Err()
}

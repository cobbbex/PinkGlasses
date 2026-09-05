package store

import (
	"context"
	"log/slog"
	"time"
)

// Listen delivers every notification on a Postgres channel to fn, for as long
// as ctx lives, reconnecting when the connection drops.
//
// A dedicated connection is held for the whole time: LISTEN is per session, and
// a pooled connection handed back would stop listening. One is cheap; the
// alternative — every process that changes a run also calling into a hub — is
// what left the events stream with no publisher for months.
func (s *Store) Listen(ctx context.Context, channel string, fn func(payload string)) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := s.listenOnce(ctx, channel, fn); err != nil && ctx.Err() == nil {
			slog.Warn("notification listener dropped; reconnecting", "channel", channel, "err", err, "in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (s *Store) listenOnce(ctx context.Context, channel string, fn func(string)) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	slog.Info("listening for notifications", "channel", channel)
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		fn(n.Payload)
	}
}

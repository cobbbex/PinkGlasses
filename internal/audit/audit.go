// Package audit writes append-only audit records: who added a target, enrolled
// a worker, triggered a run, exported data (architecture.md §10.1).
package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/store"
)

// Logger appends audit records.
type Logger struct{ st *store.Store }

// New builds an audit logger.
func New(st *store.Store) *Logger { return &Logger{st: st} }

// Log records one audit entry against a name only.
//
// Prefer LogUser: a name is what a request called itself, while a user id is
// who it actually was. This remains for the few places with no request behind
// them, and for anything written before there were user accounts at all.
func (l *Logger) Log(ctx context.Context, actor, action, subject string, detail map[string]any) {
	l.write(ctx, nil, actor, action, subject, detail)
}

// LogUser records an entry against a real account.
//
// The point of the user id is that it survives a rename and cannot be claimed
// by a header: "who started this run" becomes a fact rather than a string
// somebody sent us.
func (l *Logger) LogUser(ctx context.Context, userID uuid.UUID, actor, action, subject string, detail map[string]any) {
	var id *uuid.UUID
	if userID != uuid.Nil {
		id = &userID
	}
	l.write(ctx, id, actor, action, subject, detail)
}

// write appends the row. Failures are swallowed — auditing must never block the
// primary action — but they are logged, because an audit trail that has quietly
// stopped recording is worse than one that is obviously absent.
func (l *Logger) write(ctx context.Context, userID *uuid.UUID, actor, action, subject string, detail map[string]any) {
	d, _ := json.Marshal(detail)
	if _, err := l.st.Pool.Exec(ctx,
		`INSERT INTO audit_log (actor, user_id, action, subject, detail) VALUES ($1,$2,$3,$4,$5)`,
		actor, userID, action, subject, d); err != nil {
		slog.Error("could not write an audit record", "action", action, "subject", subject, "err", err)
	}
}

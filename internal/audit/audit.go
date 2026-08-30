// Package audit writes append-only audit records: who added a target, enrolled
// a worker, triggered a run, exported data (architecture.md §10.1).
package audit

import (
	"context"
	"encoding/json"

	"github.com/benlik386/asm/internal/store"
)

// Logger appends audit records.
type Logger struct{ st *store.Store }

// New builds an audit logger.
func New(st *store.Store) *Logger { return &Logger{st: st} }

// Log records one audit entry. Failures are swallowed (auditing must never
// block the primary action) but should be monitored in production.
func (l *Logger) Log(ctx context.Context, actor, action, subject string, detail map[string]any) {
	d, _ := json.Marshal(detail)
	_, _ = l.st.Pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, subject, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, subject, d)
}

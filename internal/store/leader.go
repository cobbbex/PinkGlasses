package store

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Leader is a session-level advisory lock held on one dedicated connection:
// whoever holds it is the one instance that may do a job. Postgres releases
// the lock the moment the connection drops, so a leader that dies — or is
// partitioned from the database — loses the lock without any timeout to
// tune, and a standby's next attempt wins it.
type Leader struct {
	key  int64
	conn *pgxpool.Conn
}

// leaderKeyScheduler is the scheduler's lock key. Any fixed 64-bit number
// distinct from other locks on the database does.
const leaderKeyScheduler int64 = 0x50494e4b5343_48 // "PINKSCH"

// TryLeadScheduler attempts the scheduler's lock. Held is true when this
// instance is now the leader; the returned Leader keeps the connection.
func (s *Store) TryLeadScheduler(ctx context.Context) (*Leader, bool, error) {
	return s.tryLead(ctx, leaderKeyScheduler)
}

func (s *Store) tryLead(ctx context.Context, key int64) (*Leader, bool, error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !got {
		conn.Release()
		return nil, false, nil
	}
	return &Leader{key: key, conn: conn}, true, nil
}

// Alive says whether the lock is still held: the connection answers. A
// leader that finds it is not must stop leading at once.
func (l *Leader) Alive(ctx context.Context) bool {
	if l == nil || l.conn == nil {
		return false
	}
	var one int
	return l.conn.QueryRow(ctx, `SELECT 1`).Scan(&one) == nil
}

// Release gives the lock up, for a clean shutdown; a standby takes it on its
// next try rather than waiting for the connection to time out.
func (l *Leader) Release(ctx context.Context) {
	if l == nil || l.conn == nil {
		return
	}
	if _, err := l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key); err != nil {
		slog.Warn("could not release the leader lock; it goes with the connection", "err", err)
	}
	l.conn.Release()
	l.conn = nil
}

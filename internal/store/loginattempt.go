package store

import (
	"context"
	"time"
)

// CountLoginAttempt records one sign-in attempt against each key and returns
// how many that key now has inside the window — the largest count across the
// keys, so one over the limit is enough to refuse.
//
// In the database rather than in the process, because several api copies
// behind a load balancer otherwise each count their own share and N copies
// mean N times the allowed guesses.
func (s *Store) CountLoginAttempt(ctx context.Context, keys []string, window time.Duration) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		WITH ks AS (SELECT unnest($1::text[]) AS key),
		     ins AS (INSERT INTO login_attempt (key) SELECT key FROM ks)
		SELECT greatest(coalesce(max(c), 0), 1) FROM (
		  SELECT count(*) + 1 AS c
		  FROM login_attempt a JOIN ks ON ks.key = a.key
		  WHERE a.at > now() - $2::interval
		  GROUP BY a.key) t`,
		keys, window.String()).Scan(&n)
	return n, err
}

// ClearLoginAttempts forgets a key's attempts after a correct password, so
// someone who mistyped twice is not held to it for the rest of the window.
func (s *Store) ClearLoginAttempts(ctx context.Context, keys []string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM login_attempt WHERE key = ANY($1)`, keys)
	return err
}

// PruneLoginAttempts drops attempts older than the window. The scheduler calls
// it on its sweep; nothing reads a row past the window, so this only keeps the
// table small.
func (s *Store) PruneLoginAttempts(ctx context.Context, olderThan time.Duration) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM login_attempt WHERE at < now() - $1::interval`, olderThan.String())
	return ct.RowsAffected(), err
}

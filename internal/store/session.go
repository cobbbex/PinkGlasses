package store

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/auth"
)

// SessionTTL is how long a sign-in lasts without activity.
const SessionTTL = 12 * time.Hour

// Session is a signed-in browser.
type Session struct {
	UserID     uuid.UUID `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	UserAgent  string    `json:"user_agent"`
}

// CreateSession issues a session and returns the secret to put in the cookie.
// Only its hash is stored.
func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, ua, ip string) (string, error) {
	secret, hash, err := auth.NewSecret()
	if err != nil {
		return "", err
	}
	var addr *string
	if host, _, e := net.SplitHostPort(ip); e == nil {
		ip = host
	}
	if net.ParseIP(ip) != nil {
		addr = &ip
	}
	if len(ua) > 400 {
		ua = ua[:400]
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO user_session (token_hash, user_id, expires_at, user_agent, ip)
		VALUES ($1,$2,now()+$3::interval,$4,$5)`,
		hash, userID, SessionTTL.String(), ua, addr)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// LookupSession resolves a cookie value to the user it signs in as.
//
// Expiry, and the user's disabled flag, are checked in the query: a session is
// only as good as the account behind it right now, not as it was at sign-in.
func (s *Store) LookupSession(ctx context.Context, secret string) (auth.Identity, bool, error) {
	hash := auth.HashSecret(secret)
	var id auth.Identity
	err := s.Pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.role
		FROM user_session s JOIN app_user u ON u.id = s.user_id
		WHERE s.token_hash=$1 AND s.expires_at > now() AND NOT u.disabled`, hash).
		Scan(&id.UserID, &id.Username, &id.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Identity{}, false, nil
	}
	if err != nil {
		return auth.Identity{}, false, err
	}
	id.Via = "session"
	// Sliding expiry, so an active session is not logged out mid-scan, while an
	// abandoned one still ages out.
	_, _ = s.Pool.Exec(ctx, `
		UPDATE user_session SET last_seen_at=now(), expires_at=now()+$2::interval
		WHERE token_hash=$1`, hash, SessionTTL.String())
	return id, true, nil
}

// DeleteSession signs one browser out.
func (s *Store) DeleteSession(ctx context.Context, secret string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM user_session WHERE token_hash=$1`, auth.HashSecret(secret))
	return err
}

// DeleteUserSessions signs a user out everywhere. Used when their password,
// role or disabled flag changes.
func (s *Store) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM user_session WHERE user_id=$1`, userID)
	return err
}

// ListSessions returns a user's live sessions, newest first.
func (s *Store) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT user_id, created_at, expires_at, last_seen_at, user_agent
		FROM user_session WHERE user_id=$1 AND expires_at > now()
		ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var v Session
		if err := rows.Scan(&v.UserID, &v.CreatedAt, &v.ExpiresAt, &v.LastSeenAt, &v.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ReapExpiredSessions removes sessions that have aged out.
func (s *Store) ReapExpiredSessions(ctx context.Context) (int64, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM user_session WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

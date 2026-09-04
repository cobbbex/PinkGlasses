package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/auth"
)

// APIToken is a credential for automation. The secret is shown once, at
// creation, and only its hash is stored — so a lost token is replaced, never
// recovered.
type APIToken struct {
	ID         uuid.UUID  `json:"id"`
	Prefix     string     `json:"prefix"`
	Name       string     `json:"name"`
	UserID     uuid.UUID  `json:"user_id"`
	Username   string     `json:"username"`
	Role       auth.Role  `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreateAPIToken issues a token and returns the secret exactly once.
//
// The role must not exceed the owner's: a token is a way to delegate part of
// what you can do, never a way to acquire more.
func (s *Store) CreateAPIToken(ctx context.Context, userID uuid.UUID, name string, role auth.Role, ownerRole auth.Role, ttl time.Duration) (APIToken, string, error) {
	if !role.Valid() {
		return APIToken{}, "", errors.New("unknown role")
	}
	if !ownerRole.AtLeast(role) {
		return APIToken{}, "", errors.New("a token cannot be given more access than the person creating it has")
	}
	secret, hash, err := auth.NewSecret()
	if err != nil {
		return APIToken{}, "", err
	}
	full := auth.TokenPrefix + secret
	// Store the hash of the full presented string, so lookup needs no parsing.
	hash = auth.HashSecret(full)
	prefix := full[:len(auth.TokenPrefix)+6]

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	var t APIToken
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO api_token (token_hash, prefix, name, user_id, role, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, prefix, name, user_id, role, created_at, expires_at, revoked_at, last_used_at`,
		hash, prefix, name, userID, string(role), expires).
		Scan(&t.ID, &t.Prefix, &t.Name, &t.UserID, &t.Role, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	if err != nil {
		return APIToken{}, "", err
	}
	return t, full, nil
}

// LookupAPIToken resolves a presented token to an identity.
//
// Revocation, expiry and the owner's disabled flag are all checked here, so a
// token stops working the moment any of them changes.
func (s *Store) LookupAPIToken(ctx context.Context, presented string) (auth.Identity, bool, error) {
	if !strings.HasPrefix(presented, auth.TokenPrefix) {
		return auth.Identity{}, false, nil
	}
	hash := auth.HashSecret(presented)
	var id auth.Identity
	var tokenID uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		SELECT t.id, u.id, u.username, t.role
		FROM api_token t JOIN app_user u ON u.id = t.user_id
		WHERE t.token_hash=$1
		  AND t.revoked_at IS NULL
		  AND (t.expires_at IS NULL OR t.expires_at > now())
		  AND NOT u.disabled`, hash).
		Scan(&tokenID, &id.UserID, &id.Username, &id.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Identity{}, false, nil
	}
	if err != nil {
		return auth.Identity{}, false, err
	}
	id.Via, id.TokenID = "token", &tokenID
	_, _ = s.Pool.Exec(ctx, `UPDATE api_token SET last_used_at=now() WHERE id=$1`, tokenID)
	return id, true, nil
}

// ListAPITokens returns tokens: every one for an admin, otherwise the caller's.
func (s *Store) ListAPITokens(ctx context.Context, forUser *uuid.UUID) ([]APIToken, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT t.id, t.prefix, t.name, t.user_id, u.username, t.role,
		       t.created_at, t.expires_at, t.revoked_at, t.last_used_at
		FROM api_token t JOIN app_user u ON u.id = t.user_id
		WHERE $1::uuid IS NULL OR t.user_id = $1
		ORDER BY t.created_at DESC`, forUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Prefix, &t.Name, &t.UserID, &t.Username, &t.Role,
			&t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token unusable. Rows stay so the audit trail keeps
// pointing at something.
func (s *Store) RevokeAPIToken(ctx context.Context, id uuid.UUID, onlyUser *uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `
		UPDATE api_token SET revoked_at=now()
		WHERE id=$1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR user_id=$2)`, id, onlyUser)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

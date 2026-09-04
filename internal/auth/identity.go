package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// Role is what a user may do. Three levels, ordered.
type Role string

const (
	// RoleViewer may read everything and change nothing.
	RoleViewer Role = "viewer"
	// RoleOperator may additionally run scans and manage scopes, targets,
	// wordlists and notification channels — everything about *finding* things.
	RoleOperator Role = "operator"
	// RoleAdmin may additionally manage users, workers, VPN configurations and
	// API tokens — everything that changes what the system itself can do.
	RoleAdmin Role = "admin"
)

// rank orders roles so a check can be "at least this".
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// AtLeast reports whether this role includes another's powers.
func (r Role) AtLeast(min Role) bool { return r.rank() >= min.rank() && r.rank() > 0 }

// Valid reports whether this is a role we recognise. An unrecognised role grants
// nothing rather than everything.
func (r Role) Valid() bool { return r.rank() > 0 }

// Identity is who is making a request.
type Identity struct {
	UserID   uuid.UUID
	Username string
	Role     Role
	// Via says how they authenticated: "session", "token" or "proxy". Recorded
	// in the audit log, because "who" is only half the question.
	Via string
	// TokenID is set when the request came in on an API token, so a token can
	// be traced to what it did and revoked on that evidence.
	TokenID *uuid.UUID
}

type ctxKey struct{}

// WithIdentity returns a context carrying the requester's identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the requester's identity, if the request was authenticated.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// SessionCookie is the name of the cookie holding a session token.
const SessionCookie = "pg_session"

// TokenPrefix marks an API token, so one pasted into a chat or a commit is
// recognisable as a credential rather than as a random string.
const TokenPrefix = "pgt_"

// NewSecret returns a fresh 32-byte random secret, base64url encoded, together
// with the sha256 of the string form — which is what gets stored.
//
// Only the hash is ever written down. A database read therefore does not hand
// over live sessions or usable tokens.
func NewSecret() (secret string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:], nil
}

// HashSecret returns the stored form of a session or token secret.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// BearerToken returns the API token presented on a request, if any.
//
// Both `Authorization: Bearer pgt_…` and the X-API-Token header are accepted;
// the second exists because EventSource cannot set an Authorization header.
func BearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if v, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(v)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Token"))
}

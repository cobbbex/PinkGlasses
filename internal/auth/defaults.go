package auth

import (
	"crypto/rand"
	"encoding/base64"
	"os"
)

// The account a fresh install starts with.
//
// The username is fixed; the password is not. It used to be a published
// constant, which is the pattern behind Mirai and a long line of breaches, and
// this database holds a complete map of somebody's external attack surface. Now
// it is generated at first boot and printed once in the api log, and the account
// carries a must-change flag until it is replaced. Zero-config start, nothing in
// the README worth typing into a login form.
const DefaultUsername = "admin"

// DefaultAdminPassword returns the password the seed should use: the operator's
// choice from ASM_DEFAULT_ADMIN_PASSWORD, or "" meaning generate one.
//
//	ASM_DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 24)   # choose it yourself
//	ASM_DEFAULT_ADMIN_PASSWORD=-                            # create no account
func DefaultAdminPassword() string {
	v := os.Getenv("ASM_DEFAULT_ADMIN_PASSWORD")
	if v == "-" {
		return ""
	}
	return v
}

// SeedDisabled reports whether the operator has turned the default account off.
func SeedDisabled() bool { return os.Getenv("ASM_DEFAULT_ADMIN_PASSWORD") == "-" }

// GeneratePassword returns a fresh 20-character random password: 15 bytes of
// randomness, URL-safe base64, no padding — typeable, and well past the
// 12-character policy minimum.
func GeneratePassword() (string, error) {
	raw := make([]byte, 15)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

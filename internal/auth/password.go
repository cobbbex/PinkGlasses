// Package auth holds password hashing, session tokens and the request identity
// the rest of the API is authorized against.
//
// Until this existed, `actor()` read X-Forwarded-User and otherwise called
// everyone "local". Anything that could reach the API could claim to be anyone,
// and every `created_by` column recorded that claim as though it were a fact.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. Deliberately stored inside each hash rather than
// assumed, so raising the cost later does not invalidate existing passwords.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrBadHash means a stored hash is not one we wrote.
var ErrBadHash = errors.New("password hash is malformed")

// HashPassword returns an encoded argon2id hash, in the standard
// $argon2id$v=19$m=..,t=..,p=..$salt$key form.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches the encoded hash.
//
// The comparison is constant-time. The parameters come from the hash, not from
// the constants above, so a password hashed under an older cost still verifies.
func VerifyPassword(encoded, pw string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrBadHash
	}
	var mem uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return false, ErrBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, time, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when a username does not exist, so that a
// request for an unknown user costs the same as one for a known user. Without
// it, response timing enumerates who has an account.
var dummyHash, _ = HashPassword("not-a-real-password-placeholder")

// VerifyAgainstNothing burns the same work a real verification would, and
// always fails.
func VerifyAgainstNothing(pw string) {
	_, _ = VerifyPassword(dummyHash, pw)
}

// CheckPasswordPolicy rejects passwords that are not worth hashing.
//
// Length only. Composition rules ("one capital, one digit") push people toward
// predictable substitutions without adding meaningful work for an attacker,
// and this is a self-hosted tool whose operator sets their own password.
func CheckPasswordPolicy(pw string) error {
	if len([]rune(pw)) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 1024 {
		// Hashing is deliberately expensive; an unbounded input is a cheap way
		// to make the server do a lot of work.
		return errors.New("password must be at most 1024 bytes")
	}
	return nil
}

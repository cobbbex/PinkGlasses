package agentapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

// argon2 parameters for agent credentials.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// newCredential returns a fresh random credential (shown once) and its argon2id
// hash (salt-prefixed) for storage.
func newCredential() (raw string, hash []byte) {
	secret := make([]byte, 24)
	_, _ = rand.Read(secret)
	raw = hex.EncodeToString(secret)
	salt := make([]byte, saltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(raw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return raw, append(salt, key...)
}

// verifyCredential checks a raw credential against a stored salt+hash in
// constant time.
func verifyCredential(raw string, stored []byte) bool {
	if len(stored) != saltLen+argonKeyLen {
		return false
	}
	salt := stored[:saltLen]
	want := stored[saltLen:]
	got := argon2.IDKey([]byte(raw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(want, got) == 1
}

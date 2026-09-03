// Package secret encrypts values that must survive in the database but must
// never be readable from it: VPN configurations, which carry private keys and
// credentials for networks that are not ours.
//
// AES-256-GCM with a key from ASM_SECRET_KEY. There is no fallback and no
// default key: without one, storing a secret fails loudly rather than writing
// plaintext into a column that everything with database access can read.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ErrNoKey is returned when ASM_SECRET_KEY is unset or too weak to use.
var ErrNoKey = errors.New(
	"ASM_SECRET_KEY is not set: generate one with `openssl rand -base64 32` and " +
		"set it on the api and gateway before storing secrets")

var (
	once   sync.Once
	cached []byte
	keyErr error
)

// key derives the 32-byte AES key from ASM_SECRET_KEY.
//
// A base64 32-byte value is used directly; anything else is hashed to 32 bytes
// so a passphrase works too. Short values are refused rather than stretched:
// a four-character "key" protecting a WireGuard private key is worse than an
// error, because it looks like protection.
func key() ([]byte, error) {
	once.Do(func() {
		raw := strings.TrimSpace(os.Getenv("ASM_SECRET_KEY"))
		if raw == "" {
			keyErr = ErrNoKey
			return
		}
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
			cached = b
			return
		}
		if len(raw) < 16 {
			keyErr = fmt.Errorf("%w (the value set is too short)", ErrNoKey)
			return
		}
		sum := sha256.Sum256([]byte(raw))
		cached = sum[:]
	})
	return cached, keyErr
}

// Available reports whether secrets can be stored at all, so the UI can say so
// before a user pastes a private key into a form that cannot keep it.
func Available() bool {
	_, err := key()
	return err == nil
}

// Seal encrypts plaintext. The nonce is prepended to the ciphertext.
func Seal(plaintext []byte) ([]byte, error) {
	k, err := key()
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts what Seal produced. A wrong or rotated key fails here rather
// than returning rubbish, because GCM authenticates.
func Open(box []byte) ([]byte, error) {
	k, err := key()
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	if len(box) < gcm.NonceSize() {
		return nil, errors.New("stored secret is truncated")
	}
	nonce, ct := box[:gcm.NonceSize()], box[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt: wrong ASM_SECRET_KEY, or the value was tampered with")
	}
	return out, nil
}

func newGCM(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

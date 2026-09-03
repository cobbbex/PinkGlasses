package secret

import (
	"strings"
	"sync"
	"testing"
)

// reset lets a test set a different key; the package caches the key once.
func reset() { once = sync.Once{}; cached, keyErr = nil, nil }

func TestSealOpenRoundTrip(t *testing.T) {
	t.Setenv("ASM_SECRET_KEY", "a-long-enough-passphrase-for-tests")
	reset()
	defer reset()

	plain := []byte("[Interface]\nPrivateKey = notarealkey=\n")
	box, err := Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(box), "PrivateKey") {
		t.Fatal("the plaintext is visible in the sealed value")
	}
	got, err := Open(box)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Errorf("round trip = %q", got)
	}

	// Two seals of the same value must differ: a fresh nonce each time, so
	// identical configs are not identifiable by their ciphertext.
	box2, _ := Seal(plain)
	if string(box) == string(box2) {
		t.Error("two seals produced identical ciphertext")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	t.Setenv("ASM_SECRET_KEY", "the-first-passphrase-used-here")
	reset()
	box, err := Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASM_SECRET_KEY", "a-completely-different-passphrase")
	reset()
	defer reset()
	if _, err := Open(box); err == nil {
		t.Error("decrypting with the wrong key should fail, not return rubbish")
	}
}

// Without a key, storing a secret must fail rather than fall back to plaintext.
func TestNoKeyFailsClosed(t *testing.T) {
	t.Setenv("ASM_SECRET_KEY", "")
	reset()
	defer reset()
	if Available() {
		t.Error("Available() should be false without a key")
	}
	if _, err := Seal([]byte("x")); err == nil {
		t.Error("Seal should fail without a key")
	}
	t.Setenv("ASM_SECRET_KEY", "short")
	reset()
	if _, err := Seal([]byte("x")); err == nil {
		t.Error("a too-short key should be refused, not stretched")
	}
}

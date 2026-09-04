package secret

import (
	"encoding/hex"
	"os"
	"testing"
)

// A helper, not a real test: run it with PG_SEALED=<hex> to ask whether the key
// currently in the environment can still read a stored secret.
//
//	ASM_SECRET_KEY=… PG_SEALED=… go test ./internal/secret -run TestCanDecryptStored -v
func TestCanDecryptStored(t *testing.T) {
	blob := os.Getenv("PG_SEALED")
	if blob == "" {
		t.Skip("set PG_SEALED to a hex-encoded sealed value to check it")
	}
	raw, err := hex.DecodeString(blob)
	if err != nil {
		t.Fatalf("PG_SEALED is not hex: %v", err)
	}
	out, err := Open(raw)
	if err != nil {
		t.Fatalf("CANNOT DECRYPT with the current key: %v", err)
	}
	t.Logf("decrypted %d bytes, starting %.28q", len(out), string(out))
}

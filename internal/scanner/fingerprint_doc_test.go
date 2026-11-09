package scanner

import (
	"os"
	"strings"
	"testing"
)

// Every header and cookie rule has a row in the fingerprint doc; see
// internal/fingerprint/doc_test.go for why.
func TestFingerprintDocCoversHeaderAndCookieRules(t *testing.T) {
	doc, err := os.ReadFile("../../wiki/Web-Application-Fingerprints.md")
	if err != nil {
		t.Skipf("wiki not readable: %v", err)
	}
	text := string(doc)
	for _, r := range headerTechRules {
		if !strings.Contains(text, "| `"+r.Header+"` |") {
			t.Errorf("header rule %s has no row in the fingerprint doc", r.Header)
		}
	}
	for _, r := range cookieTechRules {
		if !strings.Contains(text, "`"+r.Name+"`") {
			t.Errorf("cookie rule %s is not in the fingerprint doc", r.Name)
		}
	}
}

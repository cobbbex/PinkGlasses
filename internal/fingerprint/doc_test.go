package fingerprint

import (
	"os"
	"strings"
	"testing"
)

// wiki/Web-Application-Fingerprints.md is the list of what the scanner can
// name and how. A rule added here without a row there leaves the list
// quietly wrong, which is the failure a long-lived reference has; this keeps
// the two in step the way TestAPIDocCoversEveryRoute does for the API.
func TestFingerprintDocCoversEveryRule(t *testing.T) {
	doc, err := os.ReadFile("../../wiki/Web-Application-Fingerprints.md")
	if err != nil {
		t.Skipf("wiki not readable: %v", err)
	}
	text := string(doc)
	for _, p := range rules {
		if !strings.Contains(text, "### "+p.name) && !strings.Contains(text, "`"+p.name+"`") {
			t.Errorf("product %q has no section in the fingerprint doc", p.name)
		}
		for _, s := range p.signals {
			if !strings.Contains(text, "`"+s.what+"`") {
				t.Errorf("%s: signal %q is not listed in the fingerprint doc", p.name, s.what)
			}
		}
		for _, path := range p.probes {
			if !strings.Contains(text, "`"+path+"`") {
				t.Errorf("%s: probe path %s is not listed in the fingerprint doc", p.name, path)
			}
		}
	}
	for _, d := range devices {
		if !strings.Contains(text, "### "+d.name) {
			t.Errorf("device %q has no section in the fingerprint doc", d.name)
		}
		for _, s := range d.signals {
			if !strings.Contains(text, "`"+s.what+"`") {
				t.Errorf("%s: port signal %q is not listed in the fingerprint doc", d.name, s.what)
			}
		}
	}
}

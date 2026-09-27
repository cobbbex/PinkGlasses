package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestCertFindings(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	at := func(days float64) *time.Time {
		v := now.Add(time.Duration(days * float64(24*time.Hour)))
		return &v
	}
	cases := []struct {
		name              string
		notAfter          *time.Time
		subject, issuer   string
		wantKind, wantSev string
	}{
		{"none without a date", nil, "a.example", "R3", "", ""},
		{"expired", at(-1), "a.example", "R3", "tls_certificate_expired", "high"},
		{"expires in a week", at(7), "a.example", "R3", "tls_certificate_expiring", "medium"},
		{"expires in three weeks", at(21), "a.example", "R3", "tls_certificate_expiring", "low"},
		{"healthy", at(200), "a.example", "R3", "", ""},
		{"self-signed, otherwise healthy", at(200), "a.example", "a.example", "tls_certificate_self_signed", "low"},
		{"expiry beats self-signed", at(3), "a.example", "a.example", "tls_certificate_expiring", "medium"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := certFindings(c.notAfter, c.subject, c.issuer, "www.example", now)
			if c.wantKind == "" {
				if len(got) != 0 {
					t.Fatalf("wanted nothing, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Kind != c.wantKind || got[0].Severity != c.wantSev {
				t.Fatalf("got %+v, want %s/%s", got, c.wantKind, c.wantSev)
			}
			if !strings.Contains(got[0].Title, "www.example") {
				t.Errorf("the title should name the host: %q", got[0].Title)
			}
			// The days remaining move between runs, so they belong in the
			// evidence and not in the title, which identifies the finding.
			if strings.ContainsAny(got[0].Title, "0123456789") && !strings.Contains(got[0].Title, "14 days") &&
				!strings.Contains(got[0].Title, "30 days") {
				t.Errorf("the title should not carry a changing number: %q", got[0].Title)
			}
		})
	}
}

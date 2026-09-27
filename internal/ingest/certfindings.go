package ingest

import (
	"strings"
	"time"
)

// A certificate says when it stops being valid, and that date is the one
// piece of a scan's output with a deadline attached. An expired certificate
// breaks the site; one expiring next week is about to. Both are worth a
// finding with a severity, rather than a line in the TLS details nobody
// reads until a customer calls.

// certFinding is one conclusion drawn from a certificate.
type certFinding struct {
	Kind, Severity, Title string
	Evidence              map[string]any
}

// certFindings looks at one certificate and says what, if anything, is worth
// recording. An empty result means the certificate is fine.
//
// The title carries what identifies the problem — the host and the subject —
// and never the days remaining, which change between runs: the title is a
// finding's identity, so a moving number would make a new finding every day
// instead of one that persists and then resolves.
func certFindings(notAfter *time.Time, subjectCN, issuer, host string, now time.Time) []certFinding {
	if notAfter == nil || notAfter.IsZero() {
		return nil
	}
	where := host
	if where == "" {
		where = subjectCN
	}
	ev := map[string]any{
		"not_after":  notAfter.UTC().Format(time.RFC3339),
		"subject_cn": subjectCN,
		"issuer":     issuer,
		"host":       host,
		"days_left":  int(notAfter.Sub(now).Hours() / 24),
	}
	on := func(s string) string {
		if where == "" {
			return s
		}
		return s + " on " + where
	}
	days := notAfter.Sub(now).Hours() / 24
	switch {
	case days < 0:
		return []certFinding{{"tls_certificate_expired", "high", on("TLS certificate has expired"), ev}}
	case days <= 14:
		return []certFinding{{"tls_certificate_expiring", "medium", on("TLS certificate expires within 14 days"), ev}}
	case days <= 30:
		return []certFinding{{"tls_certificate_expiring", "low", on("TLS certificate expires within 30 days"), ev}}
	}
	// A self-signed certificate is worth saying once, but only when there is
	// nothing more pressing about it.
	if issuer != "" && strings.EqualFold(issuer, subjectCN) {
		return []certFinding{{"tls_certificate_self_signed", "low", on("Self-signed TLS certificate"), ev}}
	}
	return nil
}

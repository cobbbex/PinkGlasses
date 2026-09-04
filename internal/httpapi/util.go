package httpapi

import (
	"github.com/benlik386/pinkglasses/internal/auth"
	"net"
	"net/http"
	"strings"
)

// actor returns the name of the requester, for the `created_by` columns.
//
// It used to read X-Forwarded-User straight off the request and otherwise call
// everyone "local", which meant every one of those columns recorded whatever
// the caller claimed. It now reports the authenticated identity, established by
// requireAuth before any handler runs. The fallback is unreachable through the
// router and exists so a handler called from a test does not panic.
func actor(r *http.Request) string {
	if id, ok := auth.FromContext(r.Context()); ok {
		return id.Username
	}
	return "unauthenticated"
}

// guessKind infers a scope target's kind from its value.
func guessKind(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(strings.ToUpper(v), "AS") {
		if _, err := parseUint(v[2:]); err == nil {
			return "asn"
		}
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return "cidr"
	}
	if ip := net.ParseIP(v); ip != nil {
		return "ip"
	}
	return "domain"
}

func parseUint(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errNaN
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNaN
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errNaN = &strErr{"not a number"}

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

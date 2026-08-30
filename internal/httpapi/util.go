package httpapi

import (
	"net"
	"net/http"
	"strings"
)

// actor returns an identifier for the requester (auth is out of scope for this
// build; a real deployment sits behind an identity-aware proxy — §10.2).
func actor(r *http.Request) string {
	if u := r.Header.Get("X-Forwarded-User"); u != "" {
		return u
	}
	return "local"
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

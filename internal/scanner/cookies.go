package scanner

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Cookie names are a fingerprint. A product often sets a cookie whose name is
// unique to it — "webvpn" and friends for Cisco ASA WebVPN, "BIGipServer..."
// for an F5 pool, "NSC_" for Citrix — so recording the names makes those
// products findable across the whole inventory even when the banner and title
// say nothing.
//
// Only names are kept. A cookie's value is a session token: worthless as a
// fingerprint, and something we should not be storing at all.

// cookieNamesFromResponse takes the names from a real HTTP response, where the
// Set-Cookie headers are already separate and parsed by the standard library.
func cookieNamesFromResponse(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	var names []string
	for _, c := range resp.Cookies() {
		if c != nil && c.Name != "" {
			names = append(names, c.Name)
		}
	}
	return dedupeCookies(names)
}

// setCookieNameRe matches a cookie name at the start of the header or just
// after a comma. Attributes ("path=", "expires=") follow a semicolon, so they
// never match, and the comma inside an expires date is followed by a day
// number rather than a name=value pair.
var setCookieNameRe = regexp.MustCompile(`(?:^|,)\s*([A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+)=`)

// cookieNamesFromHeader takes the names out of a Set-Cookie header value that
// has already been flattened into one string, which is how httpx reports it.
// Parsing a joined Set-Cookie is only safe because of where cookie boundaries
// can legally appear; a real response is parsed properly by the function above.
func cookieNamesFromHeader(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var names []string
	for _, m := range setCookieNameRe.FindAllStringSubmatch(v, -1) {
		names = append(names, m[1])
	}
	return dedupeCookies(names)
}

// dedupeCookies sorts and deduplicates, so the stored list is stable between
// runs and a rescan does not look like a change.
func dedupeCookies(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, n := range in {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > 50 { // a page setting more than this is noise, not a fingerprint
		out = out[:50]
	}
	return out
}

// headerField reads one header out of httpx's JSON, which lowercases names and
// replaces dashes with underscores ("Set-Cookie" -> "set_cookie").
func headerField(row map[string]any, key string) string {
	h, ok := row["header"].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := h[key].(string); ok {
		return v
	}
	return ""
}

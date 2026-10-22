// Package fingerprint names the edge products an attack surface is most often
// breached through — Citrix NetScaler, Atlassian Confluence and Jira, Zammad,
// Zimbra, Microsoft Exchange, Kerio Connect — from one HTTP response.
//
// Detection is a pure function of a response, so the same rules run inside
// the worker's web stage, over banners exported from Shodan, Censys or FOFA
// (tools/fpcheck), and over the fixtures in testdata/. Nothing here sends a
// request; Probes only says which follow-up paths would confirm a product or
// read its version, and fetch.go is the one place that asks for them.
package fingerprint

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Response is what one HTTP request returned, reduced to what the rules read.
// Cookie values are never kept: a name is a fingerprint, a value a session.
type Response struct {
	Path        string      `json:"path,omitempty"` // the request path; "" means "/"
	Status      int         `json:"status,omitempty"`
	Headers     http.Header `json:"headers,omitempty"`
	Cookies     []string    `json:"cookies,omitempty"`
	Title       string      `json:"title,omitempty"`
	Body        string      `json:"body,omitempty"`
	CertSubject string      `json:"cert_subject,omitempty"`
}

// Match is one product named by a response, or by several merged.
type Match struct {
	Product    string   `json:"product"`
	Version    string   `json:"version,omitempty"`
	Release    string   `json:"release,omitempty"` // a version's marketing name: "Exchange 2019"
	Confidence int      `json:"confidence"`
	Features   []string `json:"features,omitempty"` // "Gateway", "SAML", …
	Evidence   []string `json:"evidence,omitempty"` // which signals fired
}

// Reported is the confidence a match must reach to be stated as a fact.
// Below it a product is only suspected: enough to ask for a probe path, not
// enough to put a name on a host.
const (
	Reported  = 60
	suspected = 40
)

// The product names are the ones the tech table shows and search matches on.
const (
	NetScaler  = "Citrix NetScaler"
	Confluence = "Atlassian Confluence"
	Jira       = "Atlassian Jira"
	Zammad     = "Zammad"
	Zimbra     = "Zimbra"
	Exchange   = "Microsoft Exchange"
	Kerio      = "Kerio Connect"
)

// Products lists every product the rules know, in a stable order.
func Products() []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.name
	}
	return out
}

// Lookup resolves a short alias ("exchange", "netscaler", "citrix") or a full
// product name to the product name, "" when nothing matches.
func Lookup(alias string) string {
	a := strings.ToLower(strings.TrimSpace(alias))
	for _, r := range rules {
		if strings.ToLower(r.name) == a {
			return r.name
		}
		for _, x := range r.aliases {
			if x == a {
				return r.name
			}
		}
	}
	return ""
}

// signal is one piece of evidence. A product's confidence is its strongest
// signal, raised a little by each further one that agrees.
type signal struct {
	what    string
	weight  int
	feature string // a capability the signal shows, "" for none
	test    func(r *Response) bool
}

type product struct {
	name    string
	aliases []string
	signals []signal
	// version reads a version from a response already known to be this
	// product; "" when the response does not carry one.
	version func(r *Response) string
	// probes are paths that confirm the product or carry its version. They
	// are asked for only when the product is suspected and not yet settled.
	probes []string
	// extra adds features that depend on more than one signal.
	extra func(r *Response, m *Match)
}

// Detect names the products one response shows, strongest first. Suspected
// products (below Reported) are included so Probes can follow them up;
// callers reporting results filter on Reported, or use Settled.
func Detect(r Response) []Match {
	var out []Match
	for _, p := range rules {
		m := Match{Product: p.name}
		feats := map[string]bool{}
		strongest := 0
		for _, s := range p.signals {
			if !s.test(&r) {
				continue
			}
			m.Evidence = append(m.Evidence, s.what)
			strongest = max(strongest, s.weight)
			if s.feature != "" {
				feats[s.feature] = true
			}
		}
		if strongest < suspected {
			continue
		}
		m.Confidence = min(99, strongest+5*(len(m.Evidence)-1))
		if p.version != nil {
			m.Version = p.version(&r)
		}
		for f := range feats {
			m.Features = append(m.Features, f)
		}
		if p.extra != nil {
			p.extra(&r, &m)
		}
		sort.Strings(m.Features)
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

// Merge folds the matches of several responses from one site together: the
// higher confidence, raised when two responses agree; the first version
// found; the union of features and evidence.
func Merge(sets ...[]Match) []Match {
	var out []Match
	index := map[string]int{}
	for _, set := range sets {
		for _, m := range set {
			i, seen := index[m.Product]
			if !seen {
				index[m.Product] = len(out)
				m.Features = append([]string(nil), m.Features...)
				m.Evidence = append([]string(nil), m.Evidence...)
				out = append(out, m)
				continue
			}
			o := &out[i]
			o.Confidence = min(99, max(o.Confidence, m.Confidence)+5)
			if o.Version == "" {
				o.Version, o.Release = m.Version, m.Release
			}
			o.Features = union(o.Features, m.Features)
			o.Evidence = union(o.Evidence, m.Evidence)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

// Settled keeps the matches confident enough to report.
func Settled(ms []Match) []Match {
	var out []Match
	for _, m := range ms {
		if m.Confidence >= Reported {
			out = append(out, m)
		}
	}
	return out
}

// MaxProbes bounds the follow-up requests one site gets, whatever it
// resembles. A page that half-matches every rule is not worth twenty requests.
const MaxProbes = 6

// Probes returns the follow-up paths worth one request each: `first` when
// it is not "" (the caller's same-site redirect target — Exchange answers /
// with a redirect to /owa/), then the confirm-or-version paths of each
// product suspected but not settled. Paths already fetched (`done`) are left
// out.
func Probes(first string, ms []Match, done map[string]bool) []string {
	var out []string
	add := func(p string) {
		if p == "" || done[p] || len(out) >= MaxProbes {
			return
		}
		for _, x := range out {
			if x == p {
				return
			}
		}
		out = append(out, p)
	}
	add(first)
	for _, m := range ms {
		if m.Confidence >= 90 && m.Version != "" {
			continue
		}
		for _, p := range rules {
			if p.name == m.Product {
				for _, path := range p.probes {
					add(path)
				}
			}
		}
	}
	return out
}

// SameSitePath returns the path a redirect points to when it stays on the
// site at base ("https://host:port"), "" when it leaves. A redirect to
// another host is not followed: that host is not one this request was
// authorized for.
func SameSitePath(base string, r Response) string {
	if r.Status < 300 || r.Status >= 400 {
		return ""
	}
	loc := r.Headers.Get("Location")
	if strings.HasPrefix(loc, "//") {
		return ""
	}
	if !strings.HasPrefix(loc, "/") {
		b, err1 := url.Parse(base)
		l, err2 := url.Parse(loc)
		if err1 != nil || err2 != nil || !strings.EqualFold(l.Scheme, b.Scheme) || !strings.EqualFold(l.Host, b.Host) {
			return ""
		}
		loc = l.EscapedPath()
		if loc == "" {
			loc = "/"
		}
	}
	if i := strings.IndexAny(loc, "?#"); i >= 0 {
		loc = loc[:i]
	}
	return loc
}

func union(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	sort.Strings(a)
	return a
}

// --- signal helpers ---

func (r *Response) path() string {
	if r.Path == "" {
		return "/"
	}
	return r.Path
}

func hasHeader(name string) func(*Response) bool {
	return func(r *Response) bool { return r.Headers.Get(name) != "" }
}

func headerHas(name, sub string) func(*Response) bool {
	sub = strings.ToLower(sub)
	return func(r *Response) bool { return strings.Contains(strings.ToLower(r.Headers.Get(name)), sub) }
}

func locationHas(sub string) func(*Response) bool { return headerHas("Location", sub) }

func cookie(names ...string) func(*Response) bool {
	return func(r *Response) bool {
		for _, c := range r.Cookies {
			for _, n := range names {
				if strings.EqualFold(c, n) {
					return true
				}
			}
		}
		return false
	}
}

func cookiePrefix(prefix string) func(*Response) bool {
	prefix = strings.ToLower(prefix)
	return func(r *Response) bool {
		for _, c := range r.Cookies {
			if strings.HasPrefix(strings.ToLower(c), prefix) {
				return true
			}
		}
		return false
	}
}

// bodyHas is case-insensitive: markup casing varies between releases.
func bodyHas(subs ...string) func(*Response) bool {
	for i := range subs {
		subs[i] = strings.ToLower(subs[i])
	}
	return func(r *Response) bool {
		b := strings.ToLower(r.Body)
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}
}

// bodyHasAll needs every substring, for markers that mean little alone.
func bodyHasAll(subs ...string) func(*Response) bool {
	for i := range subs {
		subs[i] = strings.ToLower(subs[i])
	}
	return func(r *Response) bool {
		b := strings.ToLower(r.Body)
		for _, s := range subs {
			if !strings.Contains(b, s) {
				return false
			}
		}
		return true
	}
}

func titleHas(subs ...string) func(*Response) bool {
	for i := range subs {
		subs[i] = strings.ToLower(subs[i])
	}
	return func(r *Response) bool {
		t := strings.ToLower(r.Title)
		for _, s := range subs {
			if strings.Contains(t, s) {
				return true
			}
		}
		return false
	}
}

func bodyMatches(re *regexp.Regexp) func(*Response) bool {
	return func(r *Response) bool { return re.MatchString(r.Body) }
}

func all(tests ...func(*Response) bool) func(*Response) bool {
	return func(r *Response) bool {
		for _, t := range tests {
			if !t(r) {
				return false
			}
		}
		return true
	}
}

// firstGroup returns the first capture of the first expression that matches s.
func firstGroup(s string, res ...*regexp.Regexp) string {
	for _, re := range res {
		if m := re.FindStringSubmatch(s); len(m) > 1 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}

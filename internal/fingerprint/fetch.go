package fingerprint

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Fetcher asks one site for its front page and then for the follow-up paths
// Probes names, one request at a time. The client must not follow
// redirects: a redirect's Location is itself a signal, and following it
// could take the request to a host nobody authorized.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
	Delay     time.Duration // between requests to the same site
	Timeout   time.Duration // per request; 8s when zero
}

// Result is what a fetch found, with every response it read, root first.
type Result struct {
	Matches   []Match
	Responses []Response
}

// Run fetches base ("https://host:port") and up to MaxProbes follow-ups, and
// returns the merged matches that reached Reported.
func (f Fetcher) Run(ctx context.Context, base string) (Result, error) {
	base = strings.TrimRight(base, "/")
	root, err := f.get(ctx, base, "/")
	if err != nil {
		return Result{}, err
	}
	res := Result{Responses: []Response{root}}
	sets := [][]Match{Detect(root)}
	done := map[string]bool{"/": true}
	for _, path := range Probes(SameSitePath(base, root), sets[0], done) {
		if ctx.Err() != nil {
			break
		}
		done[path] = true
		if f.Delay > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(f.Delay):
			}
		}
		r, err := f.get(ctx, base, path)
		if err != nil {
			continue
		}
		res.Responses = append(res.Responses, r)
		sets = append(sets, Detect(r))
	}
	res.Matches = Settled(Merge(sets...))
	return res, nil
}

const maxBody = 512 * 1024

func (f Fetcher) get(ctx context.Context, base, path string) (Response, error) {
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return Response{}, err
	}
	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	r := Response{
		Path:    path,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    string(body),
		Title:   Title(string(body)),
	}
	for _, c := range resp.Cookies() {
		if c.Name != "" {
			r.Cookies = append(r.Cookies, c.Name)
		}
	}
	// The cookies are kept by name above; their values are sessions.
	r.Headers.Del("Set-Cookie")
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.CertSubject = resp.TLS.PeerCertificates[0].Subject.String()
	}
	return r, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Title is the page's <title>, whitespace collapsed.
func Title(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(m[1]), " ")
}

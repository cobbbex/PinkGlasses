package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// dnsBrute brute-forces subdomains with shuffledns against one wordlist. The
// planner creates one of these tasks per wordlist, so multiple lists run as
// independent tasks and can be spread across workers instead of grinding
// through millions of names on a single box.
func (s *Scanner) dnsBrute(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].Domain == "" {
		return nil, nil
	}
	root := job.Targets[0].Domain

	if !have("shuffledns") {
		slog.Warn("dns_brute skipped: shuffledns not installed")
		return nil, nil
	}

	wordlist, err := s.wordlistPath(ctx, job)
	if err != nil {
		return nil, err
	}
	if wordlist == "" {
		return nil, nil // nothing to brute-force with
	}
	resolvers, err := s.resolversPath(ctx, job)
	if err != nil {
		return nil, err
	}
	if resolvers == "" {
		slog.Warn("dns_brute skipped: no resolver list available")
		return nil, nil
	}

	pr := jobParams(job)
	threads := pr.intStr("shuffledns_threads", "300")
	inflight, _ := strconv.Atoi(threads)
	names := countLines(wordlist)
	budget := bruteTimeout(names, inflight)
	// A random subset of the resolver list, so one task holds at most that
	// many NAT and conntrack entries on the host and on whatever router is
	// in front of it — the thing a brute force can exhaust for the web app.
	maxRes, _ := strconv.Atoi(pr.intStr("shuffledns_resolvers_max", "500"))
	if sub, n, err := sampleLines(resolvers, maxRes); err == nil && sub != "" {
		defer os.Remove(sub)
		resolvers = sub
		slog.Info("dns_brute resolvers", "using", n, "cap", maxRes)
	}
	slog.Info("dns_brute starting", "domain", root, "wordlist", job.Params.WordlistName,
		"names", names, "threads", threads, "budget", budget.String())
	// No -mode flag: this shuffledns build rejects it and exits with a usage
	// error, which used to make the whole stage silently return nothing.
	// Passing -d with -w is what selects brute-force mode.
	// -strict-wildcard re-checks every hit for wildcard DNS. Without it a
	// wildcarded domain (or a resolver that hijacks NXDOMAIN) turns the whole
	// wordlist into "found" subdomains. It costs extra queries per hit, which
	// is cheap next to inventing thousands of hosts that do not exist.
	lines, runErr := runLines(ctx, budget, "shuffledns",
		"-d", root, "-w", wordlist, "-r", resolvers,
		"-t", threads,
		"-strict-wildcard", "-silent")

	seen := map[string]bool{}
	for _, l := range lines {
		name := normalizeHost(l)
		if name == "" || seen[name] || !inScope(name, root) {
			continue
		}
		seen[name] = true
	}

	// Confirm every hit through the worker's own resolution before it is
	// reported. A public resolver list always holds some that answer for
	// names that do not exist; a brute force spread over a random few
	// hundred of them surfaces those answers as "found" names. Only a name
	// that resolves again, through trusted resolvers, is a name.
	resolved := s.resolveNames(ctx, keysOf(seen), pr)
	confirmed := map[string]bool{}
	for _, o := range resolved {
		if o.Type == scanproto.ObsDNSRecord && o.Domain != "" {
			confirmed[o.Domain] = true
		}
	}
	var obs []scanproto.Observation
	for name := range seen {
		if confirmed[name] {
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsSubdomain, Domain: name, Source: "shuffledns",
			})
		}
	}
	slog.Info("dns_brute finished", "domain", root,
		"wordlist", job.Params.WordlistName, "resolvers", job.Params.ResolversName,
		"found", len(obs), "unconfirmed_dropped", len(seen)-len(obs))
	obs = append(obs, resolved...)

	// A list the tool could not get through in its budget is a failed task,
	// said so, with what was found kept — not a task that reads "done" with
	// nothing after an hour, which is what six of these once looked like.
	// Permanent, because the same list at the same rate takes the same time.
	var to *ToolTimeout
	if errors.As(runErr, &to) {
		return obs, permanent(fmt.Errorf(
			"shuffledns did not finish the %s-name list %q within %s at %s threads; "+
				"%d names found before it was stopped — raise Bruteforce threads under "+
				"Customize scanning, or brute-force with a smaller list",
			humanCount(names), job.Params.WordlistName, budget.Round(time.Minute), threads, len(confirmed)))
	}
	return obs, nil
}

// bruteTimeout is how long a brute force over `names` candidates at
// `inflight` concurrent queries may take: an hour, plus twice the time the
// list takes at a conservative ten queries per second per in-flight slot
// (100 ms round trips). 9.5M names at 300 get about 7.3 h; at 1000, 3.6 h.
// It is a ceiling for slow resolvers, not the expected duration.
func bruteTimeout(names, inflight int) time.Duration {
	if inflight < 1 {
		inflight = 1
	}
	return time.Hour + time.Duration(2*names/(inflight*10))*time.Second
}

// sampleLines writes up to n lines of path, chosen at random, to a temporary
// file and returns it with the count. A list no longer than n is used as is
// (empty path returned).
func sampleLines(path string, n int) (string, int, error) {
	if n <= 0 {
		return "", 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) <= n {
		return "", len(lines), nil
	}
	rand.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	f, err := os.CreateTemp("", "asm-resolvers-*.txt")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines[:n], "\n") + "\n"); err != nil {
		return "", 0, err
	}
	return f.Name(), n, nil
}

// countLines counts the newline-terminated lines in a file; 0 if unreadable.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	n := 0
	for {
		c, err := f.Read(buf)
		n += bytes.Count(buf[:c], []byte{'\n'})
		if err != nil {
			return n
		}
	}
}

// humanCount renders 9544235 as "9.5M" and 3244 as "3.2k".
func humanCount(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	}
	return fmt.Sprint(n)
}

// wordlistPath returns a local path to this job's wordlist.
func (s *Scanner) wordlistPath(ctx context.Context, job scanproto.Job) (string, error) {
	return s.cachedList(ctx, job.Params.WordlistURL, job.Params.WordlistSHA,
		job.Params.WordlistName, wordlistDNS())
}

// resolversPath returns a local path to this job's resolver list, falling back
// to the list baked into the image when the run has none attached.
func (s *Scanner) resolversPath(ctx context.Context, job scanproto.Job) (string, error) {
	return s.cachedList(ctx, job.Params.ResolversURL, job.Params.ResolversSHA,
		job.Params.ResolversName, resolversFile())
}

// cachedList downloads a line-list on first use and caches it by content hash,
// so a worker fetches a given file once no matter how many tasks need it. A
// missing URL falls back to the copy shipped in the image rather than failing.
// listCached reports whether a list with this hash is already on disk.
func (s *Scanner) listCached(sha, name string) bool {
	key := sha
	if key == "" {
		key = fmt.Sprintf("%x", sha256.Sum256([]byte(name)))
	}
	fi, err := os.Stat(filepath.Join(envOr("ASM_WORDLIST_CACHE", "/var/cache/asm/wordlists"), key+".txt"))
	return err == nil && fi.Size() > 0
}

func (s *Scanner) cachedList(ctx context.Context, url, sha, name, fallback string) (string, error) {
	if url == "" {
		if fileExists(fallback) {
			return fallback, nil
		}
		return "", nil
	}

	cacheDir := envOr("ASM_WORDLIST_CACHE", "/var/cache/asm/wordlists")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	key := sha
	if key == "" {
		key = fmt.Sprintf("%x", sha256.Sum256([]byte(name)))
	}
	path := filepath.Join(cacheDir, key+".txt")

	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return path, nil // already cached
	}

	slog.Info("downloading list", "name", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if s.Authorize != nil {
		s.Authorize(req) // the gateway serves lists to enrolled workers only
	}
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", name, resp.Status)
	}

	// Write to a temp file and rename, so a killed download never leaves a
	// truncated list in the cache for the next task to use.
	tmp, err := os.CreateTemp(cacheDir, ".partial-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	if sha != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != sha {
			return "", fmt.Errorf("%s hash mismatch: got %s want %s", name, got, sha)
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

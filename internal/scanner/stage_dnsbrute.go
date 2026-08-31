package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
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
	// No -mode flag: this shuffledns build rejects it and exits with a usage
	// error, which used to make the whole stage silently return nothing.
	// Passing -d with -w is what selects brute-force mode.
	lines, _ := runLines(ctx, 60*time.Minute, "shuffledns",
		"-d", root, "-w", wordlist, "-r", resolvers,
		"-t", pr.intStr("shuffledns_threads", "100"),
		"-silent")

	var obs []scanproto.Observation
	seen := map[string]bool{}
	for _, l := range lines {
		name := normalizeHost(l)
		if name == "" || seen[name] || !inScope(name, root) {
			continue
		}
		seen[name] = true
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsSubdomain, Domain: name, Source: "shuffledns",
		})
	}
	slog.Info("dns_brute finished", "domain", root,
		"wordlist", job.Params.WordlistName, "resolvers", job.Params.ResolversName,
		"found", len(obs))

	// Resolve what we found so the coalesce barrier downstream sees addresses.
	obs = append(obs, s.resolveNames(ctx, keysOf(seen), pr)...)
	return obs, nil
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

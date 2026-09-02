package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// commonPaths for the built-in fallback content probe.
var commonPaths = []string{
	"/admin", "/login", "/.git/config", "/.env", "/api", "/robots.txt",
	"/backup", "/config", "/wp-admin/", "/phpinfo.php", "/server-status", "/actuator",
}

// dirBrute follows Tools.md: crawl with katana + urlfinder to seed real paths,
// then brute-force with gobuster (Tools.md default) or ffuf. It is the loudest
// stage in the pipeline, so concurrency is deliberately modest.
func (s *Scanner) dirBrute(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	base := targetURL(job)
	if base == "" {
		return nil, nil
	}
	ip, port := targetIPPort(job)

	seen := map[string]int{}
	add := func(path string, status int) {
		path = cleanPath(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; !ok {
			seen[path] = status
		}
	}

	// --- katana crawl (Tools.md: katana -d 5 -jsl -c 3 -p 3 -rl 10 -silent) ---
	pr := jobParams(job)
	if have("katana") && pr.enabled("katana") {
		// katana emits URLs; -jsonl adds structure but plain -silent lines are
		// simplest and robust. (-json is not a valid flag and aborts the run.)
		kp := jobParams(job)
		kArgs := []string{
			"-d", kp.intStr("katana_depth", "3"),
			"-c", kp.intStr("katana_concurrency", "3"), "-p", "3",
			"-rl", kp.intStr("katana_rate_limit", "10"),
			"-silent",
		}
		if kp.boolVal("katana_js_crawl", false) {
			kArgs = append(kArgs, "-jsl")
		}
		if px := proxyFor(job, kp); proxyUsableBy("katana", px) {
			logProxy("dir_brute", "katana", px)
			kArgs = append(kArgs, "-proxy", px)
		}
		kArgs = append(kArgs, "-u", base)
		lines, _ := runLines(ctx, 90*time.Second, "katana", kArgs...)
		maxURLs := 2000
		if n, err := strconv.Atoi(kp.intStr("katana_max_urls", "2000")); err == nil {
			maxURLs = n
		}
		for i, u := range lines {
			if i >= maxURLs { // a crawl can return tens of thousands; keep it bounded
				break
			}
			add(pathOf(u), 0)
		}
	}

	// --- urlfinder passive URLs (Tools.md: urlfinder -silent) ---
	if have("urlfinder") {
		lines, _ := runLines(ctx, 30*time.Second, "urlfinder", "-silent", "-d", hostOf(base))
		for _, u := range lines {
			if inHost(u, hostOf(base)) {
				add(pathOf(u), 0)
			}
		}
	}

	// --- gobuster dir brute (Tools.md default; ffuf as the alternative) ---
	// The list this run selected in the registry, downloaded and cached by
	// content hash, or the one baked into the image when the run has none.
	wordlist, _ := s.dirWordlistPath(ctx, job)

	switch {
	case have("gobuster") && pr.enabled("gobuster") && fileExists(wordlist):
		// Tools.md: gobuster dir -u <url> -w <wordlist> -k [--exclude-length N]
		wl := wordlist
		if job.Params.WordlistURL == "" && pr.str("dir_wordlist", "common") == "dns" {
			// No registry list attached, so the shipped ones are all there is
			// and the parameter still chooses between them.
			wl = wordlistDNS()
		}
		args := []string{"dir", "-q", "-u", base, "-w", wl, "-k",
			"--no-color", "-t", pr.intStr("dir_concurrency", "10"),
			"-a", userAgent(pr)}
		if px := proxyFor(job, pr); proxyUsableBy("gobuster", px) {
			logProxy("dir_brute", "gobuster", px)
			args = append(args, "--proxy", px)
		}
		if el := pr.intStr("dir_exclude_length", "0"); el != "0" {
			args = append(args, "--exclude-length", el)
		}
		if ext := pr.str("dir_extensions", ""); ext != "" {
			args = append(args, "-x", ext)
		}
		if sc := pr.str("dir_status_codes", ""); sc != "" {
			// gobuster rejects -s combined with its default blacklist
			args = append(args, "-s", sc, "-b", "")
		}
		lines, _ := runLines(ctx, 10*time.Minute, "gobuster", args...)
		for _, ln := range lines {
			if p, st := parseGobusterLine(ln); p != "" {
				add(p, st)
			}
		}
	case have("ffuf") && pr.enabled("gobuster"):
		// ffuf is gobuster's stand-in, so it answers to the same switch: turning
		// the brute force off must not quietly swap in the other tool.
		wl := job.Params.Wordlist
		if wl == "" {
			wl = wordlist
		}
		rows, _ := runJSONL(ctx, 5*time.Minute, "ffuf", "-s", "-of", "json", "-u", base+"/FUZZ", "-w", wl)
		for _, r := range rows {
			if p := str(r, "input"); p != "" {
				add("/"+p, num(r, "status"))
			}
		}
	case !pr.enabled("gobuster"):
		// Brute forcing is switched off; the crawl's paths are still reported.
		slog.Info("directory brute force disabled", "url", base)
	default:
		// no brute-force tool: probe a short common-path list so the stage still
		// contributes something on a bare worker.
		client := proxiedClient(proxyFor(job, pr))
		for _, p := range commonPaths {
			req, _ := http.NewRequestWithContext(withTimeout(ctx, 6*time.Second), http.MethodGet, base+p, nil)
			req.Header.Set("User-Agent", userAgent(pr))
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode < 400 || resp.StatusCode == 403 {
				add(p, resp.StatusCode)
			}
		}
	}

	// Crawled/passive paths arrive with status 0. Probe them (bounded) so every
	// reported path carries a real HTTP status, and drop the ones that 404.
	obs := s.probePaths(ctx, base, ip, port, seen, pr, proxyFor(job, pr))

	byStatus := map[int]int{}
	for _, o := range obs {
		byStatus[o.Status]++
		slog.Debug("path", "url", base, "path", o.Path, "status", o.Status)
	}
	slog.Info("content discovery", "url", base, "wordlist", listName(job, wordlist),
		"candidates", len(seen), "confirmed", len(obs), "by_status", fmt.Sprint(byStatus))
	return obs, nil
}

// dirWordlistPath returns a local path to this job's directory wordlist: the
// one its run selected in the registry, or the list shipped in the worker image
// when no run list is attached.
func (s *Scanner) dirWordlistPath(ctx context.Context, job scanproto.Job) (string, error) {
	return s.cachedList(ctx, job.Params.WordlistURL, job.Params.WordlistSHA,
		job.Params.WordlistName, wordlistDir())
}

// cleanPath keeps only plausible URL paths, rejecting the text fragments a
// crawler extracts from page bodies (quotes, prose, spaces).
func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if q := strings.IndexAny(path, "?#"); q >= 0 {
		path = path[:q]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 256 {
		return ""
	}
	const badRunes = `"'<>{}|^\` + "`"
	for _, r := range path {
		// ASCII path characters only; anything else is almost certainly text
		// scraped out of the page rather than a real endpoint.
		if r > 126 || r < 33 || strings.ContainsRune(badRunes, r) {
			return ""
		}
	}
	return path
}

// probePaths GETs each candidate path (capped, modest concurrency) and returns
// observations only for paths that exist. gobuster/ffuf hits already carry a
// status and are trusted as-is; everything else is verified here.
func (s *Scanner) probePaths(ctx context.Context, base, ip string, port int, seen map[string]int,
	pr params, px string) []scanproto.Observation {
	type job struct {
		path   string
		status int
	}
	var todo []job
	for p, st := range seen {
		todo = append(todo, job{p, st})
	}
	sort.Slice(todo, func(a, b int) bool { return todo[a].path < todo[b].path })
	if len(todo) > 1500 {
		todo = todo[:1500]
	}

	client := proxiedClient(px)
	var (
		obs []scanproto.Observation
		mu  sync.Mutex
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 10) // this is the loudest stage; keep concurrency modest

	for _, j := range todo {
		if j.status != 0 { // already verified by gobuster/ffuf
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsPath, IP: ip, Port: port, Path: j.path, Status: j.status})
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			req, _ := http.NewRequestWithContext(withTimeout(ctx, 8*time.Second), http.MethodGet, base+path, nil)
			req.Header.Set("User-Agent", userAgent(pr))
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == 404 {
				return
			}
			mu.Lock()
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsPath, IP: ip, Port: port, Path: path, Status: resp.StatusCode})
			mu.Unlock()
		}(j.path)
	}
	wg.Wait()
	return obs
}

// listName names the wordlist a run actually used, so the log distinguishes a
// registry list from the image's fallback.
func listName(job scanproto.Job, path string) string {
	if job.Params.WordlistName != "" {
		return job.Params.WordlistName
	}
	return "image default (" + path + ")"
}

// pathOf extracts the path component from a URL, defaulting to "/".
func pathOf(u string) string {
	i := strings.Index(u, "://")
	if i >= 0 {
		u = u[i+3:]
	}
	if j := strings.IndexByte(u, '/'); j >= 0 {
		return u[j:]
	}
	return "/"
}

// parseGobusterLine parses one gobuster dir hit, e.g.
// "index.html           (Status: 200) [Size: 6974]" or
// "shared               (Status: 301) [Size: 312] [--> http://h/shared/]".
//
// The leading slash is optional: gobuster prints the raw wordlist entry, so in
// quiet mode a hit arrives as "index.html". Requiring the slash silently threw
// away every result this stage ever produced, leaving only the paths the
// crawler had already found.
func parseGobusterLine(ln string) (string, int) {
	ln = strings.TrimSpace(ln)
	if ln == "" {
		return "", 0
	}
	path := ln
	if i := strings.IndexAny(ln, " \t"); i > 0 {
		path = ln[:i]
	}
	// Only a hit line starts with a path; gobuster's own notices do not.
	if strings.ContainsAny(path, "()[]") {
		return "", 0
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	status := 0
	if i := strings.Index(ln, "Status: "); i >= 0 {
		fmt.Sscanf(ln[i+len("Status: "):], "%d", &status)
	}
	return path, status
}

var _ = time.Second

// hostOf returns the host[:port] component of a URL.
func hostOf(u string) string {
	i := strings.Index(u, "://")
	if i >= 0 {
		u = u[i+3:]
	}
	if j := strings.IndexByte(u, '/'); j >= 0 {
		u = u[:j]
	}
	return u
}

// inHost reports whether a discovered URL belongs to the target host, so a
// passive URL source cannot pull in unrelated paths.
func inHost(u, host string) bool {
	return host != "" && strings.Contains(u, host)
}

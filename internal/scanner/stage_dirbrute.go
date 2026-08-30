package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
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
		if path == "" {
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if _, ok := seen[path]; !ok {
			seen[path] = status
		}
	}

	// --- katana crawl (Tools.md: katana -d 5 -jsl -c 3 -p 3 -rl 10 -silent) ---
	if have("katana") {
		// katana emits URLs; -jsonl adds structure but plain -silent lines are
		// simplest and robust. (-json is not a valid flag and aborts the run.)
		lines, _ := runLines(ctx, 90*time.Second, "katana",
			"-d", "3", "-c", "3", "-p", "3", "-rl", "10", "-silent", "-u", base)
		for i, u := range lines {
			if i >= 2000 { // a crawl can return tens of thousands; keep it bounded
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
	switch {
	case have("gobuster") && fileExists(wordlistDir()):
		// Tools.md: gobuster dir -u <url> -w <wordlist> -k [--exclude-length N]
		args := []string{"dir", "-q", "-u", base, "-w", wordlistDir(), "-k",
			"--no-color", "-t", "10"}
		if el := envOr("ASM_GOBUSTER_EXCLUDE_LENGTH", ""); el != "" {
			args = append(args, "--exclude-length", el)
		}
		lines, _ := runLines(ctx, 10*time.Minute, "gobuster", args...)
		for _, ln := range lines {
			if p, st := parseGobusterLine(ln); p != "" {
				add(p, st)
			}
		}
	case have("ffuf"):
		wl := job.Params.Wordlist
		if wl == "" {
			wl = wordlistDir()
		}
		rows, _ := runJSONL(ctx, 5*time.Minute, "ffuf", "-s", "-of", "json", "-u", base+"/FUZZ", "-w", wl)
		for _, r := range rows {
			if p := str(r, "input"); p != "" {
				add("/"+p, num(r, "status"))
			}
		}
	default:
		// no brute-force tool: probe a short common-path list so the stage still
		// contributes something on a bare worker.
		client := webClient()
		for _, p := range commonPaths {
			req, _ := http.NewRequestWithContext(withTimeout(ctx, 6*time.Second), http.MethodGet, base+p, nil)
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

	var obs []scanproto.Observation
	for p, st := range seen {
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsPath, IP: ip, Port: port, Path: p, Status: st})
	}
	return obs, nil
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

// parseGobusterLine parses gobuster dir's default output, e.g.
// "/admin (Status: 301) [Size: 0]".
func parseGobusterLine(ln string) (string, int) {
	ln = strings.TrimSpace(ln)
	if !strings.HasPrefix(ln, "/") {
		return "", 0
	}
	path := ln
	status := 0
	if i := strings.Index(ln, " "); i > 0 {
		path = ln[:i]
	}
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

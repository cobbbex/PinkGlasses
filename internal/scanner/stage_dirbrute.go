package scanner

import (
	"context"
	"net/http"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

// commonPaths for the built-in fallback content probe.
var commonPaths = []string{
	"/admin", "/login", "/.git/config", "/.env", "/api", "/robots.txt",
	"/backup", "/config", "/wp-admin/", "/phpinfo.php", "/server-status", "/actuator",
}

// dirBrute: katana (crawl seed) -> ffuf/feroxbuster when present, else a small
// built-in probe of common paths (worker-pipeline.md §5 — no PD tool here).
func (s *Scanner) dirBrute(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	ip, port := targetIPPort(job)
	base := job.Targets[0].URL
	if base == "" {
		return nil, nil
	}

	if have("ffuf") {
		wl := job.Params.Wordlist
		if wl == "" {
			wl = "/usr/share/wordlists/dirb/common.txt"
		}
		rows, _ := runJSONL(ctx, 5*time.Minute, "ffuf", "-s", "-of", "json", "-u", base+"/FUZZ", "-w", wl)
		var obs []scanproto.Observation
		for _, r := range rows {
			if p := str(r, "input"); p != "" {
				obs = append(obs, scanproto.Observation{Type: scanproto.ObsPath, IP: ip, Port: port, Path: "/" + p, Status: num(r, "status")})
			}
		}
		return obs, nil
	}

	// fallback: probe a short list of interesting paths
	client := webClient()
	var obs []scanproto.Observation
	for _, p := range commonPaths {
		select {
		case <-ctx.Done():
			return obs, nil
		default:
		}
		req, _ := http.NewRequestWithContext(withTimeout(ctx, 6*time.Second), http.MethodGet, base+p, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsPath, IP: ip, Port: port, Path: p, Status: resp.StatusCode})
		}
	}
	return obs, nil
}

var _ = time.Second

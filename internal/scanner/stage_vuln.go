package scanner

import (
	"context"
	"strings"
	"time"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// vulnCheck runs nuclei against a live URL (Tools.md §Vulnerability Scanner).
//
// This stage was previously unreachable: it is declared in scanproto but was
// never handled in Scanner.Run, so nuclei could never execute.
func (s *Scanner) vulnCheck(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	url := targetURL(job)
	if url == "" || !have("nuclei") {
		return nil, nil
	}
	ip, port := targetIPPort(job)

	// Tools.md: nuclei -l urls   (default templates)
	//           nuclei -l urls -t <dir>   (custom template set)
	pr := jobParams(job)
	args := []string{"-silent", "-jsonl", "-u", url,
		"-timeout", pr.intStr("nuclei_timeout_s", "10"), "-retries", "1",
		"-rl", pr.intStr("nuclei_rate_limit", "150"),
		"-c", pr.intStr("nuclei_concurrency", "25")}
	if dir := envOr("ASM_NUCLEI_TEMPLATES", ""); dir != "" && fileExists(dir) {
		args = append(args, "-t", dir)
	}
	sev := pr.str("nuclei_severity", "low")
	if sev != "all" {
		order := []string{"info", "low", "medium", "high", "critical"}
		keep := []string{}
		start := false
		for _, s := range order {
			if s == sev {
				start = true
			}
			if start {
				keep = append(keep, s)
			}
		}
		args = append(args, "-severity", strings.Join(keep, ","))
	}

	rows, _ := runJSONL(ctx, 15*time.Minute, "nuclei", args...)

	var obs []scanproto.Observation
	for _, r := range rows {
		info, _ := r["info"].(map[string]any)
		name, severity := "", "info"
		if info != nil {
			if v, ok := info["name"].(string); ok {
				name = v
			}
			if v, ok := info["severity"].(string); ok {
				severity = v
			}
		}
		id := str(r, "template-id")
		if name == "" {
			name = id
		}
		obs = append(obs, scanproto.Observation{
			Type:            scanproto.ObsFinding,
			IP:              ip,
			Port:            port,
			FindingKind:     "nuclei:" + id,
			FindingSeverity: strings.ToLower(severity),
			FindingTitle:    name,
			Banner:          str(r, "matched-at"),
		})
	}
	return obs, nil
}

// targetURL returns the job's URL target, deriving one from ip:port if needed.
func targetURL(job scanproto.Job) string {
	if len(job.Targets) == 0 {
		return ""
	}
	if u := job.Targets[0].URL; u != "" {
		return u
	}
	ip, port := targetIPPort(job)
	if ip == "" || port == 0 {
		return ""
	}
	return schemesFor(port)[0] + "://" + ip + portSuffix(schemesFor(port)[0], port)
}

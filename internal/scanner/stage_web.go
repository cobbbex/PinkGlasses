package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func webClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // we inspect, not trust
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// serviceProbe: httpx when present, else stdlib HTTP + TLS capture
// (worker-pipeline.md §3 / §2 web versions).
func (s *Scanner) serviceProbe(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	ip, port := targetIPPort(job)
	if ip == "" {
		return nil, nil
	}
	var obs []scanproto.Observation
	client := webClient()

	for _, scheme := range schemesFor(port) {
		url := scheme + "://" + ip + portSuffix(scheme, port)
		req, _ := http.NewRequestWithContext(withTimeout(ctx, 10*time.Second), http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "asm-worker")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		headers := map[string]string{}
		for k := range resp.Header {
			headers[k] = resp.Header.Get(k)
		}
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsHTTP, IP: ip, Port: port,
			Status: resp.StatusCode, Title: extractTitle(body), Headers: headers,
			Favicon: "", Product: resp.Header.Get("Server"),
		})
		// TLS certificate capture on https.
		if scheme == "https" && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			sum := sha256.Sum256(c.Raw)
			na := c.NotAfter
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsTLS, IP: ip, Port: port,
				CertSHA256: hex.EncodeToString(sum[:]),
				SubjectCN:  c.Subject.CommonName,
				Issuer:     c.Issuer.CommonName,
				SANs:       c.DNSNames,
				NotAfter:   &na,
			})
		}
		break // first responsive scheme wins
	}
	return obs, nil
}

// techDetect probes a URL with httpx using the Tools.md flag set and records
// status, title, content-length, redirect chain and detected technologies.
func (s *Scanner) techDetect(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	url := targetURL(job)
	if url == "" {
		return nil, nil
	}
	ip, port := targetIPPort(job)
	var obs []scanproto.Observation

	if have("httpx") {
		// Tools.md: httpx -title -sc -cl -location -fr -silent -delay 1s
		rows, _ := runJSONL(ctx, 3*time.Minute, "httpx",
			"-silent", "-json", "-title", "-sc", "-cl", "-location", "-fr",
			"-tech-detect",
			"-delay", jobParams(job).intStr("httpx_delay_s", "1")+"s",
			"-timeout", jobParams(job).intStr("httpx_timeout_s", "10"),
			"-u", url)
		for _, r := range rows {
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsHTTP, IP: ip, Port: port,
				Status: num(r, "status_code"),
				Title:  str(r, "title"),
				Headers: map[string]string{
					"server":         str(r, "webserver"),
					"content-length": str(r, "content_length"),
					"location":       str(r, "location"),
				},
				Favicon: str(r, "favicon"),
				Product: str(r, "webserver"),
			})
			if techs, ok := r["tech"].([]any); ok {
				for _, t := range techs {
					name, _ := t.(string)
					if name == "" {
						continue
					}
					// httpx reports "Nginx:1.25.3" when it knows a version
					n, v := name, ""
					if i := strings.LastIndex(name, ":"); i > 0 {
						n, v = name[:i], name[i+1:]
					}
					obs = append(obs, scanproto.Observation{
						Type: scanproto.ObsTech, IP: ip, Port: port,
						TechName: n, TechVersion: v, TechConfidence: 90,
					})
				}
			}
		}
		if len(obs) > 0 {
			return obs, nil
		}
	}

	// Fallback: stdlib probe, fingerprinting from response headers.
	client := webClient()
	req, _ := http.NewRequestWithContext(withTimeout(ctx, 8*time.Second), http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if server := resp.Header.Get("Server"); server != "" {
		name, version := splitProductVersion(server)
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsTech, IP: ip, Port: port,
			TechName: name, TechVersion: version, TechConfidence: 60})
	}
	if x := resp.Header.Get("X-Powered-By"); x != "" {
		name, version := splitProductVersion(x)
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsTech, IP: ip, Port: port,
			TechName: name, TechVersion: version, TechConfidence: 60})
	}
	return obs, nil
}

// screenshot captures a page with httpx and uploads the PNG to object storage.
//
// Previously this emitted an object key without ever uploading the file, so
// every screenshot reference in the UI pointed at nothing.
func (s *Scanner) screenshot(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if !s.Detected[scanproto.CapBrowser] || !have("httpx") {
		return nil, nil
	}
	url := targetURL(job)
	if url == "" {
		return nil, nil
	}
	ip, port := targetIPPort(job)

	outDir, err := os.MkdirTemp("", "asm-shot-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	// Tools.md: httpx -sc -title -tech-detect -screenshot -timeout 200 -screenshot-timeout 200
	_, _ = runLines(ctx, 5*time.Minute, "httpx",
		"-silent", "-sc", "-title", "-tech-detect", "-screenshot",
		"-timeout", "200", "-screenshot-timeout", "200",
		"-srd", outDir, "-u", url)

	png := findFirstFile(outDir, ".png")
	if png == "" {
		return nil, nil // nothing captured; not an error
	}
	data, err := os.ReadFile(png)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	key := "screenshots/" + job.RunID + "/" + sanitizeKey(url) + ".png"
	if s.Upload == nil {
		// stage-test mode: report what would be stored, without persisting.
		return []scanproto.Observation{{
			Type: scanproto.ObsScreenshot, IP: ip, Port: port,
			ScreenshotKey: key + " (not uploaded: no store configured)",
		}}, nil
	}
	stored, err := s.Upload(ctx, key, data)
	if err != nil {
		return nil, err
	}
	return []scanproto.Observation{{
		Type: scanproto.ObsScreenshot, IP: ip, Port: port, ScreenshotKey: stored,
	}}, nil
}

// findFirstFile returns the first file under dir with the given extension.
func findFirstFile(dir, ext string) string {
	var found string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found != "" {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ext) && info.Size() > 0 {
			found = p
		}
		return nil
	})
	return found
}

// sanitizeKey turns a URL into a safe object-storage key segment.
func sanitizeKey(u string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ":", "_", "?", "_", "&", "_", "=", "_", " ", "_")
	k := r.Replace(u)
	if len(k) > 120 {
		k = k[:120]
	}
	return k
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(html(string(m[1])))
}

func html(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func splitProductVersion(s string) (string, string) {
	if i := strings.IndexByte(s, '/'); i > 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return strings.TrimSpace(s), ""
}

func schemesFor(port int) []string {
	switch port {
	case 443, 8443:
		return []string{"https"}
	case 80, 8080, 8000, 8888:
		return []string{"http"}
	default:
		return []string{"https", "http"}
	}
}

func portSuffix(scheme string, port int) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return ""
	}
	return ":" + itoaSafe(port)
}

func targetIPPort(job scanproto.Job) (string, int) {
	if len(job.Targets) == 0 {
		return "", 0
	}
	t := job.Targets[0]
	if t.IP != "" {
		return t.IP, t.Port
	}
	// derive from URL host if needed
	return "", t.Port
}

func itoaSafe(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

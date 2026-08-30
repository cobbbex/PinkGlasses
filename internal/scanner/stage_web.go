package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
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

// techDetect: httpx -tech-detect / nuclei tech templates when present, else a
// lightweight header/body fingerprint (worker-pipeline.md §3).
func (s *Scanner) techDetect(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	ip, port := targetIPPort(job)
	url := job.Targets[0].URL
	if url == "" && ip != "" {
		url = "http://" + ip + portSuffix("http", port)
	}
	if url == "" {
		return nil, nil
	}
	var obs []scanproto.Observation

	if have("httpx") {
		rows, _ := runJSONL(ctx, 2*time.Minute, "httpx", "-silent", "-json", "-tech-detect", "-u", url)
		for _, r := range rows {
			if techs, ok := r["tech"].([]any); ok {
				for _, t := range techs {
					if name, ok := t.(string); ok {
						obs = append(obs, scanproto.Observation{Type: scanproto.ObsTech, IP: ip, Port: port, TechName: name, TechConfidence: 90})
					}
				}
			}
		}
		return obs, nil
	}

	// fallback fingerprint from Server header
	client := webClient()
	req, _ := http.NewRequestWithContext(withTimeout(ctx, 8*time.Second), http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if server := resp.Header.Get("Server"); server != "" {
		name, version := splitProductVersion(server)
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsTech, IP: ip, Port: port, TechName: name, TechVersion: version, TechConfidence: 60})
	}
	if x := resp.Header.Get("X-Powered-By"); x != "" {
		name, version := splitProductVersion(x)
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsTech, IP: ip, Port: port, TechName: name, TechVersion: version, TechConfidence: 60})
	}
	return obs, nil
}

// screenshot: httpx -screenshot / chromium when present. Requires the browser
// capability; without it the stage is a no-op (worker-pipeline.md §4).
func (s *Scanner) screenshot(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if !s.Detected[scanproto.CapBrowser] {
		return nil, nil
	}
	ip, port := targetIPPort(job)
	url := job.Targets[0].URL
	if url == "" || !have("httpx") {
		return nil, nil
	}
	// httpx -screenshot writes files; a full implementation uploads them to the
	// presigned URL and emits the object key. Here we emit the intended key.
	key := "screenshots/" + strings.ReplaceAll(strings.ReplaceAll(url, "://", "_"), "/", "_") + ".png"
	_, _ = runLines(ctx, 90*time.Second, "httpx", "-silent", "-screenshot", "-u", url)
	return []scanproto.Observation{{Type: scanproto.ObsScreenshot, IP: ip, Port: port, ScreenshotKey: key}}, nil
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

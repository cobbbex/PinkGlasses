package scanner

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

// top ports for the connect-scan fallback (subset of naabu's top-1000).
var topPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017}

// portScan follows Tools.md §Port Scanning: naabu finds open ports fast, then
// nmap fingerprints only those ports. nmap is never asked to scan a full range
// on the standard profile — that is reserved for `deep`.
func (s *Scanner) portScan(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].IP == "" {
		return nil, nil
	}
	ip := job.Targets[0].IP
	deep := job.Profile == "deep"
	var open []int

	if have("naabu") {
		// Tools.md: naabu -c 4 -rate 20 -top-ports 100 -silent
		args := []string{"-silent", "-json", "-host", ip,
			"-c", "4", "-rate", "20"}
		if deep {
			args = append(args, "-p", "-") // full range on deep only
		} else {
			args = append(args, "-top-ports", "100")
		}
		if !s.Detected[scanproto.CapRawSocket] {
			args = append(args, "-scan-type", "c") // connect scan without CAP_NET_RAW
		}
		rows, _ := runJSONL(ctx, 15*time.Minute, "naabu", args...)
		for _, r := range rows {
			if p := num(r, "port"); p > 0 {
				open = append(open, p)
			}
		}
	} else {
		open = connectScan(ctx, ip, topPorts)
	}

	var obs []scanproto.Observation
	for _, p := range open {
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsService, IP: ip, Port: p, Proto: "tcp", State: "open",
		})
	}
	// nmap -sV over naabu's hits only (worker-pipeline.md §2: keep nmap for
	// non-web service versions, never full-range).
	if len(open) > 0 && have("nmap") {
		obs = append(obs, nmapVersions(ctx, ip, open, deep)...)
	}
	return obs, nil
}

func connectScan(ctx context.Context, ip string, ports []int) []int {
	var open []int
	d := net.Dialer{Timeout: 2 * time.Second}
	for _, p := range ports {
		select {
		case <-ctx.Done():
			return open
		default:
		}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
		if err == nil {
			_ = conn.Close()
			open = append(open, p)
		}
	}
	return open
}

// nmapVersions runs the Tools.md nmap profile against a known port list.
// `-A` (OS + script + traceroute) is deep-only: it is slow and very loud.
func nmapVersions(ctx context.Context, ip string, ports []int, deep bool) []scanproto.Observation {
	list := ""
	for i, p := range ports {
		if i > 0 {
			list += ","
		}
		list += strconv.Itoa(p)
	}

	args := []string{
		"-Pn", "--open",
		"--min-hostgroup", "256",
		"--min-rate", "10000",
		"--max-retries", "3",
		"--defeat-rst-ratelimit",
		"-p", list,
	}
	if deep {
		args = append(args, "-A", "-vvv")
	} else {
		args = append(args, "-sV")
	}
	args = append(args, "-oG", "-", ip)

	timeout := 10 * time.Minute
	if deep {
		timeout = 30 * time.Minute
	}
	lines, _ := runLines(ctx, timeout, "nmap", args...)

	var obs []scanproto.Observation
	for _, ln := range lines {
		for _, entry := range parseNmapGrepPorts(ln) {
			product, version := splitNmapProduct(entry.product)
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsService, IP: ip, Port: entry.port, Proto: "tcp", State: "open",
				Product: product, Version: version, Banner: entry.banner,
			})
		}
	}
	return obs
}

type nmapPort struct {
	port             int
	product, version, banner string
}

// parseNmapGrepPorts extracts port/service info from an nmap greppable line.
func parseNmapGrepPorts(line string) []nmapPort {
	const marker = "Ports: "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return nil
	}
	segment := line[idx+len(marker):]
	var out []nmapPort
	for _, part := range strings.Split(segment, ",") {
		// format: port/state/proto//service//product version/
		fields := strings.Split(part, "/")
		if len(fields) < 5 {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		np := nmapPort{port: p, banner: strings.TrimSpace(fields[4])}
		if len(fields) >= 7 {
			np.product = strings.TrimSpace(fields[6])
		}
		out = append(out, np)
	}
	return out
}

// splitNmapProduct separates nmap's concatenated "product version extrainfo"
// field, e.g. "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (...)" -> ("OpenSSH",
// "6.6.1p1") and "Apache httpd 2.4.7 ((Ubuntu))" -> ("Apache httpd", "2.4.7").
//
// The version is the first token beginning with a digit; everything before it
// is the product name. Without this the whole string lands in `product` and
// version-based search (`version:2.4.7`) never matches.
func splitNmapProduct(field string) (product, version string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return "", ""
	}
	tokens := strings.Fields(field)
	for i, tok := range tokens {
		if i > 0 && tok != "" && tok[0] >= '0' && tok[0] <= '9' {
			return strings.Join(tokens[:i], " "), strings.Trim(tok, "()")
		}
	}
	return field, ""
}

package scanner

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// top ports for the connect-scan fallback (subset of naabu's top-1000).
var topPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017}

// portScan follows Tools.md §Port Scanning: naabu finds open ports fast, then
// nmap fingerprints only those ports. nmap is never asked to scan a full range
// on the standard profile — that is reserved for `deep`.
func (s *Scanner) portScan(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	// The planner batches addresses into one task so the scanners can schedule
	// across a host pool. A single-address task still arrives as a pool of one.
	var hosts []string
	for _, t := range job.Targets {
		if t.IP != "" {
			hosts = append(hosts, t.IP)
		}
		hosts = append(hosts, t.IPs...)
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	deep := job.Profile == "deep"
	pr := jobParams(job)
	ports := pr.str("ports", "top-100")

	// Which scanner to use depends on how wide the sweep is. The named presets
	// have to be matched before testing for an explicit range: "top-100"
	// contains a hyphen, so a naive punctuation check treats every preset as a
	// custom range and sends the common case to the wrong scanner.
	var wide bool
	switch ports {
	case "", "top-100":
		wide = false
	case "top-1000", "full":
		wide = true
	default:
		wide = true // an explicit list or range, validated upstream
	}
	wide = wide || deep

	var obs []scanproto.Observation

	if wide && have("naabu") {
		// Wide sweeps are what naabu is for: it finds open ports far faster than
		// nmap over a large range, and nmap then fingerprints only the hits.
		open := s.naabuSweep(ctx, hosts, ports, deep, pr)
		for host, ps := range open {
			for _, port := range ps {
				obs = append(obs, scanproto.Observation{
					Type: scanproto.ObsService, IP: host, Port: port, Proto: "tcp", State: "open",
				})
			}
		}
		if have("nmap") {
			obs = append(obs, s.nmapVersions(ctx, open, deep, pr)...)
		}
		return obs, nil
	}

	if have("nmap") {
		// At top-100 width nmap alone is simpler and returns service versions in
		// the same pass, so there is nothing for a separate discovery scan to add.
		found := s.nmapScan(ctx, hosts, "--top-ports", "100", deep, pr)
		return found, nil
	}

	// No scanner installed: fall back to a Go connect scan per host.
	for _, host := range hosts {
		for _, port := range connectScan(ctx, host, topPorts) {
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsService, IP: host, Port: port, Proto: "tcp", State: "open",
			})
		}
	}
	slog.Info("port scan", "hosts", len(hosts), "open", len(obs), "scanner", "connect-scan")
	return obs, nil
}

// naabuSweep runs one naabu across the whole host pool and returns open ports
// per host. Passing the pool as a list is what lets naabu apply its concurrency
// and rate across hosts rather than to a single address at a time.
func (s *Scanner) naabuSweep(ctx context.Context, hosts []string, ports string, deep bool, pr params) map[string][]int {
	// Hosts go in on stdin. naabu has no "-list -" convention: it takes the flag
	// literally and fails trying to open a file named "-", while still exiting 0.
	args := []string{"-silent", "-json",
		"-c", pr.intStr("naabu_concurrency", "4"),
		"-rate", pr.intStr("naabu_rate", "20"),
		"-timeout", pr.intStr("naabu_timeout_ms", "1000"),
		"-retries", pr.intStr("naabu_retries", "1")}
	switch {
	case ports == "full" || deep:
		args = append(args, "-p", "-")
	case ports == "top-1000":
		args = append(args, "-top-ports", "1000")
	case strings.ContainsAny(ports, ",-"):
		args = append(args, "-p", ports) // validated upstream
	default:
		args = append(args, "-top-ports", "100")
	}
	if !s.Detected[scanproto.CapRawSocket] {
		args = append(args, "-scan-type", "c") // connect scan without CAP_NET_RAW
	}

	rows, _ := runJSONLStdin(ctx, 30*time.Minute, strings.Join(hosts, "\n"), "naabu", args...)
	open := map[string][]int{}
	for _, r := range rows {
		host, port := str(r, "host"), num(r, "port")
		if host == "" {
			host = str(r, "ip")
		}
		if host != "" && port > 0 {
			open[host] = append(open[host], port)
		}
	}
	total := 0
	for _, ps := range open {
		total += len(ps)
	}
	slog.Info("port scan", "hosts", len(hosts), "with_open_ports", len(open),
		"open", total, "scanner", "naabu")
	return open
}

// portList renders open ports for a log line, bounded so a full-range scan does
// not emit thousands of numbers.
func portList(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	show := ports
	suffix := ""
	if len(show) > 20 {
		show, suffix = show[:20], "…"
	}
	parts := make([]string, len(show))
	for i, p := range show {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",") + suffix
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

// nmapScan scans a pool of hosts with the given port selection and returns the
// open services it identifies, versions included.
func (s *Scanner) nmapScan(ctx context.Context, hosts []string, portFlag, portValue string, deep bool, pr params) []scanproto.Observation {
	return s.nmapRun(ctx, hosts, []string{portFlag, portValue}, deep, pr)
}

// nmapVersions fingerprints ports a discovery sweep already found open. It is
// given the union of those ports across the pool; --open means nmap reports
// only the ones actually open on each host, so the union costs little.
func (s *Scanner) nmapVersions(ctx context.Context, open map[string][]int, deep bool, pr params) []scanproto.Observation {
	portSet := map[int]bool{}
	var hosts []string
	for host, ports := range open {
		hosts = append(hosts, host)
		for _, p := range ports {
			portSet[p] = true
		}
	}
	if len(hosts) == 0 || len(portSet) == 0 {
		return nil
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return s.nmapRun(ctx, hosts, []string{"-p", strings.Join(parts, ",")}, deep, pr)
}

// nmapRun scans a host pool and parses nmap's greppable output.
//
// The pool is passed on stdin as a host list, which is what makes
// --min-hostgroup meaningful: given one host at a time nmap can never form a
// group, and the setting was decorative.
func (s *Scanner) nmapRun(ctx context.Context, hosts []string, portArgs []string, deep bool, pr params) []scanproto.Observation {
	args := []string{
		"-Pn", "--open",
		"--min-hostgroup", "64",
		"--min-rate", pr.intStr("nmap_min_rate", "10000"),
		"--max-retries", pr.intStr("nmap_max_retries", "3"),
		"--defeat-rst-ratelimit",
		"-" + pr.str("nmap_timing", "T4"),
	}
	args = append(args, portArgs...)
	if deep {
		args = append(args, "-A", "-vvv")
	} else {
		args = append(args, "-sV")
	}
	args = append(args, "--version-intensity", pr.intStr("nmap_version_intensity", "7"))
	args = append(args, "-oG", "-", "-iL", "-") // host pool on stdin

	timeout := 20 * time.Minute
	if deep {
		timeout = 60 * time.Minute
	}
	lines, _ := runLinesStdin(ctx, timeout, strings.Join(hosts, "\n"), "nmap", args...)

	var obs []scanproto.Observation
	hostsWithPorts := map[string]bool{}
	for _, ln := range lines {
		ip := parseNmapGrepHost(ln)
		if ip == "" {
			continue
		}
		for _, entry := range parseNmapGrepPorts(ln) {
			hostsWithPorts[ip] = true
			product, version := splitNmapProduct(entry.product)
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsService, IP: ip, Port: entry.port, Proto: "tcp", State: "open",
				Product: product, Version: version, Banner: entry.banner,
			})
		}
	}
	slog.Info("port scan", "hosts", len(hosts), "with_open_ports", len(hostsWithPorts),
		"open", len(obs), "scanner", "nmap", "ports", strings.Join(portArgs, " "))
	return obs
}

// parseNmapGrepHost pulls the address out of a greppable line, which starts
// "Host: 1.2.3.4 (name)". Without this a pooled scan would attribute every
// result to whichever host happened to be first.
func parseNmapGrepHost(line string) string {
	const marker = "Host: "
	if !strings.HasPrefix(line, marker) {
		return ""
	}
	rest := line[len(marker):]
	if i := strings.IndexAny(rest, " \t"); i > 0 {
		return rest[:i]
	}
	return ""
}

type nmapPort struct {
	port                     int
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

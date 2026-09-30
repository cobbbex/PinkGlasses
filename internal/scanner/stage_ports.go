package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
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

	if wide && have("naabu") && pr.enabled("naabu") {
		// Wide sweeps are what naabu is for: it finds open ports far faster than
		// nmap over a large range, and nmap then fingerprints only the hits.
		open, sweepErr := s.naabuSweep(ctx, hosts, ports, deep, pr)
		for host, ps := range open {
			for _, port := range ps {
				obs = append(obs, scanproto.Observation{
					Type: scanproto.ObsService, IP: host, Port: port, Proto: "tcp", State: "open",
				})
			}
		}
		var versionErr error
		if have("nmap") && pr.enabled("nmap") {
			var found []scanproto.Observation
			found, versionErr = s.nmapVersions(ctx, open, deep, pr)
			obs = append(obs, found...)
		}
		// A tool that ran out of its budget found real ports and they are
		// reported — but the task fails, so the run says the port list is
		// incomplete instead of looking like a clean finish. The services
		// already found are still probed (planner.probeNewServices). Both
		// tools can run out, and then both reasons are worth having.
		return obs, permanentJoin(sweepErr, versionErr)
	}

	if have("nmap") && pr.enabled("nmap") {
		// At top-100 width nmap alone is simpler and returns service versions in
		// the same pass, so there is nothing for a separate discovery scan to add.
		found, err := s.nmapScan(ctx, hosts, "--top-ports", "100", deep, pr)
		return found, err
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

// portCount is how many ports a port selection covers, for sizing the sweep's
// time budget. An explicit list or range is counted; a preset is its name.
// Anything unrecognised is treated as the widest case, since a budget that is
// too generous only delays a refusal while one that is too small truncates the
// scan.
func portCount(ports string, deep bool) int {
	if deep || ports == "full" {
		return 65535
	}
	switch ports {
	case "", "top-100":
		return 100
	case "top-1000":
		return 1000
	}
	n := 0
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			if _, err := strconv.Atoi(part); err != nil {
				return 65535 // not a port: assume the worst rather than count it as one
			}
			n++
			continue
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || b < a {
			return 65535
		}
		n += b - a + 1
	}
	if n == 0 {
		return 65535
	}
	return n
}

// portScanBudget is how long a sweep of `ports` ports across `hosts` addresses
// may take before it is stopped.
//
// It was a flat 30 minutes, which is both too long for a small sweep and far
// too short for a wide one: top-1000 over two addresses at the shipped rate
// spent the whole budget and returned partial results, and nothing said so.
// The time a sweep needs comes from two lower bounds:
//
//   - the send rate — ports×hosts probes cannot leave faster than `rate` a
//     second;
//   - the waiting — a port that never answers is only known to be closed once
//     its timeout and retries have elapsed, and naabu keeps `concurrency`
//     probes in flight, so a fully filtered pool costs
//     ports×hosts×timeout×(retries+1)/concurrency.
//
// The larger of the two, times four for the pacing this model does not
// capture, floored at fifteen minutes so a small sweep is never cut off by
// arithmetic, and capped at `max` so a sweep that genuinely cannot finish is
// refused with an explanation rather than run all day.
func portScanBudget(ports, hosts, rate, timeoutMS, retries, concurrency int, max time.Duration) time.Duration {
	if hosts < 1 {
		hosts = 1
	}
	if rate < 1 {
		rate = 1
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if retries < 0 {
		retries = 0
	}
	probes := ports * hosts
	bySend := time.Duration(probes/rate+1) * time.Second
	byWait := time.Duration(probes*timeoutMS*(retries+1)/concurrency) * time.Millisecond
	budget := bySend
	if byWait > budget {
		budget = byWait
	}
	budget *= 4
	if budget < 15*time.Minute {
		budget = 15 * time.Minute
	}
	if max > 0 && budget > max {
		budget = max
	}
	return budget
}

// portScanMax is the ceiling on one sweep's budget. A pool and port set that
// needs longer than this is not a scan that should be left running for a day:
// the stage stops and says what to change.
func portScanMax() time.Duration {
	if v := os.Getenv("ASM_PORT_SCAN_MAX"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		slog.Warn("ignoring ASM_PORT_SCAN_MAX: not a duration like 90m or 4h", "value", v)
	}
	return 4 * time.Hour
}

// nmapBudget is how long service detection over `ports` ports across `hosts`
// addresses may take. It was a flat 20 minutes (an hour for deep), which is
// plenty for a handful of services and not enough for a large pool — and when
// it ran out, the versions nmap had not reached were simply missing.
//
// Version detection costs a few seconds per open port, and nmap works on 64
// hosts at a time (--min-hostgroup), so the work is ports × host groups. Five
// seconds a probe, doubled for slack, four times that for deep's -A, and never
// less than the old flat budgets.
func nmapBudget(ports, hosts int, deep bool, max time.Duration) time.Duration {
	if hosts < 1 {
		hosts = 1
	}
	groups := (hosts + 63) / 64
	per := 5 * time.Second
	slack := 2
	floor := 20 * time.Minute
	if deep {
		slack = 8
		floor = 60 * time.Minute
	}
	budget := time.Duration(ports*groups*slack) * per
	if budget < floor {
		budget = floor
	}
	if max > 0 && budget > max {
		budget = max
	}
	return budget
}

// naabuSweep runs one naabu across the whole host pool and returns open ports
// per host. Passing the pool as a list is what lets naabu apply its concurrency
// and rate across hosts rather than to a single address at a time.
//
// The error is a *ToolTimeout when the sweep was stopped at its budget: the
// ports it had found are still returned, and the caller reports that the rest
// were never probed.
func (s *Scanner) naabuSweep(ctx context.Context, hosts []string, ports string, deep bool, pr params) (map[string][]int, error) {
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

	budget := portScanBudget(portCount(ports, deep), len(hosts),
		pr.intVal("naabu_rate", 20), pr.intVal("naabu_timeout_ms", 1000),
		pr.intVal("naabu_retries", 1), pr.intVal("naabu_concurrency", 4), portScanMax())
	slog.Info("port sweep starting", "hosts", len(hosts), "ports", ports,
		"rate", pr.intStr("naabu_rate", "20"), "concurrency", pr.intStr("naabu_concurrency", "4"),
		"budget", budget.Round(time.Second))

	rows, runErr := runJSONLStdin(ctx, budget, strings.Join(hosts, "\n"), "naabu", args...)
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

	var to *ToolTimeout
	if errors.As(runErr, &to) {
		// The ports found so far are real and are returned; what the caller
		// must not do is treat them as the whole answer.
		return open, permanent(fmt.Errorf(
			"the port sweep did not get through %s on %d address(es) within %s, so the "+
				"ports it reports are only those it reached: %d open on %d address(es) "+
				"before it was stopped. Raise Concurrency (naabu_concurrency, the setting "+
				"that decides how many ports wait at once) or Packets per second "+
				"(naabu_rate) under Customize scanning, or scan a narrower port set",
			ports, len(hosts), budget.Round(time.Second), total, len(open)))
	}
	return open, nil
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
func (s *Scanner) nmapScan(ctx context.Context, hosts []string, portFlag, portValue string, deep bool, pr params) ([]scanproto.Observation, error) {
	return s.nmapRun(ctx, hosts, []string{portFlag, portValue}, deep, pr)
}

// nmapVersions fingerprints ports a discovery sweep already found open. It is
// given the union of those ports across the pool; --open means nmap reports
// only the ones actually open on each host, so the union costs little.
func (s *Scanner) nmapVersions(ctx context.Context, open map[string][]int, deep bool, pr params) ([]scanproto.Observation, error) {
	portSet := map[int]bool{}
	var hosts []string
	for host, ports := range open {
		hosts = append(hosts, host)
		for _, p := range ports {
			portSet[p] = true
		}
	}
	if len(hosts) == 0 || len(portSet) == 0 {
		return nil, nil
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
// The error is a *ToolTimeout when nmap was stopped at its budget: what it
// identified is still returned, and the caller reports the rest as unreached.
func (s *Scanner) nmapRun(ctx context.Context, hosts []string, portArgs []string, deep bool, pr params) ([]scanproto.Observation, error) {
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

	budget := nmapBudget(portArgCount(portArgs), len(hosts), deep, portScanMax())
	lines, runErr := runLinesStdin(ctx, budget, strings.Join(hosts, "\n"), "nmap", args...)

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

	var to *ToolTimeout
	if errors.As(runErr, &to) {
		return obs, permanent(fmt.Errorf(
			"nmap did not finish %s on %d address(es) within %s, so the services it "+
				"identified (%d) are only those it reached. Lower Version intensity "+
				"(nmap_version_intensity) or scan a narrower port set under Customize scanning",
			strings.Join(portArgs, " "), len(hosts), budget.Round(time.Second), len(obs)))
	}
	return obs, nil
}

// portArgCount counts the ports in the flags handed to nmap, for its budget.
func portArgCount(portArgs []string) int {
	for i := 0; i < len(portArgs)-1; i++ {
		switch portArgs[i] {
		case "-p":
			return portCount(portArgs[i+1], false)
		case "--top-ports":
			if n, err := strconv.Atoi(portArgs[i+1]); err == nil {
				return n
			}
		}
	}
	return 65535
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

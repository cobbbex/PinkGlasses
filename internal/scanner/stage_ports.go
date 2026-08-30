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

// portScan: naabu when present (SYN if raw_socket), else a Go connect scan;
// then nmap -sV against the open ports for real service versions.
func (s *Scanner) portScan(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].IP == "" {
		return nil, nil
	}
	ip := job.Targets[0].IP
	var open []int

	if have("naabu") {
		args := []string{"-silent", "-json", "-host", ip, "-tp", "1000"}
		if !s.Detected[scanproto.CapRawSocket] {
			args = append(args, "-scan-type", "c") // connect scan
		}
		rows, _ := runJSONL(ctx, 5*time.Minute, "naabu", args...)
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
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsService, IP: ip, Port: p, Proto: "tcp", State: "open"})
	}
	// nmap -sV on the open ports only (worker-pipeline.md §2 decision: keep nmap).
	if len(open) > 0 && have("nmap") {
		obs = append(obs, nmapVersions(ctx, ip, open)...)
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

func nmapVersions(ctx context.Context, ip string, ports []int) []scanproto.Observation {
	list := ""
	for i, p := range ports {
		if i > 0 {
			list += ","
		}
		list += strconv.Itoa(p)
	}
	// -oG - gives greppable output; we parse the Ports: field.
	lines, _ := runLines(ctx, 5*time.Minute, "nmap", "-sV", "-Pn", "-p", list, "-oG", "-", ip)
	var obs []scanproto.Observation
	for _, ln := range lines {
		for _, entry := range parseNmapGrepPorts(ln) {
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsService, IP: ip, Port: entry.port, Proto: "tcp", State: "open",
				Product: entry.product, Version: entry.version, Banner: entry.banner,
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

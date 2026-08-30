package scanner

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

// candidate is a discovered name plus the tool that found it, so provenance
// survives into the asset graph's `sources` array.
type candidate struct{ name, source string }

// passiveEnum runs the passive subdomain sources in Tools.md order
// (assetfinder, subfinder), merges their candidates, then resolves them.
// Each tool is optional: a missing binary is skipped, never fatal.
func (s *Scanner) passiveEnum(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].Domain == "" {
		return nil, nil
	}
	root := job.Targets[0].Domain

	// name -> sources that found it
	found := map[string]map[string]bool{}
	add := func(name, source string) {
		name = normalizeHost(name)
		if !inScope(name, root) {
			return
		}
		if found[name] == nil {
			found[name] = map[string]bool{}
		}
		found[name][source] = true
	}
	add(root, "seed")

	// --- assetfinder (Tools.md: `assetfinder example.com`) ---
	if have("assetfinder") {
		lines, _ := runLines(ctx, 2*time.Minute, "assetfinder", root)
		for _, l := range lines {
			add(l, "assetfinder")
		}
	}

	// --- subfinder (Tools.md: `subfinder -d example.com`) ---
	if have("subfinder") {
		args := []string{"-silent", "-json", "-d", root}
		if s.ProviderConfig != "" {
			args = append(args, "-provider-config", s.ProviderConfig)
		}
		rows, _ := runJSONL(ctx, 3*time.Minute, "subfinder", args...)
		for _, r := range rows {
			if h := str(r, "host"); h != "" {
				add(h, "subfinder")
			}
		}
	}

	// --- shuffledns bruteforce: deep profile only (Tools.md) ---
	if job.Profile == "deep" && have("shuffledns") &&
		fileExists(wordlistDNS()) && fileExists(resolversFile()) {
		lines, _ := runLines(ctx, 10*time.Minute, "shuffledns",
			"-d", root, "-w", wordlistDNS(), "-r", resolversFile(),
			"-mode", "bruteforce", "-silent")
		for _, l := range lines {
			add(l, "shuffledns")
		}
	}

	// --- emit + resolve ---
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)

	var obs []scanproto.Observation
	for _, n := range names {
		srcs := make([]string, 0, len(found[n]))
		for sc := range found[n] {
			srcs = append(srcs, sc)
		}
		sort.Strings(srcs)
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsSubdomain, Domain: n, Source: strings.Join(srcs, ","),
		})
	}
	obs = append(obs, s.resolveNames(ctx, names)...)
	return obs, nil
}

// resolveNames turns candidate names into A/AAAA observations. dnsx is the
// primary resolver (Tools.md); the stdlib resolver is the no-binary fallback.
func (s *Scanner) resolveNames(ctx context.Context, names []string) []scanproto.Observation {
	if len(names) == 0 {
		return nil
	}
	if have("dnsx") {
		if obs := s.resolveWithDNSX(ctx, names); obs != nil {
			return obs
		}
	}
	var obs []scanproto.Observation
	res := net.Resolver{}
	for _, name := range names {
		ips, _ := res.LookupHost(withTimeout(ctx, 5*time.Second), name)
		for _, ip := range ips {
			obs = append(obs, scanproto.Observation{
				Type: scanproto.ObsDNSRecord, Domain: name, RType: rtypeOf(ip), Value: ip,
			})
		}
	}
	return obs
}

// resolveWithDNSX pipes the candidate list through `dnsx -silent -json`, which
// also filters wildcard responses that would otherwise create phantom hosts.
func (s *Scanner) resolveWithDNSX(ctx context.Context, names []string) []scanproto.Observation {
	rows, err := runJSONLStdin(ctx, 5*time.Minute, strings.Join(names, "\n"),
		"dnsx", "-silent", "-json", "-a", "-aaaa", "-resp")
	if err != nil || len(rows) == 0 {
		return nil
	}
	var obs []scanproto.Observation
	for _, r := range rows {
		host := str(r, "host")
		if host == "" {
			continue
		}
		for _, key := range []string{"a", "aaaa"} {
			vals, _ := r[key].([]any)
			for _, v := range vals {
				ip, _ := v.(string)
				if ip == "" {
					continue
				}
				obs = append(obs, scanproto.Observation{
					Type: scanproto.ObsDNSRecord, Domain: host, RType: rtypeOf(ip), Value: ip,
				})
			}
		}
	}
	return obs
}

func rtypeOf(ip string) string {
	if isV6(ip) {
		return "AAAA"
	}
	return "A"
}

// dnsResolve: full record set for the target domain via dnsx or the stdlib.
func (s *Scanner) dnsResolve(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].Domain == "" {
		return nil, nil
	}
	name := job.Targets[0].Domain
	var obs []scanproto.Observation
	res := net.Resolver{}
	c := withTimeout(ctx, 5*time.Second)

	if ips, err := res.LookupHost(c, name); err == nil {
		for _, ip := range ips {
			rt := "A"
			if isV6(ip) {
				rt = "AAAA"
			}
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: rt, Value: ip})
		}
	}
	if cname, err := res.LookupCNAME(c, name); err == nil && cname != "" && cname != name+"." {
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: "CNAME", Value: cname})
	}
	if mxs, err := res.LookupMX(c, name); err == nil {
		for _, mx := range mxs {
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: "MX", Value: mx.Host})
		}
	}
	if nss, err := res.LookupNS(c, name); err == nil {
		for _, ns := range nss {
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: "NS", Value: ns.Host})
		}
	}
	if txts, err := res.LookupTXT(c, name); err == nil {
		for _, t := range txts {
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: "TXT", Value: t})
		}
	}
	return obs, nil
}

// ipEnrich: PTR + (cloud/asn via external tools when present).
func (s *Scanner) ipEnrich(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	var obs []scanproto.Observation
	res := net.Resolver{}
	for _, t := range job.Targets {
		if t.IP == "" {
			continue
		}
		o := scanproto.Observation{Type: scanproto.ObsIP, IP: t.IP}
		if names, err := res.LookupAddr(withTimeout(ctx, 3*time.Second), t.IP); err == nil && len(names) > 0 {
			o.PTR = names[0]
		}
		obs = append(obs, o)
	}
	return obs, nil
}

// withTimeout returns a child context that auto-cancels after d. Passing cancel
// to AfterFunc ensures resources are released without a leak.
func withTimeout(ctx context.Context, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(ctx, d)
	time.AfterFunc(d, cancel)
	return c
}

func isV6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// normalizeHost lowercases a hostname and strips the trailing root dot.
func normalizeHost(name string) string {
	return strings.TrimSpace(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")))
}

// inScope reports whether a discovered name belongs to the target domain.
//
// The label boundary matters: a plain suffix match would accept
// "notexample.com" and "evilexample.com" for root "example.com", which is how
// a passive source can silently widen a scan far beyond what was authorised.
func inScope(name, root string) bool {
	if name == "" || root == "" {
		return false
	}
	return name == root || strings.HasSuffix(name, "."+root)
}

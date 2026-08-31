package scanner

import (
	"context"
	"log/slog"
	"sync"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

// candidate is a discovered name plus the tool that found it, so provenance
// survives into the asset graph's `sources` array.
type candidate struct{ name, source string }

// passiveEnum runs the passive subdomain sources, merges their candidates and
// then resolves them. Each tool is optional: a missing binary is skipped, never
// fatal.
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

	// --- subfinder (Tools.md: `subfinder -d example.com`) ---
	if have("subfinder") {
		pr := jobParams(job)
		maxTime := pr.intStr("subfinder_max_time", "3")
		args := []string{"-silent", "-json", "-d", root, "-max-time", maxTime}
		if pr.boolVal("subfinder_all", false) {
			args = append(args, "-all")
		}
		if s.ProviderConfig != "" {
			args = append(args, "-provider-config", s.ProviderConfig)
		}
		// Give the process a minute past its own budget so we read the results
		// it returns rather than killing it as it finishes.
		budget := 4 * time.Minute
		if n, err := strconv.Atoi(maxTime); err == nil {
			budget = time.Duration(n+1) * time.Minute
		}
		rows, _ := runJSONL(ctx, budget, "subfinder", args...)
		for _, r := range rows {
			if h := str(r, "host"); h != "" {
				add(h, "subfinder")
			}
		}
	}

	// NOTE: shuffledns brute-forcing is no longer done here. It runs as its own
	// dns_brute stage, one task per wordlist, so the lists can be spread across
	// workers instead of serialising inside this task (see stage_dnsbrute.go).

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
	obs = append(obs, s.resolveNames(ctx, names, jobParams(job))...)
	return obs, nil
}

// resolveNames turns candidate names into A/AAAA observations. dnsx is the
// primary resolver (Tools.md); the stdlib resolver is the no-binary fallback.
func (s *Scanner) resolveNames(ctx context.Context, names []string, pr params) []scanproto.Observation {
	if len(names) == 0 {
		return nil
	}
	if have("dnsx") {
		if obs := s.resolveWithDNSX(ctx, names, pr); obs != nil {
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
func (s *Scanner) resolveWithDNSX(ctx context.Context, names []string, pr params) []scanproto.Observation {
	dnsxArgs := []string{"-silent", "-json", "-a", "-aaaa", "-resp",
		"-t", pr.intStr("dnsx_threads", "100"),
		"-retry", pr.intStr("dnsx_retries", "2")} // dnsx spells it -retry, unlike naabu/httpx/nuclei
	if rl := pr.intStr("dnsx_rate_limit", "0"); rl != "0" {
		dnsxArgs = append(dnsxArgs, "-rl", rl)
	}
	rows, err := runJSONLStdin(ctx, 5*time.Minute, strings.Join(names, "\n"),
		"dnsx", dnsxArgs...)
	if err != nil || len(rows) == 0 {
		return nil
	}

	var obs []scanproto.Observation
	// Network provenance per address, deduped: many subdomains usually share
	// a handful of addresses, and we only need to enrich each address once.
	enriched := map[string]bool{}

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
				enriched[ip] = true
			}
		}
	}

	// Second pass: reverse DNS for the addresses we just resolved. PTR is a
	// property of the address, not the name, so it needs the IPs as input.
	obs = append(obs, s.enrichAddresses(ctx, keysOfBool(enriched, obs), pr)...)
	return obs
}

// enrichAddresses fills in the per-address facts: reverse DNS via dnsx, and AS
// number, name and announcing prefix via Team Cymru. Both are properties of the
// address rather than the name, so they run once per unique address no matter
// how many subdomains point at it.
func (s *Scanner) enrichAddresses(ctx context.Context, ips []string, pr params) []scanproto.Observation {
	if len(ips) == 0 {
		return nil
	}
	ptr := map[string]string{}
	if have("dnsx") {
		rows, err := runJSONLStdin(ctx, 3*time.Minute, strings.Join(ips, "\n"),
			"dnsx", "-silent", "-json", "-ptr", "-resp",
			"-t", pr.intStr("dnsx_threads", "100"))
		if err == nil {
			for _, r := range rows {
				ip := str(r, "host")
				ptrs, _ := r["ptr"].([]any)
				if ip == "" || len(ptrs) == 0 {
					continue
				}
				if name, _ := ptrs[0].(string); name != "" {
					ptr[ip] = normalizeHost(name)
				}
			}
		}
	}

	// Cymru lookups are independent per address; a small worker pool keeps a
	// large address set from taking minutes serially.
	type result struct {
		ip   string
		info ASNInfo
		ok   bool
	}
	asn := newASNResolver()
	jobs := make(chan string)
	out := make(chan result)
	workers := 16
	if len(ips) < workers {
		workers = len(ips)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				info, ok := asn.Lookup(ctx, ip)
				if !ok {
					slog.Debug("no ASN for address", "ip", ip)
				}
				out <- result{ip, info, ok}
			}
		}()
	}
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	infos := map[string]ASNInfo{}
	for r := range out {
		if r.ok {
			infos[r.ip] = r.info
		}
	}

	slog.Info("address enrichment",
		"addresses", len(ips), "with_asn", len(infos), "with_ptr", len(ptr))

	var obs []scanproto.Observation
	for _, ip := range ips {
		info, hasASN := infos[ip]
		name, hasPTR := ptr[ip]
		if !hasASN && !hasPTR {
			continue
		}
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsIP, IP: ip,
			PTR:     name,
			ASN:     info.Number,
			ASOrg:   info.Name,
			ASRange: info.Prefix,
			Country: info.Country,
		})
	}
	return obs
}

// keysOfBool returns every address seen while resolving, whether or not it came
// with ASN data, so reverse DNS covers them all.
func keysOfBool(enriched map[string]bool, obs []scanproto.Observation) []string {
	seen := map[string]bool{}
	for ip := range enriched {
		seen[ip] = true
	}
	for _, o := range obs {
		if o.Type == scanproto.ObsDNSRecord && (o.RType == "A" || o.RType == "AAAA") {
			seen[o.Value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
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

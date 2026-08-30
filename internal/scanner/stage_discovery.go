package scanner

import (
	"context"
	"net"
	"time"

	"github.com/benlik386/asm/internal/scanproto"
)

// passiveEnum: subfinder -> subdomains, then resolve each (worker-pipeline.md §1).
func (s *Scanner) passiveEnum(ctx context.Context, job scanproto.Job) ([]scanproto.Observation, error) {
	if len(job.Targets) == 0 || job.Targets[0].Domain == "" {
		return nil, nil
	}
	root := job.Targets[0].Domain
	names := map[string]bool{root: true}

	if have("subfinder") {
		rows, _ := runJSONL(ctx, 3*time.Minute, "subfinder", "-silent", "-json", "-d", root)
		for _, r := range rows {
			if h := str(r, "host"); h != "" {
				names[h] = true
			}
		}
	}
	// alterx permutations would expand `names` here when present.

	var obs []scanproto.Observation
	res := net.Resolver{}
	for name := range names {
		obs = append(obs, scanproto.Observation{Type: scanproto.ObsSubdomain, Domain: name, Source: "passive"})
		// resolve so discovered names feed the coalesce barrier
		ips, _ := res.LookupHost(withTimeout(ctx, 5*time.Second), name)
		for _, ip := range ips {
			rt := "A"
			if isV6(ip) {
				rt = "AAAA"
			}
			obs = append(obs, scanproto.Observation{Type: scanproto.ObsDNSRecord, Domain: name, RType: rt, Value: ip})
		}
	}
	return obs, nil
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

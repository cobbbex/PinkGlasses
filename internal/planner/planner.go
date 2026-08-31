// Package planner turns a scan run into a task DAG and advances it through the
// pipeline stages. The one hard barrier is dns_resolve -> coalesce -> port_scan
// (architecture.md §4): the union of resolved IPs across ALL targets in the run
// is deduped before any host is scanned, so a shared IP is never scanned twice.
package planner

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/benlik386/asm/internal/domain"
	"github.com/benlik386/asm/internal/scanproto"
	"github.com/benlik386/asm/internal/scopeguard"
	"github.com/benlik386/asm/internal/store"
)

const cidrHostCap = 4096

// Planner plans and advances scan runs.
type Planner struct{ st *store.Store }

// New builds a Planner.
func New(st *store.Store) *Planner { return &Planner{st: st} }

// StageSummary is the compact result the gateway stores on a completed task,
// read here to drive the next stage without re-querying the asset graph.
type StageSummary struct {
	Domains  []string    `json:"domains,omitempty"`  // discovered subdomains
	IPs      []string    `json:"ips,omitempty"`      // resolved / enriched addresses
	Services []IPPort    `json:"services,omitempty"` // open ports
	WebURLs  []string    `json:"web_urls,omitempty"` // live http(s) endpoints
}

// IPPort is an open service discovered by a port scan.
type IPPort struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// PlanInitial creates the first-stage tasks for a run and marks it running.
// Domain targets get passive_enum + dns_resolve; authorized ip/cidr targets get
// port_scan directly. Unauthorized or excluded targets are marked skipped.
func (p *Planner) PlanInitial(ctx context.Context, run domain.ScanRun, targets []domain.RunTarget, scopeTargets []domain.ScopeTarget) error {
	if err := p.st.SetRunStatus(ctx, run.ID, domain.RunRunning); err != nil {
		return err
	}
	auth := authIndex(scopeTargets)
	passive := run.Profile == domain.ProfilePassive

	var specs []store.TaskSpec
	for _, t := range targets {
		switch t.Kind {
		case "domain":
			specs = append(specs,
				spec(scanproto.StagePassiveEnum, scanproto.Target{Domain: t.Value}, 10, t.ID),
				spec(scanproto.StageDNSResolve, scanproto.Target{Domain: t.Value}, 30, t.ID),
			)
			_ = p.st.SetRunTargetStatus(ctx, t.ID, domain.TargetRunning, nil)
		case "ip", "cidr":
			if passive || !authorized(auth, t.Value) {
				reason := "not_authorized"
				if passive {
					reason = "passive_profile"
				}
				_ = p.st.SetRunTargetStatus(ctx, t.ID, domain.TargetSkipped, &reason)
				continue
			}
			// This is an EXTERNAL attack-surface monitor: internal ranges are
			// out of scope for every worker, local ones included. Skipping them
			// here also closes the scanner-as-SSRF hole (architecture.md §10.1).
			if isPrivateTarget(t.Value) {
				reason := "internal_range_out_of_scope"
				_ = p.st.SetRunTargetStatus(ctx, t.ID, domain.TargetSkipped, &reason)
				continue
			}
			caps := []string{string(scanproto.CapRawSocket)}
			if t.Kind == "ip" {
				specs = append(specs, spec(scanproto.StagePortScan, scanproto.Target{IP: t.Value},
					100, t.ID, caps...))
			} else {
				for _, ip := range scopeguard.ExpandCIDRHosts(t.Value, cidrHostCap) {
					specs = append(specs, spec(scanproto.StagePortScan, scanproto.Target{IP: ip},
						100, t.ID, caps...))
				}
			}
			_ = p.st.SetRunTargetStatus(ctx, t.ID, domain.TargetRunning, nil)
		}
	}
	// One shuffledns task per wordlist, so the lists run as independent tasks
	// and the dispatcher can spread them across different workers rather than
	// grinding through millions of names on a single box.
	specs = append(specs, p.dnsBruteSpecs(ctx, run, targets)...)

	if len(specs) == 0 {
		return p.st.SetRunStatus(ctx, run.ID, domain.RunCompleted)
	}
	_, err := p.st.InsertTasks(ctx, run.ID, specs)
	return err
}

// dnsBruteSpecs builds one dns_brute task per (domain target, wordlist) pair.
// A run with no ready wordlists simply gets no brute-force tasks — the rest of
// the pipeline is unaffected.
func (p *Planner) dnsBruteSpecs(ctx context.Context, run domain.ScanRun, targets []domain.RunTarget) []store.TaskSpec {
	if run.Profile == domain.ProfilePassive {
		return nil // passive runs send no DNS traffic of their own
	}
	// The shuffledns switch in scan settings gates the whole stage.
	if params, err := p.st.GetRunParams(ctx, run.ID); err == nil {
		if v, ok := params["dns_bruteforce"]; ok && v == "false" {
			return nil
		}
	}
	lists, err := p.st.RunWordlists(ctx, run.ID)
	if err != nil || len(lists) == 0 {
		return nil
	}
	var out []store.TaskSpec
	for _, t := range targets {
		if t.Kind != "domain" || t.Status == domain.TargetSkipped {
			continue
		}
		for _, wl := range lists {
			sp := spec(scanproto.StageDNSBrute, scanproto.Target{Domain: t.Value}, 20, t.ID)
			sp.Wordlist = wl.ID.String()
			out = append(out, sp)
		}
	}
	return out
}

// Advance moves a run through its stage machine. It is idempotent and safe to
// call repeatedly (the scheduler calls it each tick). Returns true if the run
// finished during this call.
func (p *Planner) Advance(ctx context.Context, run domain.ScanRun) (bool, error) {
	if run.Status != domain.RunRunning {
		return false, nil
	}
	passive := run.Profile == domain.ProfilePassive

	// Barrier: once all discovery tasks are done, coalesce IPs -> port_scan.
	if !passive {
		if err := p.maybeCoalescePortScan(ctx, run); err != nil {
			return false, err
		}
		if err := p.maybeProbe(ctx, run); err != nil {
			return false, err
		}
		if err := p.maybePostProbe(ctx, run); err != nil {
			return false, err
		}
	}

	// Completion: no outstanding tasks anywhere.
	prog, err := p.st.RunProgress(ctx, run.ID)
	if err != nil {
		return false, err
	}
	if prog.Total > 0 && prog.Outstanding == 0 {
		if err := p.finish(ctx, run); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// maybeCoalescePortScan implements the dns_resolve -> coalesce -> port_scan barrier.
func (p *Planner) maybeCoalescePortScan(ctx context.Context, run domain.ScanRun) error {
	if exists, _ := p.st.StageExists(ctx, run.ID, scanproto.StagePortScan); exists {
		return nil
	}
	out, err := p.st.StageOutstanding(ctx, run.ID,
		string(scanproto.StagePassiveEnum), string(scanproto.StageDNSBrute),
		string(scanproto.StageDNSResolve))
	if err != nil || out > 0 {
		return err
	}
	// Union all resolved IPs across every discovery task in the run
	// (passive_enum resolves what it finds; dns_resolve resolves the root).
	ipSet := map[string][]uuid.UUID{}
	for _, stage := range []scanproto.Stage{
		scanproto.StagePassiveEnum, scanproto.StageDNSBrute, scanproto.StageDNSResolve} {
		tasks, err := p.st.TasksByStage(ctx, run.ID, stage)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			sum := decode(t.Result)
			origins, _ := p.st.OriginsForTask(ctx, t.ID)
			for _, ip := range sum.IPs {
				ipSet[ip] = mergeOrigins(ipSet[ip], origins)
			}
		}
	}
	if len(ipSet) == 0 {
		return nil
	}
	var specs []store.TaskSpec
	for ip, origins := range ipSet {
		specs = append(specs, spec(scanproto.StagePortScan, scanproto.Target{IP: ip},
			100, origins[0], string(scanproto.CapRawSocket)))
		// attach remaining origins so results attribute to every domain
		if len(origins) > 1 {
			specs[len(specs)-1].Origins = origins
		}
	}
	_, err = p.st.InsertTasks(ctx, run.ID, specs)
	return err
}

// maybeProbe enqueues service_probe for open ports as port scans complete.
func (p *Planner) maybeProbe(ctx context.Context, run domain.ScanRun) error {
	tasks, err := p.st.TasksByStage(ctx, run.ID, scanproto.StagePortScan)
	if err != nil {
		return err
	}
	if exists, _ := p.st.StageExists(ctx, run.ID, scanproto.StageServiceProbe); exists {
		return nil
	}
	out, _ := p.st.StageOutstanding(ctx, run.ID, string(scanproto.StagePortScan))
	if out > 0 {
		return nil
	}
	var specs []store.TaskSpec
	for _, t := range tasks {
		sum := decode(t.Result)
		origins, _ := p.st.OriginsForTask(ctx, t.ID)
		for _, s := range sum.Services {
			specs = append(specs, spec(scanproto.StageServiceProbe,
				scanproto.Target{IP: s.IP, Port: s.Port}, 200, origin0(origins)))
		}
	}
	if len(specs) == 0 {
		return nil
	}
	_, err = p.st.InsertTasks(ctx, run.ID, specs)
	return err
}

// maybePostProbe enqueues tech_detect, screenshot and dir_brute for web services.
func (p *Planner) maybePostProbe(ctx context.Context, run domain.ScanRun) error {
	if exists, _ := p.st.StageExists(ctx, run.ID, scanproto.StageTechDetect); exists {
		return nil
	}
	out, _ := p.st.StageOutstanding(ctx, run.ID, string(scanproto.StageServiceProbe))
	if out > 0 {
		return nil
	}
	tasks, err := p.st.TasksByStage(ctx, run.ID, scanproto.StageServiceProbe)
	if err != nil {
		return err
	}
	var specs []store.TaskSpec
	for _, t := range tasks {
		sum := decode(t.Result)
		origins, _ := p.st.OriginsForTask(ctx, t.ID)
		for _, u := range sum.WebURLs {
			specs = append(specs,
				spec(scanproto.StageTechDetect, scanproto.Target{URL: u}, 300, origin0(origins)),
				spec(scanproto.StageScreenshot, scanproto.Target{URL: u}, 310, origin0(origins), string(scanproto.CapBrowser)),
				spec(scanproto.StageDirBrute, scanproto.Target{URL: u}, 320, origin0(origins)),
			)
		}
	}
	if len(specs) == 0 {
		return nil
	}
	_, err = p.st.InsertTasks(ctx, run.ID, specs)
	return err
}

// finish marks the run complete and resolves per-target statuses.
func (p *Planner) finish(ctx context.Context, run domain.ScanRun) error {
	targets, err := p.st.ListRunTargets(ctx, run.ID)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.Status == domain.TargetSkipped {
			continue
		}
		st := domain.TargetCompleted
		if t.TasksTotal > 0 && t.TasksDone < t.TasksTotal {
			st = domain.TargetIncomplete
		}
		_ = p.st.SetRunTargetStatus(ctx, t.ID, st, nil)
	}
	return p.st.SetRunStatus(ctx, run.ID, domain.RunCompleted)
}

// --- helpers ---

// Apex returns the eTLD+1 of a hostname.
func Apex(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if apex, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return apex
	}
	return host
}

func spec(stage scanproto.Stage, tgt scanproto.Target, prio int, origin uuid.UUID, caps ...string) store.TaskSpec {
	return store.TaskSpec{Stage: stage, Target: tgt, Priority: prio, Requires: caps, Origins: []uuid.UUID{origin}}
}

func decode(b []byte) StageSummary {
	var s StageSummary
	if len(b) > 0 {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func origin0(o []uuid.UUID) uuid.UUID {
	if len(o) == 0 {
		return uuid.Nil
	}
	return o[0]
}

func mergeOrigins(a, b []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			a = append(a, x)
			seen[x] = true
		}
	}
	return a
}

func authIndex(ts []domain.ScopeTarget) map[string]domain.ScopeTarget {
	m := map[string]domain.ScopeTarget{}
	for _, t := range ts {
		m[t.Value] = t
	}
	return m
}

func authorized(idx map[string]domain.ScopeTarget, value string) bool {
	t, ok := idx[value]
	return ok && t.Authorized()
}

// isPrivateTarget reports whether an IP or CIDR names an internal range.
// Such targets are out of scope for this product and are never scanned.
func isPrivateTarget(v string) bool {
	if p, err := netip.ParsePrefix(v); err == nil {
		a := p.Addr()
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
	}
	return false
}

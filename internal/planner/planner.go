// Package planner turns a scan run into a task DAG and advances it through the
// pipeline stages. The one hard barrier is dns_resolve -> coalesce -> port_scan
// (architecture.md §4): the union of resolved IPs across ALL targets in the run
// is deduped before any host is scanned, so a shared IP is never scanned twice.
package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
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
	Domains  []string `json:"domains,omitempty"`  // discovered subdomains
	IPs      []string `json:"ips,omitempty"`      // resolved / enriched addresses
	Services []IPPort `json:"services,omitempty"` // open ports
	WebURLs  []string `json:"web_urls,omitempty"` // live http(s) endpoints
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
	// Only subdomain wordlists fan out; resolver lists are an input to every
	// brute task, not a task of their own.
	lists, err := p.st.RunWordlistsByKind(ctx, run.ID, "dns")
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
		if err := p.scanNewAddresses(ctx, run); err != nil {
			return false, err
		}
		if err := p.probeNewServices(ctx, run); err != nil {
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

// scanBatchSize is how many addresses go into one port-scan task. nmap is built
// to take a host list and schedule across it, and its --min-hostgroup and rate
// settings only mean anything with a real group. Batching also keeps a /24 from
// becoming 254 tasks, each spawning its own scanner.
const scanBatchSize = 64

// scanNewAddresses queues port scans for addresses discovered so far that are
// not already queued.
//
// This deliberately replaces the old discovery -> coalesce -> port_scan barrier.
// The barrier made every address wait for the slowest discovery task, so
// subfinder results (seconds) sat behind a shuffledns run over millions of names.
// Scanning incrementally starts as soon as the first names resolve, while
// deduplicating against what is already queued keeps the property the barrier
// existed for: a host that two sources both found is still scanned once.
func (p *Planner) scanNewAddresses(ctx context.Context, run domain.ScanRun) error {
	// Union the addresses every finished discovery task has reported.
	ipSet := map[string][]uuid.UUID{}
	for _, stage := range []scanproto.Stage{
		scanproto.StagePassiveEnum, scanproto.StageDNSBrute, scanproto.StageDNSResolve} {
		tasks, err := p.st.TasksByStage(ctx, run.ID, stage)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			if t.Status != string(domain.TaskDone) {
				continue // only completed tasks have a summary to read
			}
			sum := decode(t.Result)
			if len(sum.IPs) == 0 {
				continue
			}
			origins, _ := p.st.OriginsForTask(ctx, t.ID)
			for _, ip := range sum.IPs {
				ipSet[ip] = mergeOrigins(ipSet[ip], origins)
			}
		}
	}
	if len(ipSet) == 0 {
		return nil
	}

	// Port scanning an address is active scanning of the target's
	// infrastructure, so it needs the same authorization a CIDR target does.
	// Discovery is passive and runs for any target; only addresses traceable to
	// an authorized run_target may be scanned. The old barrier never completed
	// in practice, which hid this: making scanning incremental reaches it.
	authorized, err := p.authorizedRunTargets(ctx, run)
	if err != nil {
		return err
	}

	already, err := p.st.ScannedAddresses(ctx, run.ID)
	if err != nil {
		return err
	}
	fresh := make([]string, 0, len(ipSet))
	skipped := 0
	for ip, origins := range ipSet {
		if already[ip] {
			continue
		}
		permitted := false
		for _, o := range origins {
			if authorized[o] {
				permitted = true
				break
			}
		}
		if !permitted {
			skipped++
			continue
		}
		fresh = append(fresh, ip)
	}
	if skipped > 0 {
		slog.Info("not port scanning addresses from unauthorized targets",
			"run", run.ID, "addresses", skipped)
	}
	if len(fresh) == 0 {
		return nil
	}
	sort.Strings(fresh) // deterministic batches make a run reproducible

	var specs []store.TaskSpec
	for i := 0; i < len(fresh); i += scanBatchSize {
		end := i + scanBatchSize
		if end > len(fresh) {
			end = len(fresh)
		}
		batch := fresh[i:end]

		// A batch serves every run_target that contributed an address to it, so
		// results attribute back to each domain that pointed there.
		var origins []uuid.UUID
		for _, ip := range batch {
			origins = mergeOrigins(origins, ipSet[ip])
		}
		if len(origins) == 0 {
			continue
		}
		sp := spec(scanproto.StagePortScan, scanproto.Target{IPs: batch},
			100, origins[0], string(scanproto.CapRawSocket))
		sp.Origins = origins
		specs = append(specs, sp)
	}
	if len(specs) == 0 {
		return nil
	}
	slog.Info("queued port scans", "run", run.ID, "addresses", len(fresh), "tasks", len(specs))
	_, err = p.st.InsertTasks(ctx, run.ID, specs)
	return err
}

// probeNewServices enqueues service_probe for open ports as port scans finish.
//
// Incremental for the same reason scanning is: port-scan tasks now complete
// continuously rather than all at once, so waiting for the whole stage would
// reintroduce the head-of-line blocking that batching just removed.
func (p *Planner) probeNewServices(ctx context.Context, run domain.ScanRun) error {
	tasks, err := p.st.TasksByStage(ctx, run.ID, scanproto.StagePortScan)
	if err != nil {
		return err
	}
	already, err := p.st.ProbedEndpoints(ctx, run.ID)
	if err != nil {
		return err
	}

	var specs []store.TaskSpec
	for _, t := range tasks {
		if t.Status != string(domain.TaskDone) {
			continue
		}
		sum := decode(t.Result)
		if len(sum.Services) == 0 {
			continue
		}
		origins, _ := p.st.OriginsForTask(ctx, t.ID)
		for _, sv := range sum.Services {
			key := fmt.Sprintf("%s:%d", sv.IP, sv.Port)
			if already[key] {
				continue
			}
			already[key] = true // also dedupes within this pass
			specs = append(specs, spec(scanproto.StageServiceProbe,
				scanproto.Target{IP: sv.IP, Port: sv.Port}, 200, origin0(origins)))
		}
	}
	if len(specs) == 0 {
		return nil
	}
	slog.Info("queued service probes", "run", run.ID, "endpoints", len(specs))
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

// authorizedRunTargets reports which of a run's targets permit active scanning.
// A run_target carries only the value it was created from, so this maps back to
// the scope target that authorizes it.
func (p *Planner) authorizedRunTargets(ctx context.Context, run domain.ScanRun) (map[uuid.UUID]bool, error) {
	scopeTargets, err := p.st.ListTargets(ctx, run.ScopeID, "")
	if err != nil {
		return nil, err
	}
	authByValue := make(map[string]bool, len(scopeTargets))
	for _, t := range scopeTargets {
		authByValue[t.Value] = t.Authorized()
	}

	runTargets, err := p.st.ListRunTargets(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(runTargets))
	for _, rt := range runTargets {
		out[rt.ID] = authByValue[rt.Value]
	}
	return out, nil
}

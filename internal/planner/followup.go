package planner

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/scanproto"
	"github.com/benlik386/pinkglasses/internal/store"
)

// planFollowUp plans the first tasks of a follow-up run: a fresh resolution
// of every chosen name — what a passive run saw may be days old, and a name
// that has moved must not lead to someone else's address — and the port
// scans of every chosen address. Nothing is discovered: the run's settings
// have passive enumeration and brute force off (scanparams.FollowUpFixed).
func (p *Planner) planFollowUp(ctx context.Context, run domain.ScanRun, targets []domain.RunTarget, seeds []store.RunSeed, rt routing) error {
	origins := map[string][]uuid.UUID{}
	for _, sd := range seeds {
		if sd.Kind == "domain" {
			origins[sd.Value] = mergeOrigins(origins[sd.Value], []uuid.UUID{sd.RunTargetID})
		}
	}
	names := make([]string, 0, len(origins))
	for n := range origins {
		names = append(names, n)
	}
	sort.Strings(names)
	var specs []store.TaskSpec
	for _, n := range names {
		sp := spec(scanproto.StageDNSResolve, scanproto.Target{Domain: n}, 30, origins[n][0])
		sp.Origins = origins[n]
		specs = append(specs, sp)
	}
	for _, t := range targets {
		_ = p.st.SetRunTargetStatus(ctx, t.ID, domain.TargetRunning, nil)
	}
	if len(specs) > 0 {
		routed, err := routeTasks(specs, rt)
		if err != nil {
			return err
		}
		if _, err := p.st.InsertTasks(ctx, run.ID, routed); err != nil {
			return err
		}
	}
	// The chosen addresses need nothing resolved first.
	if err := p.scanNewAddresses(ctx, run); err != nil {
		return err
	}
	if prog, err := p.st.RunProgress(ctx, run.ID); err == nil && prog.Total == 0 {
		// Port scanning is off and no name was chosen: nothing to do.
		return p.finish(ctx, run)
	}
	return nil
}

// resolveNewNames queues a resolution for every name a follow-up run's web
// stages came across — the names on a certificate — that lies below one of
// its domain targets and has not been resolved in this run yet. From there
// the name goes the way a chosen one does: its addresses are port scanned
// and its services probed. An ordinary run leaves this to discovery.
func (p *Planner) resolveNewNames(ctx context.Context, run domain.ScanRun) error {
	seeds, err := p.st.RunSeeds(ctx, run.ID, "")
	if err != nil || len(seeds) == 0 {
		return err
	}
	targets, err := p.st.ListRunTargets(ctx, run.ID)
	if err != nil {
		return err
	}
	var domains []domain.RunTarget
	for _, t := range targets {
		if t.Kind == "domain" {
			domains = append(domains, t)
		}
	}
	if len(domains) == 0 {
		return nil
	}
	scopeTargets, err := p.st.ListTargetsMerged(ctx, run.ScopeID, "")
	if err != nil {
		return err
	}
	var excluded []string
	for _, t := range scopeTargets {
		if t.Mode == domain.ModeExclude && t.Kind == "domain" {
			excluded = append(excluded, strings.ToLower(t.Value))
		}
	}

	resolved := map[string]bool{}
	have, err := p.st.StageTargets(ctx, run.ID, scanproto.StageDNSResolve)
	if err != nil {
		return err
	}
	for _, t := range have {
		resolved[t.Domain] = true
	}

	var specs []store.TaskSpec
	for _, stage := range []scanproto.Stage{scanproto.StageServiceProbe, scanproto.StageTechDetect} {
		tasks, err := p.st.TasksByStage(ctx, run.ID, stage)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			for _, raw := range decode(t.Result).Names {
				n := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "*.")), ".")
				if n == "" || resolved[n] || below(n, excluded) != "" {
					continue
				}
				under := targetFor(n, domains)
				if under == nil {
					continue // a certificate names other companies' hosts too
				}
				resolved[n] = true
				specs = append(specs, spec(scanproto.StageDNSResolve, scanproto.Target{Domain: n}, 30, under.ID))
			}
		}
	}
	if len(specs) == 0 {
		return nil
	}
	slog.Info("resolving names found on certificates", "run", run.ID, "names", len(specs))
	rt, err := p.routingFor(ctx, run)
	if err != nil {
		return err
	}
	routed, err := routeTasks(specs, rt)
	if err != nil {
		return err
	}
	_, err = p.st.InsertTasks(ctx, run.ID, routed)
	return err
}

// below returns the first of the domains the name is, or lies below.
func below(name string, domains []string) string {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return d
		}
	}
	return ""
}

// targetFor returns the domain target a name lies below, the closest one when
// several do.
func targetFor(name string, targets []domain.RunTarget) *domain.RunTarget {
	var best *domain.RunTarget
	for i := range targets {
		v := strings.ToLower(targets[i].Value)
		if (name == v || strings.HasSuffix(name, "."+v)) && (best == nil || len(v) > len(best.Value)) {
			best = &targets[i]
		}
	}
	return best
}

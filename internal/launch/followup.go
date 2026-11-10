package launch

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

// A follow-up run scans what an earlier run found — its names and addresses —
// with the active stages only. Its run targets are the earlier run's, so
// authorization works exactly as it does for any run: a name or address may
// be scanned because the target it was found under is authorized. What it
// was started on is recorded as seeds under those targets.

// followUp is a follow-up run's plan before the run row exists.
type followUp struct {
	parent  domain.ScanRun
	targets []domain.RunTarget
	seeds   []pendingSeed
}

// pendingSeed is a seed whose run targets are named by value; the run's
// target rows, and with them their ids, do not exist yet.
type pendingSeed struct {
	kind, value string
	under       []string
}

// FollowUpAssets is what a run found that a follow-up could be started on:
// the run's own targets first, then the names and addresses below them. An
// excluded target, and anything found only under one, is left out.
func FollowUpAssets(ctx context.Context, st *store.Store, parentID uuid.UUID) ([]store.RunAsset, error) {
	parent, err := st.GetRun(ctx, parentID)
	if err != nil {
		return nil, err
	}
	scopeTargets, err := st.ListTargetsMerged(ctx, parent.ScopeID, "")
	if err != nil {
		return nil, err
	}
	targets, err := st.ListRunTargets(ctx, parentID)
	if err != nil {
		return nil, err
	}
	found, err := st.RunAssets(ctx, parentID)
	if err != nil {
		return nil, err
	}
	return candidates(scopeTargets, targets, found), nil
}

// candidates puts a run's targets and findings together and drops what the
// company's scope no longer allows: a target that is now excluded or gone,
// a name at or below an excluded domain.
func candidates(scopeTargets []domain.ScopeTarget, targets []domain.RunTarget, found []store.RunAsset) []store.RunAsset {
	usable := map[string]bool{}
	var excludedDomains []string
	for _, t := range scopeTargets {
		switch {
		case t.Mode == domain.ModeExclude && t.Kind == "domain":
			excludedDomains = append(excludedDomains, strings.ToLower(t.Value))
		case t.Mode != domain.ModeExclude:
			usable[t.Value] = true
		}
	}
	excluded := func(name string) bool {
		for _, d := range excludedDomains {
			if name == d || strings.HasSuffix(name, "."+d) {
				return true
			}
		}
		return false
	}

	var out []store.RunAsset
	seen := map[string]bool{}
	for _, t := range targets {
		if !usable[t.Value] || (t.Kind == "domain" && excluded(t.Value)) {
			continue
		}
		out = append(out, store.RunAsset{Kind: t.Kind, Value: t.Value, Under: []string{t.Value}, Target: true})
		seen[t.Kind+"|"+t.Value] = true
	}
	for _, a := range found {
		if seen[a.Kind+"|"+a.Value] || (a.Kind == "domain" && excluded(a.Value)) {
			continue
		}
		var under []string
		for _, u := range a.Under {
			if usable[u] {
				under = append(under, u)
			}
		}
		if len(under) == 0 {
			continue
		}
		a.Under = under
		out = append(out, a)
	}
	return out
}

// planFollowUp checks a follow-up request and works out its targets and
// seeds. assets narrows to named values; none means everything the parent
// found.
func (l *Launcher) planFollowUp(ctx context.Context, scopeID uuid.UUID, profile domain.RunProfile, o Options, scopeTargets []domain.ScopeTarget) (*followUp, *Refusal) {
	parentID, err := uuid.Parse(o.FromRunID)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "from_run_id is not a run id")
	}
	parent, err := l.st.GetRun(ctx, parentID)
	if err != nil || parent.ScopeID != scopeID {
		return nil, refuse(http.StatusNotFound, "the run to follow up was not found in this company")
	}
	switch parent.Status {
	case domain.RunCompleted, domain.RunFailed, domain.RunCancelled:
	default:
		return nil, refuse(http.StatusConflict,
			"that run is still %s; a follow-up scans the results of a run that has ended", parent.Status)
	}
	if profile == domain.ProfilePassive {
		return nil, refuse(http.StatusBadRequest,
			"a follow-up scan is the active part: choose the standard or deep profile")
	}
	targets, err := l.st.ListRunTargets(ctx, parentID)
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, "%v", err)
	}
	found, err := l.st.RunAssets(ctx, parentID)
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, "%v", err)
	}
	seeds, ref := selectSeeds(candidates(scopeTargets, targets, found), o.Assets)
	if ref != nil {
		return nil, ref
	}

	// The run covers the parent's targets that something chosen was found
	// under, and no others.
	needed := map[string]bool{}
	for _, sd := range seeds {
		for _, u := range sd.under {
			needed[u] = true
		}
	}
	f := &followUp{parent: parent, seeds: seeds}
	for _, t := range targets {
		if needed[t.Value] {
			f.targets = append(f.targets, domain.RunTarget{Kind: t.Kind, Value: t.Value})
			needed[t.Value] = false // a value listed twice is one target
		}
	}
	return f, nil
}

// selectSeeds narrows the candidates to the chosen values. A chosen value
// that is not among them is refused by name, so a typo or a value from
// another run is not quietly left out.
func selectSeeds(cands []store.RunAsset, chosen []string) ([]pendingSeed, *Refusal) {
	want := map[string]bool{}
	for _, v := range chosen {
		if v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "."); v != "" {
			want[v] = true
		}
	}
	var out []pendingSeed
	matched := map[string]bool{}
	for _, c := range cands {
		v := strings.ToLower(c.Value)
		if len(want) > 0 && !want[v] {
			continue
		}
		matched[v] = true
		out = append(out, pendingSeed{kind: c.Kind, value: c.Value, under: c.Under})
	}
	var missing []string
	for v := range want {
		if !matched[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		if len(missing) > 5 {
			missing = append(missing[:5], "…")
		}
		return nil, refuse(http.StatusBadRequest,
			"not among that run's results, or excluded from the company since: %s", strings.Join(missing, ", "))
	}
	if len(out) == 0 {
		return nil, refuse(http.StatusBadRequest,
			"that run found nothing a follow-up could scan: no names or addresses under targets the company still allows")
	}
	return out, nil
}

// saveSeeds records the seeds against the run's target rows.
func (l *Launcher) saveSeeds(ctx context.Context, runID uuid.UUID, saved []domain.RunTarget, seeds []pendingSeed) error {
	idOf := map[string]uuid.UUID{}
	for _, t := range saved {
		idOf[t.Value] = t.ID
	}
	var rows []store.RunSeed
	for _, sd := range seeds {
		for _, u := range sd.under {
			if id, ok := idOf[u]; ok {
				rows = append(rows, store.RunSeed{RunTargetID: id, Kind: sd.kind, Value: sd.value})
			}
		}
	}
	return l.st.InsertRunSeeds(ctx, runID, rows)
}

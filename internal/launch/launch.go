// Package launch starts scan runs.
//
// There is one way to start a run, and both callers use it: the API when a
// person clicks, the scheduler when a schedule is due. Run creation used to live
// in the API handler alongside exit binding and fleet requests; giving the
// scheduler its own copy would have meant two sets of rules that drift — the
// failure this codebase has paid for more than once.
package launch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/planner"
	"github.com/benlik386/pinkglasses/internal/scanparams"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Options is everything a caller may say about a run.
type Options struct {
	Profile string
	// Targets narrows to named target values; Tag to a tag; All takes every
	// non-excluded target. The first of these that is set wins.
	Targets []string
	Tag     string
	All     bool
	// Exit is where the active stages leave from: "local" (needs VPNConfigID)
	// or "remote" (needs PoolID). A passive profile needs neither.
	Exit        string
	VPNConfigID string
	PoolID      string
	WorkerCount int
	// ProfileID is a saved preset; Params are ad-hoc overrides on top of it.
	ProfileID   string
	Params      map[string]string
	WordlistIDs []string
	// Trigger is recorded on the run: "manual" or "scheduled".
	Trigger string
}

// Refusal is why a run was not started, with the HTTP status the API should
// answer. The message is written for a person and names the fix.
type Refusal struct {
	Status int
	Msg    string
}

func (r *Refusal) Error() string { return r.Msg }

func refuse(status int, format string, a ...any) *Refusal {
	return &Refusal{Status: status, Msg: fmt.Sprintf(format, a...)}
}

// Launcher starts runs.
type Launcher struct {
	st *store.Store
	pl *planner.Planner
}

// New builds a Launcher.
func New(st *store.Store, pl *planner.Planner) *Launcher { return &Launcher{st: st, pl: pl} }

// ProvisionerConfigured says whether a local exit can be built at all.
func ProvisionerConfigured() bool {
	return os.Getenv("ASM_PROVISIONER_URL") != "" && os.Getenv("ASM_PROVISIONER_TOKEN") != ""
}

// Start creates a run, binds its exit, and plans its first stage.
//
// A run row exists from the moment the targets are validated. A later refusal
// (no VPN config, empty pool) fails that row rather than deleting it, so the
// attempt and its reason stay on record.
func (l *Launcher) Start(ctx context.Context, scopeID uuid.UUID, o Options) (domain.ScanRun, *Refusal) {
	profile := domain.RunProfile(o.Profile)
	if profile == "" {
		profile = domain.ProfileStandard
	}
	if o.Trigger == "" {
		o.Trigger = "manual"
	}

	// Targets: never scan an excluded one.
	scopeTargets, err := l.st.ListTargets(ctx, scopeID, o.Tag)
	if err != nil {
		return domain.ScanRun{}, refuse(http.StatusInternalServerError, "%v", err)
	}
	want := map[string]bool{}
	for _, v := range o.Targets {
		want[v] = true
	}
	var runTargets []domain.RunTarget
	for _, t := range scopeTargets {
		if t.Mode == domain.ModeExclude {
			continue
		}
		if o.All || o.Tag != "" || want[t.Value] {
			runTargets = append(runTargets, domain.RunTarget{Kind: t.Kind, Value: t.Value})
		}
	}
	if len(runTargets) == 0 {
		all, _ := l.st.ListTargets(ctx, scopeID, "")
		usable := 0
		for _, t := range all {
			if t.Mode != domain.ModeExclude {
				usable++
			}
		}
		switch {
		case usable == 0:
			return domain.ScanRun{}, refuse(http.StatusBadRequest,
				"this scope has no targets yet — add a domain or CIDR on the Dashboard before scanning")
		case o.Tag != "":
			return domain.ScanRun{}, refuse(http.StatusBadRequest, "no targets carry the tag %q", o.Tag)
		default:
			return domain.ScanRun{}, refuse(http.StatusBadRequest, "none of the selected targets are in this scope")
		}
	}

	// Parameters: a saved preset, then ad-hoc overrides, validated as a set.
	rawParams := map[string]string{}
	var profileID *uuid.UUID
	if o.ProfileID != "" {
		if id, err := uuid.Parse(o.ProfileID); err == nil {
			if pp, err := l.st.GetScanProfileParams(ctx, id); err == nil {
				rawParams = pp
				profileID = &id
			}
		}
	}
	for k, v := range o.Params {
		rawParams[k] = v
	}
	cleanParams, err := scanparams.Validate(rawParams)
	if err != nil {
		return domain.ScanRun{}, refuse(http.StatusBadRequest, "invalid scan parameter: %v", err)
	}
	effective := scanparams.WithDefaults(cleanParams)

	// Exit: validated before any row exists. A refusal here leaves nothing
	// behind — no failed run to explain later. For a schedule that matters
	// hourly: a deleted VPN config would otherwise mint a failed run every
	// cadence on top of the reason already written on the schedule.
	var exitPlan *exitPlan
	if profile != domain.ProfilePassive {
		var ref *Refusal
		if exitPlan, ref = l.checkExit(ctx, scopeID, o); ref != nil {
			return domain.ScanRun{}, ref
		}
	}

	run := domain.ScanRun{ScopeID: scopeID, Profile: profile, Trigger: o.Trigger, MaxConcurrency: 32}
	run, saved, err := l.st.CreateRun(ctx, run, runTargets)
	if err != nil {
		return domain.ScanRun{}, refuse(http.StatusInternalServerError, "%v", err)
	}

	// Wordlists: named lists of any kind; every kind left unsaid falls back to
	// the registry defaults, so a plain scan needs no wordlist knowledge.
	chosen := map[string]bool{}
	var wlIDs []uuid.UUID
	for _, raw := range o.WordlistIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		wl, err := l.st.GetWordlist(ctx, id)
		if err != nil {
			return l.failed(ctx, run, refuse(http.StatusBadRequest, "unknown wordlist %s", raw))
		}
		if wl.Status != "ready" {
			return l.failed(ctx, run, refuse(http.StatusBadRequest, "wordlist %q is not ready (%s)", wl.Name, wl.Status))
		}
		chosen[wl.Kind] = true
		wlIDs = append(wlIDs, id)
	}
	for _, kind := range []string{"dns", "resolvers", "dir"} {
		if chosen[kind] {
			continue
		}
		if defs, err := l.st.DefaultWordlists(ctx, kind); err == nil {
			for _, d := range defs {
				wlIDs = append(wlIDs, d.ID)
			}
		}
	}
	if err := l.st.SetRunWordlists(ctx, run.ID, wlIDs); err != nil {
		return l.failed(ctx, run, refuse(http.StatusInternalServerError, "%v", err))
	}

	// Exit: bind what was validated above.
	if exitPlan != nil {
		if err := l.bindExit(ctx, run, *exitPlan); err != nil {
			return l.failed(ctx, run, refuse(http.StatusInternalServerError, "%v", err))
		}
	}

	if err := l.st.SetRunParams(ctx, run.ID, profileID, effective); err != nil {
		return l.failed(ctx, run, refuse(http.StatusInternalServerError, "%v", err))
	}
	if err := l.pl.PlanInitial(ctx, run, saved, scopeTargets); err != nil {
		return l.failed(ctx, run, refuse(http.StatusInternalServerError, "%v", err))
	}
	return run, nil
}

// failed marks a run that could not be started, keeping the record and the
// reason, and returns the refusal for the caller to report.
func (l *Launcher) failed(ctx context.Context, run domain.ScanRun, ref *Refusal) (domain.ScanRun, *Refusal) {
	_ = l.st.CancelRunTasks(ctx, run.ID)
	_ = l.st.SetRunStatus(ctx, run.ID, domain.RunFailed)
	return run, ref
}

// exitPlan is a validated exit: everything checkExit established, ready to be
// bound to a run without further refusals.
type exitPlan struct {
	kind    string // local | remote
	poolID  uuid.UUID
	vpnID   uuid.UUID
	workers int
}

// checkExit validates where a run's active stages will run from, and refuses
// if that cannot be satisfied. No side effects: nothing is written until a run
// exists to bind it to. Two exits exist; there is deliberately no "direct from
// this host" (architecture.md §7.6).
func (l *Launcher) checkExit(ctx context.Context, scopeID uuid.UUID, o Options) (*exitPlan, *Refusal) {
	switch o.Exit {
	case "remote":
		if o.PoolID == "" {
			return nil, refuse(http.StatusBadRequest, "a remote exit needs pool_id: which pool of enrolled workers should run this scan")
		}
		id, err := uuid.Parse(o.PoolID)
		if err != nil {
			return nil, refuse(http.StatusBadRequest, "bad pool id")
		}
		pool, ok, err := l.st.GetExitPool(ctx, id)
		if err != nil {
			return nil, refuse(http.StatusInternalServerError, "%v", err)
		}
		if !ok {
			return nil, refuse(http.StatusBadRequest, "that pool does not exist, or belongs to another run")
		}
		if pool.ActiveWorkers == 0 {
			return nil, refuse(http.StatusConflict,
				"pool %q has no active worker to run this scan; enrol one under Workers, or approve a pending one", pool.Name)
		}
		return &exitPlan{kind: "remote", poolID: pool.ID}, nil

	case "local":
		if !ProvisionerConfigured() {
			return nil, refuse(http.StatusBadRequest,
				"a local exit builds workers and a VPN gateway for this run, but no provisioner is "+
					"configured to create them: set ASM_PROVISIONER_URL and ASM_PROVISIONER_TOKEN, or "+
					"scan from a remote pool instead")
		}
		if o.VPNConfigID == "" {
			configs, _ := l.st.ListVPNConfigs(ctx, scopeID)
			if len(configs) == 0 {
				return nil, refuse(http.StatusConflict,
					"scanning from local workers needs a VPN so the scan never leaves from this "+
						"host's own address, and this company has no VPN configuration yet: add one "+
						"under VPN, or scan from a remote pool")
			}
			return nil, refuse(http.StatusBadRequest, "a local exit needs vpn_config_id: which tunnel this scan leaves through")
		}
		vpnID, err := uuid.Parse(o.VPNConfigID)
		if err != nil {
			return nil, refuse(http.StatusBadRequest, "bad vpn config id")
		}
		vc, err := l.st.GetVPNConfig(ctx, vpnID)
		if err != nil || vc.ScopeID != scopeID {
			return nil, refuse(http.StatusBadRequest, "unknown vpn config")
		}
		workers := o.WorkerCount
		if workers <= 0 {
			workers = defaultFleetWorkers
		}
		if workers > maxFleetWorkers {
			return nil, refuse(http.StatusBadRequest, "a run may ask for at most %d workers", maxFleetWorkers)
		}
		return &exitPlan{kind: "local", vpnID: vpnID, workers: workers}, nil

	case "":
		return nil, refuse(http.StatusBadRequest,
			"this scan sends traffic at its targets, so it needs an exit: \"local\" (own workers "+
				"behind a VPN) or \"remote\" (a pool of enrolled workers). Only a passive scan needs neither")
	default:
		return nil, refuse(http.StatusBadRequest, "exit must be \"local\" or \"remote\"")
	}
}

// bindExit applies a validated exit to a run. Only database errors can occur
// here; every reason to refuse was found by checkExit first.
func (l *Launcher) bindExit(ctx context.Context, run domain.ScanRun, p exitPlan) error {
	switch p.kind {
	case "remote":
		return l.st.SetRunPool(ctx, run.ID, p.poolID)
	case "local":
		if err := l.st.SetRunVPN(ctx, run.ID, p.vpnID); err != nil {
			return err
		}
		return l.requestRunFleet(ctx, run, p.workers, &p.vpnID)
	}
	return nil
}

const (
	defaultFleetWorkers = 2
	maxFleetWorkers     = 8
	scanKindLocal       = "local"
)

// requestRunFleet records that a run wants containers of its own: a pool no
// other run can lease from, and an enrollment token bound to it. Nothing is
// created here; the scheduler builds the fleet from this record.
func (l *Launcher) requestRunFleet(ctx context.Context, run domain.ScanRun, count int, vpnID *uuid.UUID) error {
	if count <= 0 {
		count = defaultFleetWorkers
	}
	if count > maxFleetWorkers {
		return fmt.Errorf("a run may ask for at most %d workers", maxFleetWorkers)
	}
	poolID, err := l.st.CreateRunPool(ctx, "run "+run.ID.String()[:8])
	if err != nil {
		return err
	}
	if err := l.st.SetRunPool(ctx, run.ID, poolID); err != nil {
		return err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if _, err := l.st.CreateEnrollmentToken(ctx, sum[:], &poolID, nil, 30*time.Minute, count+2, scanKindLocal); err != nil {
		return err
	}
	return l.st.CreateRunFleet(ctx, store.RunFleet{
		RunID: run.ID, PoolID: &poolID, Workers: count, EnrollToken: token, VPNConfigID: vpnID,
	})
}

// Due starts every schedule whose time has come. Called from the scheduler
// tick. A company with a run still going is skipped, never stacked; a refusal
// is written on the schedule where the UI shows it and retried next cadence.
func (l *Launcher) Due(ctx context.Context) {
	due, err := l.st.DueSchedules(ctx)
	if err != nil || len(due) == 0 {
		return
	}
	for _, sc := range due {
		busy, err := l.st.ScopeHasActiveRun(ctx, sc.ScopeID)
		if err != nil {
			continue
		}
		if busy {
			_ = l.st.ScheduleSkipped(ctx, sc.ID)
			slog.Info("scheduled scan skipped: the company still has a run going",
				"schedule", sc.ID, "scope", sc.ScopeID)
			continue
		}
		o := Options{
			Profile: sc.Profile, All: true, Exit: sc.Exit, WorkerCount: sc.WorkerCount,
			Params: sc.Params, Trigger: "scheduled",
		}
		if sc.ProfileID != nil {
			o.ProfileID = sc.ProfileID.String()
		}
		for _, w := range sc.WordlistIDs {
			o.WordlistIDs = append(o.WordlistIDs, w.String())
		}
		if sc.VPNConfigID != nil {
			o.VPNConfigID = sc.VPNConfigID.String()
		}
		if sc.PoolID != nil {
			o.PoolID = sc.PoolID.String()
		}
		run, ref := l.Start(ctx, sc.ScopeID, o)
		if ref != nil {
			_ = l.st.ScheduleFailed(ctx, sc.ID, ref.Msg)
			slog.Warn("scheduled scan did not start", "schedule", sc.ID, "scope", sc.ScopeID, "reason", ref.Msg)
			continue
		}
		_ = l.st.ScheduleStarted(ctx, sc.ID, run.ID)
		slog.Info("scheduled scan started", "schedule", sc.ID, "run", run.ID, "profile", sc.Profile, "exit", sc.Exit)
	}
}

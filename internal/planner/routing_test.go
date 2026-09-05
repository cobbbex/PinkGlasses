package planner

import (
	"testing"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/scanproto"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Every stage must be classified as sending traffic to the target or not.
//
// This is the guard that matters: a stage added to the pipeline without an
// entry here defaults to false and would silently bypass a tunnel. The leak
// this was written after was exactly that shape — port scanning from an IP
// scope target went through a planning path nobody had updated, so a run bound
// to a VPN scanned from an ordinary worker's real address.
func TestEveryStageIsClassified(t *testing.T) {
	// Traffic stages must demand the tunnel; discovery stages must not, or a
	// run bound to a VPN would stall waiting for a VPN worker to resolve DNS.
	traffic := map[scanproto.Stage]bool{
		scanproto.StagePortScan: true, scanproto.StageServiceProbe: true,
		scanproto.StageTechDetect: true, scanproto.StageScreenshot: true,
		scanproto.StageDirBrute: true, scanproto.StageVulnCheck: true,
		scanproto.StagePassiveEnum: false, scanproto.StageDNSBrute: false,
		scanproto.StageDNSResolve: false, scanproto.StageIPEnrich: false,
	}
	for _, st := range scanproto.AllStages {
		want, known := traffic[st]
		if !known {
			t.Errorf("stage %q is new and unclassified here: decide whether it sends "+
				"packets at the target, or it will silently bypass a tunnel", st)
			continue
		}
		if got := st.SendsTrafficToTarget(); got != want {
			t.Errorf("stage %q: SendsTrafficToTarget()=%v, want %v", st, got, want)
		}
	}
}

// routeTasks sends every spec to exactly one pool, chosen by stage class.
//
// The property under test is the one that closes the old lease leak: a task is
// never left for "anyone". Passive stages go to the standing pool whatever the
// run chose; active stages go to the run's exit pool; and a run with no exit
// pool leaves its active tasks with a nil pool, which the lease query matches
// against nothing — failing closed rather than running from the wrong place.
func TestRouteTasksByStageClass(t *testing.T) {
	passive := uuid.New()
	active := uuid.New()
	specs := []store.TaskSpec{
		{Stage: scanproto.StagePassiveEnum},
		{Stage: scanproto.StageDNSBrute},
		{Stage: scanproto.StageDNSResolve},
		{Stage: scanproto.StageIPEnrich},
		{Stage: scanproto.StagePortScan, Requires: []string{"raw_socket"}},
		{Stage: scanproto.StageServiceProbe},
		{Stage: scanproto.StageTechDetect},
		{Stage: scanproto.StageScreenshot, Requires: []string{"browser"}},
		{Stage: scanproto.StageDirBrute},
		{Stage: scanproto.StageVulnCheck},
	}
	got := routeTasks(specs, routing{passive: &passive, active: &active})
	for _, sp := range got {
		want := passive
		if sp.Stage.SendsTrafficToTarget() {
			want = active
		}
		if sp.PoolID == nil || *sp.PoolID != want {
			t.Errorf("%s routed to %v, want %v", sp.Stage, sp.PoolID, want)
		}
		// Routing must not touch capability requirements; those are about what
		// a worker can do, not where it is.
		if sp.Stage == scanproto.StageScreenshot && (len(sp.Requires) != 1 || sp.Requires[0] != "browser") {
			t.Errorf("screenshot requirements were altered: %v", sp.Requires)
		}
	}

	// No exit pool: active tasks get nil, passive still route. The API refuses
	// to create such a run; this is what happens if something slips past it.
	none := routeTasks([]store.TaskSpec{
		{Stage: scanproto.StagePassiveEnum}, {Stage: scanproto.StagePortScan},
	}, routing{passive: &passive, active: nil})
	if none[0].PoolID == nil || *none[0].PoolID != passive {
		t.Errorf("passive task without an exit should still go to the passive pool, got %v", none[0].PoolID)
	}
	if none[1].PoolID != nil {
		t.Errorf("active task without an exit must have no pool (fail closed), got %v", none[1].PoolID)
	}
}

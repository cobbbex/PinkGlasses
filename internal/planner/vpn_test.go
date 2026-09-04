package planner

import (
	"testing"

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

// withVPN adds the requirement to traffic stages only, and never twice.
func TestWithVPNAppliesToTrafficStagesOnly(t *testing.T) {
	specs := []store.TaskSpec{
		{Stage: scanproto.StagePassiveEnum},
		{Stage: scanproto.StageDNSResolve},
		{Stage: scanproto.StagePortScan, Requires: []string{"raw_socket"}},
		{Stage: scanproto.StageScreenshot, Requires: []string{"browser"}},
		{Stage: scanproto.StageVulnCheck},
	}
	got := withVPN(specs, []string{"vpn"})

	want := map[scanproto.Stage][]string{
		scanproto.StagePassiveEnum: {},
		scanproto.StageDNSResolve:  {},
		scanproto.StagePortScan:    {"raw_socket", "vpn"},
		scanproto.StageScreenshot:  {"browser", "vpn"},
		scanproto.StageVulnCheck:   {"vpn"},
	}
	for _, sp := range got {
		w := want[sp.Stage]
		if len(sp.Requires) != len(w) {
			t.Errorf("%s requires %v, want %v", sp.Stage, sp.Requires, w)
			continue
		}
		for i := range w {
			if sp.Requires[i] != w[i] {
				t.Errorf("%s requires %v, want %v", sp.Stage, sp.Requires, w)
				break
			}
		}
	}

	// Applying twice must not duplicate, and no tunnel means no change.
	again := withVPN(got, []string{"vpn"})
	for _, sp := range again {
		n := 0
		for _, r := range sp.Requires {
			if r == "vpn" {
				n++
			}
		}
		if n > 1 {
			t.Errorf("%s accumulated the requirement %d times", sp.Stage, n)
		}
	}
	none := withVPN([]store.TaskSpec{{Stage: scanproto.StagePortScan}}, nil)
	if len(none[0].Requires) != 0 {
		t.Errorf("with no tunnel chosen nothing should be added, got %v", none[0].Requires)
	}
}

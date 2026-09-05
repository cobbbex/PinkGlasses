package fleet

import (
	"strings"
	"testing"
)

// The ceiling is a queue, not an error. Below it a fleet builds; at or over it
// the fleet waits and the reason names the knob that changes it.
func TestCeilingDecision(t *testing.T) {
	cases := []struct {
		holding, max int
		wait         bool
	}{
		{0, 3, false}, {2, 3, false},
		{3, 3, true}, {4, 3, true},
		{0, 1, false}, {1, 1, true},
	}
	for _, c := range cases {
		wait, note := ceilingDecision(c.holding, c.max)
		if wait != c.wait {
			t.Errorf("holding=%d max=%d: wait=%v, want %v", c.holding, c.max, wait, c.wait)
		}
		if wait && !strings.Contains(note, "ASM_MAX_RUN_FLEETS") {
			t.Errorf("waiting note must name the setting that raises the ceiling: %q", note)
		}
		if !wait && note != "" {
			t.Errorf("a fleet that builds should carry no waiting note, got %q", note)
		}
	}
}

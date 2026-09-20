package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A tool killed at its budget is reported as a ToolTimeout, with whatever it
// had written kept. Six dns_brute tasks once ran for exactly their hour and
// finished "done" with nothing, because the runner only logged the kill.
func TestRunLinesReportsTimeout(t *testing.T) {
	lines, err := runLines(context.Background(), 300*time.Millisecond,
		"sh", "-c", "echo first; sleep 5; echo never")
	var to *ToolTimeout
	if !errors.As(err, &to) {
		t.Fatalf("err = %v, want a ToolTimeout", err)
	}
	if to.Tool != "sh" || to.Timeout != 300*time.Millisecond {
		t.Errorf("timeout error names %q after %s", to.Tool, to.Timeout)
	}
	if len(lines) != 1 || lines[0] != "first" {
		t.Errorf("partial output was lost: %v", lines)
	}
	if _, err := runLines(context.Background(), 5*time.Second, "sh", "-c", "echo done"); err != nil {
		t.Errorf("a tool that finishes must not report a timeout: %v", err)
	}
}

// A permanent error stays permanent through wrapping, and an ordinary one
// is not mistaken for it.
func TestPermanentError(t *testing.T) {
	base := errors.New("could not finish")
	if !isPermanent(permanent(base)) {
		t.Error("permanent(err) must be recognised")
	}
	if isPermanent(base) {
		t.Error("a plain error must not read as permanent")
	}
	if !errors.Is(permanent(base), base) {
		t.Error("the cause must still be reachable through the wrapper")
	}
}

// The brute-force budget grows with the list: an hour for anything small,
// about 3.6 h for the 9.5M-name assetnote list.
func TestBruteTimeout(t *testing.T) {
	cases := []struct {
		names int
		want  time.Duration
	}{
		{0, time.Hour},
		{4_751, time.Hour + 4*time.Second},
		{3_244_387, time.Hour + 3244*time.Second},
		{9_544_235, time.Hour + 9544*time.Second},
	}
	for _, c := range cases {
		if got := bruteTimeout(c.names); got != c.want {
			t.Errorf("bruteTimeout(%d) = %s, want %s", c.names, got, c.want)
		}
	}
	if humanCount(9_544_235) != "9.5M" || humanCount(4_751) != "4.8k" || humanCount(12) != "12" {
		t.Errorf("humanCount: %s %s %s", humanCount(9_544_235), humanCount(4_751), humanCount(12))
	}
}

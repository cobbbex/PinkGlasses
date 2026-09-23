package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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

// The brute-force budget grows with the list and shrinks with the rate.
func TestBruteTimeout(t *testing.T) {
	cases := []struct {
		names, inflight int
		want            time.Duration
	}{
		{0, 300, time.Hour},
		{4_751, 300, time.Hour + 3*time.Second},
		{9_544_235, 300, time.Hour + 6362*time.Second},
		{9_544_235, 1000, time.Hour + 1908*time.Second},
		{1000, 0, time.Hour + 200*time.Second},
	}
	for _, c := range cases {
		if got := bruteTimeout(c.names, c.inflight); got != c.want {
			t.Errorf("bruteTimeout(%d, %d) = %s, want %s", c.names, c.inflight, got, c.want)
		}
	}
	dir := t.TempDir()
	p := dir + "/r.txt"
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "10.0.0.%d\n", i)
	}
	_ = os.WriteFile(p, []byte(b.String()), 0o600)
	sub, n, err := sampleLines(p, 10)
	if err != nil || sub == "" || n != 10 {
		t.Fatalf("sampleLines: %q %d %v", sub, n, err)
	}
	got, _ := os.ReadFile(sub)
	if c := strings.Count(string(got), "\n"); c != 10 {
		t.Errorf("sample holds %d lines, want 10", c)
	}
	if sub, n, _ := sampleLines(p, 100); sub != "" || n != 50 {
		t.Errorf("a list within the cap is used as is: %q %d", sub, n)
	}
	if humanCount(9_544_235) != "9.5M" || humanCount(4_751) != "4.8k" || humanCount(12) != "12" {
		t.Errorf("humanCount: %s %s %s", humanCount(9_544_235), humanCount(4_751), humanCount(12))
	}
}

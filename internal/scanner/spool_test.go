package scanner

import (
	"context"
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

func res(task string, seq int) scanproto.Result {
	return scanproto.Result{TaskID: task, Seq: seq,
		Observations: []scanproto.Observation{{Type: scanproto.ObsService, IP: "1.2.3.4", Port: 22}}}
}

// Batches come back out in the order they went in, and a delivered batch is
// gone from disk afterwards.
func TestSpoolReplaysInOrderAndClears(t *testing.T) {
	s := newSpool(t.TempDir())
	for i := 0; i < 3; i++ {
		if err := s.put("http://gw/results", res("task-a", i)); err != nil {
			t.Fatal(err)
		}
	}
	var got []int
	s.replay(context.Background(), func(_ context.Context, url string, r scanproto.Result) (outcome, string) {
		if url != "http://gw/results" {
			t.Errorf("url lost: %q", url)
		}
		got = append(got, r.Seq)
		return delivered, ""
	})
	if len(got) != 3 || got[0] != 0 || got[2] != 2 {
		t.Errorf("replay order = %v", got)
	}
	if left := s.pending(); len(left) != 0 {
		t.Errorf("delivered batches still on disk: %v", left)
	}
}

// A 4xx is final: the batch is dropped rather than retried forever. A transport
// failure is not: the batch stays, and the pass stops so order is preserved.
func TestSpoolRefusedDropsAndUnreachableKeeps(t *testing.T) {
	s := newSpool(t.TempDir())
	_ = s.put("u", res("stale", 0))
	_ = s.put("u", res("fine", 0))
	_ = s.put("u", res("fine", 1))

	calls := 0
	s.replay(context.Background(), func(_ context.Context, _ string, r scanproto.Result) (outcome, string) {
		calls++
		if r.TaskID == "stale" {
			return refused, "HTTP 409"
		}
		return unreachable, "connection refused"
	})
	if calls != 2 {
		t.Errorf("expected replay to stop at the first unreachable batch, made %d calls", calls)
	}
	left := s.pending()
	if len(left) != 2 {
		t.Fatalf("expected the two undelivered batches kept, got %v", left)
	}
	for _, n := range left {
		if n[21:26] == "stale" {
			t.Errorf("refused batch should have been dropped: %s", n)
		}
	}
}

// A spool with nowhere to write reports itself disabled instead of panicking
// or pretending to store things.
func TestSpoolDisabledWithoutDir(t *testing.T) {
	s := newSpool("/proc/nonexistent/cannot/create")
	if s.enabled() {
		t.Fatal("spool should be disabled when its directory cannot be created")
	}
	if err := s.put("u", res("x", 0)); err == nil {
		t.Error("put on a disabled spool should fail loudly")
	}
}

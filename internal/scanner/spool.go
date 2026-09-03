package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// A spool holds result batches the gateway could not be reached for, so a
// stage's output survives a gateway restart or a network blip between the
// worker finishing and the results landing. Before this, the agent logged
// "spooling would retry" next to a spool that did not exist, and the results
// were gone.
//
// Only transient failures are spooled: a connection error or a 5xx. A 4xx is
// the gateway saying no — stale lease, confinement violation, bad body — and
// re-sending it later would only be refused again.
//
// The limit the spool cannot get around: a lease lives ASM_LEASE_TTL (two
// minutes by default) and is kept alive by heartbeats over the control channel.
// If the gateway is away longer than that, the reaper hands the task to another
// worker and the spooled batch is refused on replay as stale. The replay drops
// it and says so; the task was re-run, so nothing is lost, only duplicated work.
type spool struct {
	dir string
	mu  sync.Mutex
}

// spoolEntry is one batch on disk, with the URL it was bound for.
type spoolEntry struct {
	URL    string           `json:"url"`
	Result scanproto.Result `json:"result"`
	At     time.Time        `json:"at"`
}

// maxSpoolFiles bounds the spool: past this the oldest batches are dropped,
// since a gateway gone long enough to pile up this many has long since
// re-queued the tasks they belong to.
const maxSpoolFiles = 2000

func newSpool(dir string) *spool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("spool directory unavailable; results that cannot be posted will be lost",
			"dir", dir, "err", err)
		return &spool{}
	}
	return &spool{dir: dir}
}

// enabled reports whether the spool has somewhere to write.
func (s *spool) enabled() bool { return s != nil && s.dir != "" }

// put stores a batch. The name sorts by time, then task, then sequence, so
// replay delivers in the order the worker produced.
func (s *spool) put(url string, res scanproto.Result) error {
	if !s.enabled() {
		return fmt.Errorf("spool disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trimLocked()
	b, err := json.Marshal(spoolEntry{URL: url, Result: res, At: time.Now()})
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s-%06d.json", time.Now().UnixNano(), res.TaskID, res.Seq)
	tmp := filepath.Join(s.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// rename is atomic: a crash mid-write leaves a .tmp, never a half-file that
	// replay would try to parse.
	return os.Rename(tmp, filepath.Join(s.dir, name))
}

// pending lists spooled batches oldest first.
func (s *spool) pending() []string {
	if !s.enabled() {
		return nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// trimLocked drops the oldest files past the cap. Caller holds mu.
func (s *spool) trimLocked() {
	names := s.pending()
	if len(names) < maxSpoolFiles {
		return
	}
	drop := names[:len(names)-maxSpoolFiles+1]
	for _, n := range drop {
		_ = os.Remove(filepath.Join(s.dir, n))
	}
	slog.Warn("spool full; oldest batches dropped", "dropped", len(drop), "kept", maxSpoolFiles-1)
}

// outcome classifies one delivery attempt.
type outcome int

const (
	delivered   outcome = iota // 2xx
	refused                    // 4xx: the gateway said no; retrying cannot help
	unreachable                // transport error or 5xx: try again later
)

// replay re-sends spooled batches in order. Delivered and refused batches are
// removed — a refusal is final — and the first unreachable stops the pass so
// order is kept and a still-absent gateway is not hammered.
func (s *spool) replay(ctx context.Context, post func(ctx context.Context, url string, res scanproto.Result) (outcome, string)) {
	if !s.enabled() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	names := s.pending()
	if len(names) == 0 {
		return
	}
	slog.Info("replaying spooled results", "batches", len(names))
	sent, dropped := 0, 0
	for _, n := range names {
		if ctx.Err() != nil {
			return
		}
		path := filepath.Join(s.dir, n)
		b, err := os.ReadFile(path)
		if err != nil {
			_ = os.Remove(path)
			continue
		}
		var e spoolEntry
		if err := json.Unmarshal(b, &e); err != nil {
			slog.Warn("spooled batch unreadable; dropped", "file", n, "err", err)
			_ = os.Remove(path)
			continue
		}
		switch o, why := post(ctx, e.URL, e.Result); o {
		case delivered:
			_ = os.Remove(path)
			sent++
		case refused:
			// Usually "stale or invalid lease": the gateway was away longer than
			// the lease lived and another worker has re-run this task. The batch
			// is gone, the results are not — they came from the re-run.
			slog.Warn("spooled batch refused; dropped", "task", e.Result.TaskID, "seq", e.Result.Seq,
				"observations", len(e.Result.Observations), "spooled_at", e.At.Format(time.RFC3339), "reason", why)
			_ = os.Remove(path)
			dropped++
		case unreachable:
			slog.Info("gateway still unreachable; spool kept", "remaining", len(names)-sent-dropped, "reason", why)
			return
		}
	}
	slog.Info("spool replay finished", "delivered", sent, "dropped", dropped)
}

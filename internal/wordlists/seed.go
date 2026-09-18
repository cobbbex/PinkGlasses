// Package wordlists loads registered wordlists into object storage at first
// boot. The shipped lists come with the control-plane image (fetched at image
// build time, gzip-compressed, see tools/fetchwordlists), so a deployment has
// every list without reaching the internet; a list the bundle lacks — an
// install built without it, or a builtin added after the image — falls back to
// its source URL. Workers then cache lists from the gateway by content hash.
package wordlists

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/store"
	"github.com/benlik386/pinkglasses/internal/wordlists/builtin"
)

// Seeder downloads pending wordlists and publishes them to object storage.
type Seeder struct {
	st  *store.Store
	obj *obj.Store
}

// NewSeeder builds a Seeder.
func NewSeeder(st *store.Store, o *obj.Store) *Seeder { return &Seeder{st: st, obj: o} }

// Run fetches every wordlist still waiting for its file. Safe to call
// repeatedly: entries already marked ready are skipped.
func (s *Seeder) Run(ctx context.Context) {
	// The bucket may not exist yet on a fresh volume; creating it is a no-op
	// when it already does.
	if err := s.obj.EnsureBucket(ctx); err != nil {
		slog.Warn("wordlists: could not ensure bucket", "err", err)
	}
	pending, err := s.st.PendingWordlists(ctx)
	if err != nil {
		slog.Error("wordlists: list pending", "err", err)
		return
	}
	for _, w := range pending {
		if w.SourceURL == nil || *w.SourceURL == "" {
			continue // user upload that never completed; nothing to fetch
		}
		if err := s.fetchOne(ctx, w); err != nil {
			slog.Error("wordlists: fetch failed", "name", w.Name, "err", err)
			_ = s.st.MarkWordlistFailed(ctx, w.ID, err.Error())
			continue
		}
	}
}

func (s *Seeder) fetchOne(ctx context.Context, w store.Wordlist) error {
	if err := s.st.SetWordlistStatus(ctx, w.ID, "fetching"); err != nil {
		return err
	}
	body, source, err := s.open(ctx, w)
	if err != nil {
		return err
	}
	defer body.Close()
	slog.Info("wordlists: loading", "name", w.Name, "from", source)

	// Stream to a temp file so we can hash and count without holding a
	// multi-hundred-megabyte list in memory.
	tmp, err := os.CreateTemp("", "asm-wordlist-*")
	if err != nil {
		return err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()

	h := sha256.New()
	counter := &lineCounter{}
	size, err := io.Copy(io.MultiWriter(tmp, h, counter), body)
	if err != nil {
		return err
	}
	if size == 0 {
		return fmt.Errorf("source returned an empty file")
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := s.obj.Put(ctx, w.ObjectKey, tmp, size, "text/plain"); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := s.st.MarkWordlistReady(ctx, w.ID, sum, size, counter.n); err != nil {
		return err
	}
	slog.Info("wordlists: ready", "name", w.Name, "lines", counter.n, "bytes", size)
	return nil
}

// open returns the list's bytes: from the bundle the image carries when it has
// this list, otherwise from the source URL.
func (s *Seeder) open(ctx context.Context, w store.Wordlist) (io.ReadCloser, string, error) {
	bundled := builtin.BundleFile(builtin.BundleDir(), w.ObjectKey)
	if f, err := os.Open(bundled); err == nil {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, "", fmt.Errorf("bundled %s is not gzip: %w", bundled, err)
		}
		return &gzFile{gz: gz, f: f}, "bundle " + bundled, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *w.SourceURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, "", fmt.Errorf("source returned %s", resp.Status)
	}
	return resp.Body, *w.SourceURL, nil
}

type gzFile struct {
	gz *gzip.Reader
	f  *os.File
}

func (g *gzFile) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzFile) Close() error               { g.gz.Close(); return g.f.Close() }

// lineCounter counts newlines in a stream without buffering it.
type lineCounter struct{ n int64 }

func (c *lineCounter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			c.n++
		}
	}
	return len(p), nil
}

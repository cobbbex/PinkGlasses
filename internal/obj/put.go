package obj

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Put uploads an object with a server-side signed PUT. Used for wordlists,
// which the control plane fetches once and workers then download by presigned
// URL — the file never travels through the gateway.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	url, err := s.PresignPut(key, 30*time.Minute, time.Now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return err
	}
	if size > 0 {
		req.ContentLength = size
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("put %s: %s: %s", key, resp.Status, string(body))
	}
	return nil
}

// Get downloads an object, refusing anything larger than max. Used to load a
// wordlist into the editor: a 140MB brute-force list has no business being
// pulled into a browser textarea, so the caller sets a sane ceiling.
func (s *Store) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	url, err := s.PresignGet(key, 15*time.Minute, time.Now())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("get %s: %s: %s", key, resp.Status, string(body))
	}
	// Read one byte past the ceiling so an oversized object is detected rather
	// than silently truncated into the editor and saved back short.
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("object is larger than %d bytes", max)
	}
	return data, nil
}

// Exists reports whether an object is present.
func (s *Store) Exists(ctx context.Context, key string) bool {
	url, err := s.PresignGet(key, 5*time.Minute, time.Now())
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// EnsureBucket creates the configured bucket if it does not exist. Nothing else
// in the stack creates it, and a fresh MinIO volume starts empty, so every
// upload path calls this first. Creating an existing bucket is a no-op.
func (s *Store) EnsureBucket(ctx context.Context) error {
	url, err := s.PresignPut("", 10*time.Minute, time.Now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("create bucket: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict: // already owned by us
		return nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("create bucket: %s: %s", resp.Status, string(body))
	}
}

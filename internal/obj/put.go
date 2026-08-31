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

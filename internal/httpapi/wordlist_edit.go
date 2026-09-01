package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// maxEditableBytes bounds what the editor will load. Resolver lists and hand
// written wordlists are kilobytes; the shipped brute-force lists are hundreds of
// megabytes and have no business being opened in a textarea.
const maxEditableBytes = 4 << 20 // 4 MB

// getWordlistContent returns a list's contents for editing.
func (s *Server) getWordlistContent(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "wordlistID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad wordlist id")
		return
	}
	wl, err := s.st.GetWordlist(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "wordlist not found")
		return
	}
	if wl.Status != "ready" {
		writeErr(w, http.StatusConflict, "this list is still "+wl.Status)
		return
	}
	if wl.SizeBytes > maxEditableBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"%s is %.1f MB — too large to edit here. Replace it by uploading a file instead.",
			wl.Name, float64(wl.SizeBytes)/(1<<20)))
		return
	}

	data, err := s.obj.Get(r.Context(), wl.ObjectKey, maxEditableBytes)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "object storage: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      wl.ID,
		"name":    wl.Name,
		"kind":    wl.Kind,
		"builtin": wl.Builtin,
		"content": string(data),
	})
}

// putWordlistContent replaces a list's contents from the editor.
func (s *Server) putWordlistContent(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "wordlistID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad wordlist id")
		return
	}
	wl, err := s.st.GetWordlist(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "wordlist not found")
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	// Allow a little headroom over the content ceiling for JSON escaping, so an
	// oversized list is reported as too large rather than as a decode failure.
	if err := readJSONLimit(r, &in, maxEditableBytes+(1<<20)); err != nil {
		if strings.Contains(err.Error(), "too large") {
			writeErr(w, http.StatusRequestEntityTooLarge, "content exceeds the 4 MB edit limit")
			return
		}
		writeErr(w, http.StatusBadRequest, "content required")
		return
	}
	if len(in.Content) > maxEditableBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "content exceeds the 4 MB edit limit")
		return
	}

	entries, problems := normalizeList(in.Content, wl.Kind)
	if len(problems) > 0 {
		// Refuse rather than save junk: a malformed resolver silently degrades
		// every brute force that uses the list, with no visible error.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    fmt.Sprintf("%d invalid line(s)", len(problems)),
			"problems": problems,
		})
		return
	}
	if len(entries) == 0 {
		writeErr(w, http.StatusBadRequest, "the list is empty")
		return
	}

	body := strings.Join(entries, "\n") + "\n"
	sum := sha256.Sum256([]byte(body))

	if err := s.obj.EnsureBucket(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, "object storage: "+err.Error())
		return
	}
	if err := s.obj.Put(r.Context(), wl.ObjectKey, bytes.NewReader([]byte(body)),
		int64(len(body)), "text/plain"); err != nil {
		writeErr(w, http.StatusBadGateway, "object storage: "+err.Error())
		return
	}
	// The sha changes, so every worker re-downloads on next use rather than
	// serving the old file from its content-addressed cache.
	if err := s.st.MarkWordlistReady(r.Context(), id, hex.EncodeToString(sum[:]),
		int64(len(body)), int64(len(entries))); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(r.Context(), actor(r), "wordlist.edit", id.String(),
		map[string]any{"name": wl.Name, "lines": len(entries)})

	updated, _ := s.st.GetWordlist(r.Context(), id)
	writeJSON(w, http.StatusOK, updated)
}

// normalizeList trims and de-duplicates a pasted list, dropping blank lines and
// # comments. For resolver lists every remaining line must be an IP address,
// optionally with a port; anything else is reported rather than stored.
func normalizeList(content, kind string) (entries []string, problems []string) {
	seen := map[string]bool{}
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if kind == "resolvers" {
			if err := validResolver(line); err != nil {
				if len(problems) < 20 { // enough to fix, not a wall of text
					problems = append(problems, fmt.Sprintf("line %d: %q — %s", i+1, line, err))
				}
				continue
			}
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		entries = append(entries, line)
	}
	return entries, problems
}

// validResolver accepts "1.1.1.1", "1.1.1.1:53" and the IPv6 equivalents.
func validResolver(s string) error {
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q", p)
		}
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("not an IP address")
	}
	return nil
}

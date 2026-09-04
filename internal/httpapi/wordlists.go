package httpapi

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// maxWordlistBytes caps an upload. The shipped assetnote lists are ~100MB, so
// this leaves room for comparable custom lists without allowing an unbounded
// write into object storage.
const maxWordlistBytes = 512 << 20

func (s *Server) listWordlists(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.ListWordlists(r.Context(), r.URL.Query().Get("kind"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// uploadWordlist accepts a user-supplied list as multipart form data, streams it
// into object storage, and registers it as ready.
func (s *Server) uploadWordlist(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "expected a multipart upload")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file field required")
		return
	}
	defer file.Close()

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = hdr.Filename
	}
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	// Known kinds only. Coercing an unknown kind silently files the upload
	// under the wrong one, which is how a resolver list ends up being
	// brute-forced as a wordlist.
	kind := r.FormValue("kind")
	switch kind {
	case "dns", "dir", "resolvers":
	case "":
		kind = "dns"
	default:
		writeErr(w, http.StatusBadRequest, "unknown kind "+kind+" (expected dns, dir or resolvers)")
		return
	}

	key := "wordlists/user/" + uuid.NewString() + ".txt"
	id, err := s.st.CreateWordlist(r.Context(), name, kind, key, actor(r))
	if err != nil {
		writeErr(w, http.StatusConflict, "could not register the wordlist (is the name already used?): "+err.Error())
		return
	}

	// Spool to disk first so we can hash and count lines without holding a
	// large list in memory, then hand the file to object storage.
	tmp, err := os.CreateTemp("", "asm-upload-*")
	if err != nil {
		_ = s.st.MarkWordlistFailed(r.Context(), id, err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(file, maxWordlistBytes))
	if err != nil {
		_ = s.st.MarkWordlistFailed(r.Context(), id, err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if size == 0 {
		_ = s.st.MarkWordlistFailed(r.Context(), id, "empty file")
		writeErr(w, http.StatusBadRequest, "the file is empty")
		return
	}

	lines := int64(0)
	if _, err := tmp.Seek(0, io.SeekStart); err == nil {
		sc := bufio.NewScanner(tmp)
		sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
		for sc.Scan() {
			lines++
		}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.obj.EnsureBucket(r.Context())
	if err := s.obj.Put(r.Context(), key, tmp, size, "text/plain"); err != nil {
		_ = s.st.MarkWordlistFailed(r.Context(), id, err.Error())
		writeErr(w, http.StatusBadGateway, "object storage: "+err.Error())
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := s.st.MarkWordlistReady(r.Context(), id, sum, size, lines); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "wordlist.upload", id.String(),
		map[string]any{"name": name, "lines": lines, "bytes": size})

	wl, _ := s.st.GetWordlist(r.Context(), id)
	writeJSON(w, http.StatusCreated, wl)
}

func (s *Server) patchWordlist(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "wordlistID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad wordlist id")
		return
	}
	var in struct {
		IsDefault *bool `json:"is_default"`
	}
	if err := readJSON(r, &in); err != nil || in.IsDefault == nil {
		writeErr(w, http.StatusBadRequest, "is_default required")
		return
	}
	if err := s.st.SetWordlistDefault(r.Context(), id, *in.IsDefault); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "wordlist.default", id.String(),
		map[string]any{"is_default": *in.IsDefault})
	writeJSON(w, http.StatusOK, map[string]bool{"is_default": *in.IsDefault})
}

func (s *Server) deleteWordlist(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "wordlistID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad wordlist id")
		return
	}
	ok, err := s.st.DeleteWordlist(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, "built-in wordlists cannot be deleted")
		return
	}
	s.auditReq(r, "wordlist.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

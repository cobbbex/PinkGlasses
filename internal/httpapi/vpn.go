package httpapi

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/secret"
	"github.com/benlik386/pinkglasses/internal/store"
	"github.com/benlik386/pinkglasses/internal/vpnconf"
)

// listVPNConfigs returns a scope's tunnels — metadata only, never the config
// body. It also reports whether secrets can be stored at all, so the UI can say
// why uploading is unavailable instead of failing at submit.
func (s *Server) listVPNConfigs(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListVPNConfigs(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configs":        list,
		"secrets_ready":  secret.Available(),
		"secrets_reason": secretsReason(),
	})
}

func secretsReason() string {
	if secret.Available() {
		return ""
	}
	return secret.ErrNoKey.Error()
}

// createVPNConfig accepts a pasted or uploaded config, recognises it, and
// stores it sealed. The body is never echoed back.
func (s *Server) createVPNConfig(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	if !secret.Available() {
		writeErr(w, http.StatusPreconditionFailed, secret.ErrNoKey.Error())
		return
	}

	var name, body string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, "bad upload")
			return
		}
		name = r.FormValue("name")
		f, hdr, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "file required")
			return
		}
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, 512<<10))
		body = string(b)
		if name == "" && hdr != nil {
			name = hdr.Filename
		}
	} else {
		var in struct{ Name, Config string }
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, "bad body")
			return
		}
		name, body = in.Name, in.Config
	}

	name = strings.TrimSpace(name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	kind, endpoint, err := vpnconf.Detect(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	v := store.VPNConfig{ScopeID: scopeID, Name: name, Kind: kind, CreatedBy: actor(r)}
	if endpoint != "" {
		v.Endpoint = &endpoint
	}
	saved, err := s.st.CreateVPNConfig(r.Context(), v, []byte(body))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The endpoint is metadata; the config body never reaches the audit log.
	s.auditReq(r, "vpn.create", saved.ID.String(),
		map[string]any{"name": saved.Name, "kind": saved.Kind, "endpoint": endpoint})
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) deleteVPNConfig(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "vpnID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.st.DeleteVPNConfig(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.auditReq(r, "vpn.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

package httpapi

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/secret"
	"github.com/benlik386/pinkglasses/internal/store"
	"github.com/benlik386/pinkglasses/internal/vpnconf"
)

// VPN configurations belong to the account that added them and are usable in
// any company that account scans. Nothing here takes a company id.

// listVPNConfigs returns the requester's tunnels — metadata only, never the
// config body. It also reports whether secrets can be stored at all, so the
// UI can say why uploading is unavailable instead of failing at submit.
func (s *Server) listVPNConfigs(w http.ResponseWriter, r *http.Request) {
	uid := userIDOf(r)
	if uid == nil {
		writeErr(w, http.StatusUnauthorized, "sign in to continue")
		return
	}
	list, err := s.st.ListVPNConfigs(r.Context(), *uid)
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
// stores it sealed under the requester's account. The body is never echoed back.
func (s *Server) createVPNConfig(w http.ResponseWriter, r *http.Request) {
	uid := userIDOf(r)
	if uid == nil {
		writeErr(w, http.StatusUnauthorized, "sign in to continue")
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
	v := store.VPNConfig{OwnerID: *uid, Name: name, Kind: kind, CreatedBy: actor(r)}
	if endpoint != "" {
		v.Endpoint = &endpoint
	}
	saved, err := s.st.CreateVPNConfig(r.Context(), v, []byte(body))
	if err != nil {
		if strings.Contains(err.Error(), "vpn_config_owner_id_name_key") {
			writeErr(w, http.StatusConflict, "you already have a VPN configuration named \""+name+"\"")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The endpoint is metadata; the config body never reaches the audit log.
	s.auditReq(r, "vpn.create", saved.ID.String(),
		map[string]any{"name": saved.Name, "kind": saved.Kind, "endpoint": endpoint})
	writeJSON(w, http.StatusCreated, saved)
}

// deleteVPNConfig removes one of the requester's tunnels; an administrator
// may remove anyone's.
func (s *Server) deleteVPNConfig(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "vpnID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	owner := userIDOf(r)
	if currentUser(r).Role == auth.RoleAdmin {
		owner = nil
	}
	ok, err := s.st.DeleteVPNConfig(r.Context(), id, owner)
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

// ownsVPN says whether the requester may bind this configuration to a run, a
// schedule or a company default: it must be theirs. The message names the fix.
func (s *Server) ownsVPN(r *http.Request, id uuid.UUID) *exitErr {
	uid := userIDOf(r)
	if uid == nil {
		return &exitErr{http.StatusUnauthorized, "sign in to continue"}
	}
	ok, err := s.st.VPNConfigOwnedBy(r.Context(), id, *uid)
	if err != nil {
		return &exitErr{http.StatusInternalServerError, err.Error()}
	}
	if !ok {
		return &exitErr{http.StatusForbidden, "that VPN configuration is not yours (or no longer exists); pick one of yours under VPN"}
	}
	return nil
}

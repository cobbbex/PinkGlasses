package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/auth"
	"github.com/benlik386/pinkglasses/internal/secret"
	"github.com/benlik386/pinkglasses/internal/sshexit"
	"github.com/benlik386/pinkglasses/internal/store"
)

// SSH exits: a VPS the connector reaches over SSH to carry a worker for a
// stack nothing on the internet can reach. The api only stores and asks; the
// connector holds the sessions and does the work (internal/sshexit).

func exitOwner(r *http.Request) *uuid.UUID {
	if currentUser(r).Role == auth.RoleAdmin {
		return nil
	}
	return userIDOf(r)
}

func (s *Server) listSSHExits(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListSSHExits(r.Context(), exitOwner(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exits":          list,
		"secrets_ready":  secret.Available(),
		"secrets_reason": secretsReason(),
	})
}

// createSSHExit stores a new exit. With no private key given, one is
// generated, and its public half is returned for the VPS's authorized_keys.
// The private key is never returned.
func (s *Server) createSSHExit(w http.ResponseWriter, r *http.Request) {
	uid := userIDOf(r)
	if uid == nil {
		writeErr(w, http.StatusUnauthorized, "sign in to continue")
		return
	}
	if !secret.Available() {
		writeErr(w, http.StatusPreconditionFailed, secret.ErrNoKey.Error())
		return
	}
	var in struct {
		Name       string `json:"name"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		PrivateKey string `json:"private_key"`
		RemotePort int    `json:"remote_port"`
		PoolID     string `json:"pool_id"`
		WorkerName string `json:"worker_name"`
	}
	if err := readJSONLimit(r, &in, 64<<10); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	in.Name, in.Host, in.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), strings.TrimSpace(in.Username)
	if in.Port == 0 {
		in.Port = 22
	}
	if in.Username == "" {
		in.Username = "root"
	}
	if in.RemotePort == 0 {
		in.RemotePort = 47090
	}
	if in.WorkerName == "" {
		in.WorkerName = in.Name
	}
	switch {
	case in.Name == "":
		writeErr(w, http.StatusBadRequest, "name required")
		return
	case !sshexit.ValidHost(in.Host):
		writeErr(w, http.StatusBadRequest, "host: a name or an IP address")
		return
	case in.Port < 1 || in.Port > 65535:
		writeErr(w, http.StatusBadRequest, "port: 1–65535")
		return
	case !sshexit.ValidUser(in.Username):
		writeErr(w, http.StatusBadRequest, "username: a Unix user name, like root or ubuntu")
		return
	case in.RemotePort < 1024 || in.RemotePort > 65535:
		writeErr(w, http.StatusBadRequest, "remote_port: 1024–65535, a port free on the VPS's loopback")
		return
	case !sshexit.ValidName(in.WorkerName):
		writeErr(w, http.StatusBadRequest, "worker_name: letters, digits, dot, dash and underscore")
		return
	}

	comment := "pinkglasses-" + in.WorkerName
	var key []byte
	var pub string
	var err error
	if strings.TrimSpace(in.PrivateKey) == "" {
		key, pub, err = sshexit.GenerateKey(comment)
	} else {
		key = []byte(strings.TrimSpace(in.PrivateKey) + "\n")
		pub, err = sshexit.AuthorizedLine(key, comment)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var poolID *uuid.UUID
	if in.PoolID != "" {
		id, err := uuid.Parse(in.PoolID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad pool_id")
			return
		}
		poolID = &id
	} else if id, err := s.st.PoolByName(r.Context(), "remote"); err == nil {
		// Where remote workers go by default, so a run with exit "remote"
		// finds this one without being told about it.
		poolID = &id
	}

	saved, err := s.st.CreateSSHExit(r.Context(), store.SSHExit{
		OwnerID: *uid, Name: in.Name, Host: in.Host, Port: in.Port, Username: in.Username,
		PublicKey: pub, RemotePort: in.RemotePort, PoolID: poolID, WorkerName: in.WorkerName,
		CreatedBy: actor(r),
	}, key)
	if err != nil {
		if strings.Contains(err.Error(), "ssh_exit_owner_id_name_key") {
			writeErr(w, http.StatusConflict, "you already have an SSH exit named \""+in.Name+"\"")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "ssh_exit.create", saved.ID.String(),
		map[string]any{"name": saved.Name, "host": saved.Host, "user": saved.Username, "generated_key": in.PrivateKey == ""})
	writeJSON(w, http.StatusCreated, saved)
}

// installSSHExit asks the connector to install (or reinstall) the worker.
func (s *Server) installSSHExit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "exitID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if _, ok, err := s.st.GetSSHExit(r.Context(), id, exitOwner(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ok, err := s.st.RequestSSHExitInstall(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "an install is already under way, or the exit is being removed")
		return
	}
	s.auditReq(r, "ssh_exit.install", id.String(), nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"install_status": "pending"})
}

// deleteSSHExit hands the exit to the connector, which removes the worker
// from the VPS if it can still reach it, closes the session and deletes it.
func (s *Server) deleteSSHExit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "exitID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.st.MarkSSHExitDeleting(r.Context(), id, exitOwner(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.auditReq(r, "ssh_exit.delete", id.String(), nil)
	writeJSON(w, http.StatusAccepted, map[string]bool{"deleting": true})
}

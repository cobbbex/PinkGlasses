package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/notify"
	"github.com/benlik386/pinkglasses/internal/store"
)

// The change kinds a channel may subscribe to, in the order the UI shows them.
var notifyEvents = []string{"finding_returned", "new_finding", "finding_gone", "new_port", "new_subdomain"}

// mask hides a webhook URL's path — for Slack the path is the secret.
func mask(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "…"
	}
	tail := ""
	if len(u.Path) > 4 {
		tail = u.Path[len(u.Path)-4:]
	}
	return u.Scheme + "://" + u.Host + "/…" + tail
}

func present(c store.NotificationChannel) store.NotificationChannel {
	c.MaskedURL = mask(c.URL)
	return c
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListChannels(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range list {
		list[i] = present(list[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": list, "events": notifyEvents})
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var in struct {
		Name        string   `json:"name"`
		Kind        string   `json:"kind"`
		URL         string   `json:"url"`
		Events      []string `json:"events"`
		MinSeverity string   `json:"min_severity"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if in.Kind != "webhook" && in.Kind != "slack" {
		writeErr(w, http.StatusBadRequest, "kind must be webhook or slack")
		return
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeErr(w, http.StatusBadRequest, "url must be http(s)://host/…")
		return
	}
	if len(in.Events) == 0 {
		writeErr(w, http.StatusBadRequest, "choose at least one event")
		return
	}
	for _, e := range in.Events {
		known := false
		for _, k := range notifyEvents {
			if e == k {
				known = true
			}
		}
		if !known {
			writeErr(w, http.StatusBadRequest, "unknown event "+e)
			return
		}
	}
	switch in.MinSeverity {
	case "":
		in.MinSeverity = "low"
	case "info", "low", "medium", "high", "critical":
	default:
		writeErr(w, http.StatusBadRequest, "bad min_severity")
		return
	}
	c, err := s.st.CreateChannel(r.Context(), store.NotificationChannel{
		ScopeID: scopeID, Name: in.Name, Kind: in.Kind, URL: u.String(),
		Events: in.Events, MinSeverity: in.MinSeverity, Enabled: true, CreatedBy: actor(r),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditReq(r, "notification.create", c.ID.String(),
		map[string]any{"name": c.Name, "kind": c.Kind, "host": u.Host})
	writeJSON(w, http.StatusCreated, present(c))
}

func (s *Server) patchChannel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "channelID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad channel id")
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil || in.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled required")
		return
	}
	if err := s.st.SetChannelEnabled(r.Context(), id, *in.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": *in.Enabled})
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "channelID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad channel id")
		return
	}
	ok, err := s.st.DeleteChannel(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	s.auditReq(r, "notification.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// testChannel sends a sample digest so a destination can be checked before a
// real change happens. The outcome is recorded like any delivery.
func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "channelID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad channel id")
		return
	}
	ch, err := s.st.GetChannel(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	if err := notify.New(s.st, "").Test(r.Context(), ch); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"sent": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListDeliveries(r.Context(), scopeID, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

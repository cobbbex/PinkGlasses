package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// maxScreenshot bounds what the API will relay. A page screenshot is a few
// hundred kilobytes; anything far larger is a bug or an attempt to make the
// server hold a big response in flight.
const maxScreenshot = 16 << 20

// serviceScreenshot streams the most recent screenshot of a service.
//
// The image is relayed by the API rather than handed to the browser as a
// presigned object-store URL, for two reasons: the app's CSP allows images
// from 'self' only, so a cross-origin URL would be blocked with no visible
// error; and a presigned URL is a bearer token for that object, which would
// then be readable by anything that can see the page. Callers address a
// screenshot by service id, so the object key never leaves the server and no
// caller can ask for an arbitrary key.
func (s *Server) serviceScreenshot(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(chi.URLParam(r, "serviceID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad service id")
		return
	}
	key, err := s.st.LatestScreenshotKey(r.Context(), serviceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if key == "" {
		writeErr(w, http.StatusNotFound, "no screenshot for this service")
		return
	}

	url, err := s.obj.PresignGet(key, 2*time.Minute, time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not sign object url")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := screenshotClient.Do(req)
	if err != nil {
		slog.Warn("screenshot fetch failed", "service", serviceID, "err", err)
		writeErr(w, http.StatusBadGateway, "artifact store unreachable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The row says there is an image but the store disagrees — a bucket
		// emptied by hand, or an upload that never completed.
		slog.Warn("screenshot missing from object store",
			"service", serviceID, "key", key, "status", resp.StatusCode)
		writeErr(w, http.StatusNotFound, "screenshot is no longer stored")
		return
	}

	// A screenshot is a picture of an attacker-controlled page. It is served
	// with an explicit image type and, via the global headers, nosniff — so it
	// can never be interpreted as script in this origin.
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=300")
	if n := resp.Header.Get("Content-Length"); n != "" {
		w.Header().Set("Content-Length", n)
	}
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxScreenshot)); err != nil {
		slog.Warn("screenshot relay interrupted", "service", serviceID, "err", err)
	}
}

var screenshotClient = &http.Client{Timeout: 30 * time.Second}

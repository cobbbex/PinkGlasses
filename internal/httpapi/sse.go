package httpapi

import (
	"encoding/json"
	"net/http"
	"sync"
)

// SSEHub fans run-progress events out to subscribed browser clients.
type SSEHub struct {
	mu   sync.RWMutex
	subs map[string]map[chan []byte]struct{} // runID -> set of client channels
}

// NewSSEHub builds an SSE hub.
func NewSSEHub() *SSEHub {
	return &SSEHub{subs: map[string]map[chan []byte]struct{}{}}
}

func (h *SSEHub) subscribe(runID string) chan []byte {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[runID] == nil {
		h.subs[runID] = map[chan []byte]struct{}{}
	}
	h.subs[runID][ch] = struct{}{}
	return ch
}

func (h *SSEHub) unsubscribe(runID string, ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.subs[runID]; set != nil {
		delete(set, ch)
		if len(set) == 0 {
			delete(h.subs, runID)
		}
	}
	close(ch)
}

// Publish sends an event to all subscribers of a run (best-effort, non-blocking).
func (h *SSEHub) Publish(runID string, event any) {
	data, _ := json.Marshal(event)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs[runID] {
		select {
		case ch <- data:
		default: // slow client; drop
		}
	}
}

// stream writes SSE frames for a run until the client disconnects.
func (h *SSEHub) stream(w http.ResponseWriter, r *http.Request, runID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.subscribe(runID)
	defer h.unsubscribe(runID, ch)

	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

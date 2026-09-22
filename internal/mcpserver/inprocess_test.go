package mcpserver

import (
	"context"
	"net/http"
	"testing"
)

// An in-process client reaches the router with the same path, method,
// token and body a wire request would carry, and reads back the status and
// the JSON the router wrote — including the API's own refusal sentence.
func TestInProcessClientSpeaksToTheRouter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pgt_test" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"sign in to continue"}`))
			return
		}
		if r.RemoteAddr != "127.0.0.1:0" {
			t.Errorf("remote address %q, want the loopback", r.RemoteAddr)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"1","name":"acme"}]`))
	})
	c := NewInProcessClient(mux, "pgt_test")
	var out []map[string]string
	if err := c.get(context.Background(), "/scopes", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(out) != 1 || out[0]["name"] != "acme" {
		t.Errorf("got %v", out)
	}
	bad := NewInProcessClient(mux, "wrong")
	err := bad.get(context.Background(), "/scopes", &out)
	if apiErr, ok := err.(*APIError); !ok || apiErr.Status != http.StatusUnauthorized || apiErr.Msg != "sign in to continue" {
		t.Errorf("a refusal must come back as the API's own error: %v", err)
	}
}

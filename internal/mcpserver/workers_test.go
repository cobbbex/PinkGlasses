package mcpserver

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func tool(t *testing.T, o Options, name string) toolDef {
	t.Helper()
	for _, tl := range Tools(o) {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("no tool %s", name)
	return toolDef{}
}

// The worker tools exist only when the install switches them on.
func TestWorkerToolsAreOptIn(t *testing.T) {
	for _, tl := range Tools(Options{}) {
		for _, w := range workerTools() {
			if tl.Name == w.Name {
				t.Errorf("%s offered without AllowWorkers", tl.Name)
			}
		}
	}
	if strings.Contains(SkillFiles(Options{})["pinkglasses/reference/tools.md"], "## add_remote_worker") {
		t.Error("worker tools documented although the server does not offer them")
	}
}

// No tool takes a private key: add_ssh_exit has the server generate one.
func TestNoToolTakesAPrivateKey(t *testing.T) {
	for _, tl := range Tools(allTools) {
		props, _ := tl.Schema["properties"].(map[string]any)
		for k := range props {
			if strings.Contains(k, "private") || strings.Contains(k, "key") {
				t.Errorf("%s takes %q", tl.Name, k)
			}
		}
	}
}

// remove_worker removes a remote worker only, named back exactly, and the
// destructive approve_worker actions need confirm.
func TestRemoveWorkerGuards(t *testing.T) {
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/workers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"w1","name":"vps-1","kind":"vps"},{"id":"w2","name":"abc123","kind":"local"}]`))
	})
	mux.HandleFunc("/api/v1/workers/", func(w http.ResponseWriter, r *http.Request) {
		deleted = append(deleted, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted":true}`))
	})
	c := NewInProcessClient(mux, "pgt_test")
	rm := tool(t, allTools, "remove_worker")
	ctx := context.Background()

	if _, err := rm.Run(ctx, c, args{"worker_id": "w1", "name": "vps-1"}); err != errConfirm {
		t.Errorf("without confirm: %v", err)
	}
	if _, err := rm.Run(ctx, c, args{"worker_id": "w1", "name": "vps-2", "confirm": true}); err == nil {
		t.Error("removed with the wrong name")
	}
	if _, err := rm.Run(ctx, c, args{"worker_id": "w2", "name": "abc123", "confirm": true}); err == nil {
		t.Error("removed a local worker")
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted before the guards passed: %v", deleted)
	}
	if _, err := rm.Run(ctx, c, args{"worker_id": "w1", "name": "vps-1", "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "DELETE /api/v1/workers/w1" {
		t.Errorf("calls %v", deleted)
	}

	act := tool(t, allTools, "approve_worker")
	for _, a := range []string{"quarantine", "revoke"} {
		if _, err := act.Run(ctx, c, args{"worker_id": "w1", "action": a}); err != errConfirm {
			t.Errorf("%s without confirm: %v", a, err)
		}
	}
	if _, err := act.Run(ctx, c, args{"worker_id": "w1", "action": "delete"}); err == nil {
		t.Error("unknown action accepted")
	}
}

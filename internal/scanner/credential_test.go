package scanner

import (
	"encoding/json"
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// The worker saves its credential as the enrolment response it was given and
// reads it back on the next start. Those two have to agree: they did not, and
// because the read failed silently, every restart enrolled as a new worker —
// a second row waiting for approval while the row it replaced still looked
// live, and its pool looked staffed by a container that no longer existed.
func TestSavedCredentialIsLoadedBack(t *testing.T) {
	saved, err := json.Marshal(scanproto.EnrollResponse{
		WorkerID: "60dc0c7c-6cd2-4511-983f-182bfbf4f00d", Credential: "83792796a8f2",
	})
	if err != nil {
		t.Fatal(err)
	}
	var back scanproto.EnrollResponse
	if err := json.Unmarshal(saved, &back); err != nil {
		t.Fatal(err)
	}
	if back.WorkerID == "" || back.Credential == "" {
		t.Fatalf("a saved credential did not survive the round trip: %s -> %+v", saved, back)
	}

	// The shape that failed, kept as the reason this test exists: an untagged
	// struct cannot read the snake_case keys the file is written with.
	var untagged struct{ WorkerID, Credential string }
	if json.Unmarshal(saved, &untagged) == nil && untagged.WorkerID != "" {
		t.Error("an untagged struct now reads worker_id; this test no longer guards anything")
	}
}

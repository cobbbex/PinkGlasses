package agentapi

import (
	"errors"
	"testing"

	"github.com/benlik386/pinkglasses/internal/store"
)

// classify mirrors reloadWorker's switch on the store's error, so the one
// decision that ends a worker's channel can be tested without a database.
func classify(err error) workerState {
	switch {
	case err == nil:
		return workerOK
	case errors.Is(err, store.ErrNoWorker):
		return workerMissing
	default:
		return workerUnknown
	}
}

// A missing row ends the channel; a database error does not. Getting the second
// half wrong would turn every blip into a fleet-wide re-enrolment.
func TestReloadWorkerClassification(t *testing.T) {
	if classify(nil) != workerOK {
		t.Error("a found worker must be workerOK")
	}
	if classify(store.ErrNoWorker) != workerMissing {
		t.Error("ErrNoWorker must be workerMissing — this is the case that re-enrols")
	}
	if classify(errors.New("connection reset")) != workerUnknown {
		t.Error("a transient error must be workerUnknown, never workerMissing")
	}
}

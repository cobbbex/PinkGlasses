package httpapi

import (
	"context"
	"sync"
	"time"

	"github.com/benlik386/pinkglasses/internal/obj"
	"github.com/benlik386/pinkglasses/internal/store"
)

// Storage, on the System page and in the metrics.
//
// Nothing in this application removes a past scan: a run is the record of what
// was exposed on a day, and comparing today with a year ago is the point of
// keeping it. The cost of that choice is disk, so the size is put where it can
// be seen — and alerted on — long before a disk is full.

// storageInfo is what the install occupies, and how much of it is history.
type storageInfo struct {
	Database store.DBUsage `json:"database"`
	// Objects is the bucket: screenshots (history) and wordlists (the
	// install's own). Absent when object storage could not be listed.
	Objects      *obj.Usage `json:"objects,omitempty"`
	ObjectsError string     `json:"objects_error,omitempty"`
	MeasuredAt   time.Time  `json:"measured_at"`
}

// Sizes move slowly and a bucket listing is a request per thousand objects,
// so the answer is held for a while; both the System page and a scrape reuse
// the same measurement.
const storageCacheFor = 5 * time.Minute

type storageCache struct {
	mu   sync.Mutex
	at   time.Time
	info storageInfo
}

func (s *Server) storageUsage(ctx context.Context) storageInfo {
	s.storage.mu.Lock()
	defer s.storage.mu.Unlock()
	if time.Since(s.storage.at) < storageCacheFor && !s.storage.info.MeasuredAt.IsZero() {
		return s.storage.info
	}
	var info storageInfo
	info.MeasuredAt = time.Now()
	if u, err := s.st.DBUsage(ctx); err == nil {
		info.Database = u
	}
	if s.obj != nil {
		if u, err := s.obj.Usage(ctx); err != nil {
			info.ObjectsError = err.Error()
		} else {
			info.Objects = &u
		}
	}
	s.storage.at = time.Now()
	s.storage.info = info
	return info
}

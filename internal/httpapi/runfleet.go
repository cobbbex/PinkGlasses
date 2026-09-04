package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

// defaultFleetWorkers is how many containers a run gets when it does not say.
// One is enough to make progress; the point of a fleet is isolation and egress,
// not parallelism.
const defaultFleetWorkers = 2

// maxFleetWorkers bounds what a single run can ask for, so a mistyped number
// cannot fill the host. The provisioner enforces its own ceiling too.
const maxFleetWorkers = 8

// requestRunFleet records that a run wants containers of its own: a pool no
// other run can lease from, and an enrollment token bound to it.
//
// Nothing is created here. The scheduler builds the fleet from this record, so
// a control-plane restart between asking and building leaves a run that can
// still be finished rather than one waiting for workers that were never
// started.
func (s *Server) requestRunFleet(ctx context.Context, run domain.ScanRun, count int, vpnID *uuid.UUID) error {
	if count <= 0 {
		count = defaultFleetWorkers
	}
	if count > maxFleetWorkers {
		return fmt.Errorf("a run may ask for at most %d workers", maxFleetWorkers)
	}

	poolID, err := s.st.CreateRunPool(ctx, "run "+run.ID.String()[:8])
	if err != nil {
		return err
	}
	if err := s.st.SetRunPool(ctx, run.ID, poolID); err != nil {
		return err
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	// Long enough for a slow image pull, short enough that a leaked token from
	// a finished run is worthless.
	if _, err := s.st.CreateEnrollmentToken(ctx, sum[:], &poolID, nil,
		30*time.Minute, count+2, scanKindLocal); err != nil {
		return err
	}

	return s.st.CreateRunFleet(ctx, store.RunFleet{
		RunID: run.ID, PoolID: &poolID, Workers: count,
		EnrollToken: token, VPNConfigID: vpnID,
	})
}

// scanKindLocal is the worker kind a fleet enrols as: these containers run on
// this host, beside the control plane.
const scanKindLocal = "local"

package httpapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// exitError is a refusal to start a run, with the status it should answer.
type exitError struct {
	status int
	msg    string
}

func (e *exitError) Error() string { return e.msg }

func refuse(status int, format string, a ...any) *exitError {
	return &exitError{status: status, msg: fmt.Sprintf(format, a...)}
}

// bindExit records where a run's active stages will run from, and refuses the
// run if that cannot be satisfied.
//
// Two exits exist. "remote" binds the run to an existing pool of enrolled
// workers; "local" builds an ephemeral fleet behind a VPN gateway, so it needs
// a VPN configuration and a provisioner. Each refusal names what is missing and
// how to fix it, because "could not start" from a scanner is otherwise a
// half-hour of guessing.
func (s *Server) bindExit(ctx context.Context, run domain.ScanRun, scopeID uuid.UUID, exit, vpnConfigID, poolID string, workers int) *exitError {
	switch exit {
	case "remote":
		if poolID == "" {
			return refuse(http.StatusBadRequest, "a remote exit needs pool_id: which pool of enrolled workers should run this scan")
		}
		id, err := uuid.Parse(poolID)
		if err != nil {
			return refuse(http.StatusBadRequest, "bad pool id")
		}
		pool, ok, err := s.st.GetExitPool(ctx, id)
		if err != nil {
			return refuse(http.StatusInternalServerError, "%v", err)
		}
		if !ok {
			return refuse(http.StatusBadRequest, "that pool does not exist, or belongs to another run")
		}
		if pool.ActiveWorkers == 0 {
			// Binding anyway would leave the run's active tasks pending forever
			// with nothing able to lease them.
			return refuse(http.StatusConflict,
				"pool %q has no active worker to run this scan; enrol one under Workers, "+
					"or approve a pending one", pool.Name)
		}
		if err := s.st.SetRunPool(ctx, run.ID, pool.ID); err != nil {
			return refuse(http.StatusInternalServerError, "%v", err)
		}
		return nil

	case "local":
		if !newProvisionClient().enabled() {
			return refuse(http.StatusBadRequest,
				"a local exit builds workers and a VPN gateway for this run, but no provisioner is "+
					"configured to create them: set ASM_PROVISIONER_URL and ASM_PROVISIONER_TOKEN, or "+
					"scan from a remote pool instead")
		}
		if vpnConfigID == "" {
			configs, _ := s.st.ListVPNConfigs(ctx, scopeID)
			if len(configs) == 0 {
				return refuse(http.StatusConflict,
					"scanning from local workers needs a VPN so the scan never leaves from this "+
						"host's own address, and this company has no VPN configuration yet: add one "+
						"under VPN, or scan from a remote pool")
			}
			return refuse(http.StatusBadRequest, "a local exit needs vpn_config_id: which tunnel this scan leaves through")
		}
		vpnID, err := uuid.Parse(vpnConfigID)
		if err != nil {
			return refuse(http.StatusBadRequest, "bad vpn config id")
		}
		vc, err := s.st.GetVPNConfig(ctx, vpnID)
		if err != nil || vc.ScopeID != scopeID {
			return refuse(http.StatusBadRequest, "unknown vpn config")
		}
		if err := s.st.SetRunVPN(ctx, run.ID, vpnID); err != nil {
			return refuse(http.StatusInternalServerError, "%v", err)
		}
		if err := s.requestRunFleet(ctx, run, workers, &vpnID); err != nil {
			return refuse(http.StatusInternalServerError, "could not request workers for this run: %v", err)
		}
		return nil

	case "":
		return refuse(http.StatusBadRequest,
			"this scan sends traffic at its targets, so it needs an exit: \"local\" (own workers "+
				"behind a VPN) or \"remote\" (a pool of enrolled workers). Only a passive scan needs neither")
	default:
		return refuse(http.StatusBadRequest, "exit must be \"local\" or \"remote\"")
	}
}

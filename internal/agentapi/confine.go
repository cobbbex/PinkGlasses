package agentapi

import (
	"encoding/json"

	"github.com/benlik386/asm/internal/scanproto"
)

// confineViolation reports whether any observation falls outside the task's
// assigned target set. A worker reporting assets it was never given is a strong
// signal of compromise or a bug, and the gateway rejects the whole batch and
// quarantines the worker (architecture.md §10.3).
func confineViolation(taskTargetRaw []byte, obs []scanproto.Observation) (bool, string) {
	var tgt scanproto.Target
	_ = json.Unmarshal(taskTargetRaw, &tgt)

	// Only IP-scoped stages are confined by IP. Domain-discovery stages legitimately
	// surface new names, so they are not IP-confined here.
	if tgt.IP == "" {
		return false, ""
	}
	for _, o := range obs {
		switch o.Type {
		case scanproto.ObsService, scanproto.ObsHTTP, scanproto.ObsTLS,
			scanproto.ObsTech, scanproto.ObsScreenshot, scanproto.ObsPath:
			if o.IP != "" && o.IP != tgt.IP {
				return true, "observation IP " + o.IP + " outside assigned target " + tgt.IP
			}
		}
	}
	return false, ""
}

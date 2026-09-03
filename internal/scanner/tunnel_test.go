package scanner

import (
	"context"
	"strings"
	"testing"
)

// A tunnel that failed to come up must not be remembered as up.
//
// The bug this guards: `up` recorded the interface and config id before
// running wg-quick, and the error path only deleted the temporary directory.
// The next task with the same config took the "already carrying this one"
// early return and scanned with no tunnel — the exact leak the feature exists
// to prevent, made worse by looking like success.
func TestFailedTunnelIsNotRememberedAsUp(t *testing.T) {
	var tun tunnel

	// An unsupported kind fails after the state fields would have been set.
	err := tun.up(context.Background(), "config-1", "not-a-real-kind", "body")
	if err == nil {
		t.Fatal("an unsupported tunnel kind should fail")
	}
	if tun.iface != "" || tun.configID != "" || tun.kind != "" {
		t.Errorf("failed attempt left state behind: iface=%q configID=%q kind=%q",
			tun.iface, tun.configID, tun.kind)
	}
	if tun.currentEgress() != "" {
		t.Errorf("failed attempt reported an egress address: %q", tun.currentEgress())
	}

	// The second attempt must actually try again rather than short-circuit.
	err = tun.up(context.Background(), "config-1", "not-a-real-kind", "body")
	if err == nil {
		t.Fatal("the second attempt returned success: a failed tunnel was treated as live")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected the same failure, got %v", err)
	}
}

// down() on a tunnel that was never up must be safe and leave nothing behind.
func TestTunnelDownWhenNeverUp(t *testing.T) {
	var tun tunnel
	tun.down()
	if tun.iface != "" || tun.dir != "" || tun.configID != "" {
		t.Error("down() on an unused tunnel left state behind")
	}
}

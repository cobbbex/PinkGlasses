// Package tunnel brings up a VPN and refuses to pretend it worked.
//
// The one rule this package exists to enforce: traffic must be shown to leave
// by a different address than it did before, or the tunnel is not considered
// up. A tunnel that failed to establish, or established without changing the
// route, would send a scan out of the address the tunnel was chosen to avoid —
// so an unverifiable tunnel is a failure, never a fallback.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tunnel is a VPN this process is routing through.
//
// The rule this file exists to enforce: a scan bound to a VPN must not run if
// the VPN is not carrying it. A tunnel that failed to come up, or came up
// without changing the route, would leak the worker's real address to the
// target — the precise thing choosing a VPN was meant to prevent. So the
// address is measured before and after, and the tunnel is only considered up if
// it changed.
type Tunnel struct {
	mu       sync.Mutex
	configID string
	iface    string
	kind     string
	dir      string
	egressIP string
	baseIP   string
	cmd      *exec.Cmd // openvpn runs in the foreground; wireguard does not
	// restore puts the routing back the way it was, for tunnels that changed it.
	restore func(context.Context)
	// openvpn's own output, kept so a failure can explain itself.
	logFile *os.File
	logPath string
}

// tunnelLogTail returns the last few lines of a tunnel client's own log, for
// putting the reason a tunnel failed into the error the task reports.
func tunnelLogTail(path string, lines int) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, " | ")
}

// egressCheckURLs are asked what address we appear to come from. Several, so
// one being unreachable through a tunnel is not mistaken for the tunnel being
// broken.
var egressCheckURLs = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// ObservedEgressIP reports the address this box appears to come from, or "" if
// nothing answered.
func ObservedEgressIP(ctx context.Context) string {
	c := &http.Client{Timeout: 12 * time.Second}
	for _, u := range egressCheckURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := strings.TrimSpace(string(b)); ip != "" && len(ip) < 46 {
			return ip
		}
	}
	return ""
}

// up brings the tunnel described by cfg online and verifies the egress address
// changed. It is idempotent for the same config id.
func (t *Tunnel) Up(ctx context.Context, configID, kind, body string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.configID == configID && t.iface != "" {
		return nil // already carrying this one
	}
	if t.iface != "" {
		t.downLocked()
	}

	// The address before connecting is the baseline the change is measured
	// against. Without it there is nothing to compare, so the tunnel cannot be
	// verified — and an unverifiable tunnel must not carry a scan. Refusing
	// here is the difference between a VPN and a hope.
	base := ObservedEgressIP(ctx)
	if base == "" {
		return fmt.Errorf("cannot determine this worker's address, so a tunnel cannot be verified; refusing to scan")
	}

	dir, err := os.MkdirTemp("", "pg-vpn-")
	if err != nil {
		return err
	}
	// 0700 dir, 0600 file: the config holds a private key, and it is removed
	// as soon as the tunnel is down.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	// State is committed only once the tunnel is verified. Recording it up
	// front left a failed attempt looking like a live tunnel: the next task
	// with the same config took the "already carrying this one" path and
	// scanned with no tunnel at all.
	t.dir, t.kind = dir, kind

	switch kind {
	case "wireguard":
		iface := "pgvpn0"
		// A previous attempt that died mid-way can leave the interface behind.
		_, _ = runTunnelCmd(ctx, 10*time.Second, "ip", "link", "del", iface)
		undo, err := t.wgUp(ctx, iface, body, dir)
		if err != nil {
			t.resetLocked()
			return err
		}
		t.restore = undo
		t.iface = iface
	case "openvpn":
		path := filepath.Join(dir, "client.ovpn")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.resetLocked()
			return err
		}
		// openvpn stays in the foreground so it can be killed on down(), and
		// its output is kept: when a tunnel does not come up, openvpn's own
		// explanation is the only thing that says why. The first version threw
		// it away and passed a flag that does not exist, so a failure looked
		// identical to a VPN that simply did not route.
		logPath := filepath.Join(dir, "openvpn.log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.resetLocked()
			return err
		}
		cmd := exec.Command("openvpn", "--config", path, "--verb", "3")
		cmd.Dir = dir
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			logFile.Close()
			t.resetLocked()
			return fmt.Errorf("openvpn start: %w", err)
		}
		t.logFile, t.logPath = logFile, logPath
		t.cmd, t.iface = cmd, "tun0"
	default:
		t.resetLocked()
		return fmt.Errorf("unsupported tunnel kind %q", kind)
	}

	// Wait for the address to change. This is the check that makes the feature
	// trustworthy rather than decorative.
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			t.downLocked()
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
		got := ObservedEgressIP(ctx)
		if got == "" || got == base {
			continue // nothing answered yet, or traffic is still taking the old path
		}
		// Only here is the tunnel considered real, and only here is it recorded
		// as the one this worker is carrying.
		t.configID, t.egressIP, t.baseIP = configID, got, base
		slog.Info("scanning through tunnel", "kind", kind, "was", base, "now", got)
		return nil
	}
	detail := ""
	if t.logPath != "" {
		if tail := tunnelLogTail(t.logPath, 8); tail != "" {
			detail = ": " + tail
		}
	}
	t.downLocked()
	return fmt.Errorf("the tunnel did not change this worker's address within 45s (still %s); refusing to scan%s", base, detail)
}

// down tears the tunnel down and removes the config from disk.
func (t *Tunnel) Down() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked()
}

func (t *Tunnel) downLocked() {
	if t.iface == "" {
		t.cleanupLocked()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch t.kind {
	case "wireguard":
		if t.restore != nil {
			t.restore(ctx)
		}
	case "openvpn":
		if t.cmd != nil && t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
			_ = t.cmd.Wait()
		}
		if t.logFile != nil {
			_ = t.logFile.Close()
		}
	}
	slog.Info("tunnel down", "kind", t.kind, "iface", t.iface)
	t.resetLocked()
}

// cleanupLocked removes the temporary directory holding the config.
func (t *Tunnel) cleanupLocked() {
	if t.dir != "" {
		_ = os.RemoveAll(t.dir)
		t.dir = ""
	}
}

// resetLocked forgets everything about a tunnel that is not up, so a failed
// attempt can never be mistaken for a live one.
func (t *Tunnel) resetLocked() {
	t.iface, t.kind, t.configID, t.egressIP, t.baseIP, t.cmd = "", "", "", "", "", nil
	t.restore = nil
	if t.logFile != nil {
		_ = t.logFile.Close()
		t.logFile = nil
	}
	t.logPath = ""
	t.cleanupLocked()
}

// currentEgress reports the address the tunnel is exiting from, or "".
func (t *Tunnel) Egress() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.egressIP
}

func runTunnelCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

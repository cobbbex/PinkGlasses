package tunnel

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
	var tun Tunnel

	// An unsupported kind fails after the state fields would have been set.
	err := tun.Up(context.Background(), "config-1", "not-a-real-kind", "body")
	if err == nil {
		t.Fatal("an unsupported tunnel kind should fail")
	}
	if tun.iface != "" || tun.configID != "" || tun.kind != "" {
		t.Errorf("failed attempt left state behind: iface=%q configID=%q kind=%q",
			tun.iface, tun.configID, tun.kind)
	}
	if tun.Egress() != "" {
		t.Errorf("failed attempt reported an egress address: %q", tun.Egress())
	}

	// The second attempt must actually try again rather than short-circuit.
	err = tun.Up(context.Background(), "config-1", "not-a-real-kind", "body")
	if err == nil {
		t.Fatal("the second attempt returned success: a failed tunnel was treated as live")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected the same failure, got %v", err)
	}
}

// down() on a tunnel that was never up must be safe and leave nothing behind.
func TestTunnelDownWhenNeverUp(t *testing.T) {
	var tun Tunnel
	tun.Down()
	if tun.iface != "" || tun.dir != "" || tun.configID != "" {
		t.Error("down() on an unused tunnel left state behind")
	}
}

// The WireGuard parser has to read real configurations, including the parts
// wg-quick handles that we ignore (DNS, PostUp) and the ones we must not
// (PrivateKey, Endpoint, AllowedIPs).
func TestParseWG(t *testing.T) {
	cfg, err := parseWG(`[Interface]
# a comment
PrivateKey = QO6VZ8k1sJZ9wEo7pYb2cVd4TgHl6mAz5UfKx8QWabc=
Address = 10.66.66.2/24, fd42::2/64
DNS = 1.1.1.1
MTU = 1380
PostUp = something wg-quick would run

[Peer]
PublicKey = mQ2xKp9Zb1LcVn7RtYu3Ei6Ao8Sd5Wf0Gh4JkLm2NpQ=
PresharedKey = pskpskpskpskpskpskpskpskpskpskpskpskpskpskps=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.privateKey == "" || cfg.peerKey == "" {
		t.Error("keys not parsed")
	}
	if cfg.endpoint != "vpn.example.com:51820" || cfg.mtu != "1380" || cfg.keepalive != "25" {
		t.Errorf("endpoint/mtu/keepalive wrong: %+v", cfg)
	}
	if len(cfg.addresses) != 2 || cfg.addresses[0] != "10.66.66.2/24" {
		t.Errorf("addresses = %v", cfg.addresses)
	}
	if !carriesDefault(cfg.allowedIPs) {
		t.Errorf("0.0.0.0/0 should mean a full tunnel: %v", cfg.allowedIPs)
	}
	if cfg.presharedKey == "" {
		t.Error("preshared key not parsed")
	}

	// A split tunnel must not be mistaken for a full one.
	split, err := parseWG(`[Interface]
PrivateKey = k
Address = 10.0.0.2/32
[Peer]
PublicKey = p
Endpoint = h:1
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
`)
	if err != nil {
		t.Fatal(err)
	}
	if carriesDefault(split.allowedIPs) {
		t.Error("a split tunnel was read as carrying the default route")
	}

	// Missing essentials are refused with a reason, not silently defaulted.
	for name, body := range map[string]string{
		"no private key": "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = p\nEndpoint = h:1\n",
		"no peer key":    "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = h:1\n",
		"no endpoint":    "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = p\n",
		"no address":     "[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = h:1\n",
	} {
		if _, err := parseWG(body); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func TestEndpointIP(t *testing.T) {
	if ip, err := endpointIP("203.0.113.7:51820"); err != nil || ip != "203.0.113.7" {
		t.Errorf("literal endpoint: %q %v", ip, err)
	}
	if ip, err := endpointIP("203.0.113.7"); err != nil || ip != "203.0.113.7" {
		t.Errorf("endpoint without a port: %q %v", ip, err)
	}
	if _, err := endpointIP("no-such-host.invalid:51820"); err == nil {
		t.Error("an unresolvable endpoint should fail rather than be guessed at")
	}
}

package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WireGuard is brought up with ip(8) and wg(8) directly rather than wg-quick.
//
// wg-quick is written for a host with an init system. In a container it fails
// on two things it does unconditionally: `sysctl net.ipv4.conf.all.src_valid_mark=1`,
// which cannot be written because /proc/sys is read-only, and resolvconf, which
// needs an init system to detect. Both belong to conveniences a scanner does
// not need — DNS handover and fwmark policy routing — so the interface is built
// here instead, with routing done the plain way: a host route to the tunnel
// endpoint via the existing gateway, then the default route replaced.
//
// That also keeps the container's own network reachable, because the connected
// route for the Docker subnet is more specific than the default and is left
// alone: the worker keeps talking to the gateway while its scans go out the
// tunnel.

// wgConfig is the part of a WireGuard configuration this needs.
type wgConfig struct {
	privateKey   string
	addresses    []string
	mtu          string
	peerKey      string
	presharedKey string
	endpoint     string
	allowedIPs   []string
	keepalive    string
}

// parseWG reads the INI-ish WireGuard format. Unknown keys are ignored: DNS,
// SaveConfig, PostUp and friends are wg-quick's business, not ours.
func parseWG(body string) (wgConfig, error) {
	var c wgConfig
	section := ""
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				c.privateKey = val
			case "address":
				c.addresses = splitList(val)
			case "mtu":
				c.mtu = val
			}
		case "peer":
			switch key {
			case "publickey":
				c.peerKey = val
			case "presharedkey":
				c.presharedKey = val
			case "endpoint":
				c.endpoint = val
			case "allowedips":
				c.allowedIPs = splitList(val)
			case "persistentkeepalive":
				c.keepalive = val
			}
		}
	}
	if c.privateKey == "" {
		return c, fmt.Errorf("no PrivateKey in [Interface]")
	}
	if c.peerKey == "" {
		return c, fmt.Errorf("no PublicKey in [Peer]")
	}
	if c.endpoint == "" {
		return c, fmt.Errorf("no Endpoint in [Peer]")
	}
	if len(c.addresses) == 0 {
		return c, fmt.Errorf("no Address in [Interface]")
	}
	if len(c.allowedIPs) == 0 {
		c.allowedIPs = []string{"0.0.0.0/0"}
	}
	return c, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// carriesDefault reports whether these AllowedIPs mean "everything".
func carriesDefault(allowed []string) bool {
	for _, a := range allowed {
		if a == "0.0.0.0/0" || a == "::/0" {
			return true
		}
	}
	return false
}

// wgUp builds the interface. It returns the routing it changed so wgDown can
// put it back.
func (t *Tunnel) wgUp(ctx context.Context, iface, body, dir string) (restore func(context.Context), err error) {
	cfg, err := parseWG(body)
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}

	// The private key goes to a 0600 file rather than the command line, where
	// it would be visible in /proc to anything that can read it.
	keyPath := filepath.Join(dir, "wg.key")
	if err := os.WriteFile(keyPath, []byte(cfg.privateKey+"\n"), 0o600); err != nil {
		return nil, err
	}

	if out, err := runTunnelCmd(ctx, 15*time.Second, "ip", "link", "add", iface, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("creating the interface: %w: %s", err, out)
	}
	undo := func(c context.Context) { _, _ = runTunnelCmd(c, 15*time.Second, "ip", "link", "del", iface) }

	set := []string{"set", iface, "private-key", keyPath, "peer", cfg.peerKey,
		"endpoint", cfg.endpoint, "allowed-ips", strings.Join(cfg.allowedIPs, ",")}
	if cfg.keepalive != "" {
		set = append(set, "persistent-keepalive", cfg.keepalive)
	}
	if cfg.presharedKey != "" {
		pskPath := filepath.Join(dir, "wg.psk")
		if err := os.WriteFile(pskPath, []byte(cfg.presharedKey+"\n"), 0o600); err != nil {
			undo(ctx)
			return nil, err
		}
		set = append(set, "preshared-key", pskPath)
	}
	if out, err := runTunnelCmd(ctx, 20*time.Second, "wg", set...); err != nil {
		undo(ctx)
		return nil, fmt.Errorf("configuring the peer: %w: %s", err, out)
	}

	for _, addr := range cfg.addresses {
		if strings.Contains(addr, ":") {
			continue // this build routes IPv4 only; a v6 address is not fatal
		}
		if out, err := runTunnelCmd(ctx, 15*time.Second, "ip", "address", "add", addr, "dev", iface); err != nil {
			undo(ctx)
			return nil, fmt.Errorf("adding %s: %w: %s", addr, err, out)
		}
	}
	mtu := cfg.mtu
	if mtu == "" {
		mtu = "1420"
	}
	if out, err := runTunnelCmd(ctx, 15*time.Second, "ip", "link", "set", "mtu", mtu, "up", "dev", iface); err != nil {
		undo(ctx)
		return nil, fmt.Errorf("bringing the interface up: %w: %s", err, out)
	}

	if !carriesDefault(cfg.allowedIPs) {
		// Split tunnel: route only what the peer claims.
		for _, a := range cfg.allowedIPs {
			_, _ = runTunnelCmd(ctx, 15*time.Second, "ip", "route", "add", a, "dev", iface)
		}
		return undo, nil
	}

	// Full tunnel. Pin the endpoint to the old path first, or the tunnel's own
	// packets would try to travel through the tunnel.
	gw, dev, err := defaultRoute(ctx)
	if err != nil {
		undo(ctx)
		return nil, err
	}
	epIP, err := endpointIP(cfg.endpoint)
	if err != nil {
		undo(ctx)
		return nil, err
	}
	if out, err := runTunnelCmd(ctx, 15*time.Second,
		"ip", "route", "add", epIP+"/32", "via", gw, "dev", dev); err != nil {
		// Already present is fine; anything else is not.
		if !strings.Contains(out, "File exists") {
			undo(ctx)
			return nil, fmt.Errorf("pinning the endpoint route: %w: %s", err, out)
		}
	}
	if out, err := runTunnelCmd(ctx, 15*time.Second, "ip", "route", "replace", "default", "dev", iface); err != nil {
		_, _ = runTunnelCmd(ctx, 10*time.Second, "ip", "route", "del", epIP+"/32")
		undo(ctx)
		return nil, fmt.Errorf("routing through the tunnel: %w: %s", err, out)
	}

	return func(c context.Context) {
		// Order matters: put the old default back before the interface goes,
		// so the worker is never left with no route at all.
		_, _ = runTunnelCmd(c, 15*time.Second, "ip", "route", "replace", "default", "via", gw, "dev", dev)
		_, _ = runTunnelCmd(c, 10*time.Second, "ip", "route", "del", epIP+"/32")
		undo(c)
	}, nil
}

// defaultRoute returns the gateway and device of the current default route.
func defaultRoute(ctx context.Context) (gw, dev string, err error) {
	out, err := runTunnelCmd(ctx, 10*time.Second, "ip", "-4", "route", "show", "default")
	if err != nil {
		return "", "", fmt.Errorf("reading the default route: %w: %s", err, out)
	}
	f := strings.Fields(out)
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if gw == "" || dev == "" {
		return "", "", fmt.Errorf("no usable default route to fall back on (%q)", out)
	}
	return gw, dev, nil
}

// endpointIP resolves the peer endpoint to a single address.
func endpointIP(endpoint string) (string, error) {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve the tunnel endpoint %q: %v", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("the tunnel endpoint %q has no IPv4 address", host)
}

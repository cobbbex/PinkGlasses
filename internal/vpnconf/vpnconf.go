// Package vpnconf recognises and lightly validates VPN configuration files, so
// a paste that is not one is refused at upload rather than at scan time on a
// worker where the failure is far less visible.
package vpnconf

import (
	"fmt"
	"regexp"
	"strings"
)

// The tunnel kinds this scanner can bring up.
const (
	WireGuard = "wireguard"
	OpenVPN   = "openvpn"
)

var (
	wgEndpointRe  = regexp.MustCompile(`(?mi)^\s*Endpoint\s*=\s*(\S+)`)
	ovpnRemoteRe  = regexp.MustCompile(`(?mi)^\s*remote\s+(\S+)(?:\s+(\d+))?`)
	wgPrivateKeyR = regexp.MustCompile(`(?mi)^\s*PrivateKey\s*=`)
)

// Detect identifies a config and returns its kind and endpoint for display.
//
// The endpoint is metadata: it tells a user which exit a config is without
// reopening a file they should not need to look at again after uploading it.
func Detect(body string) (kind, endpoint string, err error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return "", "", fmt.Errorf("the configuration is empty")
	}
	if len(trimmed) > 512*1024 {
		return "", "", fmt.Errorf("the configuration is implausibly large (over 512 KB)")
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lower, "[interface]"):
		if !wgPrivateKeyR.MatchString(trimmed) {
			return "", "", fmt.Errorf("this looks like a WireGuard config but has no PrivateKey; " +
				"the scanner cannot bring up a tunnel without one")
		}
		if !strings.Contains(lower, "[peer]") {
			return "", "", fmt.Errorf("this WireGuard config has no [Peer] section, so there is nothing to connect to")
		}
		if m := wgEndpointRe.FindStringSubmatch(trimmed); m != nil {
			endpoint = m[1]
		}
		return WireGuard, endpoint, nil

	case ovpnRemoteRe.MatchString(trimmed):
		if m := ovpnRemoteRe.FindStringSubmatch(trimmed); m != nil {
			endpoint = m[1]
			if m[2] != "" {
				endpoint += ":" + m[2]
			}
		}
		// An .ovpn with no inline key and no credentials stops to ask for them
		// on the worker, where nobody is watching. Better to say so now.
		if !strings.Contains(lower, "<key>") && !strings.Contains(lower, "auth-user-pass") &&
			!strings.Contains(lower, "pkcs12") {
			return "", "", fmt.Errorf("this OpenVPN config has no inline <key>, pkcs12 or auth-user-pass; " +
				"it would stop and ask for credentials on the worker")
		}
		return OpenVPN, endpoint, nil
	}
	return "", "", fmt.Errorf("not recognised as WireGuard ([Interface]) or OpenVPN (remote …)")
}

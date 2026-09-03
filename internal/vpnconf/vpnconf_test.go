package vpnconf

import "testing"

const wg = `[Interface]
PrivateKey = aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSByZWFsIGtleQ==
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = c29tZSBwdWJsaWMga2V5IHZhbHVlIGhlcmUgb2sgdGhlbg==
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
`

const ovpn = `client
dev tun
proto udp
remote vpn.example.org 1194
resolv-retry infinite
<key>
-----BEGIN PRIVATE KEY-----
notarealkey
-----END PRIVATE KEY-----
</key>
`

func TestDetect(t *testing.T) {
	if k, ep, err := Detect(wg); err != nil || k != WireGuard || ep != "vpn.example.com:51820" {
		t.Errorf("wireguard: kind=%q endpoint=%q err=%v", k, ep, err)
	}
	if k, ep, err := Detect(ovpn); err != nil || k != OpenVPN || ep != "vpn.example.org:1194" {
		t.Errorf("openvpn: kind=%q endpoint=%q err=%v", k, ep, err)
	}
}

// Anything that would fail on the worker should fail at upload, where the
// person who can fix it is looking at the screen.
func TestDetectRejectsUnusableConfigs(t *testing.T) {
	cases := map[string]string{
		"empty":                  "",
		"not a config":           "hello there",
		"wireguard without key":  "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = a:1\n",
		"wireguard without peer": "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n",
		"openvpn without creds":  "client\ndev tun\nremote vpn.example.org 1194\n",
	}
	for name, body := range cases {
		if _, _, err := Detect(body); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

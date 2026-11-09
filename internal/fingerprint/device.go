package fingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// A device is named from a host's open ports taken together, not from one
// HTTP response: a MikroTik router shows itself in nmap's names for its FTP,
// SSH and API services, and in ports no other product listens on (Winbox
// 8291). Any one of those may be closed or filtered, so the host is judged on
// all of them at once, with the same arithmetic as the web rules: the
// strongest signal, raised a little by each further one that agrees.

// Service is what the port scan learned about one open port.
type Service struct {
	Port    int
	Name    string // nmap's service name: "ftp", "routeros-api", "ssl|unknown"
	Product string // nmap's product: "MikroTik router ftpd"
	Version string // nmap's version, which for some services is a protocol
}

// DeviceMatch is a device named on a host, and the ports it showed on with
// what each showed ("Winbox", "API", …). A port is listed only when a signal
// fired on it, so a host's unrelated services are never labelled.
type DeviceMatch struct {
	Match
	Ports map[int][]string `json:"ports"`
}

type portSignal struct {
	what    string
	weight  int
	feature string
	test    func(s *Service) bool
}

type device struct {
	name    string
	aliases []string
	signals []portSignal
	version func(s *Service) string
}

var devices = []device{mikrotikDevice}

// DetectDevice names the devices one host's open services show, strongest
// first. Like Detect it keeps suspected matches; DeviceMatch.Confidence says
// whether one reached Reported.
func DetectDevice(svcs []Service) []DeviceMatch {
	var out []DeviceMatch
	for _, d := range devices {
		m := DeviceMatch{Match: Match{Product: d.name}, Ports: map[int][]string{}}
		feats := map[string]bool{}
		strongest := 0
		for i := range svcs {
			s := &svcs[i]
			for _, sig := range d.signals {
				if !sig.test(s) {
					continue
				}
				m.Evidence = append(m.Evidence, sig.what)
				strongest = max(strongest, sig.weight)
				if _, ok := m.Ports[s.Port]; !ok {
					m.Ports[s.Port] = nil
				}
				if sig.feature != "" {
					feats[sig.feature] = true
					m.Ports[s.Port] = union(m.Ports[s.Port], []string{sig.feature})
				}
				if m.Version == "" && d.version != nil {
					m.Version = d.version(s)
				}
			}
		}
		if strongest < suspected {
			continue
		}
		m.Confidence = min(99, strongest+5*(len(m.Evidence)-1))
		// Port numbers only confirm. Three hints add up to Reported, and an
		// open 8291, 8728 and 8729 on one host is still not proof of a router.
		if strongest < Reported {
			m.Confidence = min(m.Confidence, Reported-1)
		}
		for f := range feats {
			m.Features = append(m.Features, f)
		}
		sort.Strings(m.Features)
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

// DeviceNames lists every device the port rules know, for the docs test and
// for fpcheck's usage line.
func DeviceNames() []string {
	out := make([]string, len(devices))
	for i, d := range devices {
		out[i] = d.name
	}
	return out
}

func nmapProduct(sub string) func(*Service) bool {
	sub = strings.ToLower(sub)
	return func(s *Service) bool { return strings.Contains(strings.ToLower(s.Product), sub) }
}

// unnamedPort is an open port nmap could not name, or named only as TLS:
// on its own number it is a hint, never a fact.
func unnamedPort(port int) func(*Service) bool {
	return func(s *Service) bool {
		if s.Port != port || s.Product != "" {
			return false
		}
		n := strings.ToLower(s.Name)
		return n == "" || n == "unknown" || n == "ssl|unknown" || n == "ssl"
	}
}

// --- MikroTik RouterOS ---
//
// Checked against RouterOS 6.49.10 and 7.16 (CHR) with the worker's nmap and
// its flags (-sV --version-intensity 7):
//
//	21    ftp             MikroTik router ftpd 6.49.10       the exact version
//	22    ssh             MikroTik RouterOS sshd (protocol 2.0)
//	2000  bandwidth-test  MikroTik bandwidth-test server
//	8728  routeros-api    MikroTik RouterOS API              7.x only; 6.x unnamed
//	8291                  (unnamed)                          Winbox
//	8729  ssl|unknown                                        API over TLS
//	23    telnet          Linux telnetd                      wrong, so not read
//
// nmap's probe database names more than the lab showed (WinBox, HotSpot,
// the 6.x WebFig over HTTP/1.0, the web proxy, DNS, SNMP); each of those is
// a signal too, and any other product nmap calls MikroTik counts for less.
// Its WebFig match wants HTTP/1.0, and 6.49 answers HTTP/1.1, so in the lab
// port 80 came back unnamed: the web rule (rules.go) is what names it there.
//
// The SSH "version" is the protocol (2.0), never RouterOS's, so only the FTP
// banner supplies one here; the web rule reads it from /webfig/roteros.info.

const MikroTik = "MikroTik RouterOS"

var mikrotikFTPVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:rc[0-9]+|beta[0-9]+)?$`)

var mikrotikDevice = device{
	name:    MikroTik,
	aliases: []string{"mikrotik", "routeros"},
	signals: []portSignal{
		{"nmap MikroTik router ftpd", 95, "FTP", nmapProduct("mikrotik router ftpd")},
		{"nmap MikroTik RouterOS sshd", 95, "SSH", nmapProduct("mikrotik routeros sshd")},
		{"nmap MikroTik RouterOS API", 95, "API", nmapProduct("mikrotik routeros api")},
		{"nmap MikroTik WinBox", 95, "Winbox", nmapProduct("mikrotik winbox")},
		{"nmap MikroTik bandwidth-test server", 92, "Bandwidth test", nmapProduct("mikrotik bandwidth-test")},
		{"nmap MikroTik HotSpot", 92, "Hotspot", nmapProduct("mikrotik hotspot")},
		{"nmap MikroTik router config httpd", 92, "WebFig", func(s *Service) bool {
			return nmapProduct("mikrotik router config httpd")(s) || nmapProduct("mikrotik router http config")(s)
		}},
		{"nmap MikroTik http proxy", 90, "Web proxy", func(s *Service) bool {
			// The HotSpot's own proxy is the HotSpot, read above.
			return (nmapProduct("mikrotik http proxy")(s) || nmapProduct("mikrotik httpproxy")(s)) &&
				!nmapProduct("hotspot")(s)
		}},
		{"nmap names MikroTik", 85, "", func(s *Service) bool {
			return nmapProduct("mikrotik")(s) && !mikrotikNamed(s)
		}},
		{"port 8291 open, unnamed (Winbox)", 50, "Winbox", unnamedPort(8291)},
		{"port 8728 open, unnamed (API)", 45, "API", unnamedPort(8728)},
		{"port 8729 open, TLS or unnamed (API-SSL)", 45, "API-SSL", unnamedPort(8729)},
	},
	version: func(s *Service) string {
		if !strings.Contains(strings.ToLower(s.Product), "mikrotik router ftpd") {
			return ""
		}
		if mikrotikFTPVersion.MatchString(s.Version) {
			return s.Version
		}
		return ""
	},
}

// mikrotikNamed is the products the specific signals above already read, so
// the catch-all does not count the same port twice.
func mikrotikNamed(s *Service) bool {
	p := strings.ToLower(s.Product)
	for _, sub := range []string{"router ftpd", "routeros sshd", "routeros api", "winbox",
		"bandwidth-test", "hotspot", "router config httpd", "router http config", "http proxy", "httpproxy"} {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

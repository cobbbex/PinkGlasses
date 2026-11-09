package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What nmap -sV said about the two lab routers (deploy/fplab, RouterOS CHR).
var (
	routerOS6 = []Service{
		{Port: 21, Name: "ftp", Product: "MikroTik router ftpd", Version: "6.49.10"},
		{Port: 22, Name: "ssh", Product: "MikroTik RouterOS sshd", Version: "2.0"},
		{Port: 23, Name: "telnet", Product: "Linux telnetd"},
		{Port: 80, Name: "http"},
		{Port: 2000, Name: "bandwidth-test", Product: "MikroTik bandwidth-test server"},
		{Port: 8291},
		{Port: 8728},
		{Port: 8729, Name: "ssl|unknown"},
	}
	routerOS7 = []Service{
		{Port: 21, Name: "ftp", Product: "MikroTik router ftpd", Version: "7.16"},
		{Port: 22, Name: "ssh", Product: "MikroTik RouterOS sshd", Version: "2.0"},
		{Port: 23, Name: "telnet", Product: "Linux telnetd"},
		{Port: 80, Name: "http"},
		{Port: 2000, Name: "bandwidth-test", Product: "MikroTik bandwidth-test server"},
		{Port: 8291},
		{Port: 8728, Name: "routeros-api", Product: "MikroTik RouterOS API"},
		{Port: 8729, Name: "ssl|unknown"},
	}
)

func TestDeviceMikroTikLab(t *testing.T) {
	for name, c := range map[string]struct {
		svcs    []Service
		version string
	}{"6.49.10": {routerOS6, "6.49.10"}, "7.16": {routerOS7, "7.16"}} {
		t.Run(name, func(t *testing.T) {
			ms := DetectDevice(c.svcs)
			if len(ms) != 1 || ms[0].Product != MikroTik || ms[0].Confidence < Reported {
				t.Fatalf("got %+v", ms)
			}
			m := ms[0]
			if m.Version != c.version {
				t.Errorf("version %q, want %q (the SSH protocol is not a version)", m.Version, c.version)
			}
			// Telnet (misnamed by nmap) and the plain web port are not
			// labelled from the port scan: the web rule speaks for port 80.
			for _, p := range []int{23, 80} {
				if _, ok := m.Ports[p]; ok {
					t.Errorf("port %d labelled %v", p, m.Ports[p])
				}
			}
			for port, want := range map[int]string{21: "FTP", 22: "SSH", 2000: "Bandwidth test", 8291: "Winbox", 8728: "API", 8729: "API-SSL"} {
				if strings.Join(m.Ports[port], ",") != want {
					t.Errorf("port %d shows %v, want %s", port, m.Ports[port], want)
				}
			}
		})
	}
}

// A port number nmap could not name is never enough on its own, and an
// ordinary host is not a router.
func TestDeviceNoFalsePositives(t *testing.T) {
	for name, svcs := range map[string][]Service{
		"winbox port only":      {{Port: 8291}},
		"every MikroTik port":   {{Port: 8291}, {Port: 8728}, {Port: 8729, Name: "ssl|unknown"}},
		"linux host":            {{Port: 21, Name: "ftp", Product: "vsftpd", Version: "3.0.5"}, {Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6p1"}},
		"8291 named as another": {{Port: 8291, Name: "http", Product: "nginx"}, {Port: 22, Product: "OpenSSH"}},
	} {
		for _, m := range DetectDevice(svcs) {
			if m.Confidence >= Reported {
				t.Errorf("%s: named %+v", name, m)
			}
		}
	}
}

func TestDeviceNamesFromNmapDatabase(t *testing.T) {
	for product, feature := range map[string]string{
		"MikroTik WinBox management console": "Winbox",
		"MikroTik HotSpot":                   "Hotspot",
		"MikroTik router config httpd":       "WebFig",
		"MikroTik http proxy":                "Web proxy",
		"Mikrotik HotSpot http proxy":        "Hotspot",
		"Mikrotik DNS":                       "",
	} {
		ms := DetectDevice([]Service{{Port: 1, Product: product}})
		if len(ms) != 1 || ms[0].Confidence < Reported {
			t.Errorf("%s: got %+v", product, ms)
			continue
		}
		if strings.Join(ms[0].Features, ",") != feature {
			t.Errorf("%s: features %v, want %q", product, ms[0].Features, feature)
		}
		if len(ms[0].Evidence) != 1 {
			t.Errorf("%s: counted %v", product, ms[0].Evidence)
		}
	}
}

// RouterOS 7 prints no version on its front page; the fetcher reads it from
// /webfig/roteros.info, which every release serves without a login.
func TestFetcherReadsRouterOS7Version(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<!doctype html><title>RouterOS</title><a href="https://mikrotik.com"><img src="mikrotik_logo.png" style="float: right;" alt="Mikrotik"></a><h1>RouterOS</h1>`))
		case "/webfig/roteros.info":
			w.Write([]byte(`{ crc: 1861359319, size: 100546, name: "roteros.jg", unique: "roteros-2e0cdf77b287.jg", version: "7.16" },`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := Fetcher{Client: client}.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Product != MikroTik || res.Matches[0].Version != "7.16" {
		t.Fatalf("matches %+v", res.Matches)
	}
	if strings.Join(res.Matches[0].Features, ",") != "WebFig" {
		t.Errorf("features %v", res.Matches[0].Features)
	}
}

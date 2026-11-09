package scanner

import (
	"sort"
	"strings"
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// The worker's nmap -oG line for the RouterOS 7.16 lab, through the same
// parsing nmapRun does.
const routerOS7Grep = "Host: 172.18.0.14 (fplab-routeros7.pinkglasses_default)\tPorts: " +
	"21/open/tcp//ftp//MikroTik router ftpd 7.16/, 22/open/tcp//ssh//MikroTik RouterOS sshd (protocol 2.0)/, " +
	"23/open/tcp//telnet//Linux telnetd/, 80/open/tcp//http///, 2000/open/tcp//bandwidth-test//MikroTik bandwidth-test server/, " +
	"8291/open/tcp/////, 8728/open/tcp//routeros-api//MikroTik RouterOS API/, 8729/open/tcp//ssl|unknown///\tIgnored State: closed (4)"

func TestDeviceObservationsFromNmap(t *testing.T) {
	ip := parseNmapGrepHost(routerOS7Grep)
	var svcs []scanproto.Observation
	for _, e := range parseNmapGrepPorts(routerOS7Grep) {
		product, version := splitNmapProduct(e.product)
		svcs = append(svcs, scanproto.Observation{Type: scanproto.ObsService, IP: ip, Port: e.port,
			Proto: "tcp", State: "open", Product: product, Version: version, Banner: e.banner})
	}
	got := map[int][]string{}
	for _, o := range deviceObservations(svcs) {
		if o.Type != scanproto.ObsTech || o.IP != ip {
			t.Fatalf("observation %+v", o)
		}
		name := o.TechName
		if o.TechVersion != "" {
			name += " " + o.TechVersion
		}
		got[o.Port] = append(got[o.Port], name)
	}
	want := map[int]string{
		21:   "MikroTik RouterOS 7.16,MikroTik RouterOS FTP",
		22:   "MikroTik RouterOS 7.16,MikroTik RouterOS SSH",
		2000: "MikroTik RouterOS 7.16,MikroTik RouterOS Bandwidth test",
		8291: "MikroTik RouterOS 7.16,MikroTik RouterOS Winbox",
		8728: "MikroTik RouterOS 7.16,MikroTik RouterOS API",
		8729: "MikroTik RouterOS 7.16,MikroTik RouterOS API-SSL",
	}
	if len(got) != len(want) {
		t.Errorf("ports %v, want %d of them", keys(got), len(want))
	}
	for port, w := range want {
		if strings.Join(got[port], ",") != w {
			t.Errorf("port %d: %v, want %s", port, got[port], w)
		}
	}
}

func keys(m map[int][]string) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// A host with only the port numbers is not named, and neither is an ordinary
// server.
func TestDeviceObservationsNeedMoreThanPorts(t *testing.T) {
	svcs := []scanproto.Observation{
		{Type: scanproto.ObsService, IP: "192.0.2.1", Port: 8291},
		{Type: scanproto.ObsService, IP: "192.0.2.1", Port: 8728},
		{Type: scanproto.ObsService, IP: "192.0.2.2", Port: 22, Product: "OpenSSH", Version: "9.6p1", Banner: "ssh"},
	}
	if obs := deviceObservations(svcs); len(obs) != 0 {
		t.Errorf("named %+v", obs)
	}
}

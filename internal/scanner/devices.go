package scanner

import (
	"log/slog"
	"sort"

	"github.com/benlik386/pinkglasses/internal/fingerprint"
	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// deviceObservations names the devices — MikroTik routers so far — that a
// host's open ports show together, from what nmap already learned about
// them: no request of its own. A device is recorded as a technology on every
// port that showed it, with the version where one port gave it away and the
// role of that port as a technology of its own ("MikroTik RouterOS Winbox"),
// so the inventory can be searched for every router with Winbox exposed.
//
// A port nmap could not name (Winbox on 8291) counts only beside one it
// could: an open 8291 alone is a hint, not a router.
func deviceObservations(services []scanproto.Observation) []scanproto.Observation {
	byIP := map[string][]fingerprint.Service{}
	var ips []string
	for _, o := range services {
		if o.Type != scanproto.ObsService || o.IP == "" {
			continue
		}
		if _, ok := byIP[o.IP]; !ok {
			ips = append(ips, o.IP)
		}
		byIP[o.IP] = append(byIP[o.IP], fingerprint.Service{
			Port: o.Port, Name: o.Banner, Product: o.Product, Version: o.Version,
		})
	}
	var obs []scanproto.Observation
	for _, ip := range ips {
		for _, m := range fingerprint.DetectDevice(byIP[ip]) {
			if m.Confidence < fingerprint.Reported {
				continue
			}
			slog.Info("device", "ip", ip, "device", m.Product, "version", m.Version,
				"confidence", m.Confidence, "features", m.Features, "evidence", m.Evidence)
			ports := make([]int, 0, len(m.Ports))
			for p := range m.Ports {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, port := range ports {
				obs = append(obs, scanproto.Observation{
					Type: scanproto.ObsTech, IP: ip, Port: port,
					TechName: m.Product, TechVersion: m.Version, TechConfidence: m.Confidence,
				})
				for _, feat := range m.Ports[port] {
					obs = append(obs, scanproto.Observation{
						Type: scanproto.ObsTech, IP: ip, Port: port,
						TechName: m.Product + " " + feat, TechConfidence: m.Confidence,
					})
				}
			}
		}
	}
	return obs
}

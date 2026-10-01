package scanner

import "strings"

// Addresses that belong to a CDN or a scrubbing service, rather than to the
// client whose name pointed at them.
//
// This matters more than it sounds. A company's name resolving to Cloudflare
// means the client's own host is somewhere behind it, unreachable and unknown;
// what answers on that address is Cloudflare's edge, shared with a few million
// other sites. Port scanning it learns nothing about the client, and it aims
// traffic at a third party who did not authorize anything — the one thing this
// tool's authorization model exists to prevent.
//
// Measured on a real company: of eight addresses its three domains resolved to,
// four were Cloudflare and two Akamai. Six eighths of a full-port sweep —
// eighteen hours of probing — was pointed at someone else's edge.
//
// Detection is by ASN first, then by the operator name the ASN carries, since
// the registries name these networks plainly ("CLOUDFLARENET - Cloudflare,
// Inc., US", "AKAMAI-AMS - Akamai International B.V., NL") and a name match
// keeps working as these providers add networks.

// cdnASNs are networks that exist only to front other people's sites.
// Deliberately not here: AWS, Google Cloud, Azure, Hetzner, DigitalOcean. A
// host in a cloud is usually the client's own machine, and refusing to scan it
// would refuse most of the modern internet.
var cdnASNs = map[int]string{
	13335:  "cloudflare",
	209242: "cloudflare",
	132892: "cloudflare",
	395747: "cloudflare",
	20940:  "akamai",
	16625:  "akamai",
	33905:  "akamai",
	32787:  "akamai",
	12222:  "akamai",
	21342:  "akamai",
	35994:  "akamai",
	23454:  "akamai",
	54113:  "fastly",
	394192: "fastly",
	19551:  "imperva",
	198949: "imperva",
	30148:  "sucuri",
	12989:  "stackpath",
	33438:  "stackpath",
	60068:  "cdn77",
	200325: "bunny",
	15133:  "edgecast",
	22822:  "limelight",
	30081:  "cachefly",
	200449: "qrator",
	262254: "ddos-guard",
	199524: "gcore",
	55770:  "akamai",
}

// cdnNames are matched against the ASN's operator name, lowercased. One of
// these inside the name is enough: registries do not hide who they are.
var cdnNames = []struct{ needle, provider string }{
	{"cloudflare", "cloudflare"},
	{"akamai", "akamai"},
	{"fastly", "fastly"},
	{"cloudfront", "cloudfront"},
	{"incapsula", "imperva"},
	{"imperva", "imperva"},
	{"sucuri", "sucuri"},
	{"stackpath", "stackpath"},
	{"highwinds", "stackpath"},
	{"cdn77", "cdn77"},
	{"bunnycdn", "bunny"},
	{"edgecast", "edgecast"},
	{"limelight", "limelight"},
	{"cachefly", "cachefly"},
	{"qrator", "qrator"},
	{"ddos-guard", "ddos-guard"},
	{"g-core", "gcore"},
	{"gcore", "gcore"},
	{"myracloud", "myra"},
	{"netscout", "netscout"},
}

// cdnProvider names the CDN or scrubbing service an address belongs to, or ""
// when it looks like an ordinary host. Takes what address enrichment already
// found, so it costs no extra lookup.
func cdnProvider(asn int, asOrg string) string {
	if p, ok := cdnASNs[asn]; ok {
		return p
	}
	low := strings.ToLower(asOrg)
	for _, c := range cdnNames {
		if strings.Contains(low, c.needle) {
			return c.provider
		}
	}
	return ""
}

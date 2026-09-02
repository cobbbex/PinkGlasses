// Package scanparams defines the whitelist of user-settable scan parameters and
// validates them. This is the security boundary for configurable scans: every
// value here becomes a process argument on a scan box, so nothing reaches exec
// unless it passed through Validate. Raw user strings are never forwarded.
package scanparams

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Kind constrains how a parameter value is validated. Serialized as a string so
// the UI can render the right control without knowing Go's iota ordering.
type Kind string

const (
	KindInt      Kind = "int"      // integer within [Min, Max]
	KindEnum     Kind = "enum"     // one of Enum
	KindPorts    Kind = "ports"    // "top-100" | "top-1000" | "full" | "1-1024" | "80,443"
	KindWordlist Kind = "wordlist" // a named wordlist key, resolved to a server path
	KindBool     Kind = "bool"
	// KindCSV is a short comma-separated token list (e.g. "php,html" or
	// "200,301"). Deliberately narrow: letters, digits, dot, dash, underscore
	// and commas only, and it may never begin with '-' — otherwise a value
	// could smuggle in an extra flag when it lands in the argv of a scan tool.
	KindCSV Kind = "csv"
	// KindText is a free-text value that becomes one process argument — a
	// User-Agent, say. Printable ASCII only, no control characters and never
	// leading '-', so it cannot smuggle in another flag.
	KindText Kind = "text"
	// KindProxy is a list of proxy URLs, one per line or comma-separated. Each
	// must parse as a URL with an http, socks4 or socks5 scheme.
	KindProxy Kind = "proxy"
)

// iPhoneUA is the default User-Agent for web probing: a current mobile Safari.
// A phone is the least remarkable client in a web log, and some sites serve a
// reduced page to anything that announces itself as a tool.
const iPhoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) " +
	"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

// textRe bounds KindText: printable ASCII, no leading dash.
var textRe = regexp.MustCompile(`^[A-Za-z0-9][ -~]{0,255}$`)

// csvRe bounds KindCSV values. No spaces, no shell metacharacters, no path
// separators: this string becomes a process argument on a scan box.
var csvRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9,._-]{0,119}$`)

// Spec describes one settable parameter. Tool groups parameters in the UI so a
// user sees settings organised per tool rather than as a flat list.
type Spec struct {
	Key     string   `json:"key"`
	Tool    string   `json:"tool"`
	Label   string   `json:"label"`
	Kind    Kind     `json:"kind"`
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
	Enum    []string `json:"enum,omitempty"`
	Default string   `json:"default"`
	Help    string   `json:"help"`
}

// Specs is the complete, closed set of settable parameters. A key not present
// here is rejected — the UI cannot invent new flags, and neither can a crafted
// API request. Defaults come from Tools.md.
//
// Every entry here MUST be consumed by a worker stage; exposing a knob the
// worker ignores would be a lie in the UI.
var Specs = []Spec{
	// --- which tools run at all ---
	//
	// One switch per tool, so a scan can be narrowed to the stages you actually
	// want without editing a profile. A disabled tool is skipped, not run and
	// discarded: the stage either falls back to the pure-Go implementation or
	// contributes nothing. shuffledns has no switch here because it already had
	// one — dns_bruteforce, below — and two switches for one tool is a bug
	// waiting to be filed.
	{Key: "subfinder_enabled", Tool: "subfinder", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Passive subdomain enumeration. Off leaves only the seed names and whatever brute force finds."},
	{Key: "dnsx_enabled", Tool: "dnsx", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Off falls back to the worker's own resolver, which is slower and does no wildcard filtering or PTR lookups."},
	{Key: "naabu_enabled", Tool: "naabu", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "The fast port sweep, used only for wide port sets. Off sends the whole port selection to nmap instead."},
	{Key: "nmap_enabled", Tool: "nmap", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Service and version detection. Off reports open ports with no idea what is behind them."},
	{Key: "katana_enabled", Tool: "katana", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Crawling seeds directory search with real linked paths. Off leaves the brute force guessing blind."},
	{Key: "httpx_enabled", Tool: "httpx", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Web probing, technology detection and screenshots. Off falls back to a plain header fingerprint."},
	{Key: "gobuster_enabled", Tool: "gobuster", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Directory brute force — the loudest stage. Off still reports the paths crawling found."},
	{Key: "nuclei_enabled", Tool: "nuclei", Label: "Enabled", Kind: KindBool,
		Default: "true",
		Help: "Vulnerability templates. Off skips the vuln_check stage entirely."},

	// --- subdomain discovery ---
	{Key: "subfinder_max_time", Tool: "subfinder", Label: "Max enumeration time (min)", Kind: KindInt,
		Min: 1, Max: 30, Default: "3",
		Help: "How long subfinder may keep querying its passive sources before returning what it has."},
	{Key: "subfinder_all", Tool: "subfinder", Label: "Query all sources", Kind: KindBool,
		Default: "false",
		Help: "Include the slow sources too. Finds more subdomains and takes noticeably longer. Still passive — no packets reach the target."},

	{Key: "dns_bruteforce", Tool: "shuffledns", Label: "DNS bruteforce", Kind: KindBool,
		Default: "true",
		Help: "Brute-force subdomains with the selected wordlists, as a separate task per list. Very high DNS volume — turn it off for a quick, quiet scan."},
	{Key: "shuffledns_threads", Tool: "shuffledns", Label: "Bruteforce threads", Kind: KindInt,
		Min: 1, Max: 1000, Default: "100", Help: "Concurrent resolutions while brute-forcing."},

	{Key: "dnsx_threads", Tool: "dnsx", Label: "Resolver threads", Kind: KindInt,
		Min: 1, Max: 500, Default: "100", Help: "Concurrent DNS resolutions."},
	{Key: "dnsx_rate_limit", Tool: "dnsx", Label: "Rate limit (per second)", Kind: KindInt,
		Min: 0, Max: 10000, Default: "0", Help: "Queries per second. 0 leaves it unlimited."},
	{Key: "dnsx_retries", Tool: "dnsx", Label: "Retries", Kind: KindInt,
		Min: 1, Max: 5, Default: "2", Help: "Retries per name before giving up. Raise it on lossy links."},

	// --- port scanning ---
	{Key: "ports", Tool: "naabu", Label: "Port set", Kind: KindPorts,
		Default: "top-100", Help: "top-100, top-1000, full, a range like 1-1024, or a list like 80,443."},
	{Key: "naabu_rate", Tool: "naabu", Label: "Packets per second", Kind: KindInt,
		Min: 1, Max: 1000, Default: "20", Help: "Higher is faster but far more likely to be rate-limited or blocked."},
	{Key: "naabu_concurrency", Tool: "naabu", Label: "Concurrency", Kind: KindInt,
		Min: 1, Max: 64, Default: "4", Help: "Parallel hosts scanned at once."},
	{Key: "naabu_timeout_ms", Tool: "naabu", Label: "Port timeout (ms)", Kind: KindInt,
		Min: 100, Max: 10000, Default: "1000", Help: "How long to wait for a port to answer. Raise it for distant or slow hosts."},
	{Key: "naabu_retries", Tool: "naabu", Label: "Retries", Kind: KindInt,
		Min: 1, Max: 5, Default: "1", Help: "Retries per port. Higher finds more on lossy links, and takes longer."},

	// --- service versions ---
	{Key: "nmap_min_rate", Tool: "nmap", Label: "Minimum rate", Kind: KindInt,
		Min: 100, Max: 50000, Default: "10000", Help: "nmap --min-rate. Applies only to ports naabu already found open."},
	{Key: "nmap_timing", Tool: "nmap", Label: "Timing template", Kind: KindEnum,
		Enum: []string{"T0", "T1", "T2", "T3", "T4", "T5"}, Default: "T4",
		Help: "T0 is paranoid and very slow, T5 is fastest and most likely to be dropped or noticed. T4 is the usual choice."},
	{Key: "nmap_version_intensity", Tool: "nmap", Label: "Version intensity", Kind: KindInt,
		Min: 0, Max: 9, Default: "7", Help: "How hard nmap works to identify a service. 9 tries every probe; 0 only the likeliest."},
	{Key: "nmap_max_retries", Tool: "nmap", Label: "Max retries", Kind: KindInt,
		Min: 0, Max: 10, Default: "3", Help: "Probe retransmissions per port."},

	// --- web discovery ---
	{Key: "katana_depth", Tool: "katana", Label: "Crawl depth", Kind: KindInt,
		Min: 1, Max: 10, Default: "3", Help: "How many links deep to crawl."},
	{Key: "katana_rate_limit", Tool: "katana", Label: "Requests per second", Kind: KindInt,
		Min: 1, Max: 200, Default: "10", Help: "Crawl rate limit."},
	{Key: "katana_concurrency", Tool: "katana", Label: "Concurrency", Kind: KindInt,
		Min: 1, Max: 50, Default: "3", Help: "Parallel fetches while crawling."},
	{Key: "katana_js_crawl", Tool: "katana", Label: "Parse JavaScript", Kind: KindBool,
		Default: "false", Help: "Pull endpoints out of JavaScript files. Finds more on single-page apps; slower."},
	{Key: "katana_max_urls", Tool: "katana", Label: "Max URLs kept", Kind: KindInt,
		Min: 100, Max: 20000, Default: "2000", Help: "Upper bound on crawled URLs carried into directory search."},
	{Key: "httpx_delay_s", Tool: "httpx", Label: "Delay between requests (s)", Kind: KindInt,
		Min: 0, Max: 10, Default: "1", Help: "Politeness delay when probing web services."},
	{Key: "httpx_timeout_s", Tool: "httpx", Label: "Request timeout (s)", Kind: KindInt,
		Min: 1, Max: 120, Default: "10", Help: "Per-request timeout."},
	{Key: "httpx_threads", Tool: "httpx", Label: "Threads", Kind: KindInt,
		Min: 1, Max: 200, Default: "50", Help: "Concurrent probes."},
	{Key: "httpx_retries", Tool: "httpx", Label: "Retries", Kind: KindInt,
		Min: 0, Max: 5, Default: "1", Help: "Retries per endpoint."},
	{Key: "httpx_user_agent", Tool: "httpx", Label: "User-Agent", Kind: KindText,
		Default: iPhoneUA,
		Help: "Sent by every web request the scan makes. The default is a current iPhone Safari string: a mobile browser is the least remarkable thing in a web log, and some sites serve a stripped-down site to anything that looks automated."},
	{Key: "httpx_proxy", Tool: "httpx", Label: "Proxies", Kind: KindProxy,
		Default: "",
		Help: "Route web probing through a proxy. One per line or comma-separated; a task picks one, so a list spreads a scan across several egress addresses. http://, socks4:// and socks5:// are accepted, with optional user:pass@ credentials. Empty means direct."},
	{Key: "httpx_follow_redirects", Tool: "httpx", Label: "Follow redirects", Kind: KindBool,
		Default: "true", Help: "Follow 3xx responses to the final destination. Turn off to record the redirect itself."},

	// --- directory search ---
	{Key: "dir_wordlist", Tool: "gobuster", Label: "Wordlist", Kind: KindWordlist,
		Enum: []string{"common", "dns"}, Default: "common",
		Help: "Which list baked into the worker image to brute-force with. Ignored when a directory wordlist is marked default in the registry, which is delivered to the worker instead."},
	{Key: "dir_concurrency", Tool: "gobuster", Label: "Threads", Kind: KindInt,
		Min: 1, Max: 30, Default: "10", Help: "This is the loudest stage; keep it modest against production hosts."},
	{Key: "dir_exclude_length", Tool: "gobuster", Label: "Exclude response length", Kind: KindInt,
		Min: 0, Max: 1000000, Default: "0", Help: "Filter out uniform-size false positives. 0 disables it."},
	{Key: "dir_extensions", Tool: "gobuster", Label: "Extensions", Kind: KindCSV,
		Default: "", Help: "Try these file extensions on every word, e.g. php,html,bak. Empty means directories only."},
	{Key: "dir_status_codes", Tool: "gobuster", Label: "Status codes", Kind: KindCSV,
		Default: "", Help: "Treat only these responses as hits, e.g. 200,204,301,401. Empty uses gobuster's own defaults."},

	// --- vulnerabilities ---
	{Key: "nuclei_severity", Tool: "nuclei", Label: "Minimum severity", Kind: KindEnum,
		Enum: []string{"all", "info", "low", "medium", "high", "critical"}, Default: "low",
		Help: "Only run templates at or above this severity."},
	{Key: "nuclei_rate_limit", Tool: "nuclei", Label: "Requests per second", Kind: KindInt,
		Min: 1, Max: 500, Default: "150", Help: "Global request rate. Lower it against fragile targets."},
	{Key: "nuclei_concurrency", Tool: "nuclei", Label: "Concurrency", Kind: KindInt,
		Min: 1, Max: 100, Default: "25", Help: "Templates executed in parallel."},
	{Key: "nuclei_timeout_s", Tool: "nuclei", Label: "Request timeout (s)", Kind: KindInt,
		Min: 1, Max: 60, Default: "10", Help: "Per-request timeout."},
}

// ToolOrder is the pipeline order used to group the settings UI.
var ToolOrder = []string{"subfinder", "shuffledns", "dnsx", "naabu", "nmap", "katana", "httpx", "gobuster", "nuclei"}

var specByKey = func() map[string]Spec {
	m := map[string]Spec{}
	for _, s := range Specs {
		m[s.Key] = s
	}
	return m
}()

var portListRe = regexp.MustCompile(`^\d{1,5}(,\d{1,5})*$`)
var portRangeRe = regexp.MustCompile(`^\d{1,5}-\d{1,5}$`)

// Validate checks a raw parameter map and returns a clean, typed copy. Unknown
// keys and invalid values are errors, never silently dropped or forwarded.
func Validate(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range in {
		spec, ok := specByKey[k]
		if !ok {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
		v = strings.TrimSpace(v)
		if err := validateOne(spec, v); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out[k] = v
	}
	return out, nil
}

func validateOne(spec Spec, v string) error {
	switch spec.Kind {
	case KindInt:
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("not an integer")
		}
		if n < spec.Min || n > spec.Max {
			return fmt.Errorf("out of range [%d,%d]", spec.Min, spec.Max)
		}
	case KindBool:
		if v != "true" && v != "false" {
			return fmt.Errorf("must be true or false")
		}
	case KindEnum, KindWordlist:
		for _, e := range spec.Enum {
			if v == e {
				return nil
			}
		}
		return fmt.Errorf("must be one of %v", spec.Enum)
	case KindText:
		if v == "" {
			return nil
		}
		if !textRe.MatchString(v) {
			return fmt.Errorf("must be printable ASCII and may not start with '-'")
		}
		return nil
	case KindProxy:
		return validateProxies(v)
	case KindCSV:
		if v == "" {
			return nil // empty means "leave the tool's own default alone"
		}
		if !csvRe.MatchString(v) {
			return fmt.Errorf("only letters, digits, dot, dash, underscore and commas; cannot start with '-'")
		}
	case KindPorts:
		switch {
		case v == "top-100" || v == "top-1000" || v == "full":
		case portRangeRe.MatchString(v):
		case portListRe.MatchString(v):
		default:
			return fmt.Errorf("bad port spec")
		}
	}
	return nil
}

// Defaults returns the shipped default for every parameter.
func Defaults() map[string]string {
	out := map[string]string{}
	for _, s := range Specs {
		out[s.Key] = s.Default
	}
	return out
}

// WithDefaults fills unset parameters from Tools.md defaults.
func WithDefaults(p map[string]string) map[string]string {
	out := Defaults()
	for k, v := range p {
		out[k] = v
	}
	return out
}

// ParseProxies splits a proxy field into individual proxy URLs. Entries are
// separated by newlines or commas so a list can be pasted from anywhere.
func ParseProxies(v string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(v, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	}) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validateProxies checks every entry of a proxy list. A proxy string becomes a
// process argument and carries credentials, so it is parsed properly rather
// than pattern-matched: scheme must be one this pipeline can actually use, and
// a host and port must be present.
func validateProxies(v string) error {
	list := ParseProxies(v)
	if len(list) == 0 {
		return nil // empty means scan direct
	}
	if len(list) > 64 {
		return fmt.Errorf("at most 64 proxies")
	}
	for _, raw := range list {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("%q is not a URL: %v", raw, err)
		}
		switch u.Scheme {
		case "http", "https", "socks4", "socks5", "socks5h":
		case "":
			return fmt.Errorf("%q needs a scheme, e.g. socks5://%s", raw, raw)
		default:
			return fmt.Errorf("%q: unsupported scheme %q (use http, socks4 or socks5)", raw, u.Scheme)
		}
		if u.Hostname() == "" {
			return fmt.Errorf("%q has no host", raw)
		}
		if u.Port() == "" {
			return fmt.Errorf("%q has no port", raw)
		}
		if strings.ContainsAny(raw, " \t\n\r\"'`$;|&<>") {
			return fmt.Errorf("%q contains characters that are not allowed in a proxy URL", raw)
		}
	}
	return nil
}

// Package scanparams defines the whitelist of user-settable scan parameters and
// validates them. This is the security boundary for configurable scans: every
// value here becomes a process argument on a scan box, so nothing reaches exec
// unless it passed through Validate. Raw user strings are never forwarded.
package scanparams

import (
	"fmt"
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
)

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
	// --- subdomain discovery ---
	{Key: "dns_bruteforce", Tool: "shuffledns", Label: "DNS bruteforce", Kind: KindBool,
		Default: "false", Help: "Brute-force subdomains with a wordlist. High volume; on by default for deep scans."},
	{Key: "dnsx_threads", Tool: "dnsx", Label: "Resolver threads", Kind: KindInt,
		Min: 1, Max: 500, Default: "100", Help: "Concurrent DNS resolutions."},

	// --- port scanning ---
	{Key: "ports", Tool: "naabu", Label: "Port set", Kind: KindPorts,
		Default: "top-100", Help: "top-100, top-1000, full, a range like 1-1024, or a list like 80,443."},
	{Key: "naabu_rate", Tool: "naabu", Label: "Packets per second", Kind: KindInt,
		Min: 1, Max: 1000, Default: "20", Help: "Higher is faster but far more likely to be rate-limited or blocked."},
	{Key: "naabu_concurrency", Tool: "naabu", Label: "Concurrency", Kind: KindInt,
		Min: 1, Max: 64, Default: "4", Help: "Parallel hosts scanned at once."},

	// --- service versions ---
	{Key: "nmap_min_rate", Tool: "nmap", Label: "Minimum rate", Kind: KindInt,
		Min: 100, Max: 50000, Default: "10000", Help: "nmap --min-rate. Applies only to ports naabu already found open."},

	// --- web discovery ---
	{Key: "katana_depth", Tool: "katana", Label: "Crawl depth", Kind: KindInt,
		Min: 1, Max: 10, Default: "3", Help: "How many links deep to crawl."},
	{Key: "katana_rate_limit", Tool: "katana", Label: "Requests per second", Kind: KindInt,
		Min: 1, Max: 200, Default: "10", Help: "Crawl rate limit."},
	{Key: "httpx_delay_s", Tool: "httpx", Label: "Delay between requests (s)", Kind: KindInt,
		Min: 0, Max: 10, Default: "1", Help: "Politeness delay when probing web services."},
	{Key: "httpx_timeout_s", Tool: "httpx", Label: "Request timeout (s)", Kind: KindInt,
		Min: 1, Max: 120, Default: "10", Help: "Per-request timeout."},

	// --- directory search ---
	{Key: "dir_wordlist", Tool: "gobuster", Label: "Wordlist", Kind: KindWordlist,
		Enum: []string{"common", "dns"}, Default: "common", Help: "Which shipped wordlist to brute-force with."},
	{Key: "dir_concurrency", Tool: "gobuster", Label: "Threads", Kind: KindInt,
		Min: 1, Max: 30, Default: "10", Help: "This is the loudest stage; keep it modest against production hosts."},
	{Key: "dir_exclude_length", Tool: "gobuster", Label: "Exclude response length", Kind: KindInt,
		Min: 0, Max: 1000000, Default: "0", Help: "Filter out uniform-size false positives. 0 disables it."},

	// --- vulnerabilities ---
	{Key: "nuclei_severity", Tool: "nuclei", Label: "Minimum severity", Kind: KindEnum,
		Enum: []string{"all", "info", "low", "medium", "high", "critical"}, Default: "low",
		Help: "Only run templates at or above this severity."},
}

// ToolOrder is the pipeline order used to group the settings UI.
var ToolOrder = []string{"shuffledns", "dnsx", "naabu", "nmap", "katana", "httpx", "gobuster", "nuclei"}

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

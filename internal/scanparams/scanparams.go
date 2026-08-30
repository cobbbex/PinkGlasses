// Package scanparams defines the whitelist of user-settable scan parameters and
// validates them. This is the security boundary for Phase 15: every value here
// becomes a process argument on a scan box, so nothing reaches exec unless it
// passed through Validate. Raw user strings are never forwarded.
package scanparams

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind constrains how a parameter value is validated.
type Kind int

const (
	KindInt Kind = iota // integer within [Min, Max]
	KindEnum            // one of Enum
	KindPorts           // "top-100" | "top-1000" | "1-65535" | "80,443,8080"
	KindWordlistID      // a named wordlist key, resolved to a server path
	KindBool
)

// Spec describes one settable parameter.
type Spec struct {
	Key     string
	Kind    Kind
	Min     int
	Max     int
	Enum    []string
	Default string
	Help    string
}

// Specs is the complete, closed set of settable parameters. A key not present
// here is rejected — the UI cannot invent new flags, and neither can a crafted
// API request. Defaults come from Tools.md.
var Specs = []Spec{
	// discovery
	{Key: "dns_bruteforce", Kind: KindBool, Default: "false", Help: "shuffledns bruteforce (deep)"},
	// port scan
	{Key: "ports", Kind: KindPorts, Default: "top-100", Help: "naabu/nmap port set"},
	{Key: "naabu_rate", Kind: KindInt, Min: 1, Max: 1000, Default: "20", Help: "naabu packets/sec"},
	{Key: "naabu_concurrency", Kind: KindInt, Min: 1, Max: 64, Default: "4", Help: "naabu -c"},
	{Key: "nmap_min_rate", Kind: KindInt, Min: 100, Max: 50000, Default: "10000", Help: "nmap --min-rate"},
	// web
	{Key: "katana_depth", Kind: KindInt, Min: 1, Max: 10, Default: "5", Help: "katana -d"},
	{Key: "httpx_delay_s", Kind: KindInt, Min: 0, Max: 10, Default: "1", Help: "httpx -delay seconds"},
	// dir brute
	{Key: "dir_wordlist", Kind: KindWordlistID, Enum: []string{"common", "dns"}, Default: "common", Help: "gobuster/ffuf wordlist"},
	{Key: "dir_exclude_length", Kind: KindInt, Min: 0, Max: 1000000, Default: "0", Help: "gobuster --exclude-length (0=off)"},
	{Key: "dir_concurrency", Kind: KindInt, Min: 1, Max: 30, Default: "10", Help: "dir brute threads"},
	// vuln
	{Key: "nuclei_severity", Kind: KindEnum, Enum: []string{"all", "info", "low", "medium", "high", "critical"}, Default: "low", Help: "min nuclei severity"},
}

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
	case KindEnum, KindWordlistID:
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

// WithDefaults fills unset parameters from Tools.md defaults.
func WithDefaults(p map[string]string) map[string]string {
	out := map[string]string{}
	for _, s := range Specs {
		out[s.Key] = s.Default
	}
	for k, v := range p {
		out[k] = v
	}
	return out
}

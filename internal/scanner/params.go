package scanner

import (
	"strconv"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// params reads a job's validated per-tool overrides with safe defaults. Values
// were whitelisted server-side (internal/scanparams); this is a typed accessor,
// not a second validation layer.
type params struct{ m map[string]string }

func jobParams(job scanproto.Job) params { return params{m: job.Params.Tool} }

func (p params) str(key, def string) string {
	if p.m != nil {
		if v, ok := p.m[key]; ok && v != "" {
			return v
		}
	}
	return def
}

func (p params) intStr(key, def string) string {
	v := p.str(key, def)
	if _, err := strconv.Atoi(v); err != nil {
		return def
	}
	return v
}

func (p params) boolVal(key string, def bool) bool {
	switch p.str(key, "") {
	case "true":
		return true
	case "false":
		return false
	default:
		return def
	}
}

// enabled reports whether a tool may run. Every tool has an on/off switch in
// the scan settings (shuffledns's is "dns_bruteforce", which predates the
// others), and a disabled tool is skipped rather than run and ignored — the
// stage falls back to its pure-Go implementation or contributes nothing.
func (p params) enabled(tool string) bool {
	key := tool + "_enabled"
	if tool == "shuffledns" {
		key = "dns_bruteforce"
	}
	return p.boolVal(key, true)
}

package scanparams

import "testing"

func TestValidate_RejectsUnknownAndInjection(t *testing.T) {
	bad := []map[string]string{
		{"unknown_key": "1"},                       // not in the whitelist
		{"ports": "80; rm -rf /"},                   // command injection
		{"ports": "$(curl evil)"},                   // substitution
		{"ports": "80`whoami`"},                     // backtick
		{"naabu_rate": "9999999"},                   // out of range
		{"naabu_rate": "-1"},                        // negative
		{"naabu_rate": "abc"},                       // not int
		{"nuclei_severity": "critical; drop"},       // enum with payload
		{"dir_wordlist": "/etc/passwd"},             // path instead of id
		{"katana_depth": "50"},                      // over max
	}
	for _, in := range bad {
		if _, err := Validate(in); err == nil {
			t.Errorf("Validate(%v) accepted a bad input", in)
		}
	}
}

func TestValidate_AcceptsGoodValues(t *testing.T) {
	good := map[string]string{
		"ports": "top-1000", "naabu_rate": "20", "nmap_min_rate": "10000",
		"katana_depth": "5", "httpx_delay_s": "1", "dir_wordlist": "common",
		"nuclei_severity": "high", "dns_bruteforce": "true", "dir_exclude_length": "503",
	}
	out, err := Validate(good)
	if err != nil {
		t.Fatalf("Validate rejected valid input: %v", err)
	}
	if len(out) != len(good) {
		t.Fatalf("lost params: got %d want %d", len(out), len(good))
	}
	for _, p := range []string{"top-100", "80,443", "80,443,8080", "1-65535", "full"} {
		if _, err := Validate(map[string]string{"ports": p}); err != nil {
			t.Errorf("ports %q rejected: %v", p, err)
		}
	}
}

func TestWithDefaults(t *testing.T) {
	out := WithDefaults(map[string]string{"naabu_rate": "50"})
	if out["naabu_rate"] != "50" {
		t.Errorf("override lost: %q", out["naabu_rate"])
	}
	if out["ports"] != "top-100" {
		t.Errorf("default missing: %q", out["ports"])
	}
}

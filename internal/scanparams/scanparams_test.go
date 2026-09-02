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

// A proxy string carries credentials and becomes a process argument, so it is
// parsed rather than pattern-matched.
func TestValidateProxies(t *testing.T) {
	good := []string{
		"",
		"socks5://184.178.172.17:4145",
		"socks4://98.182.147.97:4145",
		"http://127.0.0.1:8080",
		"http://user:pass@10.0.0.1:3128",
		"socks5://184.178.172.17:4145\nsocks4://98.182.147.97:4145",
		"socks5://1.2.3.4:1080, http://5.6.7.8:8080",
	}
	for _, v := range good {
		if _, err := Validate(map[string]string{"httpx_proxy": v}); err != nil {
			t.Errorf("rejected valid proxy field %q: %v", v, err)
		}
	}

	bad := []string{
		"184.178.172.17:4145",             // no scheme
		"socks5://184.178.172.17",         // no port
		"ftp://1.2.3.4:21",                // unusable scheme
		"socks5://",                       // no host
		"socks5://1.2.3.4:1080; rm -rf /", // command injection
		"socks5://1.2.3.4:1080 && curl x",
	}
	for _, v := range bad {
		if _, err := Validate(map[string]string{"httpx_proxy": v}); err == nil {
			t.Errorf("accepted bad proxy field %q", v)
		}
	}
}

func TestParseProxies(t *testing.T) {
	got := ParseProxies(" socks5://1.2.3.4:1080\n\nhttp://5.6.7.8:8080 , socks4://9.9.9.9:4145\r\n")
	want := []string{"socks5://1.2.3.4:1080", "http://5.6.7.8:8080", "socks4://9.9.9.9:4145"}
	if len(got) != len(want) {
		t.Fatalf("ParseProxies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseProxies[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The User-Agent becomes one process argument, so it may not start a new flag.
func TestValidateUserAgent(t *testing.T) {
	if _, err := Validate(map[string]string{
		"httpx_user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Safari/604.1",
	}); err != nil {
		t.Errorf("rejected a normal user agent: %v", err)
	}
	for _, bad := range []string{"-oN /tmp/x", "ua\nInjected: header", "ua\x00"} {
		if _, err := Validate(map[string]string{"httpx_user_agent": bad}); err == nil {
			t.Errorf("accepted bad user agent %q", bad)
		}
	}
}

// Every tool must have exactly one switch, and the default must be "on" —
// a scan that silently skips a stage is worse than one that is loud.
func TestEveryToolHasOneEnableSwitch(t *testing.T) {
	switches := map[string]string{}
	for _, s := range Specs {
		if s.Key == s.Tool+"_enabled" || s.Key == "dns_bruteforce" {
			if prev, dup := switches[s.Tool]; dup {
				t.Errorf("%s has two switches: %s and %s", s.Tool, prev, s.Key)
			}
			switches[s.Tool] = s.Key
			if s.Default != "true" {
				t.Errorf("%s defaults to %q, want \"true\"", s.Key, s.Default)
			}
			if s.Kind != KindBool {
				t.Errorf("%s is %q, want bool", s.Key, s.Kind)
			}
		}
	}
	for _, tool := range ToolOrder {
		if _, ok := switches[tool]; !ok {
			t.Errorf("tool %q has no enable switch", tool)
		}
	}
}

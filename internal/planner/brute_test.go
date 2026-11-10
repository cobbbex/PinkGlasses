package planner

import (
	"testing"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// The shuffledns switch decides, in every profile: on by default, off by
// default in a passive run, and switched on there it runs.
func TestBruteForceWanted(t *testing.T) {
	on := map[string]string{"dns_bruteforce": "true"}
	off := map[string]string{"dns_bruteforce": "false"}
	for _, c := range []struct {
		profile domain.RunProfile
		params  map[string]string
		want    bool
	}{
		{domain.ProfileStandard, nil, true},
		{domain.ProfileStandard, on, true},
		{domain.ProfileStandard, off, false},
		{domain.ProfilePassive, nil, false},
		{domain.ProfilePassive, on, true},
		{domain.ProfilePassive, off, false},
	} {
		if got := bruteForceWanted(c.profile, c.params); got != c.want {
			t.Errorf("%s %v: got %v, want %v", c.profile, c.params, got, c.want)
		}
	}
}

func TestPortScanWanted(t *testing.T) {
	for _, c := range []struct {
		params map[string]string
		want   bool
	}{
		{nil, true},
		{map[string]string{"naabu_enabled": "false"}, true},
		{map[string]string{"nmap_enabled": "false"}, true},
		{map[string]string{"naabu_enabled": "false", "nmap_enabled": "false"}, false},
	} {
		if got := portScanWanted(c.params); got != c.want {
			t.Errorf("%v: got %v, want %v", c.params, got, c.want)
		}
	}
}

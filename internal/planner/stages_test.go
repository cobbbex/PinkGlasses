package planner

import "testing"

// The run page must not show a stage the person switched off. dir_brute is
// two tools behind one stage, so it goes only when both are off; vuln_check
// is nuclei alone. Missing keys mean the shipped defaults, which are on.
func TestPostProbeStagesFollowTheSwitches(t *testing.T) {
	cases := []struct {
		name              string
		params            map[string]string
		wantDir, wantVuln bool
	}{
		{"defaults", map[string]string{}, true, true},
		{"nil params", nil, true, true},
		{"brute force off, crawl on: stage stays for the crawl", map[string]string{"gobuster_enabled": "false"}, true, true},
		{"crawl off, brute force on", map[string]string{"katana_enabled": "false"}, true, true},
		{"both off: no directory stage", map[string]string{"gobuster_enabled": "false", "katana_enabled": "false"}, false, true},
		{"nuclei off", map[string]string{"nuclei_enabled": "false"}, true, false},
		{"everything off", map[string]string{"gobuster_enabled": "false", "katana_enabled": "false", "nuclei_enabled": "false"}, false, false},
		{"explicit on", map[string]string{"gobuster_enabled": "true", "katana_enabled": "true", "nuclei_enabled": "true"}, true, true},
	}
	for _, c := range cases {
		dir, vuln := postProbeStages(c.params)
		if dir != c.wantDir || vuln != c.wantVuln {
			t.Errorf("%s: dir_brute=%v vuln_check=%v, want %v %v", c.name, dir, vuln, c.wantDir, c.wantVuln)
		}
	}
}

package scanparams

import "testing"

func TestCSVRejectsFlagInjection(t *testing.T) {
	bad := []string{"-oN /tmp/x", "--script=http-shellshock", "php;rm -rf /", "a b", "../../etc/passwd", "-x"}
	for _, v := range bad {
		if _, err := Validate(map[string]string{"dir_extensions": v}); err == nil {
			t.Errorf("accepted dangerous value %q", v)
		}
	}
	good := []string{"", "php,html,bak", "200,301,401"}
	for _, v := range good {
		if _, err := Validate(map[string]string{"dir_extensions": v}); err != nil {
			t.Errorf("rejected safe value %q: %v", v, err)
		}
	}
}

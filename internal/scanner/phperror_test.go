package scanner

import (
	"strings"
	"testing"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

func TestPHPErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []phpError
	}{
		{"classic html warning",
			"<br />\n<b>Warning</b>:  include(config.php): Failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>12</b><br />",
			[]phpError{{"Warning", "include(config.php): Failed to open stream: No such file or directory", "/var/www/html/index.php", "12"}}},
		{"uncaught exception, php 8",
			"PHP Fatal error:  Uncaught Error: Call to undefined function mysql_connect() in /home/acme/public_html/db.php:7\nStack trace:\n#0 {main}",
			[]phpError{{"Fatal error", "Uncaught Error: Call to undefined function mysql_connect()", "/home/acme/public_html/db.php", "7"}}},
		{"windows path",
			"<b>Notice</b>: Undefined variable: id in <b>C:\\inetpub\\wwwroot\\shop\\cart.php</b> on line <b>88</b>",
			[]phpError{{"Notice", "Undefined variable: id", `C:\inetpub\wwwroot\shop\cart.php`, "88"}}},
		{"html entities in the message",
			"<b>Deprecated</b>: Function create_function() is deprecated in <b>/srv/app/lib/old.inc</b> on line <b>3</b>",
			[]phpError{{"Deprecated", "Function create_function() is deprecated", "/srv/app/lib/old.inc", "3"}}},
		{"prose that says warning", "<p>Warning: the office is closed in December, on line 3 of the rota.</p>", nil},
		{"a page about php errors without a path", "Fatal error: something in somefile on line 3", nil},
		{"nothing", "<html><title>Welcome</title></html>", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := phpErrors(c.body)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("error %d: got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// One page with errors is one finding, carrying the URL and the first error,
// plus PHP as a technology.
func TestPHPErrorObservations(t *testing.T) {
	errs := phpErrors("<b>Warning</b>: a in <b>/var/www/a.php</b> on line <b>1</b>\n<b>Warning</b>: b in <b>/var/www/b.php</b> on line <b>2</b>")
	obs := phpErrorObservations("192.0.2.1", 443, "shop.example.org", "https://shop.example.org/", errs)
	if len(obs) != 2 || obs[0].Type != scanproto.ObsFinding || obs[1].TechName != "PHP" {
		t.Fatalf("observations %+v", obs)
	}
	f := obs[0]
	if f.FindingKind != "php_error_disclosure" || f.FindingSeverity != "low" {
		t.Errorf("finding %+v", f)
	}
	if !strings.Contains(f.Banner, "https://shop.example.org/") || !strings.Contains(f.Banner, "/var/www/a.php on line 1") ||
		!strings.HasSuffix(f.Banner, "(+1 more)") {
		t.Errorf("evidence %q", f.Banner)
	}
}
